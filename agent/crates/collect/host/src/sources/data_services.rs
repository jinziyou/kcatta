//! Metadata-only discovery of databases, message brokers, and caches.

use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::io;
use std::path::Path;
use std::process::{Command, Stdio};

use agent_contract::{
    Asset, DataMetadataCoverage, DataMetadataStatus, DataObject, DataPrincipal, DataService,
    DataServiceCategory, NetworkService, Package, ProcessAsset, Service,
};
use walkdir::WalkDir;

use crate::root::join_root;
use crate::ScanContext;

const MAX_CONFIG_PATHS: usize = 32;

/// Same-pass diagnostics for filesystem/config evidence used by data services.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct DataServiceCoverage {
    source_incomplete: bool,
}

impl DataServiceCoverage {
    pub(crate) fn source_incomplete(self) -> bool {
        self.source_incomplete
    }
}

pub(crate) fn config_path_limit_reached<'a>(
    assets: impl IntoIterator<Item = &'a Asset>,
    category: DataServiceCategory,
) -> bool {
    assets.into_iter().any(|asset| {
        matches!(
            asset,
            Asset::DataService(service)
                if service.category == category && service.config_paths.len() >= MAX_CONFIG_PATHS
        )
    })
}

#[derive(Clone, Copy)]
struct Product {
    category: DataServiceCategory,
    engine: &'static str,
}

/// Discover live/configured stateful services without authenticating or reading records.
#[allow(dead_code)] // Compatibility wrapper for crate-local callers outside the scan runner.
pub fn collect(
    ctx: &ScanContext,
    processes: &[Asset],
    network_services: &[Asset],
    services: &[Asset],
    packages: &[Asset],
) -> Vec<Asset> {
    collect_with_coverage(ctx, processes, network_services, services, packages).0
}

/// Discover data services and retain read/parse failures from the same pass.
pub(crate) fn collect_with_coverage(
    ctx: &ScanContext,
    processes: &[Asset],
    network_services: &[Asset],
    services: &[Asset],
    packages: &[Asset],
) -> (Vec<Asset>, DataServiceCoverage) {
    let mut coverage = DataServiceCoverage::default();
    let package_versions = package_versions(packages);
    let networks: Vec<&NetworkService> = network_services
        .iter()
        .filter_map(|asset| match asset {
            Asset::NetworkService(value) => Some(value),
            _ => None,
        })
        .collect();
    let process_products: HashMap<u32, Product> = processes
        .iter()
        .filter_map(|asset| match asset {
            Asset::Process(process) => {
                identify_process(process).map(|product| (process.pid, product))
            }
            _ => None,
        })
        .collect();
    let mut found: Vec<DataService> = Vec::new();
    for asset in processes {
        let Asset::Process(process) = asset else {
            continue;
        };
        let Some(product) = identify_process(process) else {
            continue;
        };
        let parent_is_same_product = process
            .ppid
            .and_then(|ppid| process_products.get(&ppid))
            .is_some_and(|parent| parent.engine == product.engine);
        if !parent_is_same_product {
            found.push(from_process(
                ctx,
                process,
                product,
                &networks,
                &package_versions,
                &mut coverage,
            ));
        }
    }

    // Configured services remain useful evidence even if their live process is
    // absent/unreadable, but they must not be represented as running.
    for service in services.iter().filter_map(|asset| match asset {
        Asset::Service(value) => Some(value),
        _ => None,
    }) {
        let Some(product) = identify_text(&service.name, service.exec_path.as_deref()) else {
            continue;
        };
        if found.iter().any(|row| row.engine == product.engine) {
            continue;
        }
        found.push(from_service(
            ctx,
            service,
            product,
            &package_versions,
            &mut coverage,
        ));
    }

    found.sort_by(|left, right| {
        left.engine
            .cmp(&right.engine)
            .then(left.process_asset_id.cmp(&right.process_asset_id))
    });
    found.dedup_by(|left, right| left.engine == right.engine && left.endpoints == right.endpoints);
    (
        found.into_iter().map(Asset::DataService).collect(),
        coverage,
    )
}

fn identify_process(process: &ProcessAsset) -> Option<Product> {
    identify_text(&process.name, process.command_line.as_deref())
}

fn identify_text(name: &str, detail: Option<&str>) -> Option<Product> {
    let text = format!(
        "{} {}",
        name.to_ascii_lowercase(),
        detail.unwrap_or("").to_ascii_lowercase()
    );
    let database = |engine| Product {
        category: DataServiceCategory::Database,
        engine,
    };
    let queue = |engine| Product {
        category: DataServiceCategory::MessageQueue,
        engine,
    };
    let cache = |engine| Product {
        category: DataServiceCategory::Cache,
        engine,
    };
    if text.contains("postgres") || text.contains("postmaster") {
        Some(database("postgresql"))
    } else if text.contains("mariadbd") {
        Some(database("mariadb"))
    } else if text.contains("mysqld") {
        Some(database("mysql"))
    } else if text.contains("mongod") {
        Some(database("mongodb"))
    } else if text.contains("clickhouse-server") {
        Some(database("clickhouse"))
    } else if text.contains("neo4j") {
        Some(database("neo4j"))
    } else if text.contains("rabbitmq") || (text.contains("beam.smp") && text.contains("rabbit")) {
        Some(queue("rabbitmq"))
    } else if text.contains("kafka.kafka") || text.contains("kafka-server-start") {
        Some(queue("kafka"))
    } else if text.contains("nats-server") {
        Some(queue("nats"))
    } else if text.contains("pulsar") {
        Some(queue("pulsar"))
    } else if text.contains("mqnamesrv") || text.contains("mqbroker") || text.contains("rocketmq") {
        Some(queue("rocketmq"))
    } else if text.contains("redis-server") || text.contains("keydb-server") {
        Some(cache(if text.contains("keydb") {
            "keydb"
        } else {
            "redis"
        }))
    } else {
        None
    }
}

fn from_process(
    ctx: &ScanContext,
    process: &ProcessAsset,
    product: Product,
    networks: &[&NetworkService],
    package_versions: &HashMap<String, String>,
    coverage: &mut DataServiceCoverage,
) -> DataService {
    let related: Vec<&NetworkService> = networks
        .iter()
        .copied()
        .filter(|network| {
            network.process_asset_id.as_deref() == Some(process.asset_id.as_str())
                || (network.process_asset_id.is_none()
                    && network
                        .process_name
                        .as_deref()
                        .is_some_and(|name| name.eq_ignore_ascii_case(&process.name)))
        })
        .collect();
    let data_paths = discover_data_paths(process, product.engine);
    let mut config_paths = discover_config_paths(ctx, product.engine, coverage);
    config_paths.extend(discover_data_config_paths(
        ctx,
        product.engine,
        &data_paths,
        coverage,
    ));
    config_paths.sort();
    config_paths.dedup();
    config_paths.truncate(MAX_CONFIG_PATHS);
    let postgres = (product.engine == "postgresql")
        .then(|| postgres_security(ctx, &config_paths, coverage))
        .flatten();
    let (principals, principal_coverage, objects, object_coverage) =
        if product.engine == "postgresql" {
            postgres_catalog(process, coverage)
        } else {
            unsupported_catalog()
        };
    let version = lookup_version(package_versions, product.engine)
        .or_else(|| data_version(ctx, product.engine, &data_paths, coverage));
    DataService {
        asset_id: format!("data-service-{}-{}", product.engine, process.pid),
        parent_asset_id: None,
        category: product.category,
        engine: product.engine.to_string(),
        version,
        process_asset_id: Some(process.asset_id.clone()),
        network_service_ids: related.iter().map(|row| row.asset_id.clone()).collect(),
        endpoints: related
            .iter()
            .map(|row| format!("{}://{}:{}", proto(row), row.listen_addr, row.port))
            .collect(),
        config_paths,
        data_paths,
        tls_enabled: postgres.as_ref().and_then(|state| state.ssl),
        authentication_enabled: postgres.as_ref().and_then(|state| state.authentication),
        anonymous_access: postgres.as_ref().and_then(|state| state.trust),
        audit_enabled: postgres.as_ref().and_then(|state| state.audit),
        replication_enabled: postgres.as_ref().and_then(|state| state.replication),
        backup_enabled: None,
        principals,
        principal_coverage,
        objects,
        object_coverage,
        discovery_source: "process+listener+config".to_string(),
    }
}

fn from_service(
    ctx: &ScanContext,
    service: &Service,
    product: Product,
    package_versions: &HashMap<String, String>,
    coverage: &mut DataServiceCoverage,
) -> DataService {
    DataService {
        asset_id: format!("data-service-{}-configured", product.engine),
        parent_asset_id: None,
        category: product.category,
        engine: product.engine.to_string(),
        version: lookup_version(package_versions, product.engine),
        process_asset_id: None,
        network_service_ids: Vec::new(),
        endpoints: Vec::new(),
        config_paths: discover_config_paths(ctx, product.engine, coverage),
        data_paths: Vec::new(),
        tls_enabled: None,
        authentication_enabled: None,
        anonymous_access: None,
        audit_enabled: None,
        replication_enabled: None,
        backup_enabled: None,
        principals: Vec::new(),
        principal_coverage: DataMetadataCoverage {
            status: DataMetadataStatus::Unavailable,
            record_count: 0,
            reason: Some("runtime_service_not_running".to_string()),
        },
        objects: Vec::new(),
        object_coverage: DataMetadataCoverage {
            status: DataMetadataStatus::Unavailable,
            record_count: 0,
            reason: Some("runtime_service_not_running".to_string()),
        },
        discovery_source: format!("service:{}", service.name),
    }
}

fn unsupported_catalog() -> (
    Vec<DataPrincipal>,
    DataMetadataCoverage,
    Vec<DataObject>,
    DataMetadataCoverage,
) {
    (
        Vec::new(),
        DataMetadataCoverage {
            status: DataMetadataStatus::Unsupported,
            record_count: 0,
            reason: Some("safe_runtime_principal_connector_unavailable".to_string()),
        },
        Vec::new(),
        DataMetadataCoverage {
            status: DataMetadataStatus::Unsupported,
            record_count: 0,
            reason: Some("safe_runtime_object_connector_unavailable".to_string()),
        },
    )
}

fn postgres_catalog(
    process: &ProcessAsset,
    coverage: &mut DataServiceCoverage,
) -> (
    Vec<DataPrincipal>,
    DataMetadataCoverage,
    Vec<DataObject>,
    DataMetadataCoverage,
) {
    let Some(psql) = process
        .exe_path
        .as_deref()
        .and_then(|path| Path::new(path).parent())
        .map(|parent| parent.join("psql"))
        .filter(|path| path.is_file())
    else {
        return (
            Vec::new(),
            DataMetadataCoverage {
                status: DataMetadataStatus::Unavailable,
                record_count: 0,
                reason: Some("postgres_client_unavailable".to_string()),
            },
            Vec::new(),
            DataMetadataCoverage {
                status: DataMetadataStatus::Unavailable,
                record_count: 0,
                reason: Some("postgres_client_unavailable".to_string()),
            },
        );
    };
    let users: Vec<&str> = process
        .username
        .as_deref()
        .into_iter()
        .chain(["postgres"])
        .collect();
    let roles_query = concat!(
        "SELECT json_build_object(",
        "'name',r.rolname,'can_login',r.rolcanlogin,'privileged',r.rolsuper,",
        "'replication',r.rolreplication,'member_of',COALESCE((",
        "SELECT json_agg(parent.rolname ORDER BY parent.rolname) ",
        "FROM pg_auth_members m JOIN pg_roles parent ON parent.oid=m.roleid ",
        "WHERE m.member=r.oid),'[]'::json))::text ",
        "FROM pg_roles r ORDER BY r.rolname LIMIT 64"
    );
    let objects_query = concat!(
        "SELECT json_build_object(",
        "'name',d.datname,'object_type','database',",
        "'owner',pg_get_userbyid(d.datdba),'access_enabled',d.datallowconn,",
        "'connection_limit',d.datconnlimit,",
        "'acl_entry_count',COALESCE(cardinality(d.datacl),0))::text ",
        "FROM pg_database d WHERE NOT d.datistemplate ORDER BY d.datname LIMIT 64"
    );
    let role_rows = postgres_query(&psql, &users, roles_query);
    let object_rows = postgres_query(&psql, &users, objects_query);
    let principals = role_rows
        .as_ref()
        .map(|rows| {
            rows.iter()
                .filter_map(|row| match serde_json::from_str::<DataPrincipal>(row) {
                    Ok(principal) => Some(principal),
                    Err(_) => {
                        coverage.source_incomplete = true;
                        None
                    }
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let objects = object_rows
        .as_ref()
        .map(|rows| {
            rows.iter()
                .filter_map(|row| match serde_json::from_str::<DataObject>(row) {
                    Ok(object) => Some(object),
                    Err(_) => {
                        coverage.source_incomplete = true;
                        None
                    }
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let coverage = |available: bool, count: usize, label: &str| DataMetadataCoverage {
        status: if available {
            DataMetadataStatus::Complete
        } else {
            DataMetadataStatus::NotAuthorized
        },
        record_count: count,
        reason: (!available).then(|| format!("postgres_{label}_catalog_access_denied")),
    };
    (
        principals.clone(),
        coverage(role_rows.is_some(), principals.len(), "principal"),
        objects.clone(),
        coverage(object_rows.is_some(), objects.len(), "object"),
    )
}

fn postgres_query(psql: &Path, users: &[&str], query: &str) -> Option<Vec<String>> {
    for user in users {
        let output = Command::new(psql)
            .args([
                "-X",
                "-w",
                "-q",
                "-A",
                "-t",
                "-v",
                "ON_ERROR_STOP=1",
                "-U",
                user,
                "-d",
                "postgres",
                "-c",
                query,
            ])
            .env_remove("PGPASSWORD")
            .env_remove("PGPASSFILE")
            .env_remove("PGHOST")
            .env_remove("PGPORT")
            .env_remove("PGUSER")
            .env_remove("PGDATABASE")
            .env_remove("PGSERVICE")
            .env_remove("PGSERVICEFILE")
            .env("PGCONNECT_TIMEOUT", "2")
            .env(
                "PGOPTIONS",
                "-c statement_timeout=3000 -c default_transaction_read_only=on",
            )
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .ok()?;
        if output.status.success() && output.stdout.len() <= 1024 * 1024 {
            let text = String::from_utf8(output.stdout).ok()?;
            return Some(
                text.lines()
                    .filter(|line| !line.trim().is_empty())
                    .map(str::to_string)
                    .collect(),
            );
        }
    }
    None
}

fn proto(network: &NetworkService) -> &'static str {
    match network.proto {
        agent_contract::PortProto::Tcp => "tcp",
        agent_contract::PortProto::Udp => "udp",
    }
}

fn package_versions(packages: &[Asset]) -> HashMap<String, String> {
    packages
        .iter()
        .filter_map(|asset| match asset {
            Asset::Package(Package { name, version, .. }) => {
                Some((name.to_ascii_lowercase(), version.clone()))
            }
            _ => None,
        })
        .collect()
}

fn lookup_version(packages: &HashMap<String, String>, engine: &str) -> Option<String> {
    let aliases: Vec<&str> = match engine {
        "postgresql" => vec!["postgresql", "postgresql-server"],
        "mysql" => vec!["mysql-server", "mysql-community-server"],
        "mariadb" => vec!["mariadb-server"],
        "mongodb" => vec!["mongodb-org-server", "mongodb-server"],
        "rabbitmq" => vec!["rabbitmq-server"],
        "redis" => vec!["redis"],
        "kafka" => vec!["kafka"],
        other => vec![other],
    };
    aliases
        .into_iter()
        .find_map(|name| packages.get(name).cloned())
}

fn discover_config_paths(
    ctx: &ScanContext,
    engine: &str,
    coverage: &mut DataServiceCoverage,
) -> Vec<String> {
    let roots: &[&str] = match engine {
        "postgresql" => &["etc/postgresql", "var/lib/pgsql"],
        "mysql" | "mariadb" => &["etc/my.cnf", "etc/my.cnf.d", "etc/mysql"],
        "mongodb" => &["etc/mongod.conf", "etc/mongodb.conf"],
        "redis" | "keydb" => &["etc/redis", "etc/redis.conf", "etc/keydb"],
        "rabbitmq" => &["etc/rabbitmq"],
        "kafka" => &["etc/kafka", "opt/kafka/config"],
        "nats" => &["etc/nats"],
        "pulsar" => &["etc/pulsar", "opt/pulsar/conf"],
        "rocketmq" => &["etc/rocketmq", "opt/rocketmq/conf"],
        "clickhouse" => &["etc/clickhouse-server"],
        "neo4j" => &["etc/neo4j"],
        _ => &[],
    };
    let mut paths = BTreeSet::new();
    for relative in roots {
        let path = join_root(ctx, relative);
        let Some(metadata) = optional_metadata(&path, coverage) else {
            continue;
        };
        if metadata.file_type().is_file() && is_config_path(engine, &path) {
            paths.insert(display_path(ctx, &path));
            continue;
        }
        if !metadata.file_type().is_dir() {
            continue;
        }
        for item in WalkDir::new(&path)
            .follow_links(false)
            .max_depth(4)
            .into_iter()
        {
            let entry = match item {
                Ok(entry) => entry,
                Err(_) => {
                    coverage.source_incomplete = true;
                    continue;
                }
            };
            if !entry.file_type().is_file() || !is_config_path(engine, entry.path()) {
                continue;
            }
            if paths.len() >= MAX_CONFIG_PATHS {
                break;
            }
            paths.insert(display_path(ctx, entry.path()));
        }
    }
    paths.into_iter().take(MAX_CONFIG_PATHS).collect()
}

fn is_config_path(engine: &str, path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
        return false;
    };
    let name = name.to_ascii_lowercase();
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    match engine {
        "postgresql" => matches!(
            name.as_str(),
            "postgresql.conf" | "postgresql.auto.conf" | "pg_hba.conf" | "pg_ident.conf"
        ),
        "mysql" | "mariadb" => name == "my.cnf" || matches!(extension.as_str(), "cnf" | "conf"),
        "mongodb" => matches!(name.as_str(), "mongod.conf" | "mongodb.conf"),
        "redis" | "keydb" => matches!(extension.as_str(), "conf" | "acl"),
        "rabbitmq" => {
            matches!(
                name.as_str(),
                "rabbitmq.conf" | "advanced.config" | "enabled_plugins"
            ) || matches!(extension.as_str(), "conf" | "config")
        }
        "kafka" | "nats" | "pulsar" | "rocketmq" => {
            matches!(
                extension.as_str(),
                "conf" | "config" | "properties" | "yaml" | "yml" | "json"
            )
        }
        "clickhouse" => matches!(extension.as_str(), "xml" | "conf"),
        "neo4j" => extension == "conf",
        _ => false,
    }
}

fn discover_data_paths(process: &ProcessAsset, engine: &str) -> Vec<String> {
    let Some(command) = process.command_line.as_deref() else {
        return Vec::new();
    };
    let mut paths = BTreeSet::new();
    let args: Vec<&str> = command.split_whitespace().collect();
    for (index, arg) in args.iter().enumerate() {
        if matches!(*arg, "-D" | "--datadir" | "--dbpath" | "--dir") {
            if let Some(value) = args.get(index + 1).filter(|value| value.starts_with('/')) {
                paths.insert((*value).to_string());
            }
        }
        for prefix in ["--datadir=", "--dbpath=", "--dir="] {
            if let Some(value) = arg
                .strip_prefix(prefix)
                .filter(|value| value.starts_with('/'))
            {
                paths.insert(value.to_string());
            }
        }
    }
    if paths.is_empty() && engine == "postgresql" {
        paths.insert("/var/lib/pgsql/data".to_string());
    }
    paths.into_iter().collect()
}

fn discover_data_config_paths(
    ctx: &ScanContext,
    engine: &str,
    data_paths: &[String],
    coverage: &mut DataServiceCoverage,
) -> Vec<String> {
    let filenames: &[&str] = match engine {
        "postgresql" => &[
            "postgresql.conf",
            "postgresql.auto.conf",
            "pg_hba.conf",
            "pg_ident.conf",
        ],
        _ => &[],
    };
    let mut paths = Vec::new();
    for data_path in data_paths {
        let base = join_root(ctx, data_path.trim_start_matches('/'));
        for filename in filenames {
            let path = base.join(filename);
            if optional_metadata(&path, coverage)
                .is_some_and(|metadata| metadata.file_type().is_file())
                && is_config_path(engine, &path)
            {
                paths.push(display_path(ctx, &path));
            }
        }
    }
    paths
}

fn data_version(
    ctx: &ScanContext,
    engine: &str,
    data_paths: &[String],
    coverage: &mut DataServiceCoverage,
) -> Option<String> {
    if engine != "postgresql" {
        return None;
    }
    for data_path in data_paths {
        let path = join_root(ctx, data_path.trim_start_matches('/')).join("PG_VERSION");
        let Some(metadata) = optional_metadata(&path, coverage) else {
            continue;
        };
        if !metadata.file_type().is_file() {
            continue;
        }
        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(_) => {
                coverage.source_incomplete = true;
                continue;
            }
        };
        if bytes.len() > 64 {
            coverage.source_incomplete = true;
            continue;
        }
        let Ok(text) = String::from_utf8(bytes) else {
            coverage.source_incomplete = true;
            continue;
        };
        let value = text.trim().to_string();
        if !value.is_empty() && value.chars().all(|ch| ch.is_ascii_digit() || ch == '.') {
            return Some(value);
        }
        coverage.source_incomplete = true;
    }
    None
}

fn optional_metadata(path: &Path, coverage: &mut DataServiceCoverage) -> Option<fs::Metadata> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Some(metadata),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(_) => {
            coverage.source_incomplete = true;
            None
        }
    }
}

fn display_path(ctx: &ScanContext, path: &Path) -> String {
    let relative = path.strip_prefix(&ctx.scan_root).unwrap_or(path);
    format!("/{}", relative.to_string_lossy().trim_start_matches('/'))
}

#[derive(Default)]
struct PostgresSecurity {
    ssl: Option<bool>,
    authentication: Option<bool>,
    trust: Option<bool>,
    audit: Option<bool>,
    replication: Option<bool>,
}

fn postgres_security(
    ctx: &ScanContext,
    config_paths: &[String],
    coverage: &mut DataServiceCoverage,
) -> Option<PostgresSecurity> {
    let mut state = PostgresSecurity::default();
    let mut inspected = false;
    for display in config_paths {
        let path = join_root(ctx, display.trim_start_matches('/'));
        let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
            coverage.source_incomplete = true;
            continue;
        };
        let Ok(text) = fs::read_to_string(&path) else {
            coverage.source_incomplete = true;
            continue;
        };
        if text.len() > 4 * 1024 * 1024 {
            coverage.source_incomplete = true;
            continue;
        }
        inspected = true;
        if name == "postgresql.conf" {
            state.ssl = parse_bool_setting(&text, "ssl");
            if setting_value(&text, "ssl").is_some() && state.ssl.is_none() {
                coverage.source_incomplete = true;
            }
            state.audit = Some(
                setting_value(&text, "shared_preload_libraries")
                    .is_some_and(|value| value.to_ascii_lowercase().contains("pgaudit")),
            );
            state.replication = Some(
                setting_value(&text, "primary_conninfo").is_some()
                    || setting_value(&text, "primary_slot_name").is_some(),
            );
        } else if name == "pg_hba.conf" {
            let mut methods = Vec::new();
            for line in text.lines().map(str::trim) {
                let line = line.split('#').next().unwrap_or("").trim();
                if line.is_empty() {
                    continue;
                }
                let fields: Vec<&str> = line.split_whitespace().collect();
                if fields.len() < 4 {
                    coverage.source_incomplete = true;
                    continue;
                }
                methods.push(*fields.last().expect("non-empty fields"));
            }
            if !methods.is_empty() {
                state.trust = Some(methods.contains(&"trust"));
                state.authentication = Some(methods.iter().any(|method| *method != "trust"));
                state.replication = Some(
                    state.replication.unwrap_or(false)
                        || text.lines().any(|line| {
                            let line = line.trim();
                            !line.starts_with('#')
                                && line.split_whitespace().any(|field| field == "replication")
                        }),
                );
            }
        }
    }
    inspected.then_some(state)
}

fn setting_value<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    text.lines().find_map(|line| {
        let line = line.trim();
        if line.starts_with('#') {
            return None;
        }
        let (name, value) = line.split_once('=')?;
        (name.trim() == key).then(|| value.trim().trim_matches('\'').trim_matches('"'))
    })
}

fn parse_bool_setting(text: &str, key: &str) -> Option<bool> {
    match setting_value(text, key)?.to_ascii_lowercase().as_str() {
        "on" | "true" | "yes" | "1" => Some(true),
        "off" | "false" | "no" | "0" => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_contract::{PortProto, ProcessAsset};

    fn postgres_process() -> Asset {
        Asset::Process(ProcessAsset {
            asset_id: "process-42".to_string(),
            parent_asset_id: None,
            pid: 42,
            ppid: Some(1),
            name: "postgres".to_string(),
            exe_path: Some("/usr/bin/postgres".to_string()),
            executable_sha256: None,
            uid: Some(26),
            username: Some("postgres".to_string()),
            command_line: Some("postgres -D /var/lib/pgsql/data".to_string()),
            command_line_redacted: false,
            systemd_unit: Some("postgresql.service".to_string()),
            container_id: None,
            started_at: None,
        })
    }

    #[test]
    fn discovers_postgres_without_reading_database_rows() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        fs::create_dir_all(root.join("var/lib/pgsql/data")).unwrap();
        fs::write(
            root.join("var/lib/pgsql/data/postgresql.conf"),
            "ssl = on\nshared_preload_libraries = 'pgaudit'\n",
        )
        .unwrap();
        fs::write(
            root.join("var/lib/pgsql/data/pg_hba.conf"),
            "host all all 10.0.0.0/8 scram-sha-256\n",
        )
        .unwrap();
        fs::write(root.join("var/lib/pgsql/data/PG_VERSION"), "17\n").unwrap();
        fs::create_dir_all(root.join("var/lib/pgsql/data/base/1")).unwrap();
        fs::write(
            root.join("var/lib/pgsql/data/base/1/16384"),
            b"database bytes",
        )
        .unwrap();
        let mut processes = vec![Asset::Process(ProcessAsset {
            asset_id: "process-42".to_string(),
            parent_asset_id: None,
            pid: 42,
            ppid: Some(1),
            name: "postgres".to_string(),
            exe_path: Some("/usr/bin/postgres".to_string()),
            executable_sha256: None,
            uid: Some(26),
            username: Some("postgres".to_string()),
            command_line: Some("postgres -D /var/lib/pgsql/data".to_string()),
            command_line_redacted: false,
            systemd_unit: Some("postgresql.service".to_string()),
            container_id: None,
            started_at: None,
        })];
        processes.push(Asset::Process(ProcessAsset {
            asset_id: "process-43".to_string(),
            parent_asset_id: None,
            pid: 43,
            ppid: Some(42),
            name: "postgres".to_string(),
            exe_path: Some("/usr/bin/postgres".to_string()),
            executable_sha256: None,
            uid: Some(26),
            username: Some("postgres".to_string()),
            command_line: Some("postgres: io worker 0".to_string()),
            command_line_redacted: false,
            systemd_unit: Some("postgresql.service".to_string()),
            container_id: None,
            started_at: None,
        }));
        let networks = vec![Asset::NetworkService(NetworkService {
            asset_id: "network-service-port-5432".to_string(),
            parent_asset_id: None,
            proto: PortProto::Tcp,
            port: 5432,
            listen_addr: "127.0.0.1".to_string(),
            port_asset_id: "port-5432".to_string(),
            process_asset_id: Some("process-42".to_string()),
            service_asset_id: Some("svc-postgresql".to_string()),
            process_name: Some("postgres".to_string()),
            exe_path: Some("/usr/bin/postgres".to_string()),
            executable_sha256: None,
            uid: Some(26),
            username: Some("postgres".to_string()),
            systemd_unit: Some("postgresql.service".to_string()),
            container_id: None,
            package_name: Some("postgresql-server".to_string()),
        })];
        let rows = collect(&ScanContext::at(root), &processes, &networks, &[], &[]);
        assert_eq!(rows.len(), 1, "worker processes are not separate instances");
        let Asset::DataService(postgres) = &rows[0] else {
            panic!("expected data service");
        };
        assert_eq!(postgres.engine, "postgresql");
        assert_eq!(postgres.version.as_deref(), Some("17"));
        assert_eq!(postgres.tls_enabled, Some(true));
        assert_eq!(postgres.authentication_enabled, Some(true));
        assert_eq!(postgres.anonymous_access, Some(false));
        assert_eq!(postgres.audit_enabled, Some(true));
        assert!(postgres
            .config_paths
            .iter()
            .any(|path| path.ends_with("pg_hba.conf")));
        assert!(
            !postgres
                .config_paths
                .iter()
                .any(|path| path.ends_with("16384")),
            "database relation files must never be reported as configuration"
        );
    }

    #[test]
    fn coverage_marks_config_walk_read_and_parse_failures() {
        let traversal = tempfile::tempdir().unwrap();
        fs::write(traversal.path().join("etc"), b"not a directory").unwrap();
        let (rows, coverage) = collect_with_coverage(
            &ScanContext::at(traversal.path()),
            &[postgres_process()],
            &[],
            &[],
            &[],
        );
        assert_eq!(rows.len(), 1);
        assert!(coverage.source_incomplete());

        let config = tempfile::tempdir().unwrap();
        fs::create_dir_all(config.path().join("var/lib/pgsql/data")).unwrap();
        let config_path = config.path().join("var/lib/pgsql/data/postgresql.conf");
        fs::write(&config_path, [0xff, 0xfe]).unwrap();
        let (_, coverage) = collect_with_coverage(
            &ScanContext::at(config.path()),
            &[postgres_process()],
            &[],
            &[],
            &[],
        );
        assert!(coverage.source_incomplete());

        fs::write(&config_path, "ssl = definitely\n").unwrap();
        let (_, coverage) = collect_with_coverage(
            &ScanContext::at(config.path()),
            &[postgres_process()],
            &[],
            &[],
            &[],
        );
        assert!(coverage.source_incomplete());
    }
}
