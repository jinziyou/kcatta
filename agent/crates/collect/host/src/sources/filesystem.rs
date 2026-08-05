//! Filesystem-backed inventory source.
//!
//! One filesystem pass owns all readers whose truth comes from files under the
//! scan root. It emits the host descriptor first, followed by independent asset
//! batches, so callers keep the existing wire representation without treating
//! each asset category as a separate information source.

use agent_contract::{
    Asset, CollectionKind, CollectionRun, CollectionRunStatus, DataServiceCategory,
};

use crate::collectors::{
    collect_accounts_with_coverage, collect_containers_with_coverage,
    collect_credentials_with_coverage, collect_host, collect_images, collect_nested_assets,
    collect_packages_with_coverage, collect_services_with_coverage, ContainerCoverage,
};
use crate::sources::{
    configuration, data_services, mounts, network_services, ports, processes, security_controls,
};
use crate::{ContainerScanOptions, ScanContext, Source, SourceCollection, SourceResult};

/// Inventory read from a mounted or live filesystem.
///
/// Host-level packages, services, ports, accounts, credentials, and container
/// metadata are always considered. Empty batches are omitted. Nested container
/// roots and local images are controlled by [`ContainerScanOptions`].
#[derive(Debug, Clone, Default)]
pub struct FilesystemSource {
    /// Nested container and local image collection settings.
    pub container_scan: ContainerScanOptions,
}

struct FilesystemCollection {
    results: Vec<SourceResult>,
    package_coverage: crate::sources::packages::PackageCoverage,
    service_coverage: crate::sources::services::ServiceCoverage,
    port_run: CollectionRun,
    process_run: CollectionRun,
    mount_run: CollectionRun,
    configuration_coverage: configuration::ConfigurationCoverage,
    data_service_coverage: data_services::DataServiceCoverage,
    security_control_coverage: security_controls::SecurityControlCoverage,
    account_coverage: crate::sources::accounts::AccountCoverage,
    credential_coverage: crate::sources::credentials::CredentialCoverage,
    container_coverage: ContainerCoverage,
}

impl FilesystemSource {
    /// Build a filesystem source with nested/image scan settings.
    pub fn new(container_scan: ContainerScanOptions) -> Self {
        Self { container_scan }
    }

    fn collect_snapshot(&self, ctx: &mut ScanContext) -> anyhow::Result<FilesystemCollection> {
        let host = collect_host(ctx)?;
        ctx.host_id = Some(host.host_id.clone());
        ctx.host = Some(host.clone());

        let (packages, package_coverage) = collect_packages_with_coverage(ctx, None);
        let (services, service_coverage) = collect_services_with_coverage(ctx);
        let (ports, port_run) = ports::collect_with_coverage(ctx);
        let (processes, process_run) = processes::collect_with_coverage(ctx);
        let network_services = network_services::collect(&ports, &processes, &services, &packages);
        let (data_services, data_service_coverage) = data_services::collect_with_coverage(
            ctx,
            &processes,
            &network_services,
            &services,
            &packages,
        );
        let (mounts, mount_run) = mounts::collect_with_coverage(ctx);
        let (security_controls, security_control_coverage) =
            security_controls::collect_with_coverage(ctx, &processes);
        let (sensitive_files, persistence_entries, configuration_coverage) =
            configuration::collect_with_coverage(ctx);
        let (accounts, account_coverage) = collect_accounts_with_coverage(ctx);
        let (credentials, credential_coverage) = collect_credentials_with_coverage(ctx);
        let (containers, container_coverage) = collect_containers_with_coverage(ctx);

        let mut results = vec![SourceResult::Host(host)];
        push_assets(&mut results, packages);
        push_assets(&mut results, services);
        push_assets(&mut results, ports);
        push_assets(&mut results, processes);
        push_assets(&mut results, network_services);
        push_assets(&mut results, mounts);
        push_assets(&mut results, data_services);
        push_assets(&mut results, security_controls);
        push_assets(&mut results, sensitive_files);
        push_assets(&mut results, persistence_entries);
        push_assets(&mut results, accounts);
        push_assets(&mut results, credentials);
        push_assets(&mut results, containers);

        if self.container_scan.enabled {
            push_assets(
                &mut results,
                collect_nested_assets(ctx, &self.container_scan),
            );
            if self.container_scan.scan_images {
                push_assets(&mut results, collect_images(ctx, &self.container_scan));
            }
        }

        Ok(FilesystemCollection {
            results,
            package_coverage,
            service_coverage,
            port_run,
            process_run,
            mount_run,
            configuration_coverage,
            data_service_coverage,
            security_control_coverage,
            account_coverage,
            credential_coverage,
            container_coverage,
        })
    }

    fn coverage_runs(&self, snapshot: &FilesystemCollection) -> Vec<CollectionRun> {
        let FilesystemCollection {
            results,
            package_coverage,
            service_coverage,
            port_run,
            process_run,
            mount_run,
            configuration_coverage,
            data_service_coverage,
            security_control_coverage,
            account_coverage,
            credential_coverage,
            container_coverage,
        } = snapshot;
        let count = |collector| {
            emitted_assets(results)
                .filter(|asset| collection_kind(asset) == Some(collector))
                .count()
        };
        debug_assert_eq!(port_run.record_count, count(CollectionKind::Port));
        debug_assert_eq!(process_run.record_count, count(CollectionKind::Process));
        debug_assert_eq!(
            mount_run.record_count,
            count(CollectionKind::FilesystemMount)
        );

        let process = CoverageOutcome::from(process_run);
        let port = CoverageOutcome::from(port_run);
        let source_coverage = |incomplete, reason| {
            if incomplete {
                CoverageOutcome::partial(reason)
            } else {
                CoverageOutcome::complete()
            }
        };
        let mut network_service =
            dependent_coverage("network_service_dependencies_incomplete", [&process, &port]);
        if network_service.status == CollectionRunStatus::Complete
            && emitted_assets(results).any(|asset| {
                matches!(
                    asset,
                    Asset::NetworkService(service)
                        if service.process_asset_id.is_none()
                            && service.service_asset_id.is_none()
                            && service.container_id.is_none()
                )
            })
        {
            network_service = CoverageOutcome::partial("network_service_ownership_unresolved");
        }
        let live_discovery =
            dependent_coverage("live_service_discovery_incomplete", [&process, &port]);
        let security_control = if process.status != CollectionRunStatus::Complete {
            CoverageOutcome::partial("security_control_runtime_evidence_incomplete")
        } else if security_control_coverage.source_incomplete() {
            CoverageOutcome::partial("security_control_source_incomplete")
        } else {
            CoverageOutcome::complete()
        };
        let sensitive_file = if configuration_coverage.sensitive_file_incomplete() {
            CoverageOutcome::partial("sensitive_file_source_incomplete")
        } else if configuration::sensitive_file_limit_reached(count(CollectionKind::SensitiveFile))
        {
            CoverageOutcome::partial("sensitive_file_limit_reached")
        } else {
            CoverageOutcome::complete()
        };
        let persistence = if configuration_coverage.persistence_entry_incomplete() {
            CoverageOutcome::partial("persistence_source_incomplete")
        } else if configuration::persistence_limit_reached(count(CollectionKind::PersistenceEntry))
        {
            CoverageOutcome::partial("persistence_limit_reached")
        } else {
            CoverageOutcome::complete()
        };
        let data_coverage = |category, collector| {
            (if live_discovery.status != CollectionRunStatus::Complete {
                live_discovery.clone()
            } else if data_service_coverage.source_incomplete() {
                CoverageOutcome::partial("data_service_source_incomplete")
            } else if data_services::config_path_limit_reached(emitted_assets(results), category) {
                CoverageOutcome::partial("data_service_config_limit_reached")
            } else {
                CoverageOutcome::complete()
            })
            .into_run(collector, count(collector))
        };
        let image = if !self.container_scan.enabled || !self.container_scan.scan_images {
            CoverageOutcome::disabled("image_collection_disabled")
        } else if count(CollectionKind::Image) >= self.container_scan.max_images {
            CoverageOutcome::partial("image_limit_reached")
        } else {
            CoverageOutcome::complete()
        };

        let mut runs = vec![
            CoverageOutcome::complete().into_run(CollectionKind::Host, 1),
            source_coverage(
                package_coverage.source_incomplete(),
                "package_source_incomplete",
            )
            .into_run(CollectionKind::Package, count(CollectionKind::Package)),
            source_coverage(
                service_coverage.source_incomplete(),
                "service_source_incomplete",
            )
            .into_run(CollectionKind::Service, count(CollectionKind::Service)),
            port_run.clone(),
            process_run.clone(),
            network_service.into_run(
                CollectionKind::NetworkService,
                count(CollectionKind::NetworkService),
            ),
            mount_run.clone(),
            data_coverage(DataServiceCategory::Database, CollectionKind::Database),
            data_coverage(
                DataServiceCategory::MessageQueue,
                CollectionKind::MessageQueue,
            ),
            data_coverage(DataServiceCategory::Cache, CollectionKind::Cache),
            security_control.into_run(
                CollectionKind::SecurityControl,
                count(CollectionKind::SecurityControl),
            ),
            sensitive_file.into_run(
                CollectionKind::SensitiveFile,
                count(CollectionKind::SensitiveFile),
            ),
            persistence.into_run(
                CollectionKind::PersistenceEntry,
                count(CollectionKind::PersistenceEntry),
            ),
            source_coverage(
                account_coverage.source_incomplete(),
                "account_source_incomplete",
            )
            .into_run(CollectionKind::Account, count(CollectionKind::Account)),
            source_coverage(
                credential_coverage.source_incomplete(),
                "credential_source_incomplete",
            )
            .into_run(
                CollectionKind::Credential,
                count(CollectionKind::Credential),
            ),
            source_coverage(
                container_coverage.source_incomplete(),
                "container_source_incomplete",
            )
            .into_run(CollectionKind::Container, count(CollectionKind::Container)),
        ];
        runs.push(image.into_run(CollectionKind::Image, count(CollectionKind::Image)));
        runs
    }
}

impl Source for FilesystemSource {
    fn id(&self) -> &'static str {
        "filesystem"
    }

    fn collect(&self, ctx: &mut ScanContext) -> anyhow::Result<Vec<SourceResult>> {
        self.collect_snapshot(ctx).map(|snapshot| snapshot.results)
    }

    fn collect_with_coverage(&self, ctx: &mut ScanContext) -> anyhow::Result<SourceCollection> {
        let snapshot = self.collect_snapshot(ctx)?;
        let collection_runs = self.coverage_runs(&snapshot);
        Ok(SourceCollection {
            results: snapshot.results,
            collection_runs: Some(collection_runs),
        })
    }

    fn collection_runs(&self, assets: &[Asset]) -> Option<Vec<CollectionRun>> {
        // Preserve the pre-existing direct Source API without upgrading a
        // post-hoc asset slice into verified-zero evidence. The scan runner
        // uses `collect_with_coverage` and therefore receives the precise
        // same-pass statuses above.
        let count = |collector| {
            assets
                .iter()
                .filter(|asset| collection_kind(asset) == Some(collector))
                .count()
        };
        let partial = |collector| CollectionRun {
            collector,
            status: CollectionRunStatus::Partial,
            record_count: count(collector),
            reason: Some("same_pass_coverage_unavailable".to_string()),
        };
        let mut runs = vec![CoverageOutcome::complete().into_run(CollectionKind::Host, 1)];
        runs.extend(
            [
                CollectionKind::Package,
                CollectionKind::Service,
                CollectionKind::Port,
                CollectionKind::Process,
                CollectionKind::NetworkService,
                CollectionKind::FilesystemMount,
                CollectionKind::Database,
                CollectionKind::MessageQueue,
                CollectionKind::Cache,
                CollectionKind::SecurityControl,
                CollectionKind::SensitiveFile,
                CollectionKind::PersistenceEntry,
                CollectionKind::Account,
                CollectionKind::Credential,
                CollectionKind::Container,
            ]
            .into_iter()
            .map(partial),
        );
        runs.push(
            if !self.container_scan.enabled || !self.container_scan.scan_images {
                CoverageOutcome::disabled("image_collection_disabled")
            } else {
                CoverageOutcome::partial("same_pass_coverage_unavailable")
            }
            .into_run(CollectionKind::Image, count(CollectionKind::Image)),
        );
        Some(runs)
    }
}

#[derive(Clone)]
struct CoverageOutcome {
    status: CollectionRunStatus,
    reason: Option<String>,
}

impl CoverageOutcome {
    fn complete() -> Self {
        Self {
            status: CollectionRunStatus::Complete,
            reason: None,
        }
    }

    fn partial(reason: &str) -> Self {
        Self {
            status: CollectionRunStatus::Partial,
            reason: Some(reason.to_string()),
        }
    }

    fn disabled(reason: &str) -> Self {
        Self {
            status: CollectionRunStatus::Disabled,
            reason: Some(reason.to_string()),
        }
    }

    fn into_run(self, collector: CollectionKind, record_count: usize) -> CollectionRun {
        CollectionRun {
            collector,
            status: self.status,
            record_count,
            reason: self.reason,
        }
    }
}

impl From<&CollectionRun> for CoverageOutcome {
    fn from(run: &CollectionRun) -> Self {
        Self {
            status: run.status,
            reason: run.reason.clone(),
        }
    }
}

fn dependent_coverage<'a>(
    reason: &str,
    dependencies: impl IntoIterator<Item = &'a CoverageOutcome>,
) -> CoverageOutcome {
    if dependencies
        .into_iter()
        .all(|dependency| dependency.status == CollectionRunStatus::Complete)
    {
        CoverageOutcome::complete()
    } else {
        CoverageOutcome::partial(reason)
    }
}

fn collection_kind(asset: &Asset) -> Option<CollectionKind> {
    Some(match asset {
        Asset::Package(_) => CollectionKind::Package,
        Asset::Service(_) => CollectionKind::Service,
        Asset::Port(_) => CollectionKind::Port,
        Asset::Process(_) => CollectionKind::Process,
        Asset::NetworkService(_) => CollectionKind::NetworkService,
        Asset::FilesystemMount(_) => CollectionKind::FilesystemMount,
        Asset::DataService(service) => match service.category {
            DataServiceCategory::Database => CollectionKind::Database,
            DataServiceCategory::MessageQueue => CollectionKind::MessageQueue,
            DataServiceCategory::Cache => CollectionKind::Cache,
        },
        Asset::SecurityControl(_) => CollectionKind::SecurityControl,
        Asset::SensitiveFile(_) => CollectionKind::SensitiveFile,
        Asset::PersistenceEntry(_) => CollectionKind::PersistenceEntry,
        Asset::Account(_) => CollectionKind::Account,
        Asset::Credential(_) => CollectionKind::Credential,
        Asset::Container(_) => CollectionKind::Container,
        Asset::Image(_) => CollectionKind::Image,
        Asset::SecurityProduct(_) => return None,
    })
}

fn emitted_assets(results: &[SourceResult]) -> impl Iterator<Item = &Asset> {
    results
        .iter()
        .filter_map(|result| match result {
            SourceResult::Host(_) => None,
            SourceResult::Assets(assets) => Some(assets.as_slice()),
        })
        .flatten()
}

fn push_assets(results: &mut Vec<SourceResult>, assets: Vec<Asset>) {
    if !assets.is_empty() {
        results.push(SourceResult::Assets(assets));
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use agent_contract::Asset;

    use super::*;

    #[test]
    fn emits_host_and_multiple_non_empty_asset_batches() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        fs::create_dir_all(root.join("etc/init.d")).unwrap();
        fs::write(root.join("etc/hostname"), "source-test\n").unwrap();
        fs::write(
            root.join("etc/os-release"),
            "ID=ubuntu\nVERSION_ID=\"22.04\"\nPRETTY_NAME=\"Ubuntu 22.04\"\n",
        )
        .unwrap();
        fs::write(root.join("etc/passwd"), "root:x:0:0:root:/root:/bin/bash\n").unwrap();
        fs::write(root.join("etc/init.d/sshd"), "#!/bin/sh\n").unwrap();
        fs::create_dir_all(root.join("var/lib/dpkg")).unwrap();
        fs::write(
            root.join("var/lib/dpkg/status"),
            "Package: openssl\nStatus: install ok installed\nArchitecture: amd64\nVersion: 3.0.2\n",
        )
        .unwrap();

        let mut ctx = ScanContext::at(root);
        let SourceCollection {
            results,
            collection_runs,
        } = FilesystemSource::default()
            .collect_with_coverage(&mut ctx)
            .unwrap();
        let runs = collection_runs.expect("filesystem source emits same-pass coverage");

        assert!(matches!(results.first(), Some(SourceResult::Host(_))));
        assert!(results.iter().all(|result| match result {
            SourceResult::Host(_) => true,
            SourceResult::Assets(assets) => !assets.is_empty(),
        }));

        let assets: Vec<_> = results
            .iter()
            .filter_map(|result| match result {
                SourceResult::Assets(assets) => Some(assets.as_slice()),
                SourceResult::Host(_) => None,
            })
            .flatten()
            .collect();
        assert!(assets
            .iter()
            .any(|asset| matches!(asset, Asset::Package(_))));
        assert!(assets
            .iter()
            .any(|asset| matches!(asset, Asset::Service(_))));
        assert!(assets
            .iter()
            .any(|asset| matches!(asset, Asset::Account(_))));
        assert!(
            results
                .iter()
                .filter(|result| matches!(result, SourceResult::Assets(_)))
                .count()
                >= 3
        );

        let package = runs
            .iter()
            .find(|run| run.collector == CollectionKind::Package)
            .unwrap();
        assert_eq!(package.status, CollectionRunStatus::Complete);
        assert_eq!(package.record_count, 1);
        let queue = runs
            .iter()
            .find(|run| run.collector == CollectionKind::MessageQueue)
            .unwrap();
        assert_eq!(queue.status, CollectionRunStatus::Partial);
        assert_eq!(queue.record_count, 0);
        assert_eq!(
            queue.reason.as_deref(),
            Some("live_service_discovery_incomplete")
        );
        let process = runs
            .iter()
            .find(|run| run.collector == CollectionKind::Process)
            .unwrap();
        assert_eq!(process.status, CollectionRunStatus::Failed);
        assert_eq!(
            process.reason.as_deref(),
            Some("process_source_unavailable")
        );
        let mount = runs
            .iter()
            .find(|run| run.collector == CollectionKind::FilesystemMount)
            .unwrap();
        assert_eq!(mount.status, CollectionRunStatus::Failed);
        assert_eq!(mount.reason.as_deref(), Some("mountinfo_unavailable"));
        let image = runs
            .iter()
            .find(|run| run.collector == CollectionKind::Image)
            .unwrap();
        assert_eq!(image.status, CollectionRunStatus::Disabled);
    }

    #[test]
    fn readable_empty_live_sources_are_complete_zero() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        fs::create_dir_all(root.join("etc")).unwrap();
        fs::write(root.join("etc/hostname"), "empty-live-source\n").unwrap();
        fs::write(root.join("etc/os-release"), "ID=test\nPRETTY_NAME=Test\n").unwrap();
        fs::create_dir_all(root.join("proc/net")).unwrap();
        fs::create_dir_all(root.join("proc/self")).unwrap();
        let header = "sl local_address rem_address st tx rx tr uid timeout inode\n";
        for source in ["tcp", "tcp6", "udp", "udp6"] {
            fs::write(root.join("proc/net").join(source), header).unwrap();
        }
        fs::write(root.join("proc/self/mountinfo"), "").unwrap();

        let sources: Vec<Box<dyn Source>> = vec![Box::new(FilesystemSource::default())];
        let report = crate::run_scan_at(&sources, root).unwrap();
        let runs = report.collection_runs.unwrap();
        for collector in [
            CollectionKind::Process,
            CollectionKind::Port,
            CollectionKind::NetworkService,
            CollectionKind::FilesystemMount,
            CollectionKind::Database,
            CollectionKind::MessageQueue,
            CollectionKind::Cache,
        ] {
            let run = runs.iter().find(|run| run.collector == collector).unwrap();
            assert_eq!(run.status, CollectionRunStatus::Complete, "{collector:?}");
            assert_eq!(run.record_count, 0, "{collector:?}");
            assert!(run.reason.is_none(), "{collector:?}");
        }
    }

    #[test]
    fn source_read_failures_downgrade_verified_zero_categories() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        fs::create_dir_all(root.join("etc/systemd/system")).unwrap();
        fs::create_dir_all(root.join("etc/selinux")).unwrap();
        fs::create_dir_all(root.join("var/lib/pgsql/data")).unwrap();
        fs::create_dir_all(root.join("proc/net")).unwrap();
        fs::create_dir_all(root.join("proc/self")).unwrap();
        fs::create_dir_all(root.join("proc/42")).unwrap();
        fs::write(root.join("etc/hostname"), "partial-source\n").unwrap();
        fs::write(root.join("etc/os-release"), "ID=test\nPRETTY_NAME=Test\n").unwrap();
        fs::write(
            root.join("etc/passwd"),
            "postgres:x:26:26::/var/lib/pgsql:/bin/sh\n",
        )
        .unwrap();
        fs::write(root.join("etc/systemd/system/bad.service"), [0xff, 0xfe]).unwrap();
        fs::write(root.join("etc/selinux/config"), [0xff, 0xfe]).unwrap();
        fs::write(
            root.join("var/lib/pgsql/data/postgresql.conf"),
            [0xff, 0xfe],
        )
        .unwrap();
        fs::write(
            root.join("proc/42/status"),
            "Name:\tpostgres\nUid:\t26\t26\t26\t26\n",
        )
        .unwrap();
        fs::write(root.join("proc/42/stat"), "42 (postgres) S 1 0 0 0\n").unwrap();
        fs::write(root.join("proc/42/cmdline"), b"postgres\0").unwrap();
        fs::write(
            root.join("proc/42/cgroup"),
            "0::/system.slice/postgres.service\n",
        )
        .unwrap();
        let header = "sl local_address rem_address st tx rx tr uid timeout inode\n";
        for source in ["tcp", "tcp6", "udp", "udp6"] {
            fs::write(root.join("proc/net").join(source), header).unwrap();
        }
        fs::write(root.join("proc/self/mountinfo"), "").unwrap();

        let sources: Vec<Box<dyn Source>> = vec![Box::new(FilesystemSource::default())];
        let report = crate::run_scan_at(&sources, root).unwrap();
        let runs = report.collection_runs.unwrap();
        for (collector, reason) in [
            (CollectionKind::Database, "data_service_source_incomplete"),
            (
                CollectionKind::SecurityControl,
                "security_control_source_incomplete",
            ),
            (
                CollectionKind::PersistenceEntry,
                "persistence_source_incomplete",
            ),
        ] {
            let run = runs.iter().find(|run| run.collector == collector).unwrap();
            assert_eq!(run.status, CollectionRunStatus::Partial, "{collector:?}");
            assert_eq!(run.reason.as_deref(), Some(reason), "{collector:?}");
        }
        let sensitive = runs
            .iter()
            .find(|run| run.collector == CollectionKind::SensitiveFile)
            .unwrap();
        assert_eq!(sensitive.status, CollectionRunStatus::Complete);
    }

    #[test]
    fn direct_collection_runs_api_remains_available_and_conservative() {
        let source = FilesystemSource::default();
        let runs = source
            .collection_runs(&[])
            .expect("filesystem source preserves direct coverage API");

        let port = runs
            .iter()
            .find(|run| run.collector == CollectionKind::Port)
            .unwrap();
        assert_eq!(port.status, CollectionRunStatus::Partial);
        assert_eq!(port.record_count, 0);
        assert_eq!(
            port.reason.as_deref(),
            Some("same_pass_coverage_unavailable")
        );

        let image = runs
            .iter()
            .find(|run| run.collector == CollectionKind::Image)
            .unwrap();
        assert_eq!(image.status, CollectionRunStatus::Disabled);
        assert_eq!(image.reason.as_deref(), Some("image_collection_disabled"));
    }

    #[test]
    fn inventory_source_failures_do_not_report_verified_zero() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        fs::create_dir_all(root.join("etc/passwd")).unwrap();
        fs::create_dir_all(root.join("etc/ssh")).unwrap();
        fs::create_dir_all(root.join("usr/lib/systemd/system")).unwrap();
        fs::create_dir_all(root.join("var/lib/dpkg/status")).unwrap();
        fs::create_dir_all(root.join("var/lib/docker/containers/bad")).unwrap();
        fs::create_dir_all(root.join("proc/net")).unwrap();
        fs::create_dir_all(root.join("proc/self")).unwrap();
        fs::write(root.join("etc/hostname"), "inventory-partial\n").unwrap();
        fs::write(root.join("etc/os-release"), "ID=test\nPRETTY_NAME=Test\n").unwrap();
        fs::write(root.join("etc/ssh/bad.pub"), [0xff, 0xfe]).unwrap();
        fs::write(
            root.join("usr/lib/systemd/system/bad.service"),
            [0xff, 0xfe],
        )
        .unwrap();
        fs::write(
            root.join("var/lib/docker/containers/bad/config.v2.json"),
            "not-json",
        )
        .unwrap();
        let header = "sl local_address rem_address st tx rx tr uid timeout inode\n";
        for source in ["tcp", "tcp6", "udp", "udp6"] {
            fs::write(root.join("proc/net").join(source), header).unwrap();
        }
        fs::write(root.join("proc/self/mountinfo"), "").unwrap();

        let sources: Vec<Box<dyn Source>> = vec![Box::new(FilesystemSource::default())];
        let report = crate::run_scan_at(&sources, root).unwrap();
        let runs = report.collection_runs.unwrap();
        for (collector, reason) in [
            (CollectionKind::Package, "package_source_incomplete"),
            (CollectionKind::Service, "service_source_incomplete"),
            (CollectionKind::Account, "account_source_incomplete"),
            (CollectionKind::Credential, "credential_source_incomplete"),
            (CollectionKind::Container, "container_source_incomplete"),
        ] {
            let run = runs.iter().find(|run| run.collector == collector).unwrap();
            assert_eq!(run.status, CollectionRunStatus::Partial, "{collector:?}");
            assert_eq!(run.record_count, 0, "{collector:?}");
            assert_eq!(run.reason.as_deref(), Some(reason), "{collector:?}");
        }
    }
}
