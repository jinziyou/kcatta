//! Join basic listener rows with process/service/package ownership metadata.

use std::collections::{HashMap, HashSet};

use agent_contract::{Asset, NetworkService, Package, Port, ProcessAsset};

/// Enrich every listener, including explicit unresolved ownership rows.
pub fn collect(
    ports: &[Asset],
    processes: &[Asset],
    services: &[Asset],
    packages: &[Asset],
) -> Vec<Asset> {
    let by_pid: HashMap<u32, &ProcessAsset> = processes
        .iter()
        .filter_map(|asset| match asset {
            Asset::Process(process) => Some((process.pid, process)),
            _ => None,
        })
        .collect();
    let service_ids: HashSet<&str> = services
        .iter()
        .filter_map(|asset| match asset {
            Asset::Service(service) => Some(service.asset_id.as_str()),
            _ => None,
        })
        .collect();
    let package_by_path: HashMap<&str, &Package> = packages
        .iter()
        .filter_map(|asset| match asset {
            Asset::Package(package) => package.install_path.as_deref().map(|path| (path, package)),
            _ => None,
        })
        .collect();

    ports
        .iter()
        .filter_map(|asset| match asset {
            Asset::Port(port) => Some(enrich(port, &by_pid, &service_ids, &package_by_path)),
            _ => None,
        })
        .map(Asset::NetworkService)
        .collect()
}

fn enrich(
    port: &Port,
    by_pid: &HashMap<u32, &ProcessAsset>,
    service_ids: &HashSet<&str>,
    package_by_path: &HashMap<&str, &Package>,
) -> NetworkService {
    let process = port.pid.and_then(|pid| by_pid.get(&pid).copied());
    let service_asset_id = process
        .and_then(|value| value.systemd_unit.as_deref())
        .and_then(|unit| unit.strip_suffix(".service"))
        .map(|name| format!("svc-{name}"))
        .filter(|asset_id| service_ids.contains(asset_id.as_str()));
    let package_name = process
        .and_then(|value| value.exe_path.as_deref())
        .and_then(|path| package_by_path.get(path))
        .map(|package| package.name.clone());
    NetworkService {
        asset_id: format!("network-service-{}", port.asset_id),
        parent_asset_id: None,
        proto: port.proto,
        port: port.port,
        listen_addr: port.listen_addr.clone(),
        port_asset_id: port.asset_id.clone(),
        process_asset_id: process.map(|value| value.asset_id.clone()),
        service_asset_id,
        process_name: process
            .map(|value| value.name.clone())
            .or_else(|| port.process_name.clone()),
        exe_path: process.and_then(|value| value.exe_path.clone()),
        executable_sha256: process.and_then(|value| value.executable_sha256.clone()),
        uid: process.and_then(|value| value.uid),
        username: process.and_then(|value| value.username.clone()),
        systemd_unit: process.and_then(|value| value.systemd_unit.clone()),
        container_id: process.and_then(|value| value.container_id.clone()),
        package_name,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_contract::{PortProto, Service};

    #[test]
    fn emits_explicit_unresolved_and_resolved_ownership() {
        let ports = vec![
            Asset::Port(Port {
                asset_id: "port-tcp-any-22".to_string(),
                parent_asset_id: None,
                proto: PortProto::Tcp,
                port: 22,
                listen_addr: "0.0.0.0".to_string(),
                process_name: Some("sshd".to_string()),
                pid: Some(7),
            }),
            Asset::Port(Port {
                asset_id: "port-tcp-any-99".to_string(),
                parent_asset_id: None,
                proto: PortProto::Tcp,
                port: 99,
                listen_addr: "0.0.0.0".to_string(),
                process_name: None,
                pid: None,
            }),
        ];
        let processes = vec![Asset::Process(ProcessAsset {
            asset_id: "process-7".to_string(),
            parent_asset_id: None,
            pid: 7,
            ppid: Some(1),
            name: "sshd".to_string(),
            exe_path: Some("/usr/sbin/sshd".to_string()),
            executable_sha256: Some("abc".to_string()),
            uid: Some(0),
            username: Some("root".to_string()),
            command_line: Some("/usr/sbin/sshd -D".to_string()),
            command_line_redacted: false,
            systemd_unit: Some("sshd.service".to_string()),
            container_id: None,
            started_at: None,
        })];
        let services = vec![Asset::Service(Service {
            asset_id: "svc-sshd".to_string(),
            parent_asset_id: None,
            name: "sshd".to_string(),
            status: "enabled".to_string(),
            exec_path: Some("/usr/sbin/sshd".to_string()),
        })];
        let packages = vec![Asset::Package(Package {
            asset_id: "pkg-sshd".to_string(),
            parent_asset_id: None,
            name: "openssh-server".to_string(),
            version: "1".to_string(),
            source: Some("rpm".to_string()),
            source_name: None,
            source_version: None,
            install_path: Some("/usr/sbin/sshd".to_string()),
            ecosystem: None,
        })];

        let rows = collect(&ports, &processes, &services, &packages);
        let Asset::NetworkService(resolved) = &rows[0] else {
            panic!("expected network service");
        };
        assert_eq!(resolved.process_asset_id.as_deref(), Some("process-7"));
        assert_eq!(resolved.service_asset_id.as_deref(), Some("svc-sshd"));
        assert_eq!(resolved.package_name.as_deref(), Some("openssh-server"));
        let Asset::NetworkService(unresolved) = &rows[1] else {
            panic!("expected network service");
        };
        assert!(unresolved.process_asset_id.is_none());
    }
}
