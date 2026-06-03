//! Windows services from the SYSTEM registry hive.

use probe_contract::{Asset, Service};
use probe_runtime::ScanContext;

use super::registry::{control_set_prefix, HiveKind, RegistryAccess};

/// Win32 services (`Type` 0x10 / 0x20); skip kernel/file-system drivers.
const SERVICE_TYPE_WIN32_OWN: &str = "16";
const SERVICE_TYPE_WIN32_SHARE: &str = "32";

/// Collect installed Win32 services (analogous to Linux systemd units).
pub fn collect_services(ctx: &ScanContext) -> Vec<Asset> {
    let reg = RegistryAccess::open(ctx);
    let cs = control_set_prefix(&reg);
    let base = format!("{cs}\\Services");
    let mut assets = Vec::new();

    for name in reg.list_subkeys(HiveKind::System, &base) {
        if is_noise_service(&name) {
            continue;
        }
        let path = format!("{base}\\{name}");
        let values = reg.read_values(HiveKind::System, &path);
        let service_type = values.get("Type").map(String::as_str);
        if !is_user_service_type(service_type) {
            continue;
        }
        let start = values.get("Start").map(String::as_str).unwrap_or("3");
        let status = map_start_type(start);
        let exec_path = values.get("ImagePath").cloned().filter(|p| !p.is_empty());
        let slug = name.to_ascii_lowercase();
        assets.push(Asset::Service(Service {
            asset_id: format!("svc-{slug}"),
            name,
            status,
            exec_path,
        }));
    }

    assets.sort_by(|a, b| service_name(a).cmp(service_name(b)));
    assets
}

fn is_user_service_type(service_type: Option<&str>) -> bool {
    matches!(
        service_type,
        Some(SERVICE_TYPE_WIN32_OWN) | Some(SERVICE_TYPE_WIN32_SHARE)
    )
}

fn is_noise_service(name: &str) -> bool {
    name.is_empty() || name.starts_with('_')
}

fn service_name(asset: &Asset) -> &str {
    match asset {
        Asset::Service(s) => &s.name,
        _ => "",
    }
}

/// Map SCM `Start` value to Linux-like status strings.
fn map_start_type(start: &str) -> String {
    match start {
        "0" => "boot".to_string(),
        "1" => "system".to_string(),
        "2" => "enabled".to_string(),
        "3" => "manual".to_string(),
        "4" => "disabled".to_string(),
        other => format!("start-{other}"),
    }
}
