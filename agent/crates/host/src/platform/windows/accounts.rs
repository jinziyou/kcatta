//! Local Windows accounts from SAM + profile registry hives.

use std::collections::HashMap;

use crate::ScanContext;
use agent_contract::{Account, Asset};

use super::registry::{HiveKind, RegistryAccess};

const SAM_NAMES_PATH: &str = r"SAM\Domains\Account\Users\Names";
const PROFILE_LIST: &str = r"Microsoft\Windows NT\CurrentVersion\ProfileList";

/// Local user accounts as contract [`Asset`]s.
pub fn collect_accounts(ctx: &ScanContext) -> Vec<Asset> {
    let reg = RegistryAccess::open(ctx);
    let profiles = profile_paths_by_rid(&reg);
    let mut assets = Vec::new();

    for username in reg.list_subkeys(HiveKind::Sam, SAM_NAMES_PATH) {
        if username.ends_with('$') {
            continue;
        }
        let path = format!("{SAM_NAMES_PATH}\\{username}");
        let rid = reg.get_default_dword(HiveKind::Sam, &path);
        let shell = rid
            .and_then(|r| profiles.get(&r))
            .cloned()
            .filter(|p| !p.is_empty());
        let slug = username.to_ascii_lowercase();
        assets.push(Asset::Account(Account {
            asset_id: format!("acct-{slug}"),
            parent_asset_id: None,
            username,
            uid: rid.map(i64::from),
            shell,
            last_login: None,
        }));
    }

    assets.sort_by(|a, b| account_name(a).cmp(account_name(b)));
    assets
}

fn profile_paths_by_rid(reg: &RegistryAccess) -> HashMap<u32, String> {
    let mut out = HashMap::new();
    for sid in reg.list_subkeys(HiveKind::Software, PROFILE_LIST) {
        let Some(rid) = sid.rsplit('-').next().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        let path = format!("{PROFILE_LIST}\\{sid}");
        let values = reg.read_values(HiveKind::Software, &path);
        if let Some(profile) = values
            .get("ProfileImagePath")
            .cloned()
            .filter(|p| !p.is_empty())
        {
            out.insert(rid, normalize_profile_path(&profile));
        }
    }
    out
}

fn normalize_profile_path(path: &str) -> String {
    path.trim_start_matches(r"\??\").replace('\\', "/")
}

fn account_name(asset: &Asset) -> &str {
    match asset {
        Asset::Account(a) => &a.username,
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_profile_path() {
        assert_eq!(
            normalize_profile_path(r"\??\C:\Users\alice"),
            "C:/Users/alice"
        );
    }
}
