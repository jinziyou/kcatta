//! Stamp nested assets with parent container ownership and unique ids.

use agent_contract::Asset;

/// Set `parent_asset_id` and prefix `asset_id` for assets collected inside a container.
pub fn stamp_nested_assets(assets: Vec<Asset>, parent_asset_id: &str) -> Vec<Asset> {
    assets
        .into_iter()
        .map(|asset| stamp_nested_asset(asset, parent_asset_id))
        .collect()
}

fn stamp_nested_asset(mut asset: Asset, parent_asset_id: &str) -> Asset {
    let base_id = asset_id(&asset);
    let nested_id = format!("{parent_asset_id}::{base_id}");
    set_asset_id(&mut asset, nested_id);
    set_parent_asset_id(&mut asset, Some(parent_asset_id.to_string()));
    asset
}

fn asset_id(asset: &Asset) -> &str {
    match asset {
        Asset::Package(a) => &a.asset_id,
        Asset::Service(a) => &a.asset_id,
        Asset::Port(a) => &a.asset_id,
        Asset::Account(a) => &a.asset_id,
        Asset::Credential(a) => &a.asset_id,
        Asset::Container(a) => &a.asset_id,
    }
}

fn set_asset_id(asset: &mut Asset, asset_id: String) {
    match asset {
        Asset::Package(a) => a.asset_id = asset_id,
        Asset::Service(a) => a.asset_id = asset_id,
        Asset::Port(a) => a.asset_id = asset_id,
        Asset::Account(a) => a.asset_id = asset_id,
        Asset::Credential(a) => a.asset_id = asset_id,
        Asset::Container(a) => a.asset_id = asset_id,
    }
}

fn set_parent_asset_id(asset: &mut Asset, parent_asset_id: Option<String>) {
    match asset {
        Asset::Package(a) => a.parent_asset_id = parent_asset_id,
        Asset::Service(a) => a.parent_asset_id = parent_asset_id,
        Asset::Port(a) => a.parent_asset_id = parent_asset_id,
        Asset::Account(a) => a.parent_asset_id = parent_asset_id,
        Asset::Credential(a) => a.parent_asset_id = parent_asset_id,
        Asset::Container(a) => a.parent_asset_id = parent_asset_id,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_contract::{Package, Service};

    #[test]
    fn prefixes_asset_id_and_sets_parent() {
        let assets = stamp_nested_assets(
            vec![
                Asset::Package(Package {
                    asset_id: "pkg-curl".into(),
                    parent_asset_id: None,
                    name: "curl".into(),
                    version: "1".into(),
                    source: None,
                    install_path: None,
                    ecosystem: None,
                }),
                Asset::Service(Service {
                    asset_id: "svc-nginx".into(),
                    parent_asset_id: None,
                    name: "nginx".into(),
                    status: "enabled".into(),
                    exec_path: None,
                }),
            ],
            "ctr-docker-deadbeef",
        );

        match &assets[0] {
            Asset::Package(p) => {
                assert_eq!(p.asset_id, "ctr-docker-deadbeef::pkg-curl");
                assert_eq!(p.parent_asset_id.as_deref(), Some("ctr-docker-deadbeef"));
            }
            _ => panic!("expected package"),
        }
    }
}
