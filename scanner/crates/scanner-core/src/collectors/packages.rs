//! Mock package collector for v0.
//!
//! Returns a small, deterministic set of fake packages so the end-to-end
//! pipeline (scan -> serialize -> validate against JSON Schema) can be
//! exercised without root, a real package manager, or any network.
//!
//! Replace with a real implementation that walks dpkg / rpm / apk / etc.

use crate::contract::{Asset, Package};

pub fn collect(_host_id: &str) -> Vec<Asset> {
    vec![
        Asset::Package(Package {
            asset_id: "pkg-openssl".to_string(),
            name: "openssl".to_string(),
            version: "3.0.2-0ubuntu1.18".to_string(),
            source: Some("apt".to_string()),
            install_path: Some("/usr/bin/openssl".to_string()),
        }),
        Asset::Package(Package {
            asset_id: "pkg-curl".to_string(),
            name: "curl".to_string(),
            version: "7.81.0-1ubuntu1.20".to_string(),
            source: Some("apt".to_string()),
            install_path: None,
        }),
        Asset::Package(Package {
            asset_id: "pkg-openssh-server".to_string(),
            name: "openssh-server".to_string(),
            version: "1:8.9p1-3ubuntu0.10".to_string(),
            source: Some("apt".to_string()),
            install_path: None,
        }),
    ]
}
