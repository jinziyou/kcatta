//! Filesystem-backed inventory source.
//!
//! One filesystem pass owns all readers whose truth comes from files under the
//! scan root. It emits the host descriptor first, followed by independent asset
//! batches, so callers keep the existing wire representation without treating
//! each asset category as a separate information source.

use agent_contract::Asset;

use crate::collectors::{
    collect_accounts, collect_containers, collect_credentials, collect_host, collect_images,
    collect_nested_assets, collect_packages, collect_ports, collect_services,
};
use crate::{ContainerScanOptions, ScanContext, Source, SourceResult};

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

impl FilesystemSource {
    /// Build a filesystem source with nested/image scan settings.
    pub fn new(container_scan: ContainerScanOptions) -> Self {
        Self { container_scan }
    }
}

impl Source for FilesystemSource {
    fn id(&self) -> &'static str {
        "filesystem"
    }

    fn collect(&self, ctx: &mut ScanContext) -> anyhow::Result<Vec<SourceResult>> {
        let host = collect_host(ctx)?;
        ctx.host_id = Some(host.host_id.clone());
        ctx.host = Some(host.clone());

        let mut results = vec![SourceResult::Host(host)];
        push_assets(&mut results, collect_packages(ctx, None));
        push_assets(&mut results, collect_services(ctx));
        push_assets(&mut results, collect_ports(ctx));
        push_assets(&mut results, collect_accounts(ctx));
        push_assets(&mut results, collect_credentials(ctx));
        push_assets(&mut results, collect_containers(ctx));

        if self.container_scan.enabled {
            push_assets(
                &mut results,
                collect_nested_assets(ctx, &self.container_scan),
            );
            if self.container_scan.scan_images {
                push_assets(&mut results, collect_images(ctx, &self.container_scan));
            }
        }

        Ok(results)
    }
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
        let results = FilesystemSource::default().collect(&mut ctx).unwrap();

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
    }
}
