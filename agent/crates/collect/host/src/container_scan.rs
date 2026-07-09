//! Options for nested container rootfs asset scanning.

/// Controls nested scans of Docker/Podman merged rootfs directories and static
/// scanning of local container images.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerScanOptions {
    /// When false, nested + image scanning is a no-op.
    pub enabled: bool,
    /// Upper bound on containers scanned per host pass.
    pub max_containers: usize,
    /// Include containers whose static status is not running.
    pub include_stopped: bool,
    /// Collect packages inside each container rootfs.
    pub scan_packages: bool,
    /// Collect services inside each container rootfs.
    pub scan_services: bool,
    /// Collect accounts inside each container rootfs.
    pub scan_accounts: bool,
    /// Collect credentials inside each container rootfs.
    pub scan_credentials: bool,
    /// Enumerate local container images and collect their packages (static,
    /// assembled from on-disk layers — covers images that were never run).
    pub scan_images: bool,
    /// Upper bound on images assembled + scanned per host pass.
    pub max_images: usize,
}

impl Default for ContainerScanOptions {
    fn default() -> Self {
        Self {
            enabled: false,
            max_containers: 64,
            include_stopped: true,
            scan_packages: true,
            scan_services: true,
            scan_accounts: false,
            scan_credentials: false,
            scan_images: false,
            max_images: 32,
        }
    }
}

impl ContainerScanOptions {
    /// Enable nested + image scanning with default target categories
    /// (in-container packages + services, plus local image package scanning).
    pub fn enabled() -> Self {
        Self {
            enabled: true,
            scan_images: true,
            ..Self::default()
        }
    }

    /// Parse `--container-asset-targets` (`packages,services`, …).
    pub fn parse_targets(raw: &str) -> anyhow::Result<Self> {
        let mut opts = Self::enabled();
        opts.scan_packages = false;
        opts.scan_services = false;
        opts.scan_accounts = false;
        opts.scan_credentials = false;

        for part in raw.split(',') {
            match part.trim().to_lowercase().as_str() {
                "" => {}
                "packages" | "package" => opts.scan_packages = true,
                "services" | "service" => opts.scan_services = true,
                "accounts" | "account" => opts.scan_accounts = true,
                "credentials" | "credential" => opts.scan_credentials = true,
                "all" => {
                    opts.scan_packages = true;
                    opts.scan_services = true;
                    opts.scan_accounts = true;
                    opts.scan_credentials = true;
                }
                other => {
                    anyhow::bail!(
                        "unknown container asset target {other:?} (use packages|services|accounts|credentials|all)"
                    );
                }
            }
        }

        if !opts.scan_packages
            && !opts.scan_services
            && !opts.scan_accounts
            && !opts.scan_credentials
        {
            anyhow::bail!("container asset targets must include at least one category");
        }

        Ok(opts)
    }

    /// Merge CLI flags into scan options.
    pub fn from_cli(
        scan_container_assets: bool,
        targets: Option<&str>,
        max_containers: usize,
        include_stopped: bool,
    ) -> anyhow::Result<Self> {
        if !scan_container_assets {
            return Ok(Self::default());
        }
        let mut opts = match targets {
            Some(raw) => Self::parse_targets(raw)?,
            None => Self::enabled(),
        };
        opts.max_containers = max_containers;
        opts.include_stopped = include_stopped;
        Ok(opts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_disabled() {
        assert!(!ContainerScanOptions::default().enabled);
    }

    #[test]
    fn parse_targets_all() {
        let opts = ContainerScanOptions::parse_targets("all").unwrap();
        assert!(opts.scan_packages && opts.scan_services);
        assert!(opts.scan_accounts && opts.scan_credentials);
    }
}
