//! scanner-asset: host asset discovery (packages, ports, services, ...).

mod collectors;

pub use collectors::{HostCollector, PackagesCollector, PortsCollector};

use scanner_runtime::Collector;

/// Default v0 scan plan: host descriptor + mock packages + mock ports.
pub fn default_collectors() -> Vec<Box<dyn Collector>> {
    vec![
        Box::new(HostCollector),
        Box::new(PackagesCollector),
        Box::new(PortsCollector),
    ]
}
