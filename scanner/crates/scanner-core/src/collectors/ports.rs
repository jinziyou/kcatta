//! Mock listening-port collector for v0.
//!
//! Replace with a real implementation that parses `/proc/net/tcp[6]`
//! or invokes platform APIs.

use crate::contract::{Asset, Port, PortProto};

pub fn collect(_host_id: &str) -> Vec<Asset> {
    vec![
        Asset::Port(Port {
            asset_id: "port-22-tcp".to_string(),
            proto: PortProto::Tcp,
            port: 22,
            listen_addr: "0.0.0.0".to_string(),
            process_name: Some("sshd".to_string()),
            pid: Some(1234),
        }),
        Asset::Port(Port {
            asset_id: "port-443-tcp".to_string(),
            proto: PortProto::Tcp,
            port: 443,
            listen_addr: "0.0.0.0".to_string(),
            process_name: Some("nginx".to_string()),
            pid: Some(5678),
        }),
    ]
}
