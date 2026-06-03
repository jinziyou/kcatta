//! Minimal packet parsing for flow metadata extraction.
//!
//! Parses Ethernet / IPv4 / TCP / UDP / ICMP frames captured via pcap and
//! extracts the fields needed to populate `FlowEvent` (5-tuple, byte counts,
//! DNS query names, TLS SNI, JA3).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use md5;

use crate::contract::FlowProto;

/// One parsed L3/L4 packet suitable for flow aggregation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedPacket {
    /// Capture timestamp, whole seconds since the Unix epoch.
    pub ts_secs: i64,
    /// Sub-second component of the capture timestamp, in microseconds.
    pub ts_subsec_micros: u32,
    /// IP total length in bytes (used for byte accounting).
    pub ip_total_len: u32,
    /// L4 protocol class.
    pub proto: FlowProto,
    /// Source IP address.
    pub src_ip: IpAddr,
    /// Destination IP address.
    pub dst_ip: IpAddr,
    /// Source port (`None` for ICMP).
    pub src_port: Option<u16>,
    /// Destination port (`None` for ICMP).
    pub dst_port: Option<u16>,
    /// Detected application protocol (e.g. `SSH`) when recognized.
    pub app_proto: Option<String>,
    /// DNS query name when parsed from the payload.
    pub dns_query: Option<String>,
    /// TLS SNI server name when parsed from a ClientHello.
    pub tls_sni: Option<String>,
    /// JA3 TLS fingerprint when computed.
    pub ja3: Option<String>,
}

/// Parse a raw link-layer frame (typically Ethernet) into flow metadata.
pub fn parse_frame(data: &[u8]) -> Option<ParsedPacket> {
    let (ethertype, offset) = parse_link(data)?;
    match ethertype {
        0x0800 => parse_ipv4(data, offset),
        0x86DD => parse_ipv6(data, offset),
        _ => None,
    }
}

fn parse_link(data: &[u8]) -> Option<(u16, usize)> {
    if data.len() < 14 {
        return None;
    }
    let mut ethertype = u16::from_be_bytes([data[12], data[13]]);
    let mut offset = 14usize;
    // 802.1Q VLAN tag
    while ethertype == 0x8100 {
        if data.len() < offset + 4 {
            return None;
        }
        ethertype = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
        offset += 4;
    }
    Some((ethertype, offset))
}

fn parse_ipv4(data: &[u8], offset: usize) -> Option<ParsedPacket> {
    if data.len() < offset + 20 {
        return None;
    }
    let ver_ihl = data[offset];
    if ver_ihl >> 4 != 4 {
        return None;
    }
    let ihl = (ver_ihl & 0x0f) as usize * 4;
    if ihl < 20 || data.len() < offset + ihl {
        return None;
    }

    let total_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as u32;
    let proto = data[offset + 9];
    let src = Ipv4Addr::new(
        data[offset + 12],
        data[offset + 13],
        data[offset + 14],
        data[offset + 15],
    );
    let dst = Ipv4Addr::new(
        data[offset + 16],
        data[offset + 17],
        data[offset + 18],
        data[offset + 19],
    );

    let l4 = &data[offset + ihl..];
    parse_l4(proto, IpAddr::V4(src), IpAddr::V4(dst), total_len, l4)
}

fn parse_ipv6(data: &[u8], offset: usize) -> Option<ParsedPacket> {
    if data.len() < offset + 40 {
        return None;
    }
    if data[offset] >> 4 != 6 {
        return None;
    }
    let payload_len = u16::from_be_bytes([data[offset + 4], data[offset + 5]]) as u32;
    let next_header = data[offset + 6];
    let src = Ipv6Addr::from([
        data[offset + 8],
        data[offset + 9],
        data[offset + 10],
        data[offset + 11],
        data[offset + 12],
        data[offset + 13],
        data[offset + 14],
        data[offset + 15],
        data[offset + 16],
        data[offset + 17],
        data[offset + 18],
        data[offset + 19],
        data[offset + 20],
        data[offset + 21],
        data[offset + 22],
        data[offset + 23],
    ]);
    let dst = Ipv6Addr::from([
        data[offset + 24],
        data[offset + 25],
        data[offset + 26],
        data[offset + 27],
        data[offset + 28],
        data[offset + 29],
        data[offset + 30],
        data[offset + 31],
        data[offset + 32],
        data[offset + 33],
        data[offset + 34],
        data[offset + 35],
        data[offset + 36],
        data[offset + 37],
        data[offset + 38],
        data[offset + 39],
    ]);
    let ip_total_len = payload_len + 40;
    let l4 = &data[offset + 40..];
    parse_l4(
        next_header,
        IpAddr::V6(src),
        IpAddr::V6(dst),
        ip_total_len,
        l4,
    )
}

fn parse_l4(
    proto_num: u8,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    ip_total_len: u32,
    l4: &[u8],
) -> Option<ParsedPacket> {
    match proto_num {
        6 => parse_tcp(src_ip, dst_ip, ip_total_len, l4),
        17 => parse_udp(src_ip, dst_ip, ip_total_len, l4),
        1 => Some(ParsedPacket {
            ts_secs: 0,
            ts_subsec_micros: 0,
            ip_total_len,
            proto: FlowProto::Icmp,
            src_ip,
            dst_ip,
            src_port: None,
            dst_port: None,
            app_proto: Some("ICMP".to_string()),
            dns_query: None,
            tls_sni: None,
            ja3: None,
        }),
        _ => Some(ParsedPacket {
            ts_secs: 0,
            ts_subsec_micros: 0,
            ip_total_len,
            proto: FlowProto::Other,
            src_ip,
            dst_ip,
            src_port: None,
            dst_port: None,
            app_proto: None,
            dns_query: None,
            tls_sni: None,
            ja3: None,
        }),
    }
}

fn parse_tcp(src_ip: IpAddr, dst_ip: IpAddr, ip_total_len: u32, l4: &[u8]) -> Option<ParsedPacket> {
    if l4.len() < 20 {
        return None;
    }
    let src_port = u16::from_be_bytes([l4[0], l4[1]]);
    let dst_port = u16::from_be_bytes([l4[2], l4[3]]);
    let data_offset = ((l4[12] >> 4) as usize) * 4;
    if data_offset < 20 || l4.len() < data_offset {
        return None;
    }
    let payload = &l4[data_offset..];

    let mut app_proto = None;
    let mut tls_sni = None;
    let mut ja3 = None;
    if dst_port == 443 || src_port == 443 {
        if let Some((sni, fingerprint)) = parse_tls_client_hello(payload) {
            app_proto = Some("TLS".to_string());
            tls_sni = sni;
            ja3 = fingerprint;
        }
    } else if dst_port == 22 || src_port == 22 {
        app_proto = Some("SSH".to_string());
    }

    Some(ParsedPacket {
        ts_secs: 0,
        ts_subsec_micros: 0,
        ip_total_len,
        proto: FlowProto::Tcp,
        src_ip,
        dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        app_proto,
        dns_query: None,
        tls_sni,
        ja3,
    })
}

fn parse_udp(src_ip: IpAddr, dst_ip: IpAddr, ip_total_len: u32, l4: &[u8]) -> Option<ParsedPacket> {
    if l4.len() < 8 {
        return None;
    }
    let src_port = u16::from_be_bytes([l4[0], l4[1]]);
    let dst_port = u16::from_be_bytes([l4[2], l4[3]]);
    let payload = &l4[8..];

    let mut app_proto = None;
    let mut dns_query = None;
    if dst_port == 53 || src_port == 53 {
        app_proto = Some("DNS".to_string());
        dns_query = parse_dns_query(payload);
    }

    Some(ParsedPacket {
        ts_secs: 0,
        ts_subsec_micros: 0,
        ip_total_len,
        proto: FlowProto::Udp,
        src_ip,
        dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        app_proto,
        dns_query,
        tls_sni: None,
        ja3: None,
    })
}

/// Parse TLS ClientHello for SNI and JA3 fingerprint.
fn parse_tls_client_hello(payload: &[u8]) -> Option<(Option<String>, Option<String>)> {
    if payload.len() < 5 || payload[0] != 0x16 {
        return None;
    }
    let record_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;
    if payload.len() < 5 + record_len {
        return None;
    }
    let hs = &payload[5..5 + record_len];
    if hs.len() < 4 || hs[0] != 0x01 {
        return None;
    }

    let mut offset = 4usize; // skip handshake header
    if hs.len() < offset + 2 + 32 + 1 {
        return None;
    }
    let client_version = u16::from_be_bytes([hs[offset], hs[offset + 1]]);
    offset += 2 + 32;

    let session_id_len = hs[offset] as usize;
    offset += 1;
    if hs.len() < offset + session_id_len + 2 {
        return None;
    }
    offset += session_id_len;

    let cipher_len = u16::from_be_bytes([hs[offset], hs[offset + 1]]) as usize;
    offset += 2;
    if hs.len() < offset + cipher_len + 1 {
        return None;
    }
    let ciphers = &hs[offset..offset + cipher_len];
    offset += cipher_len;

    let comp_len = hs[offset] as usize;
    offset += 1;
    if hs.len() < offset + comp_len + 2 {
        return None;
    }
    offset += comp_len;

    let mut extensions = Vec::new();
    let mut sni = None;
    let mut curves = Vec::new();
    let mut point_formats = Vec::new();

    if hs.len() >= offset + 2 {
        let ext_total = u16::from_be_bytes([hs[offset], hs[offset + 1]]) as usize;
        offset += 2;
        let ext_end = offset.saturating_add(ext_total).min(hs.len());
        while offset + 4 <= ext_end {
            let ext_type = u16::from_be_bytes([hs[offset], hs[offset + 1]]);
            let ext_len = u16::from_be_bytes([hs[offset + 2], hs[offset + 3]]) as usize;
            offset += 4;
            if offset + ext_len > ext_end {
                break;
            }
            let ext_data = &hs[offset..offset + ext_len];
            extensions.push(ext_type);
            match ext_type {
                0 => sni = parse_sni_extension(ext_data),
                10 => curves = parse_supported_groups(ext_data),
                11 => point_formats = parse_ec_point_formats(ext_data),
                _ => {}
            }
            offset += ext_len;
        }
    }

    let ja3 = Some(compute_ja3(
        client_version,
        ciphers,
        &extensions,
        &curves,
        &point_formats,
    ));
    Some((sni, ja3))
}

fn parse_sni_extension(data: &[u8]) -> Option<String> {
    if data.len() < 5 {
        return None;
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + list_len || data[2] != 0 {
        return None;
    }
    let name_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    if data.len() < 5 + name_len {
        return None;
    }
    String::from_utf8(data[5..5 + name_len].to_vec()).ok()
}

fn parse_supported_groups(data: &[u8]) -> Vec<u16> {
    if data.len() < 2 {
        return Vec::new();
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let mut groups = Vec::new();
    let mut offset = 2;
    while offset + 2 <= 2 + list_len && offset + 2 <= data.len() {
        groups.push(u16::from_be_bytes([data[offset], data[offset + 1]]));
        offset += 2;
    }
    groups
}

fn parse_ec_point_formats(data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        return Vec::new();
    }
    let list_len = data[0] as usize;
    data.get(1..1 + list_len)
        .map(|s| s.to_vec())
        .unwrap_or_default()
}

fn compute_ja3(
    version: u16,
    ciphers: &[u8],
    extensions: &[u16],
    curves: &[u16],
    point_formats: &[u8],
) -> String {
    let cipher_str = join_u16_hex(ciphers);
    let ext_str = extensions
        .iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join("-");
    let curve_str = curves
        .iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join("-");
    let pf_str = point_formats
        .iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join("-");

    let raw = format!("{version},{cipher_str},{ext_str},{curve_str},{pf_str}");
    format!("{:x}", md5::compute(raw.as_bytes()))
}

fn join_u16_hex(ciphers: &[u8]) -> String {
    ciphers
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]).to_string())
        .collect::<Vec<_>>()
        .join("-")
}

/// Parse the QNAME of the first DNS question (standard query).
fn parse_dns_query(payload: &[u8]) -> Option<String> {
    if payload.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
    if qdcount == 0 {
        return None;
    }
    decode_dns_name(payload, 12)
}

fn decode_dns_name(data: &[u8], mut offset: usize) -> Option<String> {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut jump_limit = 0usize;

    loop {
        if offset >= data.len() {
            return None;
        }
        let len = data[offset];
        if len == 0 {
            break;
        }
        if len & 0xC0 == 0xC0 {
            if offset + 1 >= data.len() {
                return None;
            }
            let pointer = u16::from_be_bytes([data[offset] & 0x3F, data[offset + 1]]) as usize;
            if !jumped {
                jump_limit = offset + 2;
            }
            offset = pointer;
            jumped = true;
            if jump_limit > 0 && offset >= jump_limit {
                // safety against loops
            }
            continue;
        }
        offset += 1;
        if offset + len as usize > data.len() {
            return None;
        }
        labels.push(String::from_utf8(data[offset..offset + len as usize].to_vec()).ok()?);
        offset += len as usize;
        if !jumped && labels.len() > 128 {
            return None;
        }
    }
    if labels.is_empty() {
        None
    } else {
        Some(labels.join("."))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eth_ipv4_udp(payload: &[u8], src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16) -> Vec<u8> {
        let udp_len = 8 + payload.len();
        let ip_len = 20 + udp_len;
        let mut frame = vec![0u8; 14 + ip_len];
        frame[12] = 0x08;
        frame[13] = 0x00;
        let ip = &mut frame[14..];
        ip[0] = 0x45;
        ip[2] = (ip_len >> 8) as u8;
        ip[3] = ip_len as u8;
        ip[9] = 17;
        ip[12..16].copy_from_slice(&src);
        ip[16..20].copy_from_slice(&dst);
        let udp = &mut ip[20..];
        udp[0..2].copy_from_slice(&sport.to_be_bytes());
        udp[2..4].copy_from_slice(&dport.to_be_bytes());
        udp[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
        udp[8..8 + payload.len()].copy_from_slice(payload);
        frame
    }

    #[test]
    fn parses_dns_query() {
        // query for example.com, standard query
        let dns = [
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01,
        ];
        let frame = eth_ipv4_udp(&dns, [10, 0, 0, 1], [8, 8, 8, 8], 43210, 53);
        let pkt = parse_frame(&frame).expect("parse");
        assert_eq!(pkt.proto, FlowProto::Udp);
        assert_eq!(pkt.dns_query.as_deref(), Some("example.com"));
        assert_eq!(pkt.app_proto.as_deref(), Some("DNS"));
    }

    #[test]
    fn parses_tls_sni_and_ja3() {
        // Minimal TLS 1.2 ClientHello with SNI=example.com
        let mut ch = Vec::new();
        ch.extend_from_slice(&[0x03, 0x03]); // client version TLS 1.2
        ch.extend_from_slice(&[0u8; 32]); // random
        ch.push(0); // session id len
        ch.extend_from_slice(&[0x00, 0x04]); // cipher suites len
        ch.extend_from_slice(&[0x00, 0x2f, 0x00, 0x35]); // two ciphers
        ch.push(1); // compression len
        ch.push(0); // null compression
                    // extensions
        let sni_name = b"example.com";
        let list_len = 1 + 2 + sni_name.len();
        let mut sni_ext_data = Vec::new();
        sni_ext_data.extend_from_slice(&(list_len as u16).to_be_bytes());
        sni_ext_data.push(0x00);
        sni_ext_data.extend_from_slice(&(sni_name.len() as u16).to_be_bytes());
        sni_ext_data.extend_from_slice(sni_name);
        let mut sni = vec![0x00, 0x00];
        sni.extend_from_slice(&(sni_ext_data.len() as u16).to_be_bytes());
        sni.extend_from_slice(&sni_ext_data);
        let supported_groups = [0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x17];
        let ec_pf = [0x00, 0x0b, 0x00, 0x02, 0x01, 0x00];
        let ext_block: Vec<u8> = sni
            .into_iter()
            .chain(supported_groups)
            .chain(ec_pf)
            .collect();
        let ext_len = ext_block.len() as u16;
        ch.extend_from_slice(&ext_len.to_be_bytes());
        ch.extend_from_slice(&ext_block);

        let hs_len = ch.len();
        let mut record = Vec::new();
        record.push(0x16); // handshake
        record.extend_from_slice(&[0x03, 0x01]);
        record.extend_from_slice(&((hs_len + 4) as u16).to_be_bytes());
        record.push(0x01); // ClientHello
        record.extend_from_slice(&(hs_len as u32).to_be_bytes()[1..]);
        record.extend_from_slice(&ch);

        let tcp_payload = record;
        let tcp_len = 20 + tcp_payload.len();
        let ip_len = 20 + tcp_len;
        let mut frame = vec![0u8; 14 + ip_len];
        frame[12] = 0x08;
        frame[13] = 0x00;
        let ip = &mut frame[14..];
        ip[0] = 0x45;
        ip[2] = (ip_len >> 8) as u8;
        ip[3] = ip_len as u8;
        ip[9] = 6;
        ip[12..16].copy_from_slice(&[10, 0, 0, 42]);
        ip[16..20].copy_from_slice(&[93, 184, 216, 34]);
        let tcp = &mut ip[20..];
        tcp[0..2].copy_from_slice(&54321u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&443u16.to_be_bytes());
        tcp[12] = 0x50; // data offset 5
        tcp[20..].copy_from_slice(&tcp_payload);

        let pkt = parse_frame(&frame).expect("parse");
        assert_eq!(pkt.proto, FlowProto::Tcp);
        assert_eq!(pkt.tls_sni.as_deref(), Some("example.com"));
        assert_eq!(pkt.app_proto.as_deref(), Some("TLS"));
        assert!(pkt.ja3.is_some());
    }
}
