//! Frugal MapResponse peer extraction.
//!
//! The full netmap is large (DERPMap, packet filter, user profiles, …) and
//! parsing it into a `serde_json::Value` tree blows the ~287 KB heap. Instead we
//! deserialize into a *typed* struct that mentions only the handful of fields the
//! data plane needs; serde_json discards every other field via `IgnoredAny`
//! without allocating it. That keeps peak memory to roughly the few small strings
//! we actually keep.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::net::Ipv4Addr;

use anyhow::{Context, Result};
use serde::Deserialize;

/// The minimum a peer needs for a direct WireGuard path.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub node_key: [u8; 32],
    pub disco_key: [u8; 32],
    pub tailscale_ip: Option<String>, // first 100.x address, /bits stripped
    pub endpoints: Vec<String>,       // candidate "ip:port" direct paths
    pub hostname: String,
}

// --- minimal wire structs: only the fields we read ---

#[derive(Deserialize)]
struct MapResp {
    #[serde(rename = "Peers")]
    peers: Option<Vec<PeerT>>,
}

#[derive(Deserialize)]
struct PeerT {
    #[serde(rename = "Key")]
    key: Option<String>,
    #[serde(rename = "DiscoKey")]
    disco_key: Option<String>,
    #[serde(rename = "Addresses")]
    addresses: Option<Vec<String>>,
    #[serde(rename = "Endpoints")]
    endpoints: Option<Vec<String>>,
    #[serde(rename = "Hostinfo")]
    hostinfo: Option<HostinfoT>,
}

#[derive(Deserialize)]
struct HostinfoT {
    #[serde(rename = "Hostname")]
    hostname: Option<String>,
}

// --- packet filter (ACL) wire structs ---

#[derive(Deserialize)]
struct FilterResp {
    #[serde(rename = "PacketFilter")]
    packet_filter: Option<Vec<FilterRule>>,
}

#[derive(Deserialize)]
struct FilterRule {
    #[serde(rename = "SrcIPs")]
    src_ips: Option<Vec<String>>,
    #[serde(rename = "DstPorts")]
    dst_ports: Option<Vec<NetPortRange>>,
}

#[derive(Deserialize)]
struct NetPortRange {
    #[serde(rename = "IP")]
    ip: Option<String>,
}

/// An allowed source as an IPv4 CIDR (network, mask).
pub type Cidr = (u32, u32);

/// Parse the netmap PacketFilter and return the IPv4 source CIDRs permitted to
/// reach us (`our_ip`). An empty result with rules present means "deny all"; if
/// there is no PacketFilter at all we return None (caller treats as allow-all).
pub fn parse_allowed_srcs(raw: &[u8], our_ip: &str) -> Option<Vec<Cidr>> {
    let f: FilterResp = serde_json::from_slice(raw).ok()?;
    let rules = f.packet_filter?;
    let our = parse_cidr(&format!("{our_ip}/32"))?;
    let mut out = Vec::new();
    for rule in rules {
        // Does this rule's destination cover us?
        let covers_us = rule
            .dst_ports
            .unwrap_or_default()
            .into_iter()
            .filter_map(|d| d.ip)
            .any(|ip| ip == "*" || cidr_contains(parse_cidr(&ip), our.0));
        if !covers_us {
            continue;
        }
        for s in rule.src_ips.unwrap_or_default() {
            if s == "*" {
                out.push((0u32, 0u32)); // any
            } else if let Some(c) = parse_cidr(&s) {
                out.push(c);
            }
        }
    }
    Some(out)
}

/// True if `ip` (host-order u32) is inside the given CIDR.
pub fn cidr_match(allowed: &[Cidr], ip: u32) -> bool {
    allowed.iter().any(|&(net, mask)| ip & mask == net & mask)
}

fn cidr_contains(c: Option<Cidr>, ip: u32) -> bool {
    match c {
        Some((net, mask)) => ip & mask == net & mask,
        None => false,
    }
}

fn parse_cidr(s: &str) -> Option<Cidr> {
    let (ip, bits) = match s.split_once('/') {
        Some((i, b)) => (i, b.parse::<u32>().ok()?),
        None => (s, 32),
    };
    let v: Ipv4Addr = ip.parse().ok()?;
    let net = u32::from_be_bytes(v.octets());
    let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits.min(32)) };
    Some((net, mask))
}

/// Parse the (full, OmitPeers=false) MapResponse JSON and return the peers that
/// have both a node key and a disco key (i.e. are usable for a direct path).
pub fn parse_peers(raw: &[u8]) -> Result<Vec<PeerInfo>> {
    let m: MapResp = serde_json::from_slice(raw).context("parse MapResponse peers")?;
    let mut out = Vec::new();
    for p in m.peers.unwrap_or_default() {
        let node_key = match p.key.as_deref().and_then(parse_keyed_hex) {
            Some(k) => k,
            None => continue,
        };
        let disco_key = match p.disco_key.as_deref().and_then(parse_keyed_hex) {
            Some(k) => k,
            None => continue,
        };
        let tailscale_ip = p
            .addresses
            .unwrap_or_default()
            .into_iter()
            .map(|a| a.split('/').next().unwrap_or("").to_string())
            .find(|a| a.starts_with("100."));
        let hostname = p
            .hostinfo
            .and_then(|h| h.hostname)
            .unwrap_or_else(|| "?".to_string());
        out.push(PeerInfo {
            node_key,
            disco_key,
            tailscale_ip,
            endpoints: p.endpoints.unwrap_or_default(),
            hostname,
        });
    }
    Ok(out)
}

/// Decode a `"<type>:<64-hex>"` key string (e.g. `nodekey:abcd…`,
/// `discokey:abcd…`) into 32 raw bytes. Accepts a bare 64-hex string too.
fn parse_keyed_hex(s: &str) -> Option<[u8; 32]> {
    let hex = s.rsplit(':').next().unwrap_or(s);
    if hex.len() != 64 {
        return None;
    }
    let bytes = hex.as_bytes();
    let mut out = [0u8; 32];
    for i in 0..32 {
        let hi = hex_val(bytes[i * 2])?;
        let lo = hex_val(bytes[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}
