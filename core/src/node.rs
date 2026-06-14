//! Shared data-plane identity + packet-filter check, used by both transports
//! (the UDP `dataplane` and the `derp` relay). The portable, allocation-only parts
//! live here; the firmware adds the channel-carrying wiring structs (`Upgrade`,
//! `MdnsLink`) that need `std::sync::mpsc`.

use alloc::string::String;
use alloc::vec::Vec;
use core::net::SocketAddr;

use crate::peers::{cidr_match, Cidr};

/// A peer we want to reach directly, with its disco + node identities and paths.
pub struct Target {
    pub name: String,
    pub disco_pub: [u8; 32],
    pub node_pub: [u8; 32],
    pub endpoints: Vec<SocketAddr>,
    /// Birthday port-spray this peer's public endpoints (for symmetric NAT).
    pub spray: bool,
}

/// Netmap lookup row used by derp-upgrade to find a relayed peer's disco key and
/// candidate UDP endpoints (to coordinate a direct hole-punch).
pub struct PeerDir {
    pub node_pub: [u8; 32],
    pub disco_pub: [u8; 32],
    pub endpoints: Vec<SocketAddr>,
}

/// Device-initiated traffic config: ping + HTTP GET out to one target peer.
#[derive(Clone)]
pub struct OutboundCfg {
    pub our_ip: core::net::Ipv4Addr,
    pub target_ip: core::net::Ipv4Addr,
    pub target_node: [u8; 32],
    pub http_port: u16,
    pub http_path: String,
}

/// Identity this node uses on the data plane.
#[derive(Clone)]
pub struct Identity {
    pub disco_priv: [u8; 32],
    pub disco_pub: [u8; 32],
    pub node_priv: [u8; 32],
    pub node_pub: [u8; 32],
    /// Allowed source CIDRs from the netmap ACL. `None` = allow all (filter off).
    pub allowed_srcs: Option<Vec<Cidr>>,
}

/// Enforce the packet filter: is the inner IPv4 packet's source allowed to reach
/// us? `None` (no ACL / feature off) allows everything.
pub fn src_allowed(allowed: &Option<Vec<Cidr>>, inner: &[u8]) -> bool {
    let cidrs = match allowed {
        Some(c) => c,
        None => return true,
    };
    if inner.len() < 16 || (inner[0] >> 4) != 4 {
        return true; // not IPv4 we understand; don't block
    }
    let src = u32::from_be_bytes([inner[12], inner[13], inner[14], inner[15]]);
    cidr_match(cidrs, src)
}
