//! Data-plane identity + packet-filter check.
//!
//! The portable parts (`Target`, `PeerDir`, `OutboundCfg`, `Identity`,
//! `src_allowed`) live in the no_std core crate ([`tailscale_core::node`]); this
//! firmware module re-exports them and adds the two wiring structs that carry
//! `std::sync::mpsc` channels (which std-less core can't hold).

pub use tailscale_core::node::*;

use std::net::{Ipv4Addr, SocketAddr};

/// Handed to the DERP thread (when `derp-upgrade` is on) so it can ask the UDP
/// dataplane to attempt a direct path to a peer it's currently relaying.
pub struct Upgrade {
    pub tx: std::sync::mpsc::Sender<Target>,
    pub our_endpoints: Vec<SocketAddr>,
    pub peers: Vec<PeerDir>,
}

/// mDNS reflector wiring handed to the data plane: where to forward captured
/// mDNS (the partner peer) and the channels to/from the reflector thread.
pub struct MdnsLink {
    pub our_ip: Ipv4Addr,
    pub partner_ip: Ipv4Addr,
    pub partner_node: [u8; 32],
    /// LAN-captured mDNS payloads to forward to the partner over the tunnel.
    pub fwd_rx: std::sync::mpsc::Receiver<Vec<u8>>,
    /// Partner mDNS payloads to re-multicast on our LAN.
    pub reinject_tx: std::sync::mpsc::Sender<Vec<u8>>,
}
