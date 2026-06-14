//! Platform capabilities the core needs, provided by adapter crates (esp32, iOS,
//! desktop, …). Keeping these as traits is what makes the core `no_std` and
//! reusable: the core never names a concrete socket, RNG, clock or store.
//!
//! Threading model: the core exposes loop functions; the *adapter* spawns them on
//! threads / run-loops. So there is no thread or channel type here.

use alloc::vec::Vec;
use core::net::{Ipv4Addr, SocketAddr};

/// Cryptographically-strong randomness (e.g. `esp_fill_random`, `getrandom`).
pub trait Rng {
    fn fill(&self, out: &mut [u8]);
}

/// Wall clock, used for the WireGuard TAI64N timestamp (must be monotonic across
/// reboots, so back it with real time where possible).
pub trait Clock {
    fn unix_secs(&self) -> u64;
    fn unix_nanos(&self) -> u32 {
        0
    }
}

/// Small persistent key/value store for the node's private keys (NVS, a file,
/// the iOS keychain, …).
pub trait Storage {
    fn get(&self, key: &str) -> Option<Vec<u8>>;
    fn set(&self, key: &str, val: &[u8]);
}

/// A connected, ordered byte stream (TCP for the ts2021 cleartext `:80` upgrade).
pub trait ByteStream {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, ()>;
    fn write_all(&mut self, buf: &[u8]) -> Result<(), ()>;
}

/// UDP socket for the data plane (STUN + disco + WireGuard share one).
pub trait UdpSock {
    fn local_port(&self) -> u16;
    fn send_to(&self, buf: &[u8], dst: SocketAddr) -> Result<(), ()>;
    fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), ()>;
    /// True when a recv returned because of the read timeout (no data), so the
    /// caller can treat it as "tick" rather than an error.
    fn would_block(&self) -> bool {
        false
    }
}

/// Opens TCP / TLS connections (TLS for `/key` HTTPS and the DERP relay).
pub trait Connector {
    type Stream: ByteStream;
    fn connect_tcp(&self, host: &str, port: u16) -> Result<Self::Stream, ()>;
    fn connect_tls(&self, host: &str, port: u16) -> Result<Self::Stream, ()>;
}

/// Join/leave IPv4 multicast + send to a group (for the mDNS reflector). Optional.
pub trait MulticastSock {
    fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), ()>;
    fn send_to(&self, buf: &[u8], dst: SocketAddr) -> Result<(), ()>;
    fn lan_ip(&self) -> Ipv4Addr;
}
