//! mDNS / Bonjour reflector over Tailscale.
//!
//! Tailscale is unicast-only, so we can't multicast over the tunnel. Instead two
//! reflectors (one per LAN) bridge the multicast domain: each captures local
//! mDNS (224.0.0.251:5353), unicasts the payload to its partner over the tunnel,
//! and the partner re-multicasts it on the far LAN. This lets cross-network
//! Bonjour work (Xcode device discovery, AirPlay, AirPrint, …).
//!
//! Loop prevention (three layers):
//!  1. Never forward a packet we just re-injected (its hash is pre-seeded).
//!  2. Dedup by recent payload hash (short window) — drops echoes.
//!  3. The data plane only forwards LAN-captured packets to the partner, and only
//!     re-injects partner-sourced packets — the two directions never cross.

use std::collections::VecDeque;
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::sync::mpsc::{Receiver, Sender};
use std::time::Duration;

pub const GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
pub const MDNS_PORT: u16 = 5353;
/// Inner-UDP port used to carry forwarded mDNS between reflectors over the tunnel.
pub const FWD_PORT: u16 = 5354;

const DEDUP_MAX: usize = 64;

/// Run the reflector: capture LAN mDNS → `fwd_tx` (data plane sends to partner);
/// `reinject_rx` delivers partner mDNS to re-multicast on our LAN.
pub fn run(lan_ip: Ipv4Addr, fwd_tx: Sender<Vec<u8>>, reinject_rx: Receiver<Vec<u8>>) {
    let sock = match bind_mdns(lan_ip) {
        Ok(s) => s,
        Err(e) => {
            println!("mdns: bind/join failed: {e} — reflector disabled");
            return;
        }
    };
    let _ = sock.set_read_timeout(Some(Duration::from_millis(400)));
    println!("mdns: reflector up (group 224.0.0.251:5353)");

    let mut seen: VecDeque<u64> = VecDeque::with_capacity(DEDUP_MAX);
    let group = SocketAddrV4::new(GROUP, MDNS_PORT);
    let mut buf = [0u8; 1500];
    let mut captured: u32 = 0;
    let mut forwarded: u32 = 0;

    loop {
        // Re-inject anything the partner sent us, onto our LAN.
        while let Ok(payload) = reinject_rx.try_recv() {
            let h = hash(&payload);
            remember(&mut seen, h); // so we don't re-forward our own injection
            let _ = sock.send_to(&payload, group);
        }

        // Capture LAN mDNS and hand it to the data plane for the partner.
        match sock.recv_from(&mut buf) {
            Ok((n, from)) => {
                // Ignore our own re-injected traffic (source = us).
                if from.ip() == std::net::IpAddr::V4(lan_ip) {
                    continue;
                }
                let pkt = &buf[..n];
                captured += 1;
                if captured <= 3 || captured % 25 == 0 {
                    println!("mdns: captured #{captured} ({n}B from {from})");
                }
                let h = hash(pkt);
                if seen.contains(&h) {
                    continue; // echo / already handled
                }
                remember(&mut seen, h);
                forwarded += 1;
                if forwarded <= 3 || forwarded % 25 == 0 {
                    println!("mdns: forward #{forwarded} to partner");
                }
                let _ = fwd_tx.send(pkt.to_vec());
            }
            Err(e) => {
                let k = e.kind();
                if k != std::io::ErrorKind::WouldBlock && k != std::io::ErrorKind::TimedOut {
                    println!("mdns: recv error: {e}");
                }
            }
        }
    }
}

fn bind_mdns(lan_ip: Ipv4Addr) -> std::io::Result<UdpSocket> {
    // No other mDNS responder runs on the dongle, so a plain bind on :5353 is fine.
    let sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, MDNS_PORT))?;
    sock.join_multicast_v4(&GROUP, &lan_ip)?;
    Ok(sock)
}

fn remember(seen: &mut VecDeque<u64>, h: u64) {
    if seen.len() >= DEDUP_MAX {
        seen.pop_front();
    }
    seen.push_back(h);
}

/// FNV-1a hash for cheap payload dedup.
fn hash(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in data {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}
