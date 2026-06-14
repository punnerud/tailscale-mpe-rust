//! Tailscale "disco" path-discovery messages.
//!
//! Disco runs on the same UDP socket as WireGuard. Each packet is:
//!   magic(6) ‖ sender_disco_pub(32) ‖ nonce(24) ‖ NaCl_box(plaintext)
//! where the box is sealed with the sender's disco private key to the recipient's
//! disco public key (Curve25519 + XSalsa20-Poly1305 = `crypto_box::SalsaBox`).
//!
//! We only need PING (probe a path) and PONG (confirm it). A peer will not route
//! WireGuard to one of our endpoints until disco has confirmed that path, so we
//! both send pings to peers and answer incoming pings with pongs.

use alloc::vec::Vec;
use core::net::{Ipv4Addr, SocketAddr};

use anyhow::{bail, Result};
use crypto_box::aead::{Aead, Nonce};
use crypto_box::{PublicKey, SalsaBox, SecretKey};

pub const MAGIC: [u8; 6] = [0x54, 0x53, 0xf0, 0x9f, 0x92, 0xac]; // "TS💬"

pub const PING: u8 = 0x01;
pub const PONG: u8 = 0x02;
pub const CALL_ME_MAYBE: u8 = 0x03;

const VERSION: u8 = 0x00;
const HDR: usize = 6 + 32 + 24; // magic + sender pub + nonce

/// True if the datagram is a disco packet (starts with the magic).
pub fn is_disco(buf: &[u8]) -> bool {
    buf.len() >= 6 && buf[..6] == MAGIC
}

/// A decoded incoming disco packet.
pub struct Incoming {
    pub sender_disco_pub: [u8; 32],
    pub msg_type: u8,
    pub txid: [u8; 12],
    /// For CALL_ME_MAYBE: the peer's candidate IPv4 endpoints (fresh ports).
    pub endpoints: Vec<SocketAddr>,
}

/// PING plaintext: type ‖ ver ‖ TxID(12) ‖ our_node_pub(32).
pub fn ping_plaintext(txid: &[u8; 12], node_pub: &[u8; 32]) -> Vec<u8> {
    let mut p = Vec::with_capacity(2 + 12 + 32);
    p.push(PING);
    p.push(VERSION);
    p.extend_from_slice(txid);
    p.extend_from_slice(node_pub);
    p
}

/// PONG plaintext: type ‖ ver ‖ TxID(12) ‖ Src(16-byte IP ‖ 2-byte port BE).
pub fn pong_plaintext(txid: &[u8; 12], src: SocketAddr) -> Vec<u8> {
    let mut p = Vec::with_capacity(2 + 12 + 18);
    p.push(PONG);
    p.push(VERSION);
    p.extend_from_slice(txid);
    p.extend_from_slice(&addr_to_bytes(src));
    p
}

/// CALL_ME_MAYBE plaintext: type ‖ ver ‖ N×AddrPort(16-byte IP ‖ 2-byte port BE).
/// Tells a peer the endpoints it should try to reach us at (NAT hole-punch).
pub fn call_me_maybe_plaintext(eps: &[SocketAddr]) -> Vec<u8> {
    let mut p = Vec::with_capacity(2 + eps.len() * 18);
    p.push(CALL_ME_MAYBE);
    p.push(VERSION);
    for e in eps {
        p.extend_from_slice(&addr_to_bytes(*e));
    }
    p
}

/// Seal a plaintext disco message into a wire packet addressed to `peer_disco_pub`.
pub fn seal(
    my_disco_priv: &[u8; 32],
    my_disco_pub: &[u8; 32],
    peer_disco_pub: &[u8; 32],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let bx = salsabox(my_disco_priv, peer_disco_pub);
    let mut nbytes = [0u8; 24];
    fill_random(&mut nbytes);
    let nonce = Nonce::<SalsaBox>::clone_from_slice(&nbytes);
    let ct = bx
        .encrypt(&nonce, plaintext)
        .map_err(|_| anyhow::anyhow!("disco seal failed"))?;

    let mut out = Vec::with_capacity(HDR + ct.len());
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(my_disco_pub);
    out.extend_from_slice(&nbytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Parse + decrypt an incoming disco packet. Returns the sender's disco pubkey,
/// message type and transaction id.
pub fn open(my_disco_priv: &[u8; 32], wire: &[u8]) -> Result<Incoming> {
    if wire.len() < HDR + 16 || wire[..6] != MAGIC {
        bail!("not a disco packet");
    }
    let mut sender = [0u8; 32];
    sender.copy_from_slice(&wire[6..38]);
    let nonce = Nonce::<SalsaBox>::clone_from_slice(&wire[38..62]);
    let bx = salsabox(my_disco_priv, &sender);
    let pt = bx
        .decrypt(&nonce, &wire[62..])
        .map_err(|_| anyhow::anyhow!("disco open failed (MAC)"))?;
    if pt.len() < 14 {
        bail!("disco plaintext too short");
    }
    let mut txid = [0u8; 12];
    txid.copy_from_slice(&pt[2..14]);
    let endpoints = if pt[0] == CALL_ME_MAYBE {
        pt[2..].chunks(18).filter_map(bytes_to_addr).collect()
    } else {
        Vec::new()
    };
    Ok(Incoming { sender_disco_pub: sender, msg_type: pt[0], txid, endpoints })
}

/// Decode an 18-byte AddrPort (16-byte IP ‖ 2-byte port BE) — IPv4 only.
fn bytes_to_addr(b: &[u8]) -> Option<SocketAddr> {
    if b.len() < 18 {
        return None;
    }
    let port = u16::from_be_bytes([b[16], b[17]]);
    // IPv4-mapped IPv6: ::ffff:a.b.c.d
    if b[..10].iter().all(|&x| x == 0) && b[10] == 0xff && b[11] == 0xff {
        return Some(SocketAddr::from((Ipv4Addr::new(b[12], b[13], b[14], b[15]), port)));
    }
    None // skip native IPv6
}

fn salsabox(my_priv: &[u8; 32], peer_pub: &[u8; 32]) -> SalsaBox {
    let sk = SecretKey::from(*my_priv);
    let pk = PublicKey::from(*peer_pub);
    SalsaBox::new(&pk, &sk)
}

/// Encode a SocketAddr as Tailscale's 18-byte AddrPort: 16-byte IP (IPv4 as the
/// 4-in-6 mapped form) followed by a big-endian u16 port.
fn addr_to_bytes(addr: SocketAddr) -> [u8; 18] {
    let mut out = [0u8; 18];
    match addr {
        SocketAddr::V4(v4) => {
            out[10] = 0xff;
            out[11] = 0xff;
            out[12..16].copy_from_slice(&v4.ip().octets());
        }
        SocketAddr::V6(v6) => {
            out[0..16].copy_from_slice(&v6.ip().octets());
        }
    }
    out[16..18].copy_from_slice(&addr.port().to_be_bytes());
    out
}

/// Random bytes via `getrandom` (esp-idf backend = esp_fill_random on-device).
fn fill_random(out: &mut [u8]) {
    getrandom::getrandom(out).expect("getrandom");
}
