//! Minimal STUN (RFC 5389) Binding client — just enough to learn our public
//! `ip:port` as seen from the internet, for Tailscale endpoint advertisement and
//! NAT traversal. We only build a Binding Request and parse XOR-MAPPED-ADDRESS
//! (falling back to the legacy MAPPED-ADDRESS) from the Binding Response.

use core::net::SocketAddrV4;

use anyhow::{bail, Result};

pub const MAGIC_COOKIE: u32 = 0x2112_A442;

const BINDING_REQUEST: u16 = 0x0001;
const BINDING_RESPONSE: u16 = 0x0101;

const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

/// A 20-byte STUN Binding Request with a random transaction id. Returns the
/// request bytes plus the 12-byte transaction id (so the caller can match the
/// response).
pub fn binding_request() -> ([u8; 20], [u8; 12]) {
    let mut txid = [0u8; 12];
    fill_random(&mut txid);

    let mut req = [0u8; 20];
    req[0..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
    req[2..4].copy_from_slice(&0u16.to_be_bytes()); // message length = 0 (no attrs)
    req[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    req[8..20].copy_from_slice(&txid);
    (req, txid)
}

/// Parse a STUN Binding Response and return the mapped (public) IPv4 address.
/// Verifies the magic cookie and that the transaction id matches our request.
pub fn parse_response(buf: &[u8], txid: &[u8; 12]) -> Result<SocketAddrV4> {
    if buf.len() < 20 {
        bail!("STUN response too short ({} bytes)", buf.len());
    }
    let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
    if msg_type != BINDING_RESPONSE {
        bail!("not a STUN Binding Response (type 0x{msg_type:04x})");
    }
    let cookie = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    if cookie != MAGIC_COOKIE {
        bail!("bad STUN magic cookie 0x{cookie:08x}");
    }
    if &buf[8..20] != txid {
        bail!("STUN transaction id mismatch");
    }

    let msg_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    let end = (20 + msg_len).min(buf.len());

    let mut i = 20;
    while i + 4 <= end {
        let atype = u16::from_be_bytes([buf[i], buf[i + 1]]);
        let alen = u16::from_be_bytes([buf[i + 2], buf[i + 3]]) as usize;
        let val_start = i + 4;
        let val_end = val_start + alen;
        if val_end > end {
            break;
        }
        let val = &buf[val_start..val_end];
        match atype {
            ATTR_XOR_MAPPED_ADDRESS => {
                if let Some(addr) = parse_xor_mapped(val) {
                    return Ok(addr);
                }
            }
            ATTR_MAPPED_ADDRESS => {
                if let Some(addr) = parse_mapped(val) {
                    return Ok(addr);
                }
            }
            _ => {}
        }
        // Attributes are padded to a 4-byte boundary.
        i = val_end + ((4 - (alen & 3)) & 3);
    }
    bail!("no MAPPED-ADDRESS attribute in STUN response")
}

/// XOR-MAPPED-ADDRESS: family(1) after 1 reserved byte, x-port(2), x-addr(4),
/// each XORed with the magic cookie (and txid for IPv6, which we ignore).
fn parse_xor_mapped(val: &[u8]) -> Option<SocketAddrV4> {
    if val.len() < 8 || val[1] != 0x01 {
        return None; // need IPv4 (family 0x01)
    }
    let x_port = u16::from_be_bytes([val[2], val[3]]);
    let port = x_port ^ (MAGIC_COOKIE >> 16) as u16;
    let x_addr = u32::from_be_bytes([val[4], val[5], val[6], val[7]]);
    let addr = x_addr ^ MAGIC_COOKIE;
    Some(SocketAddrV4::new(addr.into(), port))
}

/// Legacy MAPPED-ADDRESS (not XORed).
fn parse_mapped(val: &[u8]) -> Option<SocketAddrV4> {
    if val.len() < 8 || val[1] != 0x01 {
        return None;
    }
    let port = u16::from_be_bytes([val[2], val[3]]);
    let addr = u32::from_be_bytes([val[4], val[5], val[6], val[7]]);
    Some(SocketAddrV4::new(addr.into(), port))
}

/// True if `buf` looks like a STUN message (magic cookie at bytes 4..8). Used by
/// the unified UDP socket to demultiplex STUN from disco/WireGuard.
pub fn is_stun(buf: &[u8]) -> bool {
    buf.len() >= 8 && u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]) == MAGIC_COOKIE
}

/// Random bytes via `getrandom` (esp-idf backend = esp_fill_random on-device).
fn fill_random(out: &mut [u8]) {
    getrandom::getrandom(out).expect("getrandom");
}
