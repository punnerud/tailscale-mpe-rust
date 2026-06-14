//! Just enough IPv4 + ICMP to answer a ping. The data plane decrypts a WireGuard
//! transport packet into an inner IP packet; if it's an ICMP echo request to us,
//! `echo_reply` turns it into the matching echo reply to send back. Pure byte
//! math — no platform dependencies (the first module migrated to the core crate).

use alloc::vec::Vec;

const PROTO_ICMP: u8 = 1;
const ICMP_ECHO_REQUEST: u8 = 8;
const ICMP_ECHO_REPLY: u8 = 0;

/// If `inner` is an IPv4 ICMP echo request, build the echo reply (src/dst
/// swapped, type set to reply, both checksums recomputed). Returns None for
/// anything else.
pub fn echo_reply(inner: &[u8]) -> Option<Vec<u8>> {
    if inner.len() < 20 || (inner[0] >> 4) != 4 {
        return None; // not IPv4
    }
    let ihl = (inner[0] & 0x0f) as usize * 4;
    let total_len = u16::from_be_bytes([inner[2], inner[3]]) as usize;
    if ihl < 20 || total_len < ihl || total_len > inner.len() {
        return None;
    }
    if inner[9] != PROTO_ICMP {
        return None;
    }
    let icmp = &inner[ihl..total_len];
    if icmp.len() < 8 || icmp[0] != ICMP_ECHO_REQUEST {
        return None;
    }

    let mut pkt = inner[..total_len].to_vec();

    let mut src = [0u8; 4];
    let mut dst = [0u8; 4];
    src.copy_from_slice(&pkt[12..16]);
    dst.copy_from_slice(&pkt[16..20]);
    pkt[12..16].copy_from_slice(&dst);
    pkt[16..20].copy_from_slice(&src);

    pkt[ihl] = ICMP_ECHO_REPLY;
    pkt[ihl + 2] = 0;
    pkt[ihl + 3] = 0;
    let csum = checksum(&pkt[ihl..total_len]);
    pkt[ihl + 2..ihl + 4].copy_from_slice(&csum.to_be_bytes());

    pkt[10] = 0;
    pkt[11] = 0;
    let ipsum = checksum(&pkt[..ihl]);
    pkt[10..12].copy_from_slice(&ipsum.to_be_bytes());

    Some(pkt)
}

/// Standard internet 16-bit one's-complement checksum.
pub fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
