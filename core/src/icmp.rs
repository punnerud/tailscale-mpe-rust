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

const NEXT_HDR_ICMPV6: u8 = 58;
const ICMPV6_ECHO_REQUEST: u8 = 128;
const ICMPV6_ECHO_REPLY: u8 = 129;

/// v4 or v6: if `inner` is an ICMP/ICMPv6 echo request, build the matching reply.
/// Lets the data plane answer `ping` and `ping6` over the same WireGuard tunnel.
pub fn echo_reply_any(inner: &[u8]) -> Option<Vec<u8>> {
    match inner.first().map(|b| b >> 4) {
        Some(4) => echo_reply(inner),
        Some(6) => echo_reply_v6(inner),
        _ => None,
    }
}

/// If `inner` is an IPv6 ICMPv6 echo request (type 128), build the echo reply
/// (src/dst swapped, type → 129, ICMPv6 checksum recomputed over the IPv6
/// pseudo-header). IPv6 has no header checksum. Returns None for anything else.
pub fn echo_reply_v6(inner: &[u8]) -> Option<Vec<u8>> {
    if inner.len() < 40 || (inner[0] >> 4) != 6 || inner[6] != NEXT_HDR_ICMPV6 {
        return None; // not IPv6 with an ICMPv6 next-header (no extension headers)
    }
    let payload_len = u16::from_be_bytes([inner[4], inner[5]]) as usize;
    let total = 40 + payload_len;
    if payload_len < 8 || total > inner.len() {
        return None;
    }
    if inner[40] != ICMPV6_ECHO_REQUEST {
        return None;
    }

    let mut pkt = inner[..total].to_vec();

    // Swap src (8..24) and dst (24..40).
    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    src.copy_from_slice(&pkt[8..24]);
    dst.copy_from_slice(&pkt[24..40]);
    pkt[8..24].copy_from_slice(&dst);
    pkt[24..40].copy_from_slice(&src);

    pkt[40] = ICMPV6_ECHO_REPLY;
    pkt[42] = 0;
    pkt[43] = 0;
    // dst/src are now the reply's, in pkt; checksum over the pseudo-header + msg.
    let mut nsrc = [0u8; 16];
    let mut ndst = [0u8; 16];
    nsrc.copy_from_slice(&pkt[8..24]);
    ndst.copy_from_slice(&pkt[24..40]);
    let csum = icmpv6_checksum(&nsrc, &ndst, &pkt[40..total]);
    pkt[42..44].copy_from_slice(&csum.to_be_bytes());

    Some(pkt)
}

/// ICMPv6 checksum: one's-complement sum over the IPv6 pseudo-header
/// (src ‖ dst ‖ upper-layer-length(32) ‖ zeros(3) ‖ next-header=58) + the message.
fn icmpv6_checksum(src: &[u8; 16], dst: &[u8; 16], msg: &[u8]) -> u16 {
    fn add(sum: &mut u32, b: &[u8]) {
        let mut i = 0;
        while i + 1 < b.len() {
            *sum += u16::from_be_bytes([b[i], b[i + 1]]) as u32;
            i += 2;
        }
        if i < b.len() {
            *sum += (b[i] as u32) << 8;
        }
    }
    let mut sum: u32 = 0;
    add(&mut sum, src);
    add(&mut sum, dst);
    let len = msg.len() as u32;
    sum += (len >> 16) & 0xffff;
    sum += len & 0xffff;
    sum += NEXT_HDR_ICMPV6 as u32; // the 3 preceding zero bytes contribute nothing
    add(&mut sum, msg);
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
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
