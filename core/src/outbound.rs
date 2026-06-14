//! Device-initiated traffic: build inner IPv4 packets the dongle sends OUT through
//! a WireGuard tunnel to another tailnet peer (push telemetry / ping out / HTTP
//! client). The data plane encrypts whatever these produce and sends it to the
//! peer; replies arrive as inner packets which the driver feeds back here.
//!
//! Also shared with `mdns-forward` (it reuses `udp_datagram`), so some items here
//! may be unused in an mdns-only build.
#![allow(dead_code)]

use alloc::vec;
use alloc::vec::Vec;
use core::net::Ipv4Addr;

const PROTO_ICMP: u8 = 1;
const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;

const FIN: u8 = 0x01;
const SYN: u8 = 0x02;
const PSH: u8 = 0x08;
const ACK: u8 = 0x10;

/// Build an IPv4 ICMP echo request (ping out).
pub fn icmp_echo_request(src: Ipv4Addr, dst: Ipv4Addr, ident: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
    let mut icmp = Vec::with_capacity(8 + payload.len());
    icmp.extend_from_slice(&[8, 0, 0, 0]); // type 8 (echo request), code 0, csum placeholder
    icmp.extend_from_slice(&ident.to_be_bytes());
    icmp.extend_from_slice(&seq.to_be_bytes());
    icmp.extend_from_slice(payload);
    let c = checksum(&icmp);
    icmp[2..4].copy_from_slice(&c.to_be_bytes());
    ipv4_packet(src, dst, PROTO_ICMP, &icmp)
}

/// Build an IPv4 UDP datagram (e.g. push telemetry to a peer:port).
pub fn udp_datagram(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let mut udp = Vec::with_capacity(8 + payload.len());
    udp.extend_from_slice(&sport.to_be_bytes());
    udp.extend_from_slice(&dport.to_be_bytes());
    udp.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    udp.extend_from_slice(&[0, 0]); // checksum placeholder
    udp.extend_from_slice(payload);
    let c = l4_checksum(&src, &dst, PROTO_UDP, &udp);
    udp[6..8].copy_from_slice(&c.to_be_bytes());
    ipv4_packet(src, dst, PROTO_UDP, &udp)
}

/// A minimal single-connection TCP client (enough for one HTTP request/response).
pub struct TcpClient {
    src: Ipv4Addr,
    dst: Ipv4Addr,
    sport: u16,
    dport: u16,
    snd_nxt: u32,
    rcv_nxt: u32,
    request: Vec<u8>,
    pub response: Vec<u8>,
    pub done: bool,
    established: bool,
}

impl TcpClient {
    pub fn new(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16, request: Vec<u8>) -> Self {
        let iss = (rand32() & 0x7fff_ffff).max(1);
        Self {
            src,
            dst,
            sport,
            dport,
            snd_nxt: iss,
            rcv_nxt: 0,
            request,
            response: Vec::new(),
            done: false,
            established: false,
        }
    }

    /// First packet: SYN.
    pub fn open(&mut self) -> Vec<u8> {
        let seg = self.segment(SYN, &[]);
        self.snd_nxt = self.snd_nxt.wrapping_add(1); // SYN consumes one
        seg
    }

    /// Is `inner` a TCP segment belonging to this client connection?
    pub fn owns(&self, inner: &[u8]) -> bool {
        if inner.len() < 20 || (inner[0] >> 4) != 4 || inner[9] != PROTO_TCP {
            return false;
        }
        let ihl = (inner[0] & 0x0f) as usize * 4;
        if inner.len() < ihl + 4 {
            return false;
        }
        let dport = u16::from_be_bytes([inner[ihl + 2], inner[ihl + 3]]);
        dport == self.sport // server -> us, dst port = our source port
    }

    /// Feed a TCP segment from the server; returns segments to send back.
    pub fn on_inner(&mut self, inner: &[u8]) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        if !self.owns(inner) || self.done {
            return out;
        }
        let ihl = (inner[0] & 0x0f) as usize * 4;
        let total = u16::from_be_bytes([inner[2], inner[3]]) as usize;
        if total < ihl + 20 || total > inner.len() {
            return out;
        }
        let tcp = &inner[ihl..total];
        let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
        let data_off = (tcp[12] >> 4) as usize * 4;
        let flags = tcp[13];
        if data_off < 20 || data_off > tcp.len() {
            return out;
        }
        let payload = &tcp[data_off..];

        if flags & SYN != 0 && flags & ACK != 0 && !self.established {
            // SYN-ACK -> ACK, then send the request.
            self.rcv_nxt = seq.wrapping_add(1);
            self.established = true;
            out.push(self.segment(ACK, &[]));
            let req = self.request.clone();
            out.push(self.segment(PSH | ACK, &req));
            self.snd_nxt = self.snd_nxt.wrapping_add(req.len() as u32);
            return out;
        }

        if !payload.is_empty() {
            // Response data: accept in-order, ACK it.
            if seq == self.rcv_nxt {
                self.response.extend_from_slice(payload);
                self.rcv_nxt = self.rcv_nxt.wrapping_add(payload.len() as u32);
            }
            out.push(self.segment(ACK, &[]));
        }

        if flags & FIN != 0 {
            self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
            out.push(self.segment(ACK, &[]));
            out.push(self.segment(FIN | ACK, &[]));
            self.done = true;
        }
        out
    }

    fn segment(&self, flags: u8, payload: &[u8]) -> Vec<u8> {
        let mut tcp = vec![0u8; 20 + payload.len()];
        tcp[0..2].copy_from_slice(&self.sport.to_be_bytes());
        tcp[2..4].copy_from_slice(&self.dport.to_be_bytes());
        tcp[4..8].copy_from_slice(&self.snd_nxt.to_be_bytes());
        tcp[8..12].copy_from_slice(&self.rcv_nxt.to_be_bytes());
        tcp[12] = 5 << 4; // data offset 5 words
        tcp[13] = flags;
        tcp[14..16].copy_from_slice(&64240u16.to_be_bytes()); // window
        tcp[20..].copy_from_slice(payload);
        let c = l4_checksum(&self.src, &self.dst, PROTO_TCP, &tcp);
        tcp[16..18].copy_from_slice(&c.to_be_bytes());
        ipv4_packet(self.src, self.dst, PROTO_TCP, &tcp)
    }
}

/// Wrap an L4 payload in an IPv4 header (DF set, TTL 64), with header checksum.
fn ipv4_packet(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, l4: &[u8]) -> Vec<u8> {
    let total = 20 + l4.len();
    let mut pkt = vec![0u8; total];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    pkt[6] = 0x40; // DF
    pkt[8] = 64; // TTL
    pkt[9] = proto;
    pkt[12..16].copy_from_slice(&src.octets());
    pkt[16..20].copy_from_slice(&dst.octets());
    let c = checksum(&pkt[..20]);
    pkt[10..12].copy_from_slice(&c.to_be_bytes());
    pkt[20..].copy_from_slice(l4);
    pkt
}

fn checksum(data: &[u8]) -> u16 {
    finish(sum16(data, 0))
}

/// TCP/UDP checksum over the IPv4 pseudo-header + L4 segment.
fn l4_checksum(src: &Ipv4Addr, dst: &Ipv4Addr, proto: u8, l4: &[u8]) -> u16 {
    let mut ph = [0u8; 12];
    ph[0..4].copy_from_slice(&src.octets());
    ph[4..8].copy_from_slice(&dst.octets());
    ph[9] = proto;
    ph[10..12].copy_from_slice(&(l4.len() as u16).to_be_bytes());
    finish(sum16(l4, sum16(&ph, 0)))
}

fn sum16(data: &[u8], mut sum: u32) -> u32 {
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    sum
}

fn finish(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn rand32() -> u32 {
    let mut b = [0u8; 4];
    getrandom::getrandom(&mut b).expect("getrandom");
    u32::from_le_bytes(b)
}
