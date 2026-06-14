//! A minimal single-connection TCP server that lives inside the WireGuard
//! tunnel, just enough to serve one small HTML page on port 80.
//!
//! It is NOT a general TCP stack: one connection at a time, no retransmission, no
//! window management beyond a fixed advertised window, no options. The browser's
//! GET is answered with a single data segment that also carries FIN, then we ACK
//! the client's FIN. Good enough for "open http://100.65.240.107/ and see a page".

use alloc::format;
use alloc::vec;
use alloc::vec::Vec;

const PROTO_TCP: u8 = 6;
const HTTP_PORT: u16 = 80;

const FIN: u8 = 0x01;
const SYN: u8 = 0x02;
const RST: u8 = 0x04;
const PSH: u8 = 0x08;
const ACK: u8 = 0x10;

/// State for the (single) connection we're currently serving.
#[derive(Default)]
struct Conn {
    active: bool,
    client_ip: [u8; 4],
    our_ip: [u8; 4],
    client_port: u16,
    rcv_nxt: u32, // next sequence number we expect from the client
    snd_nxt: u32, // next sequence number we will send
}

#[derive(Default)]
pub struct TcpServer {
    conn: Conn,
}

impl TcpServer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed one inner IPv4 packet. Returns inner IPv4 packets to send back
    /// (each gets WireGuard-encrypted by the caller).
    pub fn handle(&mut self, inner: &[u8]) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        if inner.len() < 20 || (inner[0] >> 4) != 4 || inner[9] != PROTO_TCP {
            return out;
        }
        let ihl = (inner[0] & 0x0f) as usize * 4;
        let total = u16::from_be_bytes([inner[2], inner[3]]) as usize;
        if ihl < 20 || total < ihl + 20 || total > inner.len() {
            return out;
        }
        let mut dst_ip = [0u8; 4];
        let mut src_ip = [0u8; 4];
        src_ip.copy_from_slice(&inner[12..16]);
        dst_ip.copy_from_slice(&inner[16..20]);

        let tcp = &inner[ihl..total];
        let sport = u16::from_be_bytes([tcp[0], tcp[1]]);
        let dport = u16::from_be_bytes([tcp[2], tcp[3]]);
        let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
        let data_off = (tcp[12] >> 4) as usize * 4;
        let flags = tcp[13];
        if data_off < 20 || data_off > tcp.len() {
            return out;
        }
        let payload = &tcp[data_off..];

        if dport != HTTP_PORT {
            return out; // only serve :80
        }

        // New connection: SYN (and not part of the current one).
        if flags & SYN != 0 {
            let iss = rand_u32();
            self.conn = Conn {
                active: true,
                client_ip: src_ip,
                our_ip: dst_ip,
                client_port: sport,
                rcv_nxt: seq.wrapping_add(1), // SYN consumes one sequence number
                snd_nxt: iss,
            };
            // SYN-ACK
            out.push(self.segment(SYN | ACK, &[]));
            self.conn.snd_nxt = self.conn.snd_nxt.wrapping_add(1); // our SYN consumes one
            return out;
        }

        // Anything else must match the active connection.
        if !self.conn.active || src_ip != self.conn.client_ip || sport != self.conn.client_port {
            return out;
        }

        if flags & RST != 0 {
            self.conn = Conn::default();
            return out;
        }

        // Data carrying the HTTP request (the GET). Respond with the page + FIN.
        if !payload.is_empty() {
            self.conn.rcv_nxt = seq.wrapping_add(payload.len() as u32);
            let body = page(&self.conn.our_ip);
            let resp = http_response(&body);
            out.push(self.segment(PSH | ACK | FIN, &resp));
            self.conn.snd_nxt = self
                .conn
                .snd_nxt
                .wrapping_add(resp.len() as u32)
                .wrapping_add(1); // FIN consumes one
            return out;
        }

        // Pure FIN from the client: ack it and close.
        if flags & FIN != 0 {
            self.conn.rcv_nxt = seq.wrapping_add(1);
            out.push(self.segment(ACK, &[]));
            self.conn = Conn::default();
            return out;
        }

        // Bare ACK (e.g. completing the handshake, or acking our data): nothing.
        out
    }

    /// Build an inner IPv4 + TCP segment from the dongle to the client.
    fn segment(&self, flags: u8, payload: &[u8]) -> Vec<u8> {
        let c = &self.conn;
        let tcp_len = 20 + payload.len();
        let total = 20 + tcp_len;
        let mut pkt = vec![0u8; total];

        // IPv4 header
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        pkt[6] = 0x40; // Don't Fragment
        pkt[8] = 64; // TTL
        pkt[9] = PROTO_TCP;
        pkt[12..16].copy_from_slice(&c.our_ip);
        pkt[16..20].copy_from_slice(&c.client_ip);
        let ipsum = checksum(&pkt[..20]);
        pkt[10..12].copy_from_slice(&ipsum.to_be_bytes());

        // TCP header
        let t = &mut pkt[20..];
        t[0..2].copy_from_slice(&HTTP_PORT.to_be_bytes());
        t[2..4].copy_from_slice(&c.client_port.to_be_bytes());
        t[4..8].copy_from_slice(&c.snd_nxt.to_be_bytes());
        t[8..12].copy_from_slice(&c.rcv_nxt.to_be_bytes());
        t[12] = (5 << 4) | 0; // data offset = 5 words (20 bytes), no options
        t[13] = flags;
        t[14..16].copy_from_slice(&64240u16.to_be_bytes()); // window
        t[20..].copy_from_slice(payload);

        let tsum = tcp_checksum(&c.our_ip, &c.client_ip, &pkt[20..]);
        pkt[36..38].copy_from_slice(&tsum.to_be_bytes());
        pkt
    }
}

fn http_response(body: &[u8]) -> Vec<u8> {
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let mut out = head.into_bytes();
    out.extend_from_slice(body);
    out
}

fn page(our_ip: &[u8; 4]) -> Vec<u8> {
    format!(
        "<!doctype html><html><head><meta charset=utf-8><title>Tailscale-Rust</title></head>\
         <body style=\"font-family:sans-serif\"><h1>Tailscale-Rust on T-Dongle S3</h1>\
         <p>Pure-Rust WireGuard tunnel, no DERP.</p>\
         <p>Tailscale IP: {}.{}.{}.{}</p></body></html>",
        our_ip[0], our_ip[1], our_ip[2], our_ip[3]
    )
    .into_bytes()
}

/// IPv4 / generic 16-bit one's-complement checksum.
fn checksum(data: &[u8]) -> u16 {
    finish(sum16(data, 0))
}

/// TCP checksum over the pseudo-header + TCP segment.
fn tcp_checksum(src: &[u8; 4], dst: &[u8; 4], tcp: &[u8]) -> u16 {
    let mut s: u32 = 0;
    let mut ph = [0u8; 12];
    ph[0..4].copy_from_slice(src);
    ph[4..8].copy_from_slice(dst);
    ph[9] = PROTO_TCP;
    ph[10..12].copy_from_slice(&(tcp.len() as u16).to_be_bytes());
    s = sum16(&ph, s);
    s = sum16(tcp, s);
    finish(s)
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

fn rand_u32() -> u32 {
    let mut b = [0u8; 4];
    getrandom::getrandom(&mut b).expect("getrandom");
    u32::from_le_bytes(b)
}
