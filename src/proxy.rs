//! Per-service TCP proxy: a tailnet peer opens an in-tunnel TCP connection to the
//! dongle's `100.x:PROXY_LISTEN_PORT`; the dongle forwards the request to a fixed
//! `PROXY_TARGET_IP:PROXY_TARGET_PORT` on its local LAN and streams the response
//! back. Lets a peer reach ONE service on the other network without a full
//! subnet-router. Single connection at a time, request/response (one-shot): good
//! for HTTP and similar. The LAN side uses a real `std::net::TcpStream` (firmware).

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpStream};
use std::time::Duration;

use crate::config;

const PROTO_TCP: u8 = 6;
const FIN: u8 = 0x01;
const SYN: u8 = 0x02;
const RST: u8 = 0x04;
const PSH: u8 = 0x08;
const ACK: u8 = 0x10;

/// In-tunnel TCP payload per segment (kept under the WG/MTU budget).
const MSS: usize = 1024;

#[derive(Default)]
struct Conn {
    active: bool,
    client_ip: [u8; 4],
    our_ip: [u8; 4],
    client_port: u16,
    rcv_nxt: u32,
    snd_nxt: u32,
    fetched: bool,
}

#[derive(Default)]
pub struct TcpProxy {
    conn: Conn,
}

impl TcpProxy {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed one decrypted inner IPv4 packet. Returns inner packets to send back
    /// (each WG-encrypted by the caller). Empty for anything not addressed to the
    /// proxy listen port, so other traffic falls through untouched.
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
        let mut src = [0u8; 4];
        let mut dst = [0u8; 4];
        src.copy_from_slice(&inner[12..16]);
        dst.copy_from_slice(&inner[16..20]);

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

        if dport != config::PROXY_LISTEN_PORT {
            return out; // not for us — let other handlers see it
        }

        if flags & SYN != 0 {
            let iss = rand_u32();
            self.conn = Conn {
                active: true,
                client_ip: src,
                our_ip: dst,
                client_port: sport,
                rcv_nxt: seq.wrapping_add(1),
                snd_nxt: iss,
                fetched: false,
            };
            out.push(self.segment(SYN | ACK, &[]));
            self.conn.snd_nxt = self.conn.snd_nxt.wrapping_add(1);
            return out;
        }

        if !self.conn.active || src != self.conn.client_ip || sport != self.conn.client_port {
            return out;
        }
        if flags & RST != 0 {
            self.conn = Conn::default();
            return out;
        }

        // The client's request data: fetch from the LAN target and stream it back.
        if !payload.is_empty() && !self.conn.fetched {
            self.conn.rcv_nxt = seq.wrapping_add(payload.len() as u32);
            self.conn.fetched = true;
            out.push(self.segment(ACK, &[])); // ack the request

            let resp = lan_fetch(payload);
            if resp.is_empty() {
                out.push(self.segment(FIN | ACK, &[]));
                self.conn.snd_nxt = self.conn.snd_nxt.wrapping_add(1);
                return out;
            }
            let mut i = 0;
            while i < resp.len() {
                let end = (i + MSS).min(resp.len());
                let last = end == resp.len();
                let fl = if last { PSH | ACK | FIN } else { PSH | ACK };
                out.push(self.segment(fl, &resp[i..end]));
                self.conn.snd_nxt = self.conn.snd_nxt.wrapping_add((end - i) as u32);
                if last {
                    self.conn.snd_nxt = self.conn.snd_nxt.wrapping_add(1); // FIN
                }
                i = end;
            }
            return out;
        }

        if flags & FIN != 0 {
            self.conn.rcv_nxt = seq.wrapping_add(1);
            out.push(self.segment(ACK, &[]));
            self.conn = Conn::default();
            return out;
        }
        out
    }

    fn segment(&self, flags: u8, payload: &[u8]) -> Vec<u8> {
        let c = &self.conn;
        let total = 20 + 20 + payload.len();
        let mut pkt = vec![0u8; total];

        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        pkt[6] = 0x40; // DF
        pkt[8] = 64; // TTL
        pkt[9] = PROTO_TCP;
        pkt[12..16].copy_from_slice(&c.our_ip);
        pkt[16..20].copy_from_slice(&c.client_ip);
        let ipsum = tailscale_core::icmp::checksum(&pkt[..20]);
        pkt[10..12].copy_from_slice(&ipsum.to_be_bytes());

        let t = &mut pkt[20..];
        t[0..2].copy_from_slice(&config::PROXY_LISTEN_PORT.to_be_bytes());
        t[2..4].copy_from_slice(&c.client_port.to_be_bytes());
        t[4..8].copy_from_slice(&c.snd_nxt.to_be_bytes());
        t[8..12].copy_from_slice(&c.rcv_nxt.to_be_bytes());
        t[12] = 5 << 4;
        t[13] = flags;
        t[14..16].copy_from_slice(&64240u16.to_be_bytes());
        t[20..].copy_from_slice(payload);

        let tsum = tcp_checksum(&c.our_ip, &c.client_ip, &pkt[20..]);
        pkt[36..38].copy_from_slice(&tsum.to_be_bytes());
        pkt
    }
}

/// Open a TCP connection to the configured LAN target, send `request`, and read
/// the whole response (until close or timeout). Empty on any failure / no target.
fn lan_fetch(request: &[u8]) -> Vec<u8> {
    let ip: Ipv4Addr = match config::PROXY_TARGET_IP.parse() {
        Ok(ip) => ip,
        Err(_) => return Vec::new(),
    };
    let addr = SocketAddrV4::new(ip, config::PROXY_TARGET_PORT);
    let mut stream = match TcpStream::connect_timeout(&addr.into(), Duration::from_secs(3)) {
        Ok(s) => s,
        Err(e) => {
            println!("proxy: LAN connect to {addr} failed: {e}");
            return Vec::new();
        }
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
    let _ = stream.write_all(request);
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1460];
    loop {
        match stream.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&tmp[..n]);
                if buf.len() > 64 * 1024 {
                    break; // cap so one fetch can't blow the heap
                }
            }
            Err(_) => break, // timeout / error: return what we have
        }
    }
    println!("proxy: {} -> {addr} -> {} bytes", request.len(), buf.len());
    buf
}

fn tcp_checksum(src: &[u8; 4], dst: &[u8; 4], tcp: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut ph = [0u8; 12];
    ph[0..4].copy_from_slice(src);
    ph[4..8].copy_from_slice(dst);
    ph[9] = PROTO_TCP;
    ph[10..12].copy_from_slice(&(tcp.len() as u16).to_be_bytes());
    for b in [ph.as_slice(), tcp] {
        let mut i = 0;
        while i + 1 < b.len() {
            sum += u16::from_be_bytes([b[i], b[i + 1]]) as u32;
            i += 2;
        }
        if i < b.len() {
            sum += (b[i] as u32) << 8;
        }
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn rand_u32() -> u32 {
    let mut b = [0u8; 4];
    unsafe {
        esp_idf_svc::sys::esp_fill_random(b.as_mut_ptr() as *mut core::ffi::c_void, b.len());
    }
    u32::from_le_bytes(b)
}
