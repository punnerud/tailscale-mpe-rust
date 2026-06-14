//! Cleartext-TCP transport for the ts2021 control channel, over a platform
//! [`ByteStream`] (the adapter supplies a connected, timeout-configured socket).
//!
//! Tailscale's "happy path": a plain HTTP/1.1 Upgrade on port 80 carrying the
//! first Noise message in the `X-Tailscale-Handshake` header; the server replies
//! 101 and from then on the socket carries raw controlbase frames (no WebSocket,
//! no TLS — Noise provides confidentiality).

use alloc::boxed::Box;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use anyhow::{bail, Result};

use crate::platform::ByteStream;

const UPGRADE_VALUE: &str = "tailscale-control-protocol";

pub struct Conn {
    stream: Box<dyn ByteStream>,
    rx: Vec<u8>,
}

/// Perform the HTTP/1.1 upgrade over an already-connected `stream` and return the
/// live connection positioned right after the `\r\n\r\n` (any early frame bytes
/// are retained in the internal buffer). The adapter is responsible for the TCP
/// connect + sensible read/write timeouts before handing the stream in.
pub fn connect_and_upgrade(
    stream: Box<dyn ByteStream>,
    host: &str,
    handshake_b64: &str,
) -> Result<Conn> {
    let mut conn = Conn { stream, rx: Vec::new() };

    let req = format!(
        "POST /ts2021 HTTP/1.1\r\n\
         Host: {host}\r\n\
         Upgrade: {UPGRADE_VALUE}\r\n\
         Connection: upgrade\r\n\
         X-Tailscale-Handshake: {handshake_b64}\r\n\
         Content-Length: 0\r\n\r\n"
    );
    conn.stream.write_all(req.as_bytes()).map_err(|_| anyhow::anyhow!("upgrade write"))?;

    // Read until end of HTTP response headers.
    let mut head = Vec::new();
    let mut tmp = [0u8; 512];
    let body_start;
    loop {
        let n = conn.stream.read(&mut tmp).map_err(|_| anyhow::anyhow!("upgrade read"))?;
        if n == 0 {
            bail!("connection closed during upgrade");
        }
        head.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find(&head, b"\r\n\r\n") {
            body_start = pos + 4;
            break;
        }
        if head.len() > 8192 {
            bail!("upgrade response headers too large");
        }
    }

    let status_line = head
        .split(|&b| b == b'\n')
        .next()
        .map(|l| String::from_utf8_lossy(l).trim().to_string())
        .unwrap_or_default();
    if !status_line.contains(" 101 ") {
        let body = String::from_utf8_lossy(&head[body_start.min(head.len())..]);
        bail!("upgrade failed: '{status_line}' body='{}'", body.trim());
    }

    // Keep any bytes received past the header (start of the first frame).
    conn.rx.extend_from_slice(&head[body_start..]);
    Ok(conn)
}

impl Conn {
    fn fill_to(&mut self, n: usize) -> Result<()> {
        let mut tmp = [0u8; 2048];
        while self.rx.len() < n {
            let r = self.stream.read(&mut tmp).map_err(|_| anyhow::anyhow!("stream read"))?;
            if r == 0 {
                bail!("connection closed (wanted {n}, have {})", self.rx.len());
            }
            self.rx.extend_from_slice(&tmp[..r]);
        }
        Ok(())
    }

    fn take(&mut self, n: usize) -> Result<Vec<u8>> {
        self.fill_to(n)?;
        let out = self.rx[..n].to_vec();
        self.rx.drain(..n);
        Ok(out)
    }

    /// Read one controlbase frame: 3-byte header [type][len BE u16] + payload.
    pub fn read_frame(&mut self) -> Result<(u8, Vec<u8>)> {
        let hdr = self.take(3)?;
        let typ = hdr[0];
        let len = u16::from_be_bytes([hdr[1], hdr[2]]) as usize;
        let payload = self.take(len)?;
        Ok((typ, payload))
    }

    pub fn write_all(&mut self, data: &[u8]) -> Result<()> {
        self.stream.write_all(data).map_err(|_| anyhow::anyhow!("stream write"))
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Minimal standard base64 (with padding) — used for the handshake header.
pub fn base64_std(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | (b[2] as u32);
        out.push(T[((n >> 18) & 0x3f) as usize] as char);
        out.push(T[((n >> 12) & 0x3f) as usize] as char);
        out.push(if chunk.len() > 1 { T[((n >> 6) & 0x3f) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { T[(n & 0x3f) as usize] as char } else { '=' });
    }
    out
}
