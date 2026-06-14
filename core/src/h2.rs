//! Minimal HTTP/2 client running inside the ts2021 Noise tunnel.
//!
//! Only what's needed for Tailscale's control RPCs: a single SETTINGS exchange,
//! then one-shot POSTs (`/machine/register`) and one long-poll stream
//! (`/machine/map`). HPACK is literal-without-indexing, no Huffman.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use anyhow::{bail, Result};

use crate::noise::{self, Transport};
use crate::transport::Conn;

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const EARLY_MAGIC: &[u8] = b"\xff\xff\xffTS";

const FT_DATA: u8 = 0x0;
const FT_HEADERS: u8 = 0x1;
const FT_SETTINGS: u8 = 0x4;
const FT_WINDOW_UPDATE: u8 = 0x8;
const FT_GOAWAY: u8 = 0x7;
const FL_END_STREAM: u8 = 0x1;
const FL_END_HEADERS: u8 = 0x4;
const FL_ACK: u8 = 0x1;

const MAX_FRAME_SIZE: u32 = 16384;

/// HTTP/2 session over the encrypted record stream.
pub struct H2 {
    conn: Conn,
    tr: Transport,
    rx: Vec<u8>, // decrypted plaintext not yet consumed
    next_stream: u32,
    authority: String, // the `:authority` header (control host), supplied by the adapter
}

impl H2 {
    /// Take ownership of the post-handshake connection + transport and run the
    /// HTTP/2 startup: consume any early payload, exchange SETTINGS. `authority` is
    /// the control host for the `:authority` pseudo-header.
    pub fn start(conn: Conn, tr: Transport, authority: String) -> Result<(Self, Option<Vec<u8>>)> {
        let mut h = H2 { conn, tr, rx: Vec::new(), next_stream: 1, authority };

        // Client preface + our SETTINGS.
        let mut hello = Vec::new();
        hello.extend_from_slice(PREFACE);
        hello.extend_from_slice(&frame(
            FT_SETTINGS,
            0,
            0,
            &[
                0x00, 0x02, 0x00, 0x00, 0x00, 0x00, // ENABLE_PUSH = 0
                0x00, 0x05, // MAX_FRAME_SIZE
                (MAX_FRAME_SIZE >> 24) as u8,
                (MAX_FRAME_SIZE >> 16) as u8,
                (MAX_FRAME_SIZE >> 8) as u8,
                MAX_FRAME_SIZE as u8,
            ],
        ));
        h.send(&hello)?;

        // Server side begins with an optional early payload, then h2 frames.
        let early = h.consume_early_payload()?;

        // Read frames until we've seen the server SETTINGS, ACK it.
        loop {
            let fr = h.read_frame()?;
            match fr.typ {
                FT_SETTINGS => {
                    if fr.flags & FL_ACK == 0 {
                        h.send(&frame(FT_SETTINGS, FL_ACK, 0, &[]))?;
                    }
                    break;
                }
                FT_WINDOW_UPDATE | FT_HEADERS | FT_DATA => continue,
                FT_GOAWAY => bail!("server GOAWAY during startup"),
                _ => continue,
            }
        }
        Ok((h, early))
    }

    /// POST JSON on a fresh stream and read the full response body (one-shot).
    /// Returns (status, body_json_bytes).
    pub fn post_json(&mut self, path: &str, body: &[u8]) -> Result<(u16, Vec<u8>)> {
        let stream_id = self.next_stream;
        self.next_stream += 2;

        let mut hdr = Vec::new();
        enc_header(&mut hdr, ":method", "POST");
        enc_header(&mut hdr, ":scheme", "http");
        enc_header(&mut hdr, ":authority", &self.authority);
        enc_header(&mut hdr, ":path", path);
        enc_header(&mut hdr, "content-type", "application/json");
        enc_header(&mut hdr, "content-length", &body.len().to_string());
        enc_header(&mut hdr, "accept", "application/json");

        let mut out = Vec::new();
        out.extend_from_slice(&frame(FT_HEADERS, FL_END_HEADERS, stream_id, &hdr));
        out.extend_from_slice(&frame(FT_DATA, FL_END_STREAM, stream_id, body));
        self.send(&out)?;

        self.read_response(stream_id)
    }

    /// POST JSON and leave the response stream open for long-polling. Returns
    /// the stream id; read successive DATA payloads with `read_data`.
    pub fn post_stream(&mut self, path: &str, body: &[u8]) -> Result<u32> {
        let stream_id = self.next_stream;
        self.next_stream += 2;

        let mut hdr = Vec::new();
        enc_header(&mut hdr, ":method", "POST");
        enc_header(&mut hdr, ":scheme", "http");
        enc_header(&mut hdr, ":authority", &self.authority);
        enc_header(&mut hdr, ":path", path);
        enc_header(&mut hdr, "content-type", "application/json");
        enc_header(&mut hdr, "content-length", &body.len().to_string());
        enc_header(&mut hdr, "accept", "application/json");

        let mut out = Vec::new();
        out.extend_from_slice(&frame(FT_HEADERS, FL_END_HEADERS, stream_id, &hdr));
        out.extend_from_slice(&frame(FT_DATA, FL_END_STREAM, stream_id, body));
        self.send(&out)?;
        Ok(stream_id)
    }

    /// Read the next DATA payload from a streaming response and immediately
    /// release it (frugal: never accumulates, so a huge MapResponse can't blow
    /// the heap). The caller scans the chunk for what it needs and drops it.
    pub fn read_data(&mut self, stream_id: u32) -> Result<Vec<u8>> {
        loop {
            let fr = self.read_frame()?;
            match fr.typ {
                FT_DATA if fr.stream_id == stream_id => {
                    if !fr.payload.is_empty() {
                        self.window_update(stream_id, fr.payload.len() as u32)?;
                        return Ok(fr.payload);
                    }
                    if fr.flags & FL_END_STREAM != 0 {
                        bail!("map stream closed by server");
                    }
                }
                FT_HEADERS => {
                    if fr.flags & FL_END_STREAM != 0 {
                        bail!("map stream closed (HEADERS END_STREAM)");
                    }
                }
                FT_SETTINGS => {
                    if fr.flags & FL_ACK == 0 {
                        self.send(&frame(FT_SETTINGS, FL_ACK, 0, &[]))?;
                    }
                }
                FT_GOAWAY => bail!("server GOAWAY on map stream"),
                _ => {}
            }
        }
    }

    fn read_response(&mut self, stream_id: u32) -> Result<(u16, Vec<u8>)> {
        let mut status: u16 = 0;
        let mut body: Vec<u8> = Vec::new();
        loop {
            let fr = self.read_frame()?;
            if fr.stream_id != stream_id && fr.stream_id != 0 {
                continue; // ignore other streams
            }
            match fr.typ {
                FT_HEADERS => {
                    if let Some(s) = decode_status(&fr.payload) {
                        status = s;
                    }
                    if fr.flags & FL_END_STREAM != 0 {
                        break;
                    }
                }
                FT_DATA => {
                    body.extend_from_slice(&fr.payload);
                    if !fr.payload.is_empty() {
                        self.window_update(stream_id, fr.payload.len() as u32)?;
                    }
                    if fr.flags & FL_END_STREAM != 0 {
                        break;
                    }
                }
                FT_SETTINGS => {
                    if fr.flags & FL_ACK == 0 {
                        self.send(&frame(FT_SETTINGS, FL_ACK, 0, &[]))?;
                    }
                }
                FT_GOAWAY => bail!("server GOAWAY (status so far {status})"),
                _ => {}
            }
        }
        Ok((status, strip_wire_prefix(body)))
    }

    fn window_update(&mut self, stream_id: u32, inc: u32) -> Result<()> {
        let p = inc.to_be_bytes();
        self.send(&frame(FT_WINDOW_UPDATE, 0, stream_id, &p))?;
        self.send(&frame(FT_WINDOW_UPDATE, 0, 0, &p))?;
        Ok(())
    }

    // --- record stream plumbing ---

    fn send(&mut self, data: &[u8]) -> Result<()> {
        for chunk in data.chunks(2048) {
            let rec = self.tr.seal_record(chunk)?;
            self.conn.write_all(&rec)?;
        }
        Ok(())
    }

    fn pull(&mut self) -> Result<()> {
        let (typ, ct) = self.conn.read_frame()?;
        match typ {
            noise::MSG_RECORD => {
                let pt = self.tr.open_record(&ct)?;
                self.rx.extend_from_slice(&pt);
                Ok(())
            }
            noise::MSG_ERROR => bail!("control error: {}", String::from_utf8_lossy(&ct)),
            o => bail!("unexpected control frame type {o}"),
        }
    }

    fn read_exact(&mut self, n: usize) -> Result<Vec<u8>> {
        while self.rx.len() < n {
            self.pull()?;
        }
        let out = self.rx[..n].to_vec();
        self.rx.drain(..n);
        Ok(out)
    }

    fn consume_early_payload(&mut self) -> Result<Option<Vec<u8>>> {
        let hdr = self.read_exact(9)?;
        if &hdr[..5] == EARLY_MAGIC {
            let ep_len = u32::from_be_bytes([hdr[5], hdr[6], hdr[7], hdr[8]]) as usize;
            let json = self.read_exact(ep_len)?;
            Ok(Some(json))
        } else {
            // Not an early payload: these 9 bytes are the first h2 frame header.
            self.rx.splice(0..0, hdr);
            Ok(None)
        }
    }

    fn read_frame(&mut self) -> Result<Frame> {
        let hdr = self.read_exact(9)?;
        let len = ((hdr[0] as usize) << 16) | ((hdr[1] as usize) << 8) | hdr[2] as usize;
        let typ = hdr[3];
        let flags = hdr[4];
        let stream_id = u32::from_be_bytes([hdr[5], hdr[6], hdr[7], hdr[8]]) & 0x7fff_ffff;
        let payload = if len > 0 { self.read_exact(len)? } else { Vec::new() };
        Ok(Frame { typ, flags, stream_id, payload })
    }
}

struct Frame {
    typ: u8,
    flags: u8,
    stream_id: u32,
    payload: Vec<u8>,
}

fn frame(typ: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let len = payload.len();
    let mut out = Vec::with_capacity(9 + len);
    out.push((len >> 16) as u8);
    out.push((len >> 8) as u8);
    out.push(len as u8);
    out.push(typ);
    out.push(flags);
    out.extend_from_slice(&(stream_id & 0x7fff_ffff).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// HPACK: literal header field without indexing, new name (0x00) + len-prefixed
/// strings (no Huffman).
fn enc_header(block: &mut Vec<u8>, name: &str, value: &str) {
    block.push(0x00);
    enc_str(block, name.as_bytes());
    enc_str(block, value.as_bytes());
}

fn enc_str(block: &mut Vec<u8>, s: &[u8]) {
    let len = s.len();
    if len < 0x7f {
        block.push(len as u8);
    } else {
        block.push(0x7f);
        let mut rem = len - 0x7f;
        while rem >= 0x80 {
            block.push(((rem & 0x7f) | 0x80) as u8);
            rem >>= 7;
        }
        block.push(rem as u8);
    }
    block.extend_from_slice(s);
}

/// Decode `:status` from a HEADERS block. Handles the indexed `:status 200`
/// (static index 8) plus literal name/value forms.
fn decode_status(block: &[u8]) -> Option<u16> {
    let mut i = 0;
    while i < block.len() {
        let b = block[i];
        if b & 0x80 != 0 {
            // Indexed header field (static table).
            if (b & 0x7f) == 8 {
                return Some(200);
            }
            i += 1;
            continue;
        }
        if b & 0xf0 == 0x00 {
            // Literal w/o indexing, new name.
            i += 1;
            if i >= block.len() {
                break;
            }
            let nlen = (block[i] & 0x7f) as usize;
            i += 1;
            if i + nlen > block.len() {
                break;
            }
            let name = &block[i..i + nlen];
            i += nlen;
            if i >= block.len() {
                break;
            }
            let vlen = (block[i] & 0x7f) as usize;
            i += 1;
            if i + vlen > block.len() {
                break;
            }
            let val = &block[i..i + vlen];
            i += vlen;
            if name == b":status" {
                return core::str::from_utf8(val).ok()?.parse().ok();
            }
            continue;
        }
        break;
    }
    None
}

/// Tailscale prefixes some response bodies with a 4-byte length. If present
/// (first byte isn't '{' but byte 4 is), drop it.
fn strip_wire_prefix(body: Vec<u8>) -> Vec<u8> {
    if body.len() >= 5 && body[0] != b'{' && body[4] == b'{' {
        body[4..].to_vec()
    } else {
        body
    }
}
