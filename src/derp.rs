//! Minimal DERP client.
//!
//! DERP is Tailscale's relay: clients connect out to a DERP server over TLS and
//! exchange opaque packets addressed by node public key. We use it as a fallback
//! transport for our WireGuard + disco packets when a direct path can't be
//! punched (the common remote/NAT case). The dongle connects to its home DERP
//! region (nyc) so packets peers send to us via DERP actually arrive.
//!
//! Wire: after an HTTP `Upgrade: DERP`, the stream carries frames
//! `[type u8][len u32 BE][payload]`. The server opens with frameServerKey
//! (magic + its NaCl public key); we reply with an encrypted frameClientInfo;
//! thereafter frameSendPacket/frameRecvPacket carry our tunnel traffic.

use anyhow::{bail, Context, Result};
use core::ffi::c_void;

use crypto_box::aead::{Aead, Nonce};
use crypto_box::{PublicKey, SalsaBox, SecretKey};

use esp_idf_svc::sys;

pub const FRAME_SERVER_KEY: u8 = 0x01;
pub const FRAME_CLIENT_INFO: u8 = 0x02;
pub const FRAME_SERVER_INFO: u8 = 0x03;
pub const FRAME_SEND_PACKET: u8 = 0x04;
pub const FRAME_RECV_PACKET: u8 = 0x05;
pub const FRAME_KEEPALIVE: u8 = 0x06;
pub const FRAME_NOTE_PREFERRED: u8 = 0x07;
pub const FRAME_PING: u8 = 0x0c;
pub const FRAME_PONG: u8 = 0x0d;

const MAGIC: &[u8] = b"DERP\xf0\x9f\x94\x91"; // "DERP🔑"
const MAX_FRAME: usize = 64 * 1024;

/// An established DERP connection (TLS socket after the protocol handshake).
pub struct Derp {
    tls: *mut sys::esp_tls,
}

// The esp_tls handle is owned exclusively by whoever holds Derp; we only use it
// from the single DERP thread.
unsafe impl Send for Derp {}

impl Derp {
    /// Connect to `host:443`, perform the HTTP upgrade + DERP handshake using our
    /// node key as the DERP identity.
    pub fn connect(host: &str, node_priv: &[u8; 32], node_pub: &[u8; 32]) -> Result<Self> {
        let tls = tls_connect(host, 443)?;
        let mut d = Derp { tls };
        d.http_upgrade(host).context("DERP http upgrade")?;
        let server_pub = d.read_server_key().context("DERP server key")?;
        d.send_client_info(node_priv, node_pub, &server_pub)
            .context("DERP client info")?;
        Ok(d)
    }

    fn http_upgrade(&mut self, host: &str) -> Result<()> {
        let req = format!(
            "GET /derp HTTP/1.1\r\n\
             Host: {host}\r\n\
             Connection: Upgrade\r\n\
             Upgrade: DERP\r\n\r\n"
        );
        self.write_all(req.as_bytes())?;

        // Read response headers up to \r\n\r\n.
        let mut head = Vec::new();
        let mut b = [0u8; 1];
        loop {
            let n = self.read_some(&mut b)?;
            if n == 0 {
                bail!("connection closed during upgrade");
            }
            head.push(b[0]);
            if head.ends_with(b"\r\n\r\n") {
                break;
            }
            if head.len() > 4096 {
                bail!("upgrade response too large");
            }
        }
        let status = String::from_utf8_lossy(&head);
        let line = status.lines().next().unwrap_or("");
        if !line.contains(" 101 ") {
            bail!("DERP upgrade failed: '{}'", line.trim());
        }
        Ok(())
    }

    fn read_server_key(&mut self) -> Result<[u8; 32]> {
        let (typ, payload) = self.read_frame()?;
        if typ != FRAME_SERVER_KEY {
            bail!("expected server key frame, got type {typ}");
        }
        if payload.len() < MAGIC.len() + 32 || &payload[..MAGIC.len()] != MAGIC {
            bail!("bad server key frame ({} bytes)", payload.len());
        }
        let mut k = [0u8; 32];
        k.copy_from_slice(&payload[MAGIC.len()..MAGIC.len() + 32]);
        Ok(k)
    }

    fn send_client_info(
        &mut self,
        node_priv: &[u8; 32],
        node_pub: &[u8; 32],
        server_pub: &[u8; 32],
    ) -> Result<()> {
        // ClientInfo JSON, NaCl-boxed to the server's key.
        let json = br#"{"version":2}"#;
        let bx = SalsaBox::new(&PublicKey::from(*server_pub), &SecretKey::from(*node_priv));
        let mut nbytes = [0u8; 24];
        fill_random(&mut nbytes);
        let nonce = Nonce::<SalsaBox>::clone_from_slice(&nbytes);
        let ct = bx
            .encrypt(&nonce, &json[..])
            .map_err(|_| anyhow::anyhow!("clientinfo seal"))?;

        let mut payload = Vec::with_capacity(32 + 24 + ct.len());
        payload.extend_from_slice(node_pub); // our DERP identity = node public key
        payload.extend_from_slice(&nbytes);
        payload.extend_from_slice(&ct);
        self.write_frame(FRAME_CLIENT_INFO, &payload)
    }

    /// Send a tunnel packet to a peer (addressed by node public key) via the relay.
    pub fn send_packet(&mut self, dst_node_pub: &[u8; 32], pkt: &[u8]) -> Result<()> {
        let mut payload = Vec::with_capacity(32 + pkt.len());
        payload.extend_from_slice(dst_node_pub);
        payload.extend_from_slice(pkt);
        self.write_frame(FRAME_SEND_PACKET, &payload)
    }

    /// Read the next frame: returns (type, payload).
    pub fn read_frame(&mut self) -> Result<(u8, Vec<u8>)> {
        let mut hdr = [0u8; 5];
        self.read_exact(&mut hdr)?;
        let typ = hdr[0];
        let len = u32::from_be_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]) as usize;
        if len > MAX_FRAME {
            bail!("DERP frame too large: {len}");
        }
        let mut payload = vec![0u8; len];
        if len > 0 {
            self.read_exact(&mut payload)?;
        }
        Ok((typ, payload))
    }

    fn write_frame(&mut self, typ: u8, payload: &[u8]) -> Result<()> {
        let mut hdr = [0u8; 5];
        hdr[0] = typ;
        hdr[1..5].copy_from_slice(&(payload.len() as u32).to_be_bytes());
        self.write_all(&hdr)?;
        if !payload.is_empty() {
            self.write_all(payload)?;
        }
        Ok(())
    }

    // --- raw TLS I/O ---

    fn read_exact(&mut self, buf: &mut [u8]) -> Result<()> {
        let mut off = 0;
        while off < buf.len() {
            let n = self.read_some(&mut buf[off..])?;
            if n == 0 {
                bail!("DERP connection closed");
            }
            off += n;
        }
        Ok(())
    }

    fn read_some(&mut self, buf: &mut [u8]) -> Result<usize> {
        loop {
            let r =
                unsafe { sys::esp_tls_conn_read(self.tls, buf.as_mut_ptr() as *mut c_void, buf.len()) };
            if r > 0 {
                return Ok(r as usize);
            }
            if r == 0 {
                return Ok(0);
            }
            // ESP_TLS_ERR_SSL_WANT_READ/WRITE -> retry; other -> error.
            let want_read = sys::ESP_TLS_ERR_SSL_WANT_READ as isize;
            let want_write = sys::ESP_TLS_ERR_SSL_WANT_WRITE as isize;
            if r == want_read || r == want_write {
                continue;
            }
            bail!("esp_tls_conn_read error {r}");
        }
    }

    fn write_all(&mut self, buf: &[u8]) -> Result<()> {
        let mut off = 0;
        while off < buf.len() {
            let r = unsafe {
                sys::esp_tls_conn_write(
                    self.tls,
                    buf[off..].as_ptr() as *const c_void,
                    buf.len() - off,
                )
            };
            if r > 0 {
                off += r as usize;
                continue;
            }
            let want_read = sys::ESP_TLS_ERR_SSL_WANT_READ as isize;
            let want_write = sys::ESP_TLS_ERR_SSL_WANT_WRITE as isize;
            if r == want_read || r == want_write {
                continue;
            }
            bail!("esp_tls_conn_write error {r}");
        }
        Ok(())
    }
}

impl Drop for Derp {
    fn drop(&mut self) {
        unsafe {
            sys::esp_tls_conn_destroy(self.tls);
        }
    }
}

/// Open a validated TLS connection to `host:port` using the cert bundle.
fn tls_connect(host: &str, port: u16) -> Result<*mut sys::esp_tls> {
    let tls = unsafe { sys::esp_tls_init() };
    if tls.is_null() {
        bail!("esp_tls_init failed");
    }
    let mut cfg: sys::esp_tls_cfg_t = unsafe { core::mem::zeroed() };
    cfg.crt_bundle_attach = Some(sys::esp_crt_bundle_attach);
    cfg.timeout_ms = 15000;

    let host_c = std::ffi::CString::new(host).unwrap();
    let r = unsafe {
        sys::esp_tls_conn_new_sync(
            host_c.as_ptr(),
            host.len() as i32,
            port as i32,
            &cfg,
            tls,
        )
    };
    if r != 1 {
        unsafe { sys::esp_tls_conn_destroy(tls) };
        bail!("esp_tls_conn_new_sync to {host}:{port} failed (r={r})");
    }
    Ok(tls)
}

fn fill_random(out: &mut [u8]) {
    unsafe {
        sys::esp_fill_random(out.as_mut_ptr() as *mut c_void, out.len());
    }
}

/// Run the DERP relay dataplane forever: connect to our home DERP region and act
/// as a WireGuard responder for any peer that reaches us over the relay (the
/// remote/NAT case). Reconnects on error. This is independent of the UDP
/// dataplane — a DERP peer is reached only via the relay, keyed by node key.
pub fn run(id: crate::node::Identity, upgrade: Option<crate::node::Upgrade>) {
    let host = "derp1f.tailscale.com";
    loop {
        match Derp::connect(host, &id.node_priv, &id.node_pub) {
            Ok(mut d) => {
                println!("*** DERP connected to {host} (relay responder up) ***");
                serve(&mut d, &id, upgrade.as_ref());
                println!("DERP: disconnected, reconnecting in 5s");
            }
            Err(e) => println!("DERP connect failed: {e:#}"),
        }
        std::thread::sleep(std::time::Duration::from_secs(5));
    }
}

/// One peer's tunnel state, reached via the relay.
struct DerpPeer {
    tun: crate::wg::Tunnel,
    #[cfg(feature = "http-server")]
    tcp: crate::tcp::TcpServer,
}

fn serve(d: &mut Derp, id: &crate::node::Identity, upgrade: Option<&crate::node::Upgrade>) {
    use std::collections::HashMap;
    let mut peers: HashMap<[u8; 32], DerpPeer> = HashMap::new();
    let mut upgraded: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();

    loop {
        let (typ, payload) = match d.read_frame() {
            Ok(f) => f,
            Err(e) => {
                println!("DERP read error: {e:#}");
                return;
            }
        };
        if typ != FRAME_RECV_PACKET || payload.len() < 32 {
            continue; // keepalive, serverinfo, etc.
        }
        let mut src = [0u8; 32];
        src.copy_from_slice(&payload[..32]);
        let pkt = &payload[32..];
        if pkt.is_empty() {
            continue;
        }

        // derp-upgrade: first time we hear from a peer over the relay, coordinate
        // a direct path — send it CALL_ME_MAYBE with our endpoints and ask the UDP
        // dataplane to probe its endpoints.
        if let Some(up) = upgrade {
            if upgraded.insert(src) {
                try_upgrade(d, id, up, &src);
            }
        }

        // disco over DERP: PONG pings, and harvest the peer's CALL_ME_MAYBE
        // (its FRESH endpoints/ports) to drive a direct hole-punch.
        if crate::disco::is_disco(pkt) {
            if let Ok(msg) = crate::disco::open(&id.disco_priv, pkt) {
                if msg.msg_type == crate::disco::PING {
                    let any = std::net::SocketAddr::from(([0, 0, 0, 0], 0));
                    let pong = crate::disco::pong_plaintext(&msg.txid, any);
                    if let Ok(wire) =
                        crate::disco::seal(&id.disco_priv, &id.disco_pub, &msg.sender_disco_pub, &pong)
                    {
                        let _ = d.send_packet(&src, &wire);
                    }
                } else if msg.msg_type == crate::disco::CALL_ME_MAYBE && !msg.endpoints.is_empty() {
                    if let Some(up) = upgrade {
                        println!(
                            "DERP CALL_ME_MAYBE from {} -> {} fresh endpoint(s)",
                            hex8(&src),
                            msg.endpoints.len()
                        );
                        let _ = up.tx.send(crate::node::Target {
                            name: format!("derp:{}", hex8(&src)),
                            disco_pub: msg.sender_disco_pub,
                            node_pub: src,
                            endpoints: msg.endpoints,
                            spray: true,
                        });
                    }
                }
            }
            continue;
        }

        match pkt.first().copied() {
            Some(x) if x == crate::wg::MSG_INITIATION => {
                let our_index = crate::wg::random_index();
                match crate::wg::consume_initiation(&id.node_priv, &id.node_pub, pkt, our_index) {
                    Ok((resp, tun, _peer_static)) => {
                        let _ = d.send_packet(&src, &resp);
                        peers.insert(
                            src,
                            DerpPeer {
                                tun,
                                #[cfg(feature = "http-server")]
                                tcp: crate::tcp::TcpServer::new(),
                            },
                        );
                        println!("*** DERP WG HANDSHAKE COMPLETE (responder) with {} ***", hex8(&src));
                    }
                    Err(e) => println!("DERP WG init failed: {e:#}"),
                }
            }
            Some(x) if x == crate::wg::MSG_TRANSPORT => {
                if let Some(p) = peers.get_mut(&src) {
                    match p.tun.decrypt(pkt) {
                        Ok(inner)
                            if !inner.is_empty()
                                && crate::node::src_allowed(&id.allowed_srcs, &inner) =>
                        {
                            handle_inner(d, p, &src, &inner);
                        }
                        Ok(_) => {} // keepalive / filtered
                        Err(e) => println!("DERP transport decrypt failed: {e:#}"),
                    }
                }
            }
            _ => {}
        }
    }
}

/// Coordinate a direct path with a relayed peer: send it a disco CALL_ME_MAYBE
/// (our endpoints) over DERP and tell the UDP dataplane to probe its endpoints.
fn try_upgrade(d: &mut Derp, id: &crate::node::Identity, up: &crate::node::Upgrade, src: &[u8; 32]) {
    let peer = match up.peers.iter().find(|p| &p.node_pub == src) {
        Some(p) => p,
        None => return, // unknown peer / no endpoints to try
    };
    if peer.endpoints.is_empty() && up.our_endpoints.is_empty() {
        return;
    }
    // Tell the peer where to reach us directly.
    let cmm = crate::disco::call_me_maybe_plaintext(&up.our_endpoints);
    if let Ok(wire) = crate::disco::seal(&id.disco_priv, &id.disco_pub, &peer.disco_pub, &cmm) {
        let _ = d.send_packet(src, &wire);
    }
    // Ask the UDP dataplane to probe + handshake this peer directly.
    let _ = up.tx.send(crate::node::Target {
        name: format!("derp:{}", hex8(src)),
        disco_pub: peer.disco_pub,
        node_pub: *src,
        endpoints: peer.endpoints.clone(),
        spray: true, // remote peer: may be behind symmetric NAT
    });
    println!("DERP: upgrade attempt -> {} ({} ep)", hex8(src), peer.endpoints.len());
}

/// Handle a decrypted inner IP packet from a DERP peer: ICMP echo reply and/or
/// the in-tunnel HTTP server, reflecting responses back through the relay.
fn handle_inner(d: &mut Derp, p: &mut DerpPeer, src: &[u8; 32], inner: &[u8]) {
    #[cfg(feature = "icmp")]
    if let Some(reply) = tailscale_core::icmp::echo_reply(inner) {
        let out = p.tun.encrypt(&reply);
        let _ = d.send_packet(src, &out);
        println!("DERP ICMP echo -> replied to {}", hex8(src));
        return;
    }
    #[cfg(feature = "http-server")]
    {
        let replies = p.tcp.handle(inner);
        for r in &replies {
            let out = p.tun.encrypt(r);
            let _ = d.send_packet(src, &out);
        }
        if !replies.is_empty() {
            println!("DERP TCP/HTTP -> {} seg(s) to {}", replies.len(), hex8(src));
        }
    }
    let _ = (&mut *p, &*d, src, inner); // some combos use a subset of these
}

fn hex8(b: &[u8]) -> String {
    let mut s = String::new();
    for x in b.iter().take(8) {
        s.push_str(&format!("{x:02x}"));
    }
    s
}
