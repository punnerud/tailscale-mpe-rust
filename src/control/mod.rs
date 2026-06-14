//! Tailscale control-plane client (ts2021).
//!
//! M3 implements only the first, simplest step: fetching the control server's
//! Noise static public key (`mkey`) over plain HTTPS. Later milestones add the
//! Noise IK handshake (M4), registration (M5) and the netmap fetch (M6).

pub mod h2;
pub use tailscale_core::noise; // migrated to the no_std core crate
pub use tailscale_core::peers; // migrated to the no_std core crate
pub use tailscale_core::transport; // migrated to the no_std core crate (over ByteStream)

use anyhow::{bail, Context, Result};
use std::time::Duration;

use esp_idf_svc::http::client::{Configuration as HttpConfig, EspHttpConnection};
use esp_idf_svc::http::Method;

use crate::config;
use crate::keys::NodeKeys;

/// Outcome of a /machine/register call.
pub struct RegisterResult {
    pub status: u16,
    pub machine_authorized: bool,
    pub auth_url: Option<String>,
    pub raw: String,
}

/// Open the ts2021 control channel and bring up HTTP/2 (handshake + early
/// payload + SETTINGS). Returns the ready H2 session. (M5)
pub fn connect(machine_priv: &[u8; 32], control_pub: &[u8; 32]) -> Result<h2::H2> {
    let (conn, tr) = handshake(machine_priv, control_pub)?;
    let (sess, early) = h2::H2::start(conn, tr).context("http2 start")?;
    match &early {
        Some(j) => println!("early payload: {} bytes", j.len()),
        None => println!("no early payload"),
    }
    Ok(sess)
}

/// One-shot: fresh handshake + HTTP/2 + a single /machine/register. Used for the
/// interactive-auth poll loop where a fresh connection per attempt is simplest
/// and avoids stale-session issues.
pub fn connect_and_register(
    machine_priv: &[u8; 32],
    control_pub: &[u8; 32],
    keys: &NodeKeys,
    auth_key: &str,
) -> Result<RegisterResult> {
    let mut sess = connect(machine_priv, control_pub)?;
    register(&mut sess, keys, auth_key)
}

/// POST /machine/register with a pre-auth key.
pub fn register(sess: &mut h2::H2, keys: &NodeKeys, auth_key: &str) -> Result<RegisterResult> {
    let body = build_register_json(keys, auth_key);
    let (status, resp) = sess
        .post_json("/machine/register", body.as_bytes())
        .context("POST /machine/register")?;
    let raw = String::from_utf8_lossy(&resp).to_string();
    let v: serde_json::Value = serde_json::from_slice(&resp).unwrap_or(serde_json::Value::Null);
    let machine_authorized = v.get("MachineAuthorized").and_then(|x| x.as_bool()).unwrap_or(false);
    let auth_url = v
        .get("AuthURL")
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    Ok(RegisterResult { status, machine_authorized, auth_url, raw })
}

/// Outcome of a /machine/map call.
pub struct MapResult {
    pub status: u16,
    pub ip: Option<String>,
    pub body_len: usize,
}

/// POST /machine/map (one-shot, OmitPeers) and extract our Tailscale IPv4 from
/// Node.Addresses. This is the PRIMARY goal: connect + get the 100.x.y.z IP.
pub fn fetch_map(sess: &mut h2::H2, keys: &NodeKeys) -> Result<MapResult> {
    // OmitPeers=true + Stream=false is treated as an endpoint-update only (empty
    // body), so request the full map (Stream=false, OmitPeers=false).
    let body = build_map_json(keys, false, false, false, &[]);
    let (status, resp) = sess
        .post_json("/machine/map", body.as_bytes())
        .context("POST /machine/map")?;
    let ip = scan_tailscale_ip(&resp);
    Ok(MapResult { status, ip, body_len: resp.len() })
}

/// Fresh connection + a single full map (OmitPeers=false), advertising our own
/// `endpoints`, and parse out the peer list (node/disco keys + endpoints) plus
/// our Tailscale IP. Frugal: holds the raw body but never builds a serde Value.
pub fn fetch_peers(
    machine_priv: &[u8; 32],
    control_pub: &[u8; 32],
    keys: &NodeKeys,
    endpoints: &[String],
) -> Result<(Option<String>, Vec<peers::PeerInfo>, Option<Vec<peers::Cidr>>)> {
    let mut sess = connect(machine_priv, control_pub)?;
    let body = build_map_json(keys, false, false, false, endpoints);
    let (_status, resp) = sess
        .post_json("/machine/map", body.as_bytes())
        .context("POST /machine/map (peers)")?;
    let ip = scan_tailscale_ip(&resp);
    let list = peers::parse_peers(&resp)?;
    let allowed = ip
        .as_deref()
        .and_then(|our| peers::parse_allowed_srcs(&resp, our));
    Ok((ip, list, allowed))
}

/// Report our UDP endpoints to the control server so it distributes them to
/// peers (which then learn where to direct-probe us). Endpoints in the Stream=true
/// long-poll are IGNORED by the server (capver ≥ 68), so this uses a dedicated
/// Stream=false, OmitPeers=true "endpoint update" request. Call periodically.
pub fn update_endpoints(
    machine_priv: &[u8; 32],
    control_pub: &[u8; 32],
    keys: &NodeKeys,
    endpoints: &[String],
) -> Result<u16> {
    let mut sess = connect(machine_priv, control_pub)?;
    let body = build_map_json(keys, false, true, false, endpoints);
    let (status, _resp) = sess
        .post_json("/machine/map", body.as_bytes())
        .context("POST /machine/map (endpoint update)")?;
    Ok(status)
}

/// Open a streaming /machine/map long-poll. Returns the live HTTP/2 session, the
/// stream id, and our Tailscale IP from the first MapResponse. Keep calling
/// `sess.next_message(stream_id)` to stay connected (= shown online/green).
pub fn stream_map(
    machine_priv: &[u8; 32],
    control_pub: &[u8; 32],
    keys: &NodeKeys,
    endpoints: &[String],
) -> Result<(h2::H2, u32, Option<String>)> {
    let mut sess = connect(machine_priv, control_pub)?;
    // Stream + KeepAlive + OmitPeers: with Stream=true the server still sends our
    // Node (and thus our IP) but skips the large peer list.
    let body = build_map_json(keys, true, true, true, endpoints);
    let sid = sess
        .post_stream("/machine/map", body.as_bytes())
        .context("POST /machine/map (stream)")?;
    // Scan the first few streamed chunks for our 100.x address (byte scan, no
    // serde Value tree — that would blow the heap on a big map).
    let mut ip = None;
    for _ in 0..4 {
        let chunk = sess.read_data(sid).context("first MapResponse chunk")?;
        ip = scan_tailscale_ip(&chunk);
        if ip.is_some() {
            break;
        }
    }
    Ok((sess, sid, ip))
}

/// Find our 100.x.y.z Tailscale address in raw MapResponse JSON bytes, without
/// building a serde_json::Value (which would exhaust the heap on a big map).
/// Looks for the `"100.` that starts the address string in Node.Addresses.
fn scan_tailscale_ip(raw: &[u8]) -> Option<String> {
    let pat = b"\"100.";
    let pos = raw.windows(pat.len()).position(|w| w == pat)?;
    let start = pos + 1; // skip the opening quote
    let mut end = start;
    while end < raw.len() && raw[end] != b'/' && raw[end] != b'"' {
        end += 1;
    }
    let s = core::str::from_utf8(&raw[start..end]).ok()?;
    // sanity: dotted IPv4-ish
    if s.chars().all(|c| c.is_ascii_digit() || c == '.') && s.len() >= 7 {
        Some(s.to_string())
    } else {
        None
    }
}

fn build_map_json(
    keys: &NodeKeys,
    stream: bool,
    omit_peers: bool,
    keep_alive: bool,
    endpoints: &[String],
) -> String {
    let hostinfo: serde_json::Value =
        serde_json::from_str(&build_hostinfo_json()).unwrap_or(serde_json::Value::Null);
    serde_json::json!({
        "Version": config::CAPABILITY_VERSION,
        "NodeKey": format!("nodekey:{}", keys.node.public_hex()),
        "DiscoKey": format!("discokey:{}", keys.disco.public_hex()),
        "Endpoints": endpoints,
        "Hostinfo": hostinfo,
        "Stream": stream,
        "KeepAlive": keep_alive,
        "ReadOnly": false,
        "OmitPeers": omit_peers,
        "Compress": ""
    })
    .to_string()
}

fn build_hostinfo_json() -> String {
    let mut hi = serde_json::json!({
        "Hostname": config::HOSTNAME,
        "OS": config::OS_NAME,
        "OSVersion": config::OS_VERSION,
        "GoArch": config::GO_ARCH,
        "NetInfo": {
            "MappingVariesByDestIP": false,
            "HairPinning": false,
            "WorkingIPv4": true,
            "WorkingIPv6": false,
            "PreferredDERP": 1,
            "LinkType": "wired"
        },
        "InheritTailscaleNetfilter": false
    });
    if !config::ADVERTISE_TAGS.is_empty() {
        hi["RequestTags"] = serde_json::json!(config::ADVERTISE_TAGS);
    }
    // Advertise subnet routes / exit-node (admin must approve). Sent in Hostinfo.
    let mut routes: Vec<&str> = config::SUBNET_ROUTES.to_vec();
    if config::ADVERTISE_EXIT_NODE {
        routes.push("0.0.0.0/0");
        routes.push("::/0");
    }
    if !routes.is_empty() {
        hi["RoutableIPs"] = serde_json::json!(routes);
    }
    hi.to_string()
}

fn build_register_json(keys: &NodeKeys, auth_key: &str) -> String {
    let hostinfo: serde_json::Value =
        serde_json::from_str(&build_hostinfo_json()).unwrap_or(serde_json::Value::Null);
    let mut obj = serde_json::json!({
        "Version": config::CAPABILITY_VERSION,
        "NodeKey": format!("nodekey:{}", keys.node.public_hex()),
        "MachineKey": format!("mkey:{}", keys.machine.public_hex()),
        "DiscoKey": format!("discokey:{}", keys.disco.public_hex()),
        "Hostinfo": hostinfo,
        "Endpoints": [],
        "Capabilities": [],
        "DeviceName": config::DEVICE_NAME,
        "Ephemeral": false
    });
    if !auth_key.is_empty() {
        obj["Auth"] = serde_json::json!({ "AuthKey": auth_key });
    }
    obj.to_string()
}

/// Perform the ts2021 Noise IK handshake over cleartext TCP and return the live
/// connection plus the derived transport cipher. (M4)
/// Firmware adapter: a `std::net::TcpStream` as a core [`ByteStream`]. The core
/// transport does the ts2021 upgrade + framing over this; we own the actual socket.
struct TcpByteStream(std::net::TcpStream);

impl tailscale_core::platform::ByteStream for TcpByteStream {
    fn read(&mut self, buf: &mut [u8]) -> core::result::Result<usize, ()> {
        use std::io::Read;
        self.0.read(buf).map_err(|_| ())
    }
    fn write_all(&mut self, buf: &[u8]) -> core::result::Result<(), ()> {
        use std::io::Write;
        self.0.write_all(buf).map_err(|_| ())
    }
}

/// Connect TCP with the control-channel timeouts (long read for the map long-poll).
fn tcp_connect(host: &str, port: u16) -> Result<TcpByteStream> {
    let stream = std::net::TcpStream::connect((host, port))?;
    stream.set_read_timeout(Some(Duration::from_secs(75)))?;
    stream.set_write_timeout(Some(Duration::from_secs(20)))?;
    stream.set_nodelay(true).ok();
    Ok(TcpByteStream(stream))
}

pub fn handshake(
    machine_priv: &[u8; 32],
    control_pub: &[u8; 32],
) -> Result<(transport::Conn, noise::Transport)> {
    let (hs, framed_init) = noise::start(machine_priv, control_pub)?;
    let header = transport::base64_std(&framed_init);
    let stream = tcp_connect(config::CONTROL_HOST, config::TS2021_PORT).context("ts2021 tcp connect")?;
    let mut conn = transport::connect_and_upgrade(Box::new(stream), config::CONTROL_HOST, &header)
        .context("ts2021 upgrade")?;

    let (typ, payload) = conn.read_frame().context("read handshake response frame")?;
    match typ {
        noise::MSG_RESPONSE => {}
        noise::MSG_ERROR => bail!("control error: {}", String::from_utf8_lossy(&payload)),
        other => bail!("unexpected handshake frame type {other}"),
    }
    let tr = hs.complete(&payload)?;
    Ok((conn, tr))
}

/// `GET https://<control>/key?v=<n>` -> the server's 32-byte Noise static public
/// key (the remote static for the IK handshake). Response shape:
/// `{"legacyPublicKey":"mkey:..","publicKey":"mkey:<64-hex>"}`.
pub fn fetch_control_key() -> Result<[u8; 32]> {
    let url = format!(
        "https://{}/key?v={}",
        config::CONTROL_HOST,
        config::KEY_ENDPOINT_VER
    );
    let body = http_get(&url)?;
    let v: serde_json::Value = serde_json::from_slice(&body).context("parse /key JSON")?;
    let pk = v
        .get("publicKey")
        .and_then(|x| x.as_str())
        .context("/key: missing publicKey")?;
    let hex = pk.strip_prefix("mkey:").unwrap_or(pk);
    hex_decode_32(hex).context("decode mkey hex")
}

fn http_get(url: &str) -> Result<Vec<u8>> {
    let mut conn = EspHttpConnection::new(&HttpConfig {
        crt_bundle_attach: Some(esp_idf_svc::sys::esp_crt_bundle_attach),
        buffer_size: Some(2048),
        buffer_size_tx: Some(1024),
        timeout: Some(Duration::from_secs(12)),
        ..Default::default()
    })?;
    let headers = [("User-Agent", "tailscale-rust/0.1"), ("Accept", "application/json")];
    conn.initiate_request(Method::Get, url, &headers)?;
    conn.initiate_response()?;
    let mut out: Vec<u8> = Vec::new();
    let mut buf = [0u8; 512];
    loop {
        let n = conn.read(&mut buf).unwrap_or(0);
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n]);
        if out.len() >= 8192 {
            break;
        }
    }
    Ok(out)
}

/// Decode exactly 64 lowercase/uppercase hex chars into 32 bytes.
pub fn hex_decode_32(s: &str) -> Result<[u8; 32]> {
    let s = s.trim();
    anyhow::ensure!(s.len() == 64, "expected 64 hex chars, got {}", s.len());
    let mut out = [0u8; 32];
    let bytes = s.as_bytes();
    for i in 0..32 {
        let hi = hex_val(bytes[i * 2])?;
        let lo = hex_val(bytes[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_val(c: u8) -> Result<u8> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => anyhow::bail!("bad hex char {c}"),
    }
}
