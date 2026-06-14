//! Tailscale-Rust — a minimal, pure-Rust Tailscale client for the T-Dongle S3.
//!
//! Goal: join WiFi, register with Tailscale (controlplane.tailscale.com) using a
//! pre-auth key, fetch the netmap, and show the assigned 100.x.y.z address.
//! Explicit non-goals: DERP relay, DNS/MagicDNS, exit nodes, subnet routing.
//!
//! Milestone 2: WiFi up + hardware RNG + the three persisted Curve25519 keys.

mod config;
#[cfg(feature = "ts")]
mod control;
#[cfg(feature = "ts")]
mod keys;
#[cfg(feature = "ts")]
mod node;
#[cfg(feature = "ts")]
pub use tailscale_core::wg; // migrated to the no_std core crate
#[cfg(feature = "direct")]
mod dataplane;
#[cfg(any(feature = "direct", feature = "derp"))]
pub use tailscale_core::disco; // migrated to the no_std core crate
#[cfg(feature = "direct")]
mod magicsock;
#[cfg(feature = "direct")]
pub use tailscale_core::stun; // migrated to the no_std core crate
#[cfg(feature = "derp")]
mod derp;
// icmp lives in the portable core crate now (tailscale_core::icmp).
#[cfg(feature = "http-server")]
pub use tailscale_core::tcp; // migrated to the no_std core crate
#[cfg(any(feature = "outbound", feature = "mdns-forward"))]
pub use tailscale_core::outbound; // packet builders, migrated to the no_std core crate
#[cfg(feature = "mdns-forward")]
mod mdns;
#[cfg(feature = "subnet-router")]
mod router;
#[cfg(feature = "tcp-proxy")]
mod proxy;

use std::io::Write as _; // stdout().flush()

use anyhow::Result;

use esp_idf_hal::delay::Ets;
use esp_idf_hal::gpio::PinDriver;
use esp_idf_hal::peripherals::Peripherals;
use esp_idf_hal::spi::config::Config as SpiConfig;
use esp_idf_hal::spi::{SpiDeviceDriver, SpiDriverConfig};
use esp_idf_hal::units::FromValueType;

use esp_idf_svc::eventloop::EspSystemEventLoop;
use esp_idf_svc::nvs::EspDefaultNvsPartition;
use esp_idf_svc::wifi::{AuthMethod, BlockingWifi, ClientConfiguration, Configuration, EspWifi};

use mipidsi::interface::SpiInterface;
use mipidsi::models::ST7735s;
use mipidsi::options::{ColorInversion, ColorOrder, Orientation, Rotation};
use mipidsi::Builder;

use embedded_graphics::mono_font::iso_8859_1::{FONT_5X8, FONT_6X10};
use embedded_graphics::mono_font::MonoTextStyle;
use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics::prelude::*;
use embedded_graphics::text::{Baseline, Text};

// --- Display geometry (landscape), verified against the tdongles3 project ---
const H_RES: u16 = 160;
const V_RES: u16 = 80;
const OFFSET_X: u16 = 26;
const OFFSET_Y: u16 = 1;
const TITLE_H: i32 = 11;
const ROW_H: i32 = 9;
const CHAR_W: i32 = 6; // FONT_5X8 advance

fn main() -> Result<()> {
    esp_idf_svc::sys::link_patches();
    esp_idf_svc::log::EspLogger::initialize_default();
    println!("Tailscale-Rust booting");
    let _ = std::io::stdout().flush();

    let peripherals = Peripherals::take()?;
    let pins = peripherals.pins;

    // --- ST7735 over SPI (T-Dongle S3 pinout) ---
    let sclk = pins.gpio5;
    let mosi = pins.gpio3;
    let cs = pins.gpio4;
    let dc = PinDriver::output(pins.gpio2)?;
    let rst = PinDriver::output(pins.gpio1)?;
    let mut backlight = PinDriver::output(pins.gpio38)?;
    backlight.set_low()?; // T-Dongle S3 backlight is ACTIVE-LOW: LOW = on

    let spi = SpiDeviceDriver::new_single(
        peripherals.spi2,
        sclk,
        mosi,
        Option::<esp_idf_hal::gpio::AnyIOPin>::None,
        Some(cs),
        &SpiDriverConfig::new(),
        &SpiConfig::new().baudrate(20.MHz().into()),
    )?;

    let mut buffer = [0u8; 512];
    let di = SpiInterface::new(spi, dc, &mut buffer);
    let mut delay = Ets;
    let mut display = Builder::new(ST7735s, di)
        .display_size(V_RES, H_RES)
        .display_offset(OFFSET_X, OFFSET_Y)
        .invert_colors(ColorInversion::Inverted)
        .color_order(ColorOrder::Bgr)
        .orientation(Orientation::new().rotate(Rotation::Deg90))
        .reset_pin(rst)
        .init(&mut delay)
        .map_err(|e| anyhow::anyhow!("display init failed: {e:?}"))?;

    let _ = draw_message(&mut display, "Tailscale-Rust", &["connecting WiFi...", config::WIFI_SSID]);

    // --- WiFi (STA) ---
    let sysloop = EspSystemEventLoop::take()?;
    let nvs_part = EspDefaultNvsPartition::take()?;
    let mut wifi = BlockingWifi::wrap(
        EspWifi::new(peripherals.modem, sysloop.clone(), Some(nvs_part.clone()))?,
        sysloop,
    )?;
    wifi.set_configuration(&Configuration::Client(ClientConfiguration {
        ssid: config::WIFI_SSID.try_into().unwrap_or_default(),
        password: config::WIFI_PASS.try_into().unwrap_or_default(),
        auth_method: AuthMethod::WPA2Personal,
        ..Default::default()
    }))?;
    wifi.start()?;
    println!("wifi started; connecting to {}", config::WIFI_SSID);
    wifi.connect()?;
    wifi.wait_netif_up()?;
    let ip_info = wifi.wifi().sta_netif().get_ip_info()?;
    let ip = ip_info.ip.to_string();
    println!("wifi up, IP = {ip}");
    // Disable WiFi power-save (modem sleep) — it adds ~100-300ms latency to
    // incoming packets, which directly inflates tunnel ping/HTTP round-trips.
    unsafe {
        esp_idf_svc::sys::esp_wifi_set_ps(esp_idf_svc::sys::wifi_ps_type_t_WIFI_PS_NONE);
    }

    // subnet-router/exit-node: enable NAPT on the STA netif (data-path foundation;
    // the WG-netif bridge is the remaining deep work — see router.rs).
    #[cfg(feature = "subnet-router")]
    {
        use esp_idf_svc::handle::RawHandle;
        let sta = wifi.wifi().sta_netif().handle();
        let _ = router::enable_napt_on_sta(sta);
    }
    let _ = std::io::stdout().flush();

    #[cfg(feature = "ts")]
    {
    // --- SNTP: real wall-clock for WireGuard's TAI64N timestamp. The handshake
    // responder rejects a non-increasing timestamp, so it must be monotonic
    // across reboots — real time guarantees that. ---
    let _sntp = esp_idf_svc::sntp::EspSntp::new_default().ok();
    if let Some(s) = &_sntp {
        use esp_idf_svc::sntp::SyncStatus;
        for _ in 0..16 {
            if matches!(s.get_sync_status(), SyncStatus::Completed) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        println!("sntp sync status={:?}, unix={now}", s.get_sync_status());
    }
    let _ = std::io::stdout().flush();

    // --- Data plane UDP socket + our advertised endpoints (LAN + STUN public) ---
    // One persistent socket carries STUN now and disco/WireGuard later, so the
    // public mapping STUN learns is the same port peers will reach us on.
    let mut endpoints: Vec<String> = Vec::new();
    #[cfg(feature = "direct")]
    let mut magicsock = match magicsock::MagicSock::bind() {
        Ok(ms) => {
            println!("magicsock bound, local UDP port = {}", ms.local_port);
            endpoints.push(format!("{ip}:{}", ms.local_port)); // LAN endpoint
            match ms.stun_public_addr("stun.l.google.com:19302") {
                Ok(addr) => {
                    println!("*** STUN public endpoint = {addr} ***");
                    endpoints.push(addr.to_string());
                }
                Err(e) => println!("STUN query failed: {e:#}"),
            }
            Some(ms)
        }
        Err(e) => {
            println!("magicsock bind failed: {e:#}");
            None
        }
    };
    println!("advertising endpoints: {endpoints:?}");
    let _ = std::io::stdout().flush();

    // --- Keys (generate after RF is up so esp_fill_random is strong) ---
    let node_keys = keys::load_or_generate(&nvs_part)?;
    println!("machine pubkey: {}", node_keys.machine.public_hex());
    println!("node    pubkey: {}", node_keys.node.public_hex());
    println!("disco   pubkey: {}", node_keys.disco.public_hex());
    let _ = std::io::stdout().flush();

    // --- M3: fetch the control server's Noise static public key (mkey) ---
    let control_key = match control::fetch_control_key() {
        Ok(k) => {
            let hex = hex_lower(&k);
            println!("control mkey: {hex}");
            Some(hex)
        }
        Err(e) => {
            println!("fetch control key FAILED: {e:#}");
            None
        }
    };
    let _ = std::io::stdout().flush();

    // --- M5: register with interactive (tailscale-up style) auth ---
    let mut status_line = "no control key".to_string();
    if let Some(hex) = &control_key {
        let control_pub = control::hex_decode_32(hex).expect("valid control key hex");
        let mpriv_ = node_keys.machine.private;
        // With the `authkey` feature, a configured pre-auth key enables headless
        // registration; otherwise we always use interactive browser auth.
        #[cfg(feature = "authkey")]
        let auth_key = config::AUTH_KEY_DEFAULT;
        #[cfg(not(feature = "authkey"))]
        let auth_key = "";

        let mut shown_url = false;
        loop {
            match control::connect_and_register(&mpriv_, &control_pub, &node_keys, auth_key) {
                Ok(r) => {
                    println!(
                        "register status={} authorized={} auth_url={:?}",
                        r.status, r.machine_authorized, r.auth_url
                    );
                    if r.machine_authorized {
                        status_line = "registered OK".to_string();
                        break;
                    }
                    if let Some(url) = r.auth_url.as_ref() {
                        if !shown_url {
                            println!("\n>>> Open this URL in a browser to authorize this device:\n>>> {url}\n");
                            let _ = draw_auth_url(&mut display, url);
                            shown_url = true;
                        }
                    } else if !auth_key.is_empty() {
                        // Had a key but not authorized and no URL: report and stop polling.
                        status_line = format!("reg http {} not authd", r.status);
                        break;
                    }
                }
                Err(e) => println!("register attempt failed: {e:#}"),
            }
            let _ = std::io::stdout().flush();
            std::thread::sleep(std::time::Duration::from_secs(4));
        }
    }
    println!("auth result: {status_line}");
    let _ = std::io::stdout().flush();

    // --- M6 + M7: streaming netmap -> Tailscale IP, and stay online (green) ---
    if status_line == "registered OK" {
        let control_pub = control::hex_decode_32(control_key.as_ref().unwrap())
            .expect("valid control key hex");
        let lan_line = format!("LAN {ip}");

        // --- M2: one-shot full map -> peer list (frugal: typed struct, no Value) ---
        println!("free heap before peer fetch = {}", free_heap());
        let mut peer_list: Vec<control::peers::PeerInfo> = Vec::new();
        let mut allowed_srcs: Option<Vec<control::peers::Cidr>> = None;
        let mut our_ts_ip: Option<String> = None;
        match control::fetch_peers(&node_keys.machine.private, &control_pub, &node_keys, &endpoints) {
            Ok((our_ip, list, allowed)) => {
                println!("our IP from map: {our_ip:?}; {} peer(s)", list.len());
                our_ts_ip = our_ip;
                #[cfg(feature = "packet-filter")]
                {
                    match &allowed {
                        Some(c) => println!("packet-filter: {} allowed src CIDR(s)", c.len()),
                        None => println!("packet-filter: no ACL in map (allow all)"),
                    }
                    allowed_srcs = allowed;
                }
                #[cfg(not(feature = "packet-filter"))]
                {
                    let _ = allowed;
                }
                // Only print peers that have a same-LAN endpoint (the candidates).
                for p in &list {
                    if p.endpoints.iter().any(|e| e.starts_with("192.168.1.")) {
                        println!(
                            "  LAN peer {} ip={:?} endpoints={:?}",
                            p.hostname, p.tailscale_ip, p.endpoints
                        );
                    }
                }
                peer_list = list;
            }
            Err(e) => println!("fetch_peers failed: {e:#}"),
        }
        println!("free heap after peer fetch  = {}", free_heap());
        let _ = std::io::stdout().flush();

        // derp-upgrade channel: DERP thread -> UDP dataplane (direct-path targets).
        #[cfg(feature = "derp-upgrade")]
        let (up_tx, up_rx) = {
            let (t, r) = std::sync::mpsc::channel::<node::Target>();
            (Some(t), Some(r))
        };
        #[cfg(not(feature = "derp-upgrade"))]
        let (up_tx, up_rx): (
            Option<std::sync::mpsc::Sender<node::Target>>,
            Option<std::sync::mpsc::Receiver<node::Target>>,
        ) = (None, None);

        // --- endpoint-update thread: report our UDP endpoints to control so peers
        // learn where to reach us (the Stream=true map ignores Endpoints). ---
        #[cfg(feature = "direct")]
        if !endpoints.is_empty() {
            let eps = endpoints.clone();
            let mpriv = node_keys.machine.private;
            let cpub = control_pub;
            let nk = node_keys.clone();
            let _ = std::thread::Builder::new()
                .name("epupdate".into())
                .stack_size(20 * 1024)
                .spawn(move || loop {
                    match control::update_endpoints(&mpriv, &cpub, &nk, &eps) {
                        Ok(s) => println!("endpoint update -> status {s}"),
                        Err(e) => println!("endpoint update failed: {e:#}"),
                    }
                    std::thread::sleep(std::time::Duration::from_secs(45));
                });
        }

        // --- data-plane thread: disco path discovery + direct WireGuard (LAN) ---
        #[cfg(feature = "direct")]
        if let Some(ms) = magicsock.take() {
            let targets = build_lan_targets(&peer_list, &ip);
            println!("dataplane: {} same-LAN target(s)", targets.len());
            let id = node::Identity {
                disco_priv: node_keys.disco.private,
                disco_pub: node_keys.disco.public,
                node_priv: node_keys.node.private,
                node_pub: node_keys.node.public,
                allowed_srcs: allowed_srcs.clone(),
            };
            #[cfg(feature = "outbound")]
            let outbound_cfg = build_outbound_cfg(&peer_list, our_ts_ip.as_deref());
            #[cfg(not(feature = "outbound"))]
            let outbound_cfg: Option<node::OutboundCfg> = None;

            #[cfg(feature = "mdns-forward")]
            let mdns_link = build_mdns_link(&peer_list, our_ts_ip.as_deref(), &ip);
            #[cfg(not(feature = "mdns-forward"))]
            let mdns_link: Option<node::MdnsLink> = None;

            // Pin the data-plane (WireGuard decrypt) thread to core 1 — WiFi + the
            // lwIP TCP/IP task run on core 0, so this gives crypto a dedicated core
            // (more throughput, less jitter). Reset config afterwards.
            let _ = esp_idf_svc::hal::task::thread::ThreadSpawnConfiguration {
                pin_to_core: Some(esp_idf_svc::hal::cpu::Core::Core1),
                stack_size: 28 * 1024,
                ..Default::default()
            }
            .set();
            let _ = std::thread::Builder::new()
                .name("dataplane".into())
                .stack_size(28 * 1024)
                .spawn(move || dataplane::run(ms, id, targets, up_rx, outbound_cfg, mdns_link));
            let _ = esp_idf_svc::hal::task::thread::ThreadSpawnConfiguration::default().set();
        }

        // --- DERP relay responder: reach the dongle from off-LAN/remote ---
        #[cfg(feature = "derp")]
        {
            let derp_id = node::Identity {
                disco_priv: node_keys.disco.private,
                disco_pub: node_keys.disco.public,
                node_priv: node_keys.node.private,
                node_pub: node_keys.node.public,
                allowed_srcs: allowed_srcs.clone(),
            };
            let upgrade = up_tx.map(|tx| node::Upgrade {
                tx,
                our_endpoints: endpoints
                    .iter()
                    .filter_map(|e| e.parse::<std::net::SocketAddr>().ok())
                    .collect(),
                peers: peer_list
                    .iter()
                    .map(|p| node::PeerDir {
                        node_pub: p.node_key,
                        disco_pub: p.disco_key,
                        endpoints: p
                            .endpoints
                            .iter()
                            .filter_map(|e| e.parse::<std::net::SocketAddr>().ok())
                            .collect(),
                    })
                    .collect(),
            });
            let _ = std::thread::Builder::new()
                .name("derp".into())
                .stack_size(40 * 1024)
                .spawn(move || derp::run(derp_id, upgrade));
        }

        let _ = std::io::stdout().flush();

        let mut ts_ip: Option<String> = None;
        loop {
            println!("opening map stream...");
            let _ = std::io::stdout().flush();
            match control::stream_map(&node_keys.machine.private, &control_pub, &node_keys, &endpoints) {
                Ok((mut sess, sid, ip_opt)) => {
                    if ip_opt.is_some() {
                        ts_ip = ip_opt;
                    }
                    if let Some(t) = &ts_ip {
                        println!("\n*** TAILSCALE IP = {t} (online) ***\n");
                    }
                    let ts_line = match &ts_ip {
                        Some(t) => format!("TS {t}"),
                        None => "TS (no IP)".to_string(),
                    };
                    let _ = draw_message(
                        &mut display,
                        "Tailscale online",
                        &[ts_line.as_str(), lan_line.as_str(), "status: green", "(map stream up)"],
                    );
                    let _ = std::io::stdout().flush();
                    // Keep the stream alive -> node stays online/green.
                    loop {
                        match sess.read_data(sid) {
                            Ok(m) => println!("map keepalive/update ({} bytes)", m.len()),
                            Err(e) => {
                                println!("map stream ended: {e:#} — reconnecting");
                                break;
                            }
                        }
                        let _ = std::io::stdout().flush();
                    }
                }
                Err(e) => {
                    println!("map stream connect failed: {e:#}");
                    let ts_line = match &ts_ip {
                        Some(t) => format!("TS {t}"),
                        None => "TS (no IP)".to_string(),
                    };
                    let _ = draw_message(
                        &mut display,
                        "Tailscale offline",
                        &[ts_line.as_str(), lan_line.as_str(), "reconnecting...", ""],
                    );
                }
            }
            let _ = std::io::stdout().flush();
            std::thread::sleep(std::time::Duration::from_secs(5));
        }
    }
    let _ = draw_message(
        &mut display,
        "Tailscale-Rust",
        &[status_line.as_str(), "not registered", "", ""],
    );
    } // end #[cfg(feature = "ts")]

    #[cfg(not(feature = "ts"))]
    {
        let _ = draw_message(
            &mut display,
            "Baseline (no TS)",
            &["WiFi + display only", ip.as_str(), "", ""],
        );
    }

    let mut tick: u32 = 0;
    loop {
        std::thread::sleep(std::time::Duration::from_secs(10));
        tick += 1;
        println!("alive tick={tick} ip={ip}");
        let _ = std::io::stdout().flush();
    }
}

/// Show the interactive-login URL on the display as wrapped text (scheme
/// stripped for brevity), so the user can read it and open it in a browser.
#[cfg(feature = "ts")]
fn draw_auth_url<D>(display: &mut D, url: &str) -> std::result::Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    display.clear(Rgb565::BLACK)?;
    Text::with_baseline(
        "Open in browser:",
        Point::new(2, 0),
        MonoTextStyle::new(&FONT_6X10, Rgb565::CYAN),
        Baseline::Top,
    )
    .draw(display)?;

    let shown = url.strip_prefix("https://").unwrap_or(url);
    let style = MonoTextStyle::new(&FONT_5X8, Rgb565::WHITE);
    let wrap = (H_RES as usize) / (CHAR_W as usize); // chars per line
    let chars: Vec<char> = shown.chars().collect();
    let mut row = 0;
    for line in chars.chunks(wrap) {
        let s: String = line.iter().collect();
        Text::with_baseline(
            &s,
            Point::new(2, TITLE_H + 2 + row * ROW_H),
            style,
            Baseline::Top,
        )
        .draw(display)?;
        row += 1;
    }
    Text::with_baseline(
        "waiting for auth...",
        Point::new(2, TITLE_H + 2 + (row + 1) * ROW_H),
        MonoTextStyle::new(&FONT_5X8, Rgb565::YELLOW),
        Baseline::Top,
    )
    .draw(display)?;
    Ok(())
}

/// Current free heap in bytes (for watching the data-plane memory budget).
#[cfg(feature = "ts")]
fn free_heap() -> u32 {
    unsafe { esp_idf_svc::sys::esp_get_free_heap_size() }
}

#[cfg(feature = "direct")]
/// Build disco targets from the peer list, keeping only endpoints on our own /24
/// (same-LAN direct paths — fast and reliable, no hole-punching needed). Remote
/// peers are reached via DERP (see the DERP client), not by spraying disco to
/// every public endpoint (which starved the crypto thread and hurt LAN latency).
fn build_lan_targets(peers: &[control::peers::PeerInfo], our_ip: &str) -> Vec<node::Target> {
    use std::net::SocketAddr;
    let prefix = match our_ip.rsplit_once('.') {
        Some((net, _)) => format!("{net}."),
        None => return Vec::new(),
    };
    let mut out = Vec::new();
    for p in peers {
        let eps: Vec<SocketAddr> = p
            .endpoints
            .iter()
            .filter(|e| e.starts_with(&prefix))
            .filter_map(|e| e.parse::<SocketAddr>().ok())
            .collect();
        if !eps.is_empty() {
            out.push(node::Target {
                name: p.hostname.clone(),
                disco_pub: p.disco_key,
                node_pub: p.node_key,
                endpoints: eps,
                spray: false, // LAN targets are directly reachable
            });
        }
    }
    out
}

/// Build the outbound config: resolve the configured target Tailscale IP to a
/// peer's node key. Returns None if disabled or the target/our-IP isn't known.
#[cfg(feature = "outbound")]
fn build_outbound_cfg(
    peers: &[control::peers::PeerInfo],
    our_ip: Option<&str>,
) -> Option<node::OutboundCfg> {
    use std::net::Ipv4Addr;
    if config::OUTBOUND_TARGET_IP.is_empty() {
        return None;
    }
    let our_ip: Ipv4Addr = our_ip?.parse().ok()?;
    let target_ip: Ipv4Addr = config::OUTBOUND_TARGET_IP.parse().ok()?;
    let peer = peers
        .iter()
        .find(|p| p.tailscale_ip.as_deref() == Some(config::OUTBOUND_TARGET_IP))?;
    println!("outbound: target {} -> node {}", target_ip, hex_lower(&peer.node_key));
    Some(node::OutboundCfg {
        our_ip,
        target_ip,
        target_node: peer.node_key,
        http_port: config::OUTBOUND_HTTP_PORT,
        http_path: config::OUTBOUND_HTTP_PATH.to_string(),
    })
}

/// Resolve the mDNS partner + spawn the reflector thread; returns the link the
/// data plane uses to forward/receive mDNS over the tunnel. None if disabled.
#[cfg(feature = "mdns-forward")]
fn build_mdns_link(
    peers: &[control::peers::PeerInfo],
    our_ip: Option<&str>,
    lan_ip_str: &str,
) -> Option<node::MdnsLink> {
    use std::net::Ipv4Addr;
    if config::MDNS_PARTNER_IP.is_empty() {
        return None;
    }
    let our_ip: Ipv4Addr = our_ip?.parse().ok()?;
    let partner_ip: Ipv4Addr = config::MDNS_PARTNER_IP.parse().ok()?;
    let lan_ip: Ipv4Addr = lan_ip_str.parse().ok()?;
    let peer = peers
        .iter()
        .find(|p| p.tailscale_ip.as_deref() == Some(config::MDNS_PARTNER_IP))?;
    let (fwd_tx, fwd_rx) = std::sync::mpsc::channel::<Vec<u8>>();
    let (reinject_tx, reinject_rx) = std::sync::mpsc::channel::<Vec<u8>>();
    let _ = std::thread::Builder::new()
        .name("mdns".into())
        .stack_size(16 * 1024)
        .spawn(move || mdns::run(lan_ip, fwd_tx, reinject_rx));
    println!("mdns: partner {} -> node {}", partner_ip, hex_lower(&peer.node_key));
    Some(node::MdnsLink {
        our_ip,
        partner_ip,
        partner_node: peer.node_key,
        fwd_rx,
        reinject_tx,
    })
}

/// Lowercase hex of a byte slice.
#[cfg(feature = "ts")]
fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0xf) as u32, 16).unwrap());
    }
    s
}

/// Clear the screen and draw a cyan title with white body lines.
fn draw_message<D>(display: &mut D, title: &str, lines: &[&str]) -> std::result::Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    display.clear(Rgb565::BLACK)?;
    Text::with_baseline(
        title,
        Point::new(2, 0),
        MonoTextStyle::new(&FONT_6X10, Rgb565::CYAN),
        Baseline::Top,
    )
    .draw(display)?;
    let style = MonoTextStyle::new(&FONT_5X8, Rgb565::WHITE);
    for (i, l) in lines.iter().enumerate() {
        Text::with_baseline(l, Point::new(2, TITLE_H + 4 + i as i32 * ROW_H), style, Baseline::Top)
            .draw(display)?;
    }
    Ok(())
}
