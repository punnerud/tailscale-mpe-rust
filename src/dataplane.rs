//! The data-plane loop: runs on its own thread, owns the UDP socket, and drives
//! disco path discovery (M3), the WireGuard handshake — both initiator and
//! responder (M4/M8) — and, once a tunnel is up, transport + ICMP echo replies
//! and a tiny in-tunnel HTTP server (M5/M7).
//!
//! It keeps MULTIPLE concurrent tunnels (one per peer, keyed by our WireGuard
//! receiver index) so several active tailnet peers don't fight over a single
//! slot. Each tunnel carries its own TCP server state.

use std::collections::{HashMap, HashSet};
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::{Duration, Instant};

use crate::disco;
use crate::magicsock::MagicSock;
#[cfg_attr(feature = "bench", allow(unused_imports))]
use crate::node::{src_allowed, Identity, Target};
use crate::stun;
use crate::wg;

/// A handshake we've sent and are waiting on a response for. We lock onto one
/// peer (`node_pub`/`addr`) and keep retrying it rather than switching peers.
struct Pending {
    addr: SocketAddr,
    init: [u8; wg::INIT_LEN], // resent verbatim on retry so responses keep matching
    hs: wg::Handshake,
    our_index: u32,
    sent_tick: u32,
    retries: u32,
}

/// One established tunnel + its peer address + its in-tunnel TCP server.
struct TunnelEntry {
    tun: wg::Tunnel,
    addr: SocketAddr,
    #[cfg(any(feature = "outbound", feature = "mdns-forward"))]
    peer_node: [u8; 32],
    #[cfg(feature = "http-server")]
    tcp: crate::tcp::TcpServer,
}

struct State {
    pending: HashMap<[u8; 32], Pending>, // keyed by peer node pubkey (one per peer)
    tunnels: HashMap<u32, TunnelEntry>,  // keyed by our receiver index
    confirmed: HashSet<SocketAddr>,
    #[cfg(feature = "outbound")]
    outbound: Option<OutboundRun>,
    #[cfg(feature = "mdns-forward")]
    mdns_reinject: Option<std::sync::mpsc::Sender<Vec<u8>>>,
    #[cfg(feature = "mdns-forward")]
    mdns_partner: [u8; 32],
    #[cfg(feature = "bench")]
    bench_bytes: u64,
    #[cfg(feature = "bench")]
    bench_pkts: u64,
    #[cfg(feature = "bench")]
    bench_last: std::time::Instant,
}

/// Runtime state for device-initiated traffic to one target peer.
#[cfg(feature = "outbound")]
struct OutboundRun {
    cfg: crate::node::OutboundCfg,
    icmp_ident: u16,
    icmp_seq: u16,
    sport: u16,
    tcp: Option<crate::outbound::TcpClient>,
    started: bool,
    http_done: bool,
}

/// Shared mutable state for the symmetric dual-core design: BOTH decrypt threads
/// own this behind one Mutex. The expensive ChaCha20-Poly1305 runs OUTSIDE the
/// lock — each thread clones the 32-byte recv key under a brief lock, decrypts
/// lock-free (so the two LX7 cores run crypto in parallel), then re-locks only to
/// hand the plaintext to `handle_decrypted`. Out-of-order decrypt is safe: every WG
/// transport packet carries its own counter (the AEAD nonce), so decryption is
/// stateless per-packet and the inner IP protocols tolerate reordering.
#[cfg(feature = "dualcore")]
struct Shared {
    st: State,
    targets: Vec<Target>,
    tick: u32,
}

/// Process one received UDP datagram. Called by BOTH symmetric threads. Transport
/// packets (the hot, CPU-bound path) decrypt with NO lock held so both cores work
/// in parallel; everything else is handled briefly under the lock.
#[cfg(feature = "dualcore")]
fn process_packet(
    sock: &MagicSock,
    id: &Identity,
    shared: &std::sync::Mutex<Shared>,
    pkt: &[u8],
    src: SocketAddr,
) {
    if pkt.first() == Some(&wg::MSG_TRANSPORT) && pkt.len() >= 16 {
        let idx = u32::from_le_bytes([pkt[4], pkt[5], pkt[6], pkt[7]]);
        // Brief lock: just clone this tunnel's recv key.
        let key = {
            let g = shared.lock().unwrap();
            g.st.tunnels.get(&idx).map(|e| e.tun.recv_key())
        };
        let key = match key {
            Some(k) => k,
            None => return,
        };
        // Expensive decrypt with the lock RELEASED -> the two cores run in parallel.
        if let Some(inner) = wg::decrypt_transport(&key, pkt) {
            let mut g = shared.lock().unwrap();
            handle_decrypted(sock, id, &mut g.st, idx, &inner, src);
        }
    } else {
        let mut g = shared.lock().unwrap();
        let Shared { st, targets, tick } = &mut *g;
        handle_packet(sock, id, targets, st, *tick, pkt, src);
    }
}

/// Symmetric two-thread data plane: two threads (one pinned per core) each run the
/// FULL recv->decrypt->handle cycle, sharing state via a Mutex with the decrypt
/// done outside the lock. Puts BOTH cores on the CPU-bound WireGuard crypto without
/// the oversubscription of a separate dispatcher thread (the failed pipeline design).
#[cfg(feature = "dualcore")]
fn run_dualcore(
    sock: MagicSock,
    id: Identity,
    targets: Vec<Target>,
    rx: Option<std::sync::mpsc::Receiver<Target>>,
    st: State,
    stun_addr: Option<SocketAddr>,
    #[cfg(feature = "mdns-forward")] mdns_fwd_rx: Option<std::sync::mpsc::Receiver<Vec<u8>>>,
    #[cfg(feature = "mdns-forward")] mdns_our_ip: std::net::Ipv4Addr,
    #[cfg(feature = "mdns-forward")] mdns_partner_ip: std::net::Ipv4Addr,
    #[cfg(feature = "mdns-forward")] mdns_partner_node: [u8; 32],
) -> ! {
    use esp_idf_svc::hal::cpu::Core;
    use esp_idf_svc::hal::task::thread::ThreadSpawnConfiguration;
    use std::sync::{Arc, Mutex};

    let sock = Arc::new(sock);
    let shared = Arc::new(Mutex::new(Shared { st, targets, tick: 0 }));
    // lwIP does NOT allow two threads to recv_from the same UDP socket at once
    // (concurrent recvfrom double-frees the netbuf -> pbuf_free abort). So the
    // recv is serialized by this mutex; the expensive ChaCha decrypt still runs
    // lock-free in process_packet, so both cores crunch crypto in parallel. recv
    // itself is cheap (an mbox copy), so serializing it costs ~nothing.
    let recv_lock = Arc::new(Mutex::new(()));
    // Short read timeout so a blocked idle recv doesn't hold recv_lock for long.
    let _ = sock.set_read_timeout(Some(Duration::from_millis(100)));

    // Secondary recv+decrypt+handle thread, pinned to Core0 (the main data-plane
    // thread is pinned to Core1 by main.rs) => 2 threads on 2 cores, no oversub.
    {
        let sock2 = Arc::clone(&sock);
        let shared2 = Arc::clone(&shared);
        let recv_lock2 = Arc::clone(&recv_lock);
        let id2 = id.clone();
        let _ = ThreadSpawnConfiguration {
            pin_to_core: Some(Core::Core0),
            stack_size: 24 * 1024,
            ..Default::default()
        }
        .set();
        let _ = std::thread::Builder::new()
            .name("wgcore0".into())
            .stack_size(24 * 1024)
            .spawn(move || {
                let mut buf = [0u8; 1500];
                loop {
                    let r = {
                        let _g = recv_lock2.lock().unwrap();
                        sock2.recv_from(&mut buf)
                    };
                    match r {
                        Ok((n, src)) => process_packet(&sock2, &id2, &shared2, &buf[..n], src),
                        Err(e) => {
                            let k = e.kind();
                            if k != std::io::ErrorKind::WouldBlock
                                && k != std::io::ErrorKind::TimedOut
                            {
                                println!("dataplane(core0): recv error: {e}");
                            }
                        }
                    }
                }
            });
        let _ = ThreadSpawnConfiguration::default().set();
    }

    println!("dataplane: dual-core SYMMETRIC (2 recv+decrypt threads, 1 per core)");

    // Main thread (Core1): same cycle PLUS the periodic housekeeping.
    let mut strikes: HashMap<SocketAddr, u8> = HashMap::new();
    let mut last_probe = Instant::now()
        .checked_sub(Duration::from_secs(2))
        .unwrap_or_else(Instant::now);
    let mut last_stun = Instant::now();
    let mut probe_round: u32 = 0;
    let mut tick: u32 = 0;
    let mut buf = [0u8; 1500];

    loop {
        // Periodic + mDNS drain: take the lock, do the housekeeping, release.
        {
            let mut g = shared.lock().unwrap();
            let Shared { st, targets, tick: shtick } = &mut *g;
            run_periodic(
                &sock, &id, st, targets, &rx, tick, &mut strikes, &mut last_probe,
                &mut last_stun, &mut probe_round, stun_addr,
            );
            #[cfg(feature = "mdns-forward")]
            mdns_drain(&sock, st, &mdns_fwd_rx, mdns_our_ip, mdns_partner_ip, mdns_partner_node);
            *shtick = tick;
        }

        let r = {
            let _g = recv_lock.lock().unwrap();
            sock.recv_from(&mut buf)
        };
        match r {
            Ok((n, src)) => process_packet(&sock, &id, &shared, &buf[..n], src),
            Err(e) => {
                let k = e.kind();
                if k != std::io::ErrorKind::WouldBlock && k != std::io::ErrorKind::TimedOut {
                    println!("dataplane: recv error: {e}");
                }
            }
        }
        tick = tick.wrapping_add(1);
    }
}

const PENDING_TIMEOUT_TICKS: u32 = 3; // ~3s before retrying a handshake
const MAX_STRIKES: u8 = 3; // give up disco-probing an endpoint after this many send errors
const MAX_HS_RETRIES: u32 = 4; // give up + free the slot after this many retries
const MAX_TUNNELS: usize = 8;

/// Run the data-plane loop forever. `rx`, if present, delivers extra targets at
/// runtime (used by derp-upgrade to attempt a direct path to a relayed peer).
pub fn run(
    sock: MagicSock,
    id: Identity,
    mut targets: Vec<Target>,
    rx: Option<std::sync::mpsc::Receiver<Target>>,
    outbound_cfg: Option<crate::node::OutboundCfg>,
    mdns: Option<crate::node::MdnsLink>,
) {
    #[cfg(not(feature = "mdns-forward"))]
    let _ = &mdns;
    let _ = sock.set_read_timeout(Some(Duration::from_secs(1)));
    println!(
        "dataplane: started, {} target(s), {} candidate endpoint(s)",
        targets.len(),
        targets.iter().map(|t| t.endpoints.len()).sum::<usize>()
    );

    // Keep our public NAT mapping open so remote peers can reach us: re-send a
    // STUN request to a public server every ~15s (the outbound packet refreshes
    // the mapping). Resolve the server once.
    let stun_addr: Option<SocketAddr> = "stun.l.google.com:19302"
        .to_socket_addrs()
        .ok()
        .and_then(|mut it| it.find(|a| a.is_ipv4()));

    #[cfg(not(feature = "outbound"))]
    let _ = outbound_cfg;

    // Destructure the mDNS link into reusable parts.
    #[cfg(feature = "mdns-forward")]
    let (mdns_fwd_rx, mdns_our_ip, mdns_partner_ip, mdns_partner_node, mdns_reinject_tx) =
        match mdns {
            Some(m) => (
                Some(m.fwd_rx),
                m.our_ip,
                m.partner_ip,
                m.partner_node,
                Some(m.reinject_tx),
            ),
            None => (
                None,
                std::net::Ipv4Addr::UNSPECIFIED,
                std::net::Ipv4Addr::UNSPECIFIED,
                [0u8; 32],
                None,
            ),
        };

    let mut st = State {
        pending: HashMap::new(),
        tunnels: HashMap::new(),
        confirmed: HashSet::new(),
        #[cfg(feature = "outbound")]
        outbound: outbound_cfg.map(|c| {
            let mut s = [0u8; 4];
            fill_random(&mut s);
            OutboundRun {
                cfg: c,
                icmp_ident: u16::from_le_bytes([s[0], s[1]]),
                icmp_seq: 0,
                sport: 1024 + (u16::from_le_bytes([s[2], s[3]]) % 60000),
                tcp: None,
                started: false,
                http_done: false,
            }
        }),
        #[cfg(feature = "mdns-forward")]
        mdns_reinject: mdns_reinject_tx,
        #[cfg(feature = "mdns-forward")]
        mdns_partner: mdns_partner_node,
        #[cfg(feature = "bench")]
        bench_bytes: 0,
        #[cfg(feature = "bench")]
        bench_pkts: 0,
        #[cfg(feature = "bench")]
        bench_last: std::time::Instant::now(),
    };

    // Dispatch: dual-core symmetric (two recv+decrypt threads) or the single
    // threaded loop. Both share run_periodic / handle_* below.
    #[cfg(feature = "dualcore")]
    run_dualcore(
        sock,
        id,
        targets,
        rx,
        st,
        stun_addr,
        #[cfg(feature = "mdns-forward")]
        mdns_fwd_rx,
        #[cfg(feature = "mdns-forward")]
        mdns_our_ip,
        #[cfg(feature = "mdns-forward")]
        mdns_partner_ip,
        #[cfg(feature = "mdns-forward")]
        mdns_partner_node,
    );

    #[cfg(not(feature = "dualcore"))]
    {
        let mut strikes: HashMap<SocketAddr, u8> = HashMap::new();
        let mut tick: u32 = 0;
        let mut last_probe = Instant::now()
            .checked_sub(Duration::from_secs(2))
            .unwrap_or_else(Instant::now); // fire the first probe immediately
        let mut last_stun = Instant::now();
        let mut probe_round: u32 = 0;
        let mut buf = [0u8; 1500];

        loop {
            run_periodic(
                &sock, &id, &mut st, &mut targets, &rx, tick, &mut strikes, &mut last_probe,
                &mut last_stun, &mut probe_round, stun_addr,
            );
            #[cfg(feature = "mdns-forward")]
            mdns_drain(&sock, &mut st, &mdns_fwd_rx, mdns_our_ip, mdns_partner_ip, mdns_partner_node);

            match sock.recv_from(&mut buf) {
                Ok((n, src)) => handle_packet(&sock, &id, &targets, &mut st, tick, &buf[..n], src),
                Err(e) => {
                    let k = e.kind();
                    if k != std::io::ErrorKind::WouldBlock && k != std::io::ErrorKind::TimedOut {
                        println!("dataplane: recv error: {e}");
                    }
                }
            }
            tick = tick.wrapping_add(1);
        }
    }
}

/// Periodic data-plane housekeeping: pull in runtime-added targets, retry stalled
/// handshakes, disco-probe endpoints + keepalive tunnels every ~2s, and refresh the
/// public NAT mapping every ~15s. Shared by the single-core loop and the dual-core
/// main thread (which calls it while holding the shared lock). Scheduled on the
/// WALL CLOCK, not loop-iteration count, so packet load doesn't starve packet work.
#[allow(clippy::too_many_arguments)]
fn run_periodic(
    sock: &MagicSock,
    id: &Identity,
    st: &mut State,
    targets: &mut Vec<Target>,
    rx: &Option<std::sync::mpsc::Receiver<Target>>,
    tick: u32,
    strikes: &mut HashMap<SocketAddr, u8>,
    last_probe: &mut Instant,
    last_stun: &mut Instant,
    probe_round: &mut u32,
    stun_addr: Option<SocketAddr>,
) {
    // Pull in any runtime-added targets (derp-upgrade hole-punch candidates).
    if let Some(rx) = rx {
        while let Ok(t) = rx.try_recv() {
            if let Some(existing) = targets.iter_mut().find(|e| e.node_pub == t.node_pub) {
                let mut added = 0;
                for ep in t.endpoints {
                    if !existing.endpoints.contains(&ep) {
                        existing.endpoints.push(ep);
                        added += 1;
                    }
                }
                existing.spray = existing.spray || t.spray;
                if added > 0 {
                    println!("dataplane: +{added} fresh endpoint(s) for {}", existing.name);
                }
            } else {
                println!("dataplane: upgrade target {} via {} endpoint(s)", t.name, t.endpoints.len());
                targets.push(t);
            }
        }
    }

    // Per-peer handshake retry (independent slots → no head-of-line blocking
    // when several peers are confirmed at once).
    let mut drop_pending: Vec<[u8; 32]> = Vec::new();
    for (k, p) in st.pending.iter_mut() {
        let have = st.tunnels.values().any(|e| e.addr == p.addr);
        if have {
            drop_pending.push(*k);
        } else if tick.wrapping_sub(p.sent_tick) > PENDING_TIMEOUT_TICKS {
            if p.retries >= MAX_HS_RETRIES {
                println!("dataplane: handshake to {} gave up after {} tries", p.addr, p.retries);
                drop_pending.push(*k);
            } else {
                let _ = sock.send_to(&p.init, p.addr);
                p.sent_tick = tick;
                p.retries += 1;
            }
        }
    }
    for k in drop_pending {
        st.pending.remove(&k);
    }

    // Every ~2s (wall clock): disco-probe each endpoint, and keepalive tunnels.
    if last_probe.elapsed() >= Duration::from_secs(2) {
        *last_probe = Instant::now();
        *probe_round = probe_round.wrapping_add(1);
        for t in targets.iter() {
            // Skip probing peers we already have a tunnel to (saves crypto;
            // keepalives keep those paths alive).
            if t.endpoints.iter().any(|ep| st.tunnels.values().any(|e| e.addr == *ep)) {
                continue;
            }
            let mut txid = [0u8; 12];
            fill_random(&mut txid);
            let pt = disco::ping_plaintext(&txid, &id.node_pub);
            if let Ok(pkt) = disco::seal(&id.disco_priv, &id.disco_pub, &t.disco_pub, &pt) {
                for ep in &t.endpoints {
                    let s = strikes.entry(*ep).or_insert(0);
                    if *s >= MAX_STRIKES {
                        continue;
                    }
                    if let Err(e) = sock.send_to(&pkt, *ep) {
                        *s += 1;
                        if *s == MAX_STRIKES {
                            println!(
                                "dataplane: giving up on {ep} ({}) after {MAX_STRIKES} send errors ({e})",
                                t.name
                            );
                        }
                    } else {
                        *s = 0;
                    }
                }

                // Birthday port-spray: for a remote peer that may be behind
                // symmetric NAT, fire the (already-sealed) disco ping at ~256
                // ports on its public IP. Combined with the peer spraying us,
                // the birthday paradox makes a port pair collide and punch.
                #[cfg(feature = "birthday")]
                if t.spray {
                    let have = st
                        .tunnels
                        .values()
                        .any(|e| t.endpoints.iter().any(|ep| ep.ip() == e.addr.ip()));
                    if !have {
                        for ep in &t.endpoints {
                            if let std::net::IpAddr::V4(ip) = ep.ip() {
                                if is_public_v4(&ip) {
                                    for p in birthday_ports(ep.port(), *probe_round) {
                                        let _ = sock
                                            .send_to(&pkt, std::net::SocketAddr::from((ip, p)));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        for e in st.tunnels.values_mut() {
            let ka = e.tun.keepalive();
            let _ = sock.send_to(&ka, e.addr);
        }

        // Outbound: once a tunnel to the target exists, ping it and (once)
        // fire an HTTP GET through the tunnel.
        #[cfg(feature = "outbound")]
        if let Some(tn) = st.outbound.as_ref().map(|o| o.cfg.target_node) {
            if let Some(idx) = st.tunnels.iter().find(|(_, e)| e.peer_node == tn).map(|(k, _)| *k) {
                let entry = st.tunnels.get_mut(&idx).unwrap();
                let ob = st.outbound.as_mut().unwrap();
                ob.icmp_seq = ob.icmp_seq.wrapping_add(1);
                let req = crate::outbound::icmp_echo_request(
                    ob.cfg.our_ip, ob.cfg.target_ip, ob.icmp_ident, ob.icmp_seq, b"tdongle-s3",
                );
                let _ = sock.send_to(&entry.tun.encrypt(&req), entry.addr);
                if !ob.started {
                    ob.started = true;
                    let http = format!(
                        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: tdongle\r\nConnection: close\r\n\r\n",
                        ob.cfg.http_path, ob.cfg.target_ip
                    );
                    let mut c = crate::outbound::TcpClient::new(
                        ob.cfg.our_ip, ob.cfg.target_ip, ob.sport, ob.cfg.http_port, http.into_bytes(),
                    );
                    let _ = sock.send_to(&entry.tun.encrypt(&c.open()), entry.addr);
                    ob.tcp = Some(c);
                    println!("outbound: ICMP ping + HTTP GET -> {} :{}", ob.cfg.target_ip, ob.cfg.http_port);
                }
            }
        }
    }

    // Refresh the public NAT mapping (~every 15s, wall clock).
    if last_stun.elapsed() >= Duration::from_secs(15) {
        *last_stun = Instant::now();
        if let Some(a) = stun_addr {
            let (req, _txid) = stun::binding_request();
            let _ = sock.send_to(&req, a);
        }
    }
}

/// mDNS reflector: forward LAN-captured mDNS to the partner over its tunnel.
#[cfg(feature = "mdns-forward")]
fn mdns_drain(
    sock: &MagicSock,
    st: &mut State,
    mdns_fwd_rx: &Option<std::sync::mpsc::Receiver<Vec<u8>>>,
    mdns_our_ip: std::net::Ipv4Addr,
    mdns_partner_ip: std::net::Ipv4Addr,
    mdns_partner_node: [u8; 32],
) {
    if let Some(rx) = mdns_fwd_rx.as_ref() {
        while let Ok(payload) = rx.try_recv() {
            if let Some(idx) = st.tunnels.iter().find(|(_, e)| e.peer_node == mdns_partner_node).map(|(k, _)| *k) {
                let entry = st.tunnels.get_mut(&idx).unwrap();
                let inner = crate::outbound::udp_datagram(
                    mdns_our_ip, mdns_partner_ip, crate::mdns::FWD_PORT, crate::mdns::FWD_PORT, &payload,
                );
                let _ = sock.send_to(&entry.tun.encrypt(&inner), entry.addr);
            }
        }
    }
}

fn handle_packet(
    sock: &MagicSock,
    id: &Identity,
    targets: &[Target],
    st: &mut State,
    tick: u32,
    pkt: &[u8],
    src: SocketAddr,
) {
    // Diagnostic: surface any packet from a non-LAN source (a remote/5G peer),
    // excluding our STUN keepalive replies, so we can see if remote reaches us.
    let remote = match src {
        SocketAddr::V4(v4) => {
            let o = v4.ip().octets();
            !(o[0] == 192 && o[1] == 168)
        }
        _ => true,
    };
    if remote && !crate::stun::is_stun(pkt) {
        let kind = if disco::is_disco(pkt) {
            "disco"
        } else {
            match pkt.first() {
                Some(1) => "wg-init",
                Some(2) => "wg-resp",
                Some(4) => "wg-data",
                _ => "other",
            }
        };
        println!("dataplane: REMOTE inbound from {src} ({kind}, {} bytes)", pkt.len());
    }

    if disco::is_disco(pkt) {
        match disco::open(&id.disco_priv, pkt) {
            Ok(msg) => match msg.msg_type {
                disco::PING => {
                    let pt = disco::pong_plaintext(&msg.txid, src);
                    if let Ok(reply) =
                        disco::seal(&id.disco_priv, &id.disco_pub, &msg.sender_disco_pub, &pt)
                    {
                        let _ = sock.send_to(&reply, src);
                    }
                }
                disco::PONG => {
                    if st.confirmed.insert(src) {
                        let who = name_for(targets, &msg.sender_disco_pub);
                        println!("dataplane: *** disco PATH CONFIRMED: {who} @ {src} ***");
                    }
                    maybe_start_handshake(sock, id, targets, st, tick, &msg.sender_disco_pub, src);
                }
                _ => {}
            },
            Err(e) => println!("dataplane: disco open from {src} failed: {e:#}"),
        }
        return;
    }

    if crate::stun::is_stun(pkt) {
        return;
    }

    if pkt.first() == Some(&wg::MSG_INITIATION) {
        handle_wg_init(sock, id, st, pkt, src);
        return;
    }

    if pkt.first() == Some(&wg::MSG_RESPONSE) {
        handle_wg_response(sock, st, pkt, src);
        return;
    }

    if pkt.first() == Some(&wg::MSG_TRANSPORT) {
        handle_wg_transport(sock, id, st, pkt, src);
    }
}

/// On a confirmed path, start a WireGuard handshake if we have no handshake in
/// flight and no tunnel to this peer yet (and we're under the tunnel cap).
fn maybe_start_handshake(
    sock: &MagicSock,
    id: &Identity,
    targets: &[Target],
    st: &mut State,
    tick: u32,
    disco_pub: &[u8; 32],
    src: SocketAddr,
) {
    let target = match targets.iter().find(|t| &t.disco_pub == disco_pub) {
        Some(t) => t,
        None => return,
    };
    if st.pending.contains_key(&target.node_pub)
        || st.tunnels.values().any(|e| e.addr == src)
        || st.tunnels.len() + st.pending.len() >= MAX_TUNNELS
    {
        return;
    }
    let our_index = wg::random_index();
    let ts = {
        use std::time::{SystemTime, UNIX_EPOCH};
        let d = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
        wg::tai64n(d.as_secs(), d.subsec_nanos())
    };
    let (msg, hs) = wg::build_initiation(
        &id.node_priv,
        &id.node_pub,
        &target.node_pub,
        ts,
        our_index,
    );
    match sock.send_to(&msg, src) {
        Ok(_) => {
            println!("dataplane: WG handshake init -> {} @ {src}", target.name);
            st.pending.insert(
                target.node_pub,
                Pending { addr: src, init: msg, hs, our_index, sent_tick: tick, retries: 0 },
            );
        }
        Err(e) => println!("dataplane: WG init send to {src} failed: {e}"),
    }
}

/// A peer initiated a handshake to us (the common case for a remote device that
/// wants to reach the dongle). Respond and add the tunnel as responder.
fn handle_wg_init(sock: &MagicSock, id: &Identity, st: &mut State, pkt: &[u8], src: SocketAddr) {
    let our_index = wg::random_index();
    match wg::consume_initiation(&id.node_priv, &id.node_pub, pkt, our_index) {
        Ok((resp, tun, peer_static)) => {
            let _ = sock.send_to(&resp, src);
            insert_tunnel(st, our_index, tun, src, peer_static);
            println!("dataplane: *** WG HANDSHAKE COMPLETE (responder) with {src} ***");
        }
        Err(e) => println!("dataplane: WG init consume failed: {e:#}"),
    }
}

fn handle_wg_response(sock: &MagicSock, st: &mut State, pkt: &[u8], src: SocketAddr) {
    if pkt.len() < 12 {
        return;
    }
    // Find the pending handshake whose index this response targets (ignore late
    // responses from superseded attempts).
    let recv = u32::from_le_bytes([pkt[8], pkt[9], pkt[10], pkt[11]]);
    let key = match st.pending.iter().find(|(_, p)| p.our_index == recv).map(|(k, _)| *k) {
        Some(k) => k,
        None => return,
    };
    let pending = st.pending.remove(&key).unwrap();
    let our_index = pending.our_index;
    match pending.hs.consume_response(pkt) {
        Ok(mut tun) => {
            println!("dataplane: *** WG HANDSHAKE COMPLETE with {src} (our idx {our_index:#x}) ***");
            let ka = tun.keepalive();
            let _ = sock.send_to(&ka, src);
            insert_tunnel(st, our_index, tun, src, key);
        }
        Err(e) => {
            println!("dataplane: WG handshake response failed: {e:#}");
            // pending dropped; next PONG will retry.
        }
    }
}

/// Insert a new tunnel, dropping any existing tunnel to the same peer address so
/// a re-handshake replaces rather than duplicates.
fn insert_tunnel(st: &mut State, our_index: u32, tun: wg::Tunnel, addr: SocketAddr, peer_node: [u8; 32]) {
    let _ = peer_node;
    st.tunnels.retain(|_, e| e.addr != addr);
    st.tunnels.insert(
        our_index,
        TunnelEntry {
            tun,
            addr,
            #[cfg(any(feature = "outbound", feature = "mdns-forward"))]
            peer_node,
            #[cfg(feature = "http-server")]
            tcp: crate::tcp::TcpServer::new(),
        },
    );
}

fn handle_wg_transport(sock: &MagicSock, id: &Identity, st: &mut State, pkt: &[u8], src: SocketAddr) {
    if pkt.len() < 16 {
        return;
    }
    let our_index = u32::from_le_bytes([pkt[4], pkt[5], pkt[6], pkt[7]]);
    let inner = match st.tunnels.get(&our_index) {
        Some(e) => match e.tun.decrypt(pkt) {
            Ok(p) => p,
            Err(e) => {
                println!("dataplane: WG transport decrypt failed: {e:#}");
                return;
            }
        },
        None => return, // unknown tunnel
    };
    handle_decrypted(sock, id, st, our_index, &inner, src);
}

/// Handle an already-decrypted inner IP packet for tunnel `our_index`. Shared by
/// the single-thread path and the dual-core decrypt workers (which decrypt off
/// the main thread, then feed results here where all state lives single-owned).
fn handle_decrypted(
    sock: &MagicSock,
    id: &Identity,
    st: &mut State,
    our_index: u32,
    inner: &[u8],
    src: SocketAddr,
) {
    // Track peer roaming; bail on keepalive / ACL-denied / unknown tunnel.
    match st.tunnels.get_mut(&our_index) {
        Some(e) => e.addr = src,
        None => return,
    }
    if inner.is_empty() {
        return;
    }

    // bench: UDP throughput sink on :5201 (iperf-like). Count + log MB/s each sec.
    // Checked BEFORE the ACL so the host bench peer (not a real netmap node) isn't
    // filtered by src_allowed — it's a load generator, not a tailnet member.
    #[cfg(feature = "bench")]
    if udp_payload_to_port(inner, 5201).is_some() {
        st.bench_bytes += inner.len() as u64;
        st.bench_pkts += 1;
        let el = st.bench_last.elapsed();
        if el.as_millis() >= 1000 {
            let secs = el.as_secs_f64();
            let mbps = (st.bench_bytes as f64) * 8.0 / secs / 1.0e6;
            let pps = st.bench_pkts as f64 / secs;
            let avg = st.bench_bytes / st.bench_pkts.max(1);
            println!("bench: RX {mbps:.2} Mbit/s, {pps:.0} pps, {avg}B avg inner");
            // Reflect the RX rate back to the load generator through the tunnel, so
            // the host bench peer can report the dongle's decrypt throughput WITHOUT
            // needing to read the (hard-to-capture) USB-JTAG serial console.
            if let Some(e) = st.tunnels.get_mut(&our_index) {
                let stats = bench_stats_inner(mbps, pps);
                let _ = sock.send_to(&e.tun.encrypt(&stats), src);
            }
            st.bench_bytes = 0;
            st.bench_pkts = 0;
            st.bench_last = std::time::Instant::now();
        }
        return;
    }

    // ACL: drop inner packets from sources the netmap doesn't authorize. (Bench
    // traffic on :5201 already returned above, before this gate.) Skipped entirely
    // in a `bench` build so the (non-netmap) load generator's inner ICMP echoes can
    // reach the echo responder for direct-path latency measurement.
    #[cfg(not(feature = "bench"))]
    if !src_allowed(&id.allowed_srcs, inner) {
        return;
    }

    // mDNS reflector: partner-forwarded mDNS arrives as inner UDP to FWD_PORT.
    #[cfg(feature = "mdns-forward")]
    if st.tunnels.get(&our_index).map(|e| e.peer_node) == Some(st.mdns_partner) {
        if let Some(payload) = udp_payload_to_port(inner, crate::mdns::FWD_PORT) {
            if let Some(tx) = st.mdns_reinject.as_ref() {
                let _ = tx.send(payload.to_vec());
            }
            return;
        }
    }

    // Outbound: replies to traffic WE initiated (ICMP echo reply, HTTP response).
    #[cfg(feature = "outbound")]
    {
        let peer_node = st.tunnels.get(&our_index).map(|e| e.peer_node);
        let is_target = matches!(
            (peer_node, st.outbound.as_ref()),
            (Some(pn), Some(o)) if o.cfg.target_node == pn
        );
        if is_target {
            if inner.len() >= 28 && inner[9] == 1 {
                let ihl = (inner[0] & 0x0f) as usize * 4;
                if inner.get(ihl) == Some(&0) {
                    println!("outbound: ICMP echo REPLY from {src}");
                }
            }
            // Build replies from the TCP client, then encrypt+send with the tunnel.
            let mut segs: Vec<Vec<u8>> = Vec::new();
            let mut http_line: Option<(String, usize)> = None;
            if let Some(ob) = st.outbound.as_mut() {
                if let Some(tc) = ob.tcp.as_mut() {
                    if tc.owns(inner) {
                        segs = tc.on_inner(inner);
                        if tc.done && !ob.http_done {
                            ob.http_done = true;
                            let resp = String::from_utf8_lossy(&tc.response);
                            http_line = Some((resp.lines().next().unwrap_or("").trim().into(), tc.response.len()));
                        }
                    }
                }
            }
            let handled = !segs.is_empty() || http_line.is_some();
            if !segs.is_empty() {
                if let Some(e) = st.tunnels.get_mut(&our_index) {
                    for o in &segs {
                        let _ = sock.send_to(&e.tun.encrypt(o), src);
                    }
                }
            }
            if let Some((line, n)) = http_line {
                println!("outbound: HTTP response: {line} ({n} bytes)");
            }
            if handled {
                return;
            }
        }
    }

    #[cfg(feature = "icmp")]
    if let Some(reply) = tailscale_core::icmp::echo_reply(inner) {
        if let Some(e) = st.tunnels.get_mut(&our_index) {
            let out = e.tun.encrypt(&reply);
            let _ = sock.send_to(&out, src);
            println!("dataplane: ICMP echo -> replied ({} bytes) to {src}", reply.len());
        }
        return;
    }
    #[cfg(feature = "http-server")]
    if let Some(e) = st.tunnels.get_mut(&our_index) {
        let replies = e.tcp.handle(inner);
        if !replies.is_empty() {
            for r in &replies {
                let out = e.tun.encrypt(r);
                let _ = sock.send_to(&out, src);
            }
            println!("dataplane: TCP/HTTP -> sent {} segment(s) to {src}", replies.len());
        }
    }
}

/// Build an inner IPv4/UDP datagram (to :5202) carrying the bench RX rate as text,
/// reflected back to the load generator so it can report the dongle's decrypt
/// throughput without serial. Payload: "RXMBPS:<mbps> PPS:<pps>".
#[cfg(feature = "bench")]
fn bench_stats_inner(mbps: f64, pps: f64) -> Vec<u8> {
    let payload = format!("RXMBPS:{mbps:.2} PPS:{pps:.0}").into_bytes();
    let total = 20 + 8 + payload.len();
    let mut p = vec![0u8; total];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    p[8] = 64;
    p[9] = 17;
    p[12..16].copy_from_slice(&std::net::Ipv4Addr::new(100, 64, 0, 1).octets());
    p[16..20].copy_from_slice(&std::net::Ipv4Addr::new(100, 64, 0, 99).octets());
    let mut sum: u32 = 0;
    for i in (0..20).step_by(2) {
        sum += u16::from_be_bytes([p[i], p[i + 1]]) as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    p[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    p[20..22].copy_from_slice(&5202u16.to_be_bytes());
    p[22..24].copy_from_slice(&5202u16.to_be_bytes());
    p[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    p[28..].copy_from_slice(&payload);
    p
}

/// If `inner` is an IPv4 UDP packet to `port`, return its UDP payload.
#[cfg(any(feature = "mdns-forward", feature = "bench"))]
fn udp_payload_to_port(inner: &[u8], port: u16) -> Option<&[u8]> {
    if inner.len() < 20 || (inner[0] >> 4) != 4 || inner[9] != 17 {
        return None;
    }
    let ihl = (inner[0] & 0x0f) as usize * 4;
    let total = u16::from_be_bytes([inner[2], inner[3]]) as usize;
    if ihl + 8 > total || total > inner.len() {
        return None;
    }
    let udp = &inner[ihl..total];
    if u16::from_be_bytes([udp[2], udp[3]]) != port {
        return None;
    }
    Some(&udp[8..])
}

fn name_for(targets: &[Target], disco_pub: &[u8; 32]) -> String {
    targets
        .iter()
        .find(|t| &t.disco_pub == disco_pub)
        .map(|t| t.name.clone())
        .unwrap_or_else(|| "unknown".to_string())
}

fn fill_random(out: &mut [u8]) {
    unsafe {
        esp_idf_svc::sys::esp_fill_random(out.as_mut_ptr() as *mut core::ffi::c_void, out.len());
    }
}

#[cfg(feature = "birthday")]
const SWEEP_WIN: i32 = 1024; // contiguous ports covered per round

/// Candidate ports for a birthday spray, using *port prediction* rather than
/// blind randomness. Most symmetric NATs allocate ports sequentially, so we
/// sweep a contiguous window that walks OUTWARD from the (freshest known) base
/// port each round — round 0 centers on `base`, then ±W, ±2W, … — deterministically
/// covering the sequential region in a few rounds. A small random tail still
/// covers the rare truly-random NAT.
#[cfg(feature = "birthday")]
fn birthday_ports(base: u16, tick: u32) -> Vec<u16> {
    let round = (tick / 2) as i32; // disco probes run every 2 ticks
    let step = (round + 1) / 2; // 0,1,1,2,2,3,3,...
    let dir = if round % 2 == 0 { 1 } else { -1 };
    let center = base as i32 + dir * step * SWEEP_WIN;

    let mut ports = Vec::with_capacity(SWEEP_WIN as usize + 64);
    for d in 0..SWEEP_WIN {
        let p = center - SWEEP_WIN / 2 + d;
        if (1024..=65535).contains(&p) {
            ports.push(p as u16);
        }
    }
    // random tail for non-sequential (random-port) symmetric NATs — 256 gives a
    // solid birthday collision rate when the peer also sprays (see birthday_sim).
    const RANDOM_TAIL: usize = 256;
    let mut rnd = [0u8; 2 * RANDOM_TAIL];
    fill_random(&mut rnd);
    for i in 0..RANDOM_TAIL {
        let p = u16::from_le_bytes([rnd[2 * i], rnd[2 * i + 1]]);
        if p >= 1024 {
            ports.push(p);
        }
    }
    ports
}

/// Globally-routable IPv4 (not RFC1918/CGNAT/link-local/loopback).
#[cfg(feature = "birthday")]
fn is_public_v4(ip: &std::net::Ipv4Addr) -> bool {
    let o = ip.octets();
    !(o[0] == 10
        || (o[0] == 172 && (16..=31).contains(&o[1]))
        || (o[0] == 192 && o[1] == 168)
        || (o[0] == 169 && o[1] == 254)
        || o[0] == 127
        || (o[0] == 100 && (64..=127).contains(&o[1]))
        || o[0] == 0)
}
