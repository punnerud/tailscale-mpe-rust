//! Minimal WireGuard (the Tailscale data plane), initiator + responder.
//!
//! Construction: `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s` with an all-zero PSK
//! (Tailscale uses a zero PSK). We build the initiation, consume the response (and
//! vice-versa as responder), and run transport records — no cookie handling, no
//! mac2 validation. Just enough to bring up one tunnel and pass packets.
//!
//! Gotcha vs the ts2021 control plane: WireGuard's transport nonce is the
//! LITTLE-endian 64-bit counter (handshake AEAD uses nonce 0), the opposite of
//! the control channel's big-endian nonce.

use alloc::vec::Vec;

use anyhow::{bail, ensure, Result};

use blake2::digest::consts::U16;
use blake2::digest::Mac;
use blake2::{Blake2s256, Blake2sMac, Digest};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use x25519_dalek::{PublicKey, StaticSecret};

const CONSTRUCTION: &[u8] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
const IDENTIFIER: &[u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";
const LABEL_MAC1: &[u8] = b"mac1----";
const ZERO_PSK: [u8; 32] = [0u8; 32];

pub const MSG_INITIATION: u8 = 1;
pub const MSG_RESPONSE: u8 = 2;
pub const MSG_TRANSPORT: u8 = 4;

pub const INIT_LEN: usize = 148;
pub const RESP_LEN: usize = 92;

/// Handshake state kept between sending the initiation and receiving the response.
pub struct Handshake {
    chaining: [u8; 32],
    hash: [u8; 32],
    eph_priv: [u8; 32],
    our_static_priv: [u8; 32],
    our_index: u32,
}

/// An established tunnel: transport keys + indices + send counter.
pub struct Tunnel {
    send_key: [u8; 32],
    recv_key: [u8; 32],
    their_index: u32,
    our_index: u32,
    tx_counter: u64,
}

/// Build a 148-byte handshake initiation to `peer_static_pub`, using our node
/// static key. Returns the wire bytes and the in-progress handshake.
pub fn build_initiation(
    our_static_priv: &[u8; 32],
    our_static_pub: &[u8; 32],
    peer_static_pub: &[u8; 32],
    timestamp: [u8; 12],
    our_index: u32,
) -> ([u8; INIT_LEN], Handshake) {
    let mut msg = [0u8; INIT_LEN];
    msg[0] = MSG_INITIATION;
    msg[4..8].copy_from_slice(&our_index.to_le_bytes());

    let mut c = hash(&[CONSTRUCTION]);
    let mut h = hash(&[&c, IDENTIFIER]);
    h = hash(&[&h, peer_static_pub]);

    // ephemeral
    let eph_priv = random32();
    let eph_pub = pubkey(&eph_priv);
    c = kdf1(&c, &eph_pub);
    msg[8..40].copy_from_slice(&eph_pub);
    h = hash(&[&h, &eph_pub]);

    // encrypted static (our static public)
    let (c1, k) = kdf2(&c, &dh(&eph_priv, peer_static_pub));
    c = c1;
    let enc_static = seal(&k, 0, our_static_pub, &h);
    msg[40..88].copy_from_slice(&enc_static);
    h = hash(&[&h, &enc_static]);

    // encrypted timestamp
    let (c2, k2) = kdf2(&c, &dh(our_static_priv, peer_static_pub));
    c = c2;
    let enc_ts = seal(&k2, 0, &timestamp, &h);
    msg[88..116].copy_from_slice(&enc_ts);
    h = hash(&[&h, &enc_ts]);

    // mac1 = keyed-Blake2s-128( HASH(LABEL_MAC1 || peer_pub), msg[0..116] )
    let mac1_key = hash(&[LABEL_MAC1, peer_static_pub]);
    let mac1 = mac16(&mac1_key, &msg[0..116]);
    msg[116..132].copy_from_slice(&mac1);
    // mac2 stays zero (no cookie).

    (
        msg,
        Handshake {
            chaining: c,
            hash: h,
            eph_priv,
            our_static_priv: *our_static_priv,
            our_index,
        },
    )
}

/// Responder side: consume a 148-byte initiation from a peer and produce the
/// 92-byte response plus the established tunnel. Returns the response bytes, the
/// tunnel, and the initiator's static (node) public key (learned from the IK
/// handshake). No mac1/mac2 validation (we trust the encrypted-static decrypt).
pub fn consume_initiation(
    our_static_priv: &[u8; 32],
    our_static_pub: &[u8; 32],
    init: &[u8],
    our_index: u32,
) -> Result<([u8; RESP_LEN], Tunnel, [u8; 32])> {
    ensure!(init.len() >= INIT_LEN, "WG init too short ({})", init.len());
    ensure!(init[0] == MSG_INITIATION, "not a WG initiation (type {})", init[0]);
    let their_index = u32::from_le_bytes([init[4], init[5], init[6], init[7]]);
    let e_i: [u8; 32] = init[8..40].try_into().unwrap();
    let enc_static = &init[40..88];
    let enc_ts = &init[88..116];

    let mut c = hash(&[CONSTRUCTION]);
    let mut h = hash(&[&c, IDENTIFIER]);
    h = hash(&[&h, our_static_pub]);

    c = kdf1(&c, &e_i);
    h = hash(&[&h, &e_i]);

    let (c1, k) = kdf2(&c, &dh(our_static_priv, &e_i));
    c = c1;
    let s_i_vec = open(&k, 0, enc_static, &h).map_err(|_| anyhow::anyhow!("WG init static decrypt"))?;
    let s_i: [u8; 32] = s_i_vec
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("WG init static size"))?;
    h = hash(&[&h, enc_static]);

    let (c2, k2) = kdf2(&c, &dh(our_static_priv, &s_i));
    c = c2;
    let _ts = open(&k2, 0, enc_ts, &h).map_err(|_| anyhow::anyhow!("WG init timestamp decrypt"))?;
    h = hash(&[&h, enc_ts]);

    // Build response.
    let mut resp = [0u8; RESP_LEN];
    resp[0] = MSG_RESPONSE;
    resp[4..8].copy_from_slice(&our_index.to_le_bytes());
    resp[8..12].copy_from_slice(&their_index.to_le_bytes());

    let er_priv = random32();
    let er_pub = pubkey(&er_priv);
    c = kdf1(&c, &er_pub);
    resp[12..44].copy_from_slice(&er_pub);
    h = hash(&[&h, &er_pub]);

    c = kdf1(&c, &dh(&er_priv, &e_i));
    c = kdf1(&c, &dh(&er_priv, &s_i));

    let (c3, tau, k3) = kdf3(&c, &ZERO_PSK);
    c = c3;
    h = hash(&[&h, &tau]);
    let enc_empty = seal(&k3, 0, &[], &h);
    resp[44..60].copy_from_slice(&enc_empty);
    h = hash(&[&h, &enc_empty]);

    // mac1 over resp[0..60], keyed with HASH(LABEL_MAC1 || initiator static).
    let mac1_key = hash(&[LABEL_MAC1, &s_i]);
    let mac1 = mac16(&mac1_key, &resp[0..60]);
    resp[60..76].copy_from_slice(&mac1);

    // Responder: first transport key receives, second sends.
    let (recv_key, send_key) = kdf2(&c, &[]);
    let _ = h;
    Ok((
        resp,
        Tunnel {
            send_key,
            recv_key,
            their_index,
            our_index,
            tx_counter: 0,
        },
        s_i,
    ))
}

impl Handshake {
    /// Consume the 92-byte handshake response and derive the transport tunnel.
    pub fn consume_response(self, resp: &[u8]) -> Result<Tunnel> {
        ensure!(resp.len() >= RESP_LEN, "WG response too short ({})", resp.len());
        ensure!(resp[0] == MSG_RESPONSE, "not a WG response (type {})", resp[0]);
        let their_index = u32::from_le_bytes([resp[4], resp[5], resp[6], resp[7]]);
        let recv_index = u32::from_le_bytes([resp[8], resp[9], resp[10], resp[11]]);
        ensure!(
            recv_index == self.our_index,
            "WG response receiver index {recv_index:#x} != ours {:#x}",
            self.our_index
        );
        let eph_pub_r: [u8; 32] = resp[12..44].try_into().unwrap();
        let enc_empty = &resp[44..60];

        let mut c = self.chaining;
        let mut h = self.hash;

        c = kdf1(&c, &eph_pub_r);
        h = hash(&[&h, &eph_pub_r]);
        c = kdf1(&c, &dh(&self.eph_priv, &eph_pub_r));
        c = kdf1(&c, &dh(&self.our_static_priv, &eph_pub_r));

        let (c1, tau, k) = kdf3(&c, &ZERO_PSK);
        c = c1;
        h = hash(&[&h, &tau]);

        let pt = open(&k, 0, enc_empty, &h).map_err(|_| anyhow::anyhow!("WG response auth failed"))?;
        ensure!(pt.is_empty(), "WG response payload not empty");

        // Initiator: first transport key sends, second receives.
        let (send_key, recv_key) = kdf2(&c, &[]);
        Ok(Tunnel {
            send_key,
            recv_key,
            their_index,
            our_index: self.our_index,
            tx_counter: 0,
        })
    }
}

/// Decrypt a type-4 transport packet given just the receive key (stateless: the
/// counter is read from the packet, no replay tracking). Lets the dual-core
/// decrypt path run lock-free without touching the shared tunnel state.
pub fn decrypt_transport(recv_key: &[u8; 32], pkt: &[u8]) -> Option<Vec<u8>> {
    if pkt.len() < 32 || pkt[0] != MSG_TRANSPORT {
        return None;
    }
    let counter = u64::from_le_bytes(pkt[8..16].try_into().ok()?);
    open(recv_key, counter, &pkt[16..], &[]).ok()
}

impl Tunnel {
    pub fn our_index(&self) -> u32 {
        self.our_index
    }

    /// The receive key, for the stateless [`decrypt_transport`] (dual-core path).
    pub fn recv_key(&self) -> [u8; 32] {
        self.recv_key
    }

    /// Wrap an inner IP packet in a type-4 transport message.
    pub fn encrypt(&mut self, inner: &[u8]) -> Vec<u8> {
        let mut pt = inner.to_vec();
        while pt.len() % 16 != 0 {
            pt.push(0); // WireGuard pads plaintext to a 16-byte boundary
        }
        let ct = seal(&self.send_key, self.tx_counter, &pt, &[]);
        let mut out = Vec::with_capacity(16 + ct.len());
        out.push(MSG_TRANSPORT);
        out.extend_from_slice(&[0, 0, 0]);
        out.extend_from_slice(&self.their_index.to_le_bytes());
        out.extend_from_slice(&self.tx_counter.to_le_bytes());
        out.extend_from_slice(&ct);
        self.tx_counter += 1;
        out
    }

    /// A keepalive is an empty transport packet.
    pub fn keepalive(&mut self) -> Vec<u8> {
        self.encrypt(&[])
    }

    /// Decrypt a type-4 transport message, returning the (still padded) inner
    /// plaintext. Caller parses the inner IPv4 header for the true length.
    pub fn decrypt(&self, pkt: &[u8]) -> Result<Vec<u8>> {
        ensure!(pkt.len() >= 32, "WG transport too short ({})", pkt.len());
        ensure!(pkt[0] == MSG_TRANSPORT, "not a WG transport packet");
        let counter = u64::from_le_bytes(pkt[8..16].try_into().unwrap());
        let ct = &pkt[16..];
        open(&self.recv_key, counter, ct, &[]).map_err(|_| anyhow::anyhow!("WG transport auth failed"))
    }
}

// --- primitives ---

fn hash(parts: &[&[u8]]) -> [u8; 32] {
    let mut d = <Blake2s256 as Digest>::new();
    for p in parts {
        Digest::update(&mut d, p);
    }
    Digest::finalize(d).into()
}

/// Keyed BLAKE2s with a 16-byte output (WireGuard mac1).
fn mac16(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut m = <Blake2sMac<U16> as Mac>::new_from_slice(key).expect("blake2s mac key");
    Mac::update(&mut m, data);
    Mac::finalize(m).into_bytes().into()
}

/// HMAC-BLAKE2s, hand-rolled: the `hmac` crate's `Hmac` only accepts eager-buffer
/// hashes, but BLAKE2s uses a lazy buffer. Block size B = 64; all our keys are
/// ≤ 32 bytes so they never need pre-hashing.
fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    const B: usize = 64;
    let mut k = [0u8; B];
    if key.len() > B {
        k[..32].copy_from_slice(&hash(&[key]));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; B];
    let mut opad = [0x5cu8; B];
    for i in 0..B {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let inner = hash(&[&ipad, data]);
    hash(&[&opad, &inner])
}

fn kdf1(key: &[u8; 32], input: &[u8]) -> [u8; 32] {
    let t0 = hmac(key, input);
    hmac(&t0, &[0x01])
}

fn kdf2(key: &[u8; 32], input: &[u8]) -> ([u8; 32], [u8; 32]) {
    let t0 = hmac(key, input);
    let t1 = hmac(&t0, &[0x01]);
    let mut buf = t1.to_vec();
    buf.push(0x02);
    let t2 = hmac(&t0, &buf);
    (t1, t2)
}

fn kdf3(key: &[u8; 32], input: &[u8]) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let t0 = hmac(key, input);
    let t1 = hmac(&t0, &[0x01]);
    let mut b2 = t1.to_vec();
    b2.push(0x02);
    let t2 = hmac(&t0, &b2);
    let mut b3 = t2.to_vec();
    b3.push(0x03);
    let t3 = hmac(&t0, &b3);
    (t1, t2, t3)
}

fn dh(priv_: &[u8; 32], pub_: &[u8; 32]) -> [u8; 32] {
    let s = StaticSecret::from(*priv_);
    let p = PublicKey::from(*pub_);
    s.diffie_hellman(&p).to_bytes()
}

fn pubkey(priv_: &[u8; 32]) -> [u8; 32] {
    let s = StaticSecret::from(*priv_);
    PublicKey::from(&s).to_bytes()
}

/// ChaCha20-Poly1305 seal with a little-endian counter nonce and the given AAD.
fn seal(key: &[u8; 32], counter: u64, pt: &[u8], aad: &[u8]) -> Vec<u8> {
    let c = ChaCha20Poly1305::new_from_slice(key).expect("chacha key");
    let nonce = le_nonce(counter);
    c.encrypt(Nonce::from_slice(&nonce), Payload { msg: pt, aad })
        .expect("chacha seal")
}

fn open(key: &[u8; 32], counter: u64, ct: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let c = ChaCha20Poly1305::new_from_slice(key).map_err(|_| anyhow::anyhow!("chacha key"))?;
    let nonce = le_nonce(counter);
    match c.decrypt(Nonce::from_slice(&nonce), Payload { msg: ct, aad }) {
        Ok(v) => Ok(v),
        Err(_) => bail!("AEAD open failed"),
    }
}

/// 12-byte nonce: 4 zero bytes then the little-endian 64-bit counter.
fn le_nonce(counter: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&counter.to_le_bytes());
    n
}

fn random32() -> [u8; 32] {
    let mut b = [0u8; 32];
    fill_rng(&mut b);
    b
}

/// Random bytes via `getrandom` (esp-idf backend = esp_fill_random on-device).
fn fill_rng(b: &mut [u8]) {
    getrandom::getrandom(b).expect("getrandom");
}

/// Build a 12-byte TAI64N timestamp from a Unix time the caller reads from its
/// platform clock (`platform::Clock`). Kept pure (no clock dependency) so this
/// module stays `no_std`. SNTP-synced time is required so the stamp is monotonic
/// across reboots — the responder rejects non-increasing stamps.
pub fn tai64n(unix_secs: u64, nanos: u32) -> [u8; 12] {
    let secs = 0x4000_0000_0000_000a_u64 + unix_secs;
    let mut out = [0u8; 12];
    out[0..8].copy_from_slice(&secs.to_be_bytes());
    out[8..12].copy_from_slice(&nanos.to_be_bytes());
    out
}

/// A random 32-bit local index for a new handshake.
pub fn random_index() -> u32 {
    let mut b = [0u8; 4];
    fill_rng(&mut b);
    u32::from_le_bytes(b)
}
