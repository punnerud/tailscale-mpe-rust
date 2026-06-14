//! ts2021 Noise IK handshake + controlbase transport records.
//!
//! snow drives the handshake (its handshake nonces are all-zero in IK, matching
//! Tailscale). But Tailscale's *transport* phase uses a BIG-ENDIAN nonce counter
//! (offset 4..12), which is non-standard, so snow's transport mode can't interop.
//! We therefore pull the raw split keys out of snow and run records ourselves.

use anyhow::{bail, Context, Result};

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use snow::{Builder, HandshakeState};

const PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
const PROTOCOL_VERSION: u16 = 1;
const PROLOGUE: &[u8] = b"Tailscale Control Protocol v1";

pub const MSG_INITIATION: u8 = 1;
pub const MSG_RESPONSE: u8 = 2;
pub const MSG_ERROR: u8 = 3;
pub const MSG_RECORD: u8 = 4;

/// In-progress IK handshake (initiator).
pub struct Handshake {
    hs: HandshakeState,
}

/// Begin the handshake. Returns the handshake state plus the fully controlbase-
/// framed initiation message (101 bytes) to place, base64-std-encoded, in the
/// `X-Tailscale-Handshake` header.
pub fn start(machine_priv: &[u8; 32], control_pub: &[u8; 32]) -> Result<(Handshake, Vec<u8>)> {
    let params = PATTERN.parse().context("parse noise params")?;
    let mut hs = Builder::new(params)
        .prologue(PROLOGUE)
        .and_then(|b| b.local_private_key(machine_priv))
        .and_then(|b| b.remote_public_key(control_pub))
        .and_then(|b| b.build_initiator())
        .map_err(|e| anyhow::anyhow!("build_initiator: {e}"))?;

    let mut buf = [0u8; 256];
    let n = hs.write_message(&[], &mut buf).context("write initiation")?;
    let noise = &buf[..n];

    let mut framed = Vec::with_capacity(5 + n);
    framed.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    framed.push(MSG_INITIATION);
    framed.extend_from_slice(&(n as u16).to_be_bytes());
    framed.extend_from_slice(noise);
    Ok((Handshake { hs }, framed))
}

impl Handshake {
    /// Consume the server's Noise response payload (the bytes inside the type-2
    /// frame, ~48 bytes), finish the handshake, and derive the transport keys.
    pub fn complete(mut self, resp_noise: &[u8]) -> Result<Transport> {
        let mut buf = [0u8; 256];
        self.hs
            .read_message(resp_noise, &mut buf)
            .context("read handshake response")?;
        if !self.hs.is_handshake_finished() {
            bail!("handshake not finished after response");
        }
        // snow split order is (c1, c2); the initiator sends with c1, receives c2.
        let (k_send, k_recv) = self.hs.dangerously_get_raw_split();
        Transport::new(&k_send, &k_recv)
    }
}

/// Post-handshake transport: ChaCha20-Poly1305 records with a Tailscale-style
/// big-endian nonce counter and empty AAD.
pub struct Transport {
    send: ChaCha20Poly1305,
    recv: ChaCha20Poly1305,
    tx_nonce: u64,
    rx_nonce: u64,
}

impl Transport {
    fn new(send_key: &[u8; 32], recv_key: &[u8; 32]) -> Result<Self> {
        Ok(Self {
            send: ChaCha20Poly1305::new_from_slice(send_key).map_err(|_| anyhow::anyhow!("send key"))?,
            recv: ChaCha20Poly1305::new_from_slice(recv_key).map_err(|_| anyhow::anyhow!("recv key"))?,
            tx_nonce: 0,
            rx_nonce: 0,
        })
    }

    /// Encrypt one plaintext into a framed record: [0x04][len BE u16][ct||tag].
    pub fn seal_record(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce = be_nonce(self.tx_nonce);
        self.tx_nonce += 1;
        let ct = self
            .send
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad: b"" })
            .map_err(|_| anyhow::anyhow!("seal failed"))?;
        let mut out = Vec::with_capacity(3 + ct.len());
        out.push(MSG_RECORD);
        out.extend_from_slice(&(ct.len() as u16).to_be_bytes());
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Decrypt the ciphertext payload of a received type-0x04 record.
    pub fn open_record(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let nonce = be_nonce(self.rx_nonce);
        self.rx_nonce += 1;
        self.recv
            .decrypt(Nonce::from_slice(&nonce), Payload { msg: ciphertext, aad: b"" })
            .map_err(|_| anyhow::anyhow!("open failed (MAC) at rx_nonce={}", self.rx_nonce - 1))
    }
}

/// 12-byte nonce: 4 zero bytes then the big-endian 64-bit counter.
fn be_nonce(counter: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&counter.to_be_bytes());
    n
}
