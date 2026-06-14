//! The three Curve25519 identities a Tailscale node needs, persisted in NVS so
//! the node keeps the same identity (and tailnet IP) across reboots:
//!   * machine key — the ts2021 Noise static key (authenticates the device)
//!   * node key    — the WireGuard/tailnet node key (advertised in register/map)
//!   * disco key   — used for the disco NAT-traversal handshake (stretch)
//!
//! Private keys are 32 raw random bytes from `esp_fill_random` (strong only once
//! RF is up — generate AFTER WiFi starts). Public keys are derived with the same
//! curve25519 implementation snow uses, so the advertised key matches what snow
//! sends in the Noise handshake.

use anyhow::{Context, Result};
use esp_idf_svc::nvs::{EspDefaultNvsPartition, EspNvs, NvsDefault};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::config::NVS_NS;

#[derive(Clone)]
pub struct Keypair {
    pub private: [u8; 32],
    pub public: [u8; 32],
}

impl Keypair {
    fn from_private(private: [u8; 32]) -> Self {
        let secret = StaticSecret::from(private);
        let public = PublicKey::from(&secret).to_bytes();
        Self { private, public }
    }

    /// Lowercase hex of the public key (no type prefix).
    pub fn public_hex(&self) -> String {
        hex_lower(&self.public)
    }
}

#[derive(Clone)]
pub struct NodeKeys {
    pub machine: Keypair,
    pub node: Keypair,
    pub disco: Keypair,
}

/// Load the three keypairs from NVS, generating + persisting any that are absent.
pub fn load_or_generate(part: &EspDefaultNvsPartition) -> Result<NodeKeys> {
    let mut nvs = EspNvs::new(part.clone(), NVS_NS, true).context("open NVS namespace")?;
    Ok(NodeKeys {
        machine: load_or_make(&mut nvs, "k_machine")?,
        node: load_or_make(&mut nvs, "k_node")?,
        disco: load_or_make(&mut nvs, "k_disco")?,
    })
}

fn load_or_make(nvs: &mut EspNvs<NvsDefault>, key: &str) -> Result<Keypair> {
    let mut buf = [0u8; 32];
    if let Some(blob) = nvs.get_blob(key, &mut buf).context("nvs get_blob")? {
        if blob.len() == 32 {
            let mut priv_bytes = [0u8; 32];
            priv_bytes.copy_from_slice(blob);
            return Ok(Keypair::from_private(priv_bytes));
        }
    }
    let priv_bytes = random_32();
    nvs.set_blob(key, &priv_bytes).context("nvs set_blob")?;
    Ok(Keypair::from_private(priv_bytes))
}

/// 32 random bytes from the hardware RNG. Only cryptographically strong once the
/// radio is enabled (WiFi started), so call this after WiFi bring-up.
fn random_32() -> [u8; 32] {
    let mut buf = [0u8; 32];
    unsafe {
        esp_idf_svc::sys::esp_fill_random(buf.as_mut_ptr() as *mut core::ffi::c_void, buf.len());
    }
    buf
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0xf) as u32, 16).unwrap());
    }
    s
}
