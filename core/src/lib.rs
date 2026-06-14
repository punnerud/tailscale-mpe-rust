//! Portable Tailscale client core — `no_std + alloc`.
//!
//! This crate holds the platform-independent half of Tailscale-Rust: protocol
//! logic, packet construction/parsing, and (as migration proceeds) the data-plane
//! orchestration. All OS-specific capabilities — UDP/TCP/TLS transport, RNG,
//! persistent storage and the wall clock — are abstracted behind the traits in
//! [`platform`], so the same core runs on ESP32 (esp-idf), an iOS app, desktop,
//! or a WASI sandbox via thin adapter crates.
//!
//! Migration status: modules are moved here incrementally, keeping every crate
//! compiling. `icmp` is the first (fully pure). Next: the crypto primitives
//! (wg/disco/stun/…) with RNG via [`platform::Rng`], then the transport-coupled
//! orchestration behind [`platform`] transport traits. See docs in the repo.

#![no_std]

extern crate alloc;

pub mod platform;

pub mod icmp;

pub mod stun;

pub mod disco;

pub mod wg;

pub mod outbound;

pub mod tcp;

pub mod peers;

pub mod node;

pub mod noise;
