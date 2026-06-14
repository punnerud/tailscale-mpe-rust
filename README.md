# tailscale-mpe-rust

*(**MPE** = **M**orten **P**unnerud-**E**ngelstad)*

A **pure-Rust [Tailscale](https://tailscale.com) client for the ESP32-S3** (LilyGO
T-Dongle S3) — no C Tailscale, no `tailscaled`, no DERP-only shortcuts. It speaks
the real protocols against Tailscale's own coordination server: the **ts2021**
control plane (Noise IK over HTTP/2), **WireGuard** data plane, **disco** path
discovery, **STUN** NAT traversal, and an **encrypted DERP relay** fallback.

> **Not to be confused with the unrelated `tailscale-rust` crate.** This is a
> from-scratch firmware + a portable `no_std` protocol core, by Morten
> Punnerud-Engelstad (**mpe**). Different project, different scope.

A ~$10 USB dongle becomes a Tailscale node you can `ping`, browse to, and route
through — running hand-rolled WireGuard crypto on a dual-core Xtensa LX7.

---

## How big is Tailscale itself? **Under 500 kB.**

Subtract the WiFi + esp-idf runtime any networked ESP32 project already has (a
998 kB baseline here), and the Tailscale functionality *alone* adds:

| Adds on top of a WiFi baseline | Extra flash |
| --- | ---: |
| Control plane (ts2021) + WireGuard crypto | **+391 kB** |
| &nbsp;&nbsp;+ working data plane (disco + STUN + direct UDP) | **+470 kB** |
| &nbsp;&nbsp;+ DERP relay fallback (full remote reachability) | **+488 kB** |

A **complete Tailscale node — control plane, WireGuard, NAT traversal and relay
fallback — in under half a megabyte.** The full demo below (with the in-tunnel
webserver, mDNS reflector, outbound client, dual-core, etc.) adds +511 kB
(~1.5 MB total). No `tailscaled`, no Go runtime.

## What works

- **Control plane (ts2021):** registers with `controlplane.tailscale.com`,
  interactive browser auth *or* headless pre-auth-key, persists across reboots,
  shows green/online in the admin console. Frugal netmap parse that fits in
  ~287 KB of heap (no `serde_json::Value` tree).
- **Data plane (WireGuard):** `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`, initiator
  **and** responder, multiple concurrent tunnels.
  - **LAN direct** (disco ping/pong confirmed path)
  - **Remote direct** via STUN + `CALL_ME_MAYBE` NAT hole-punching, incl. a
    birthday-paradox port spray for symmetric NAT
  - **DERP relay** fallback (over real TLS) when hole-punching fails
- **In-tunnel services:** answers ICMP echo (`ping`), serves a small HTTP page,
  and can initiate traffic out (ICMP/UDP/TCP client).
- **mDNS/Bonjour reflector** across two LANs (loop-guarded).
- **Packet-filter** (enforces the netmap ACL) and **subnet-router / exit-node**
  route advertisement (+ NAPT foundation).
- **Dual-core** WireGuard decrypt for ~1.6× throughput (see Benchmarks).

## Architecture: portable `no_std` core + ESP32 adapter

The protocol logic lives in a platform-independent **`tailscale-core`** crate
(`#![no_std] + alloc`); the ESP32 firmware is a thin adapter that provides the OS
bits (WiFi/UDP/TLS, NVS storage, the ST7735 display). The same core is meant to be
reusable from an iOS app, desktop, or WASI.

Already migrated into the no_std core: `icmp`, `stun`, `disco`, `wg` (WireGuard),
`outbound`, `tcp` (in-tunnel HTTP), `peers` (netmap/ACL parser), and the pure
parts of `node`. RNG comes from `getrandom` (which has an esp-idf backend on the
device and OS backends elsewhere), so no RNG trait-threading is needed.

**Proven genuinely std-less:** the core + all its crypto dependencies compile for
a bare-metal, no-OS target (`riscv32imc-unknown-none-elf`).

The same WireGuard module (`core/src/wg.rs`) is reused unchanged by a host-side
load generator to benchmark the device over a guaranteed-direct path.

## Benchmarks (T-Dongle S3, 240 MHz, both LX7 cores)

Measured with a host WireGuard load generator that handshakes **directly** with
the dongle over the LAN (no Tailscale path negotiation, so the path can't drift
onto DERP), flooding inner UDP and reading the device's reflected RX rate.

| Metric | Single-core | Dual-core (default) |
| --- | --- | --- |
| WireGuard decrypt throughput | ~3.9–4.0 Mbit/s | **~6.0–6.6 Mbit/s** (~1.6×) |
| In-tunnel latency (ICMP RTT, median) | ~21 ms | ~20 ms |
| Latency min / loss | ~13 ms / 0% | ~13 ms / 0% |

The bottleneck is **pure-Rust ChaCha20-Poly1305** on the LX7 (the S3 has no
hardware ChaCha — its AES accelerator only helps TLS). Dual-core runs the decrypt
on both cores in parallel (recv is serialized by a small mutex because lwIP UDP
sockets aren't safe for concurrent `recvfrom`); latency is unchanged, so it's a
strict win. Fine for control / IoT / SSH / device discovery; not a bulk-transfer
gateway.

## Flash size

App image size (the bytes written to flash), via `espflash save-image`:

| Build | App image | Δ |
| --- | --- | --- |
| Baseline (`--no-default-features`: WiFi + ST7735 display only) | **998 kB** | — |
| `+ ts` — control plane (ts2021) + WireGuard + keys + all crypto/TLS | 1389 kB | +391 |
| `+ direct` — disco + STUN + magicsock + UDP data plane | 1468 kB | +79 |
| `+ derp` — encrypted relay client | 1486 kB | +18 |
| **Default — full Tailscale demo (all features)** | **1509 kB** | — |

The full demo is ~1.5 MB — a small fraction of the dongle's flash. WiFi SSID /
password (and an optional auth key) are **build-time options you must fill in**
(`src/config.rs`, git-ignored — see Build).

### Extra flash per feature

Each feature's marginal cost (leaf features measured leave-one-out from the
default build; `bench` / `subnet-router` measured added to the default):

| Feature | Extra | What it adds |
| --- | ---: | --- |
| `ts` | **+391 kB** | control plane + WireGuard + crypto + TLS (foundational — everything needs it) |
| `direct` | **+79 kB** | disco + STUN + UDP data plane (LAN + NAT-punch) |
| `derp` | +18 kB | encrypted relay fallback (remote reachability) |
| `mdns-forward` | +6 kB | mDNS/Bonjour reflector across LANs |
| `outbound` | +5 kB | device-initiated ICMP/UDP/TCP out the tunnel |
| `http-server` | +4 kB | in-tunnel TCP + the HTML web demo |
| `icmp` | +2 kB | answer ping |
| `birthday` | +2 kB | birthday-paradox port spray (symmetric NAT) |
| `dualcore` | +2 kB | 2-core parallel decrypt (+60% throughput) |
| `packet-filter` | +1 kB | enforce netmap ACLs |
| `derp-upgrade` | +1 kB | upgrade relayed peers to a direct path |
| `authkey` | ~0 kB | headless pre-auth-key provisioning |
| `bench` *(opt-in)* | +2 kB | UDP throughput sink + RX reflection |
| `subnet-router` *(opt-in)* | +1 kB | NAPT data-path foundation |

Mix features to fit a deployment, e.g. a tiny LAN-only feeder:
`--no-default-features --features "ts,direct,icmp"` (~1.47 MB).

## Build & flash

Toolchain: the [esp-rs](https://github.com/esp-rs) Xtensa toolchain
(`espup` + `. ~/export-esp.sh`) and `espflash`.

```sh
# 1. Provide your WiFi creds (and optional Tailscale auth key). This file is
#    git-ignored so secrets never get committed.
cp src/config.rs.example src/config.rs
$EDITOR src/config.rs        # set WIFI_SSID + WIFI_PASS

# 2. Build + flash + watch the serial console
. ~/export-esp.sh
cargo build --release
espflash flash --monitor --port /dev/cu.usbmodemXXXX \
  --bootloader target/xtensa-esp32s3-espidf/release/bootloader.bin \
  --partition-table target/xtensa-esp32s3-espidf/release/partition-table.bin \
  target/xtensa-esp32s3-espidf/release/tailscale-rust
```

On first boot (no auth key) the serial console prints a login URL — open it to add
the node to your tailnet. Then `ping 100.x.y.z`, or browse to `http://100.x.y.z/`.

## Security

`src/config.rs` (WiFi SSID/password, any auth key) is **git-ignored**; only
`src/config.rs.example` with placeholders is committed. Never commit real
credentials. If you advertise subnet routes / exit-node, combine with
`packet-filter` so only authorized peers can route through the device.

## Motivation — a low-latency nervous system for machines

Humanoid robots, vacuum cleaners, drones, self-driving cars and boats — the coming
wave of autonomous machines has to *coordinate*, and coordination is bounded by
latency. A cloud round-trip costs tens to hundreds of milliseconds; two machines
in the same room, or across town over 5G, can reach each other **directly** in a
few.

Tailscale already gives every device a flat, encrypted, NAT-traversing address
space where peers connect **directly, peer-to-peer** (hole-punched WireGuard),
falling back to a relay only when they truly must. That is exactly the substrate
machines need to talk to each other: **local-first, lowest-latency, no central
server in the hot path.**

The catch is that the stock Tailscale stack (Go + `tailscaled`) is too heavy for
the cheapest, most numerous devices — the microcontrollers that will actually live
*inside* those robots and appliances. This project shows the whole client fits in
**under half a megabyte of portable, no-`std` Rust**, running hand-rolled WireGuard
on a ~$10 chip. So the smallest, cheapest device can be a first-class mesh node —
not a second-class thing tethered to a gateway or a cloud account.

If every machine can securely find and reach every other machine — directly,
privately, at the lowest possible latency, on hardware anyone can afford — that is
an enabler for an **abundant, decentralized future for the benefit of all. Lifting
all boats.**

> Sibling project: [**mpee**](https://github.com/punnerud/mpee) is the fleet-routing
> *brain* (optimize who goes where); **tailscale-mpe-rust** is the low-latency
> *nervous system* (let them all talk, directly).

## Repository layout

```
src/        ESP32-S3 firmware (the platform adapter)
core/       tailscale-core — portable no_std + alloc protocol core
docs/       GitHub Pages site + design notes
```

---

*Pure-Rust Tailscale on a USB dongle. By Morten Punnerud-Engelstad.*
