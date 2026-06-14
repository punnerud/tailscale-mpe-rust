# Plan: subnet-router / exit-node for Tailscale-Rust (ESP32-S3)

## Context
We have a working pure-Rust Tailscale node with control + data plane (LAN direct,
remote-direct NAT-punched, DERP fallback), in-tunnel ICMP/HTTP server + client,
packet-filter, authkey. The next big capability is **routing**: let the dongle
forward packets between the tailnet and a local network (subnet-router) or the
internet (exit-node) — turning a tiny USB device into a bridge between two
networks. Honest up front: this is the largest single feature, and ESP32-S3
throughput will be modest (pure-Rust crypto + single core for the data path).

## Subnet-router vs exit-node
Same machinery, different advertised routes:
- **Subnet-router**: advertise `192.168.x.0/24` (a local LAN) → tailnet peers
  reach hosts on that LAN through the dongle. This is the "connect two networks"
  use case.
- **Exit-node**: advertise `0.0.0.0/0` (+ `::/0`) → a peer routes *all* its
  internet traffic through the dongle.

Both require forwarding **arbitrary** IP packets (any protocol, any destination)
with connection tracking + SNAT — not just our own 100.x flows.

## The core architectural change
Today the data plane only handles our own unicast flows (ICMP/TCP to our 100.x).
Routing needs every decrypted inner packet to be forwarded out the WiFi interface
and replies routed back. Two options:

1. **Userspace NAT/router (no lwIP netif change).** For each decrypted inner
   packet: parse 5-tuple, SNAT to the dongle's LAN IP + a mapped port, send via a
   raw/UDP/TCP socket on the WiFi side, track the flow, reverse on replies, re-encrypt
   back into the tunnel. Full conntrack table in ~256 KB heap. Most control, most code.
2. **Virtual lwIP netif (tun-like).** Present WireGuard as a netif: decrypted
   inner packets are injected into lwIP's IP stack; lwIP routes/NATs between the
   WG netif and the WiFi netif using its built-in `ip_napt`. Less hand-rolled
   forwarding, but requires wiring a custom netif + enabling `IP_FORWARD`/`IP_NAPT`
   in lwIP, and feeding the WG transport in/out of that netif. This is the lwIP
   integration the project deliberately skipped so far.

Recommendation: **option 2 (virtual netif + lwIP NAPT)** for correctness/throughput
— hand-rolling TCP/UDP/ICMP conntrack in userspace is a huge surface. lwIP already
has NAPT; we "only" need to bridge WG ↔ netif.

## Steps (option 2)
1. **Advertise routes.** Add `RoutableIPs` (subnet) or exit-node bit to the
   register/map JSON (`Hostinfo.RoutableIPs`, and the exit-node capability).
   Verify the route shows in the admin console (must be approved there).
2. **Custom WG netif.** Register an `esp_netif`/lwIP netif whose output callback
   encrypts+sends via the WG tunnel, and whose input is fed by decrypted transport
   packets from the data plane. (Use `esp_netif`/`netif_add` + `tcpip_input`.)
3. **Enable forwarding + NAPT** in `sdkconfig`: `CONFIG_LWIP_IP_FORWARD=y`,
   `CONFIG_LWIP_IPV4_NAPT=y`; set the NAPT on the WiFi netif for traffic from the
   WG netif.
4. **Route table.** Inner packets to the advertised subnet / default route go out
   WiFi (NAPT); replies return via NAPT → WG netif → tunnel.
5. **Per-peer source selection.** Map a tunnel's decrypted packets to the WG netif
   so lwIP sees them with the peer's tailscale source; SNAT on egress.
6. **Throughput + memory tuning.** Cap conntrack, MTU 1280-ish, watch heap.

## Risks
- **Throughput**: pure-Rust ChaCha/curve on one Xtensa core → low Mbps. Fine for
  control/IoT/SSH/Xcode-discovery, not bulk transfer.
- **lwIP netif integration is invasive** and the main unknown; prototype it in
  isolation first (loopback a packet through the WG netif).
- **Route approval**: the tailnet admin must approve advertised routes.
- **Security**: an exit-node/subnet-router forwards traffic — combine with the
  `packet-filter` ACL so only authorized peers can route through us.

## Smaller alternative if full routing is too much
A **per-service proxy** (no netif/NAPT): forward a few fixed TCP ports (e.g. the
dongle accepts an in-tunnel TCP connection and proxies it to a configured
`host:port` on its LAN, reusing our TCP server + an outbound TCP client). Covers
"reach one service on the other network" without a full router. Much smaller, and
composes with the existing TCP server/client code.

## Implemented so far (this round)
- **Route advertisement** (`config::SUBNET_ROUTES` / `ADVERTISE_EXIT_NODE` → `Hostinfo.RoutableIPs`
  in register/map). Off by default; admin must approve in the console.
- **NAPT foundation** (`feature = "subnet-router"`, off by default): `router::enable_napt_on_sta`
  calls `esp_netif_napt_enable(sta_handle)` (STA handle via `RawHandle::handle()`).
  `sdkconfig.defaults` now sets `CONFIG_LWIP_IP_FORWARD=y` + `CONFIG_LWIP_IPV4_NAPT=y`
  (confirmed in generated sdkconfig; `esp_netif_napt_enable`/`esp_netif_new`/
  `esp_netif_receive`/`esp_netif_attach` all present in the esp-idf-sys bindings).

## Remaining (the deep bridge — confirmed APIs)
Create the WG netif and bridge it to our tunnels:
- `esp_netif_new(&esp_netif_config_t)` with a `esp_netif_driver_ifconfig_t` whose
  `transmit(handle, data, len)` encrypts the outgoing IP packet for the dst peer
  and sends via the UDP socket; set WG netif IP = our 100.x, netmask 255.192.0.0
  (100.64.0.0/10) so lwIP routes tailnet traffic out it, LAN/default out STA (NAPT).
- Push decrypted inbound packets in with `esp_netif_receive(wg_netif, data, len, ...)`.
- Global `Mutex<routing table: dst-100.x → (transport cipher, peer UDP addr,
  their_index)>` published by the data plane so the C `transmit` callback can reach it.
- Needs: two networks + admin-approved route + iterative on-device lwIP debugging.
  Best landed in the esp32 adapter after the no_std core split.

## Verification
- `tailscale status` on a peer shows the dongle offering the route / as exit-node.
- From a peer: reach a host on the dongle's LAN by its real IP (subnet-router), or
  set the dongle as exit node and check egress IP.
- Watch dongle heap + throughput; confirm `packet-filter` still gates access.
