//! Subnet-router / exit-node data path (esp32-specific).
//!
//! Routing arbitrary packets between the tailnet and the LAN/internet needs lwIP,
//! not our userspace flow handlers. The design (confirmed against the esp-idf
//! bindings present in this build):
//!
//!  1. Enable NAPT on the WiFi STA netif: `esp_netif_napt_enable(sta_handle)`
//!     (requires `CONFIG_LWIP_IP_FORWARD=y` + `CONFIG_LWIP_IPV4_NAPT=y`). Then
//!     packets routed in from another netif and out STA are SNAT'd to the STA IP.
//!     `enable_napt_on_sta` below does this part — it is verified to link/return OK.
//!
//!  2. Create a custom "WG" netif and bridge it to our WireGuard tunnels (the
//!     remaining deep work — see TODO): `esp_netif_new(&cfg)` with a
//!     `esp_netif_driver_ifconfig_t` whose `transmit` callback encrypts the
//!     outgoing IP packet with the destination peer's transport keys and sends it
//!     via the UDP socket; decrypted inbound packets are pushed in with
//!     `esp_netif_receive(wg_netif, data, len, ...)`. Give the WG netif our 100.x
//!     IP with netmask 255.192.0.0 (100.64.0.0/10) so lwIP routes tailnet traffic
//!     out it and LAN/default out STA (NAPT).
//!
//!     This requires a globally-reachable dst-100.x -> (tunnel keys, peer addr)
//!     routing table (the `transmit` C callback can't borrow the data-plane
//!     thread's state), i.e. a `Mutex<HashMap<...>>` the data plane publishes to.
//!     Best landed in the esp32 adapter after the no_std core split, with a
//!     two-network + admin-route-approval test rig. See docs/PLAN-router-exitnode.md.

use esp_idf_svc::sys;

/// Enable NAPT on the STA netif so traffic routed in from the WG netif and out to
/// the LAN / internet is source-NAT'd to the dongle's STA address. Returns Ok on
/// success. `sta` is the raw STA `esp_netif_t*` (from `EspNetif::handle()`).
pub fn enable_napt_on_sta(sta: *mut sys::esp_netif_t) -> Result<(), i32> {
    if sta.is_null() {
        return Err(-1);
    }
    let err = unsafe { sys::esp_netif_napt_enable(sta) };
    if err == sys::ESP_OK {
        println!("router: NAPT enabled on STA netif");
        Ok(())
    } else {
        println!("router: esp_netif_napt_enable failed (err={err})");
        Err(err)
    }
}

// TODO (the WG netif bridge): esp_netif_new + esp_netif_driver_ifconfig_t.transmit
// (encrypt+send to dst peer) + esp_netif_receive(inbound) + global dst->tunnel
// routing table. This is the architecture-changing piece; do it in the esp32
// adapter post-split with a live two-network test.
