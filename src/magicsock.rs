//! The single UDP socket that carries all data-plane traffic: STUN (to learn our
//! public endpoint), disco (path discovery) and WireGuard (the tunnel itself).
//! Everything shares one ephemeral local port so the public mapping STUN learns
//! is the same one peers reach us on.
//!
//! M1 scope: bind the socket and run a STUN query to prove UdpSocket works on
//! this esp-idf build and that our XOR-MAPPED-ADDRESS parsing is correct.

use std::net::{SocketAddr, SocketAddrV4, ToSocketAddrs, UdpSocket};
use std::time::Duration;

use anyhow::{bail, Context, Result};

use crate::stun;

pub struct MagicSock {
    sock: UdpSocket,
    pub local_port: u16,
}

impl MagicSock {
    /// Bind to an OS-chosen ephemeral UDP port on all interfaces. With the `bench`
    /// feature, bind a FIXED port (51820) instead so the host-side WireGuard load
    /// generator in `bench/` can reach the data plane directly over the LAN (no
    /// Tailscale path negotiation, so the path can't drift onto DERP mid-test).
    pub fn bind() -> Result<Self> {
        #[cfg(feature = "bench")]
        let bind_addr = "0.0.0.0:51820";
        #[cfg(not(feature = "bench"))]
        let bind_addr = "0.0.0.0:0";
        let sock = UdpSocket::bind(bind_addr).context("bind UDP socket")?;
        let local_port = sock.local_addr().context("local_addr")?.port();
        sock.set_read_timeout(Some(Duration::from_secs(3)))
            .context("set_read_timeout")?;
        Ok(Self { sock, local_port })
    }

    /// Send a STUN Binding Request to `server` and return our public ip:port.
    /// `server` is anything resolvable, e.g. "stun.l.google.com:19302".
    pub fn stun_public_addr(&self, server: &str) -> Result<SocketAddrV4> {
        let target = server
            .to_socket_addrs()
            .with_context(|| format!("resolve {server}"))?
            .find(|a| a.is_ipv4())
            .with_context(|| format!("no IPv4 for {server}"))?;

        let (req, txid) = stun::binding_request();

        // A couple of tries — UDP to a public STUN server can drop a packet.
        let mut last_err = anyhow::anyhow!("no STUN reply");
        for attempt in 0..3 {
            self.sock.send_to(&req, target).context("send STUN request")?;
            let mut buf = [0u8; 512];
            match self.sock.recv_from(&mut buf) {
                Ok((n, _from)) => {
                    if !stun::is_stun(&buf[..n]) {
                        last_err = anyhow::anyhow!("non-STUN reply ({n} bytes)");
                        continue;
                    }
                    return stun::parse_response(&buf[..n], &txid);
                }
                Err(e) => {
                    last_err = anyhow::anyhow!("STUN recv attempt {attempt} failed: {e}");
                }
            }
        }
        bail!("STUN query to {server} failed: {last_err:#}");
    }

    /// Set the recv timeout for the data-plane loop.
    pub fn set_read_timeout(&self, d: Option<Duration>) -> Result<()> {
        self.sock.set_read_timeout(d).context("set_read_timeout")
    }

    pub fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        self.sock.recv_from(buf)
    }

    pub fn send_to(&self, buf: &[u8], addr: SocketAddr) -> std::io::Result<usize> {
        self.sock.send_to(buf, addr)
    }
}
