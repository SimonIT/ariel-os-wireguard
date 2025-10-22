pub use boringtun::x25519::{PublicKey, StaticSecret};
#[cfg(all(feature = "proto-ipv4", feature = "proto-ipv6"))]
use core::net::SocketAddr;
#[cfg(all(feature = "proto-ipv4", not(feature = "proto-ipv6")))]
use core::net::SocketAddrV4 as SocketAddr;
#[cfg(all(feature = "proto-ipv6", not(feature = "proto-ipv4")))]
use core::net::SocketAddrV6 as SocketAddr;

const DEFAULT_PORT_FORWARD_SOURCE: &str = "127.0.0.1";

#[derive(Clone)]
pub struct Config {
    /// The private key of this peer. The corresponding public key should be registered in the WireGuard endpoint.
    pub private_key: StaticSecret,
    /// The public key of the WireGuard endpoint (remote).
    pub endpoint_public_key: PublicKey,
    /// The pre-shared key (PSK) as configured with the peer.
    pub preshared_key: Option<[u8; 32]>,
    /// The address (IP + port) of the WireGuard endpoint (remote). Example: 1.2.3.4:51820
    pub endpoint_addr: SocketAddr,
    /// Configures a persistent keep-alive for the WireGuard tunnel, in seconds.
    pub keepalive_seconds: Option<u16>,
    /// The port for incoming packets
    pub port: u16,
}

/// Layer 7 protocols for ports.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum PortProtocol {
    /// TCP
    Tcp,
    /// UDP
    Udp,
}

impl TryFrom<&str> for PortProtocol {
    type Error = ();

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value.to_uppercase().as_str() {
            "TCP" => Ok(Self::Tcp),
            "UDP" => Ok(Self::Udp),
            _ => Err(()),
        }
    }
}
