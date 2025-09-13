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
    pub private_key: StaticSecret,
    pub endpoint_public_key: PublicKey,
    pub preshared_key: Option<[u8; 32]>,
    pub endpoint_addr: SocketAddr,
    pub endpoint_bind_addr: SocketAddr,
    pub keepalive_seconds: Option<u16>,
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
