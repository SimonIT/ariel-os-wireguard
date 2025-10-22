use crate::WGError;
use crate::WGError::{EncapsulationError, Other, SendRoutineError};
use crate::config::{Config, PortProtocol};
use boringtun::noise::errors::WireGuardError;
use boringtun::noise::{Tunn, TunnResult};
#[cfg(feature = "defmt")]
use defmt::{debug, error, trace, warn};
use embassy_net::Stack;
use embassy_net::udp::UdpSocket;
use embassy_time::{Duration, Timer};
#[cfg(feature = "proto-ipv4")]
use smoltcp::wire::Ipv4Packet;
#[cfg(feature = "proto-ipv6")]
use smoltcp::wire::Ipv6Packet;
use smoltcp::wire::{IpProtocol, IpVersion};

pub(crate) const MAX_PACKET: usize = 2048;

pub async fn send_ip_packet(
    tun: &mut Tunn,
    socket: &UdpSocket<'_>,
    config: &Config,
    packet: &[u8],
) -> Result<(), WGError> {
    trace_ip_packet("Sending IP packet", packet);
    let mut send_buf = [0u8; MAX_PACKET];
    let encapsulate_result = tun.encapsulate(packet, &mut send_buf);
    match encapsulate_result {
        TunnResult::WriteToNetwork(packet) => {
            let res = socket.send_to(packet, config.endpoint_addr).await;
            #[cfg(feature = "defmt")]
            debug!(
                "Sent {} bytes to WireGuard endpoint (encrypted IP packet)",
                packet.len()
            );
            res.map_err(WGError::SendEncryptedError)
        }
        TunnResult::Err(e) => {
            #[cfg(feature = "defmt")]
            error!("Failed to encapsulate an IP packet: {:?}", e);
            Err(EncapsulationError(e))
        }
        TunnResult::Done => {
            // Ignored
            #[cfg(feature = "defmt")]
            debug!("Encapsulation resulted in Done, ignoring");
            Ok(())
        }
        other => {
            #[cfg(feature = "defmt")]
            error!(
                "Unexpected WireGuard state during encapsulation: {:?}",
                other
            );
            Err(Other)
        }
    }
}

pub(crate) async fn handle_routine_tun_result(
    socket: &UdpSocket<'_>,
    config: &Config,
    result: TunnResult<'_>,
) -> Result<(), WGError> {
    match result {
        TunnResult::WriteToNetwork(packet) => {
            #[cfg(feature = "defmt")]
            debug!(
                "Sending a routine packet of {} bytes to {}",
                packet.len(),
                config.endpoint_addr
            );
            socket
                .send_to(packet, config.endpoint_addr)
                .await
                .map_err(SendRoutineError)
        }
        TunnResult::Err(WireGuardError::ConnectionExpired) => {
            #[cfg(feature = "defmt")]
            warn!("Wireguard handshake has expired!");

            Err(WGError::ConnectionExpired)
        }
        TunnResult::Err(e) => {
            #[cfg(feature = "defmt")]
            error!(
                "Failed to prepare a routine packet for WireGuard endpoint: {:?}",
                e
            );

            Err(WGError::PreparationError(e))
        }
        TunnResult::Done => {
            // Sleep for a bit
            #[cfg(feature = "defmt")]
            debug!("WireGuard routine task done, sleeping for 1 ms");
            Timer::after_millis(1).await;
            Ok(())
        }
        other => {
            #[cfg(feature = "defmt")]
            warn!("Unexpected WireGuard routine task state: {:?}", other);
            Err(Other)
        }
    }
}

pub async fn consume(
    stack: Stack<'_>,
    tun: &mut Tunn,
    socket: &UdpSocket<'_>,
    config: &Config,
    r: (&mut [u8], &[u8]),
) -> Result<(), WGError> {
    let (buf, rx_data) = r;
    let mut send_buf = [0u8; MAX_PACKET];

    let decapsulate_result = tun.decapsulate(None, rx_data, &mut send_buf);
    match decapsulate_result {
        TunnResult::WriteToNetwork(packet) => {
            #[cfg(feature = "defmt")]
            debug!("Decapsulation requested sending a packet to WireGuard endpoint");
            match socket.send_to(packet, config.endpoint_addr).await {
                Ok(_) => Ok(()),
                Err(e) => {
                    #[cfg(feature = "defmt")]
                    error!(
                        "Failed to send a decapsulation-instructed packet to WireGuard endpoint: {:?}",
                        e
                    );
                    Err(WGError::SendDecapsulationError(e))
                }
            }?;
            loop {
                match tun.decapsulate(None, &[], &mut send_buf) {
                    TunnResult::WriteToNetwork(packet) => {
                        match socket.send_to(packet, config.endpoint_addr).await {
                            Ok(_) => Ok(()),
                            Err(e) => {
                                #[cfg(feature = "defmt")]
                                error!(
                                    "Failed to send a decapsulation-instructed packet to WireGuard endpoint: {:?}",
                                    e
                                );
                                Err(WGError::SendDecapsulationError(e))
                            }
                        }?
                    }
                    _ => { Err(Other) }?,
                }
            }
        }
        TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => {
            #[cfg(feature = "defmt")]
            debug!(
                "WireGuard endpoint sent an IP packet of {} bytes",
                packet.len()
            );

            // For debugging purposes: parse packet
            trace_ip_packet("Received IP packet", packet);

            if let Some(proto) = route_protocol(stack, packet) {
                buf[..packet.len()].copy_from_slice(packet);
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

pub(crate) fn create_tunnel(config: &Config) -> Tunn {
    Tunn::new(
        config.private_key.clone(),
        config.endpoint_public_key,
        config.preshared_key,
        config.keepalive_seconds,
        0,
        None,
    )
}

/// Determine the inner protocol of the incoming IP packet (TCP/UDP).
pub(crate) fn route_protocol(stack: Stack, packet: &[u8]) -> Option<PortProtocol> {
    #[cfg(feature = "proto-ipv4")]
    let ipv4 = stack.config_v4().map(|ip| ip.address.address());
    #[cfg(feature = "proto-ipv6")]
    let ipv6 = stack.config_v6().map(|ip| ip.address.address());
    match IpVersion::of_packet(packet) {
        #[cfg(feature = "proto-ipv4")]
        Ok(IpVersion::Ipv4) => Ipv4Packet::new_checked(&packet)
            .ok()
            // Only care if the packet is destined for this tunnel
            .filter(|packet| ipv4.map(|ip| packet.dst_addr() == ip).unwrap_or(false))
            .and_then(|packet| match packet.next_header() {
                IpProtocol::Tcp => Some(PortProtocol::Tcp),
                IpProtocol::Udp => Some(PortProtocol::Udp),
                // Unrecognized protocol, so we cannot determine where to route
                _ => None,
            }),
        #[cfg(feature = "proto-ipv6")]
        Ok(IpVersion::Ipv6) => Ipv6Packet::new_checked(&packet)
            .ok()
            // Only care if the packet is destined for this tunnel
            .filter(|packet| ipv6.map(|ip| packet.dst_addr() == ip).unwrap_or(false))
            .and_then(|packet| match packet.next_header() {
                IpProtocol::Tcp => Some(PortProtocol::Tcp),
                IpProtocol::Udp => Some(PortProtocol::Udp),
                // Unrecognized protocol, so we cannot determine where to route
                _ => None,
            }),
        _ => None,
    }
}

fn trace_ip_packet(message: &str, packet: &[u8]) {
    #[cfg(feature = "defmt")]
    {
        use smoltcp::wire::*;

        match IpVersion::of_packet(packet) {
            #[cfg(feature = "proto-ipv4")]
            Ok(IpVersion::Ipv4) => trace!(
                "{}: {}",
                message,
                PrettyPrinter::<Ipv4Packet<&mut [u8]>>::new("", &packet)
            ),
            #[cfg(feature = "proto-ipv6")]
            Ok(IpVersion::Ipv6) => trace!(
                "{}: {}",
                message,
                PrettyPrinter::<Ipv6Packet<&mut [u8]>>::new("", &packet)
            ),
            _ => {}
        }
    }
}
