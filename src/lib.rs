#![no_std]
mod config;
mod wg;

pub use crate::config::Config;
use crate::wg::{MAX_PACKET, consume, create_tunnel, handle_routine_tun_result, send_ip_packet};
use boringtun::noise::Tunn;
use boringtun::noise::errors::WireGuardError;
use core::convert::Infallible;
use core::future::pending;
use core::mem::MaybeUninit;
#[cfg(feature = "defmt")]
use defmt::{debug, error, info, warn};
use embassy_executor::Spawner;
use embassy_futures::select::{Either, select};
use embassy_net::Stack;
use embassy_net::udp::{BindError, RecvError, SendError, UdpSocket};
use embassy_net_driver_channel as ch;
use embassy_net_driver_channel::driver::LinkState;
use embassy_net_driver_channel::{RxRunner, StateRunner, TxRunner};
use embassy_time::{Duration, Timer};
use smoltcp::socket::udp::PacketMetadata;

const MTU: usize = 1500;

/// Type alias for the embassy-net driver.
pub type Device<'d> = embassy_net_driver_channel::Device<'d, MTU>;

/// Internal state for the embassy-net integration.
pub struct State<const N_RX: usize, const N_TX: usize> {
    ch_state: ch::State<MTU, N_RX, N_TX>,
}

impl<const N_RX: usize, const N_TX: usize> State<N_RX, N_TX> {
    /// Create a new `State`.
    pub const fn new() -> Self {
        Self {
            ch_state: ch::State::new(),
        }
    }
}

/// Background runner for the driver.
///
/// You must call `.run()` in a background task for the driver to operate.
pub struct Runner<'d> {
    ch: ch::Runner<'d, MTU>,
}

/// Error returned by [`Runner::run`].
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum RunError {
    Bind(BindError),
    /// Reading from the serial port failed.
    Read(RecvError),
    /// Writing to the serial port failed.
    Write(),
    /// Writing to the serial got EOF.
    Eof,
    /// PPP protocol was terminated by the peer
    Terminated,
}

#[derive(Debug)]
pub enum WGError {
    SendRoutineError(SendError),
    SendDecapsulationError(SendError),
    SendEncryptedError(SendError),
    EncapsulationError(WireGuardError),
    ConnectionExpired,
    PreparationError(WireGuardError),
    ReceiveError,
    Other,
}

impl Runner<'static> {
    /// You must call this in a background task for the driver to operate.
    ///
    /// If reading/writing to the underlying serial port fails, the link state
    /// is set to Down and the error is returned.
    ///
    /// It is allowed to cancel this function's future (i.e. drop it). This will terminate
    /// the wireguard connection and set the link state to Down.
    ///
    /// After this function returns or is canceled, you can call it again to establish
    /// a new wireguard connection.
    pub async fn run(
        &mut self,
        stack: Stack<'static>,
        config: &Config,
        spawner: Spawner,
    ) -> Result<Infallible, RunError> {
        stack.wait_config_up().await;

        debug!("Connected to network, starting wireguard");

        let (state_chan, mut rx_chan, mut tx_chan) = self.ch.borrow_split();
        state_chan.set_link_state(LinkState::Down);
        let _ondrop = OnDrop::new(|| state_chan.set_link_state(LinkState::Down));

        let mut rx_meta = [PacketMetadata::EMPTY; 1];
        let mut rx_buf = [0; 2048];
        let mut tx_meta = [PacketMetadata::EMPTY; 1];
        let mut tx_buf = [0; 2048];

        debug!("Creating UDP socket");

        let mut socket =
            UdpSocket::new(stack, &mut rx_meta, &mut rx_buf, &mut tx_meta, &mut tx_buf);

        debug!("Bind socket");

        if let Err(e) = socket.bind(config.endpoint_bind_addr) {
            // TODO needed?
            #[cfg(feature = "log")]
            info!("bind error: {:?}", e);
            return Err(RunError::Bind(e));
        }

        debug!("Creating tunnel");

        let mut tun = create_tunnel(config);

        spawner
            .must_spawn(routine_task(&mut tun, &socket, &config, state_chan));
        spawner
            .must_spawn(consume_task(&mut tun, &socket, &config, stack, rx_chan));
        spawner
            .must_spawn(produce_task(&mut tun, &socket, &config, tx_chan));

        pending().await
    }
}

#[embassy_executor::task]
async fn routine_task(
    mut tun: &'static mut Tunn,
    socket: &'static UdpSocket<'static>,
    config: &'static Config,
    state_chan: StateRunner<'static>,
) {
    loop {
        let mut send_buf = [0u8; MAX_PACKET];
        debug!("Updating timers");
        let mut res = tun.update_timers(&mut send_buf);
        loop {
            debug!("Handling routine result");
            match handle_routine_tun_result(&socket, config, res).await {
                Ok(_) => {
                    debug!("Successfully handled routine result");
                    state_chan.set_link_state(LinkState::Up);
                    break;
                }
                Err(e) => {
                    #[cfg(feature = "defmt")]
                    error!("{:?}", e);
                    if let WGError::PreparationError(WireGuardError::ConnectionExpired) = e {
                        #[cfg(feature = "defmt")]
                        warn!("Wireguard handshake has expired!");
                        res = tun.format_handshake_initiation(&mut send_buf[..], false);
                    } else {
                        state_chan.set_link_state(LinkState::Down);
                        break;
                    }
                }
            }
        }
    }
}

#[embassy_executor::task]
async fn consume_task(
    mut tun: &'static mut Tunn,
    socket: &'static UdpSocket<'static>,
    config: &'static Config,
    stack: Stack<'static>,
    mut rx_chan: RxRunner<'static, MTU>,
) {
    loop {
        let mut buf = [0; 2048];
        let rx_buf = rx_chan.rx_buf().await;
        debug!("Got rx buffer of size {}", rx_buf.len());
        let rx_data = match socket.recv_from(&mut buf).await {
            Ok((0, remote_endpoint)) => {
                error!("Eof");
                continue;
            },
            Ok((n, remote_endpoint)) => &buf[..n],
            Err(e) => {
                error!("Failed to read from WireGuard endpoint: {:?}", e);
                // Sleep a little bit and try again
                Timer::after(Duration::from_millis(1)).await;
                continue;
            },
        };
        debug!("Received {} bytes from UDP socket", rx_data.len());
        debug!("We shall receive a packet");
        match consume(stack, &mut tun, &socket, config, (rx_buf, rx_data)).await {
            Ok(_) => {
                debug!("Consumed packet successfully");
            }
            Err(e) => {
                #[cfg(feature = "defmt")]
                error!("{:?}", e);
            }
        }
    }
}

#[embassy_executor::task]
async fn produce_task(
    mut tun: &'static mut Tunn,
    socket: &'static UdpSocket<'static>,
    config: &'static Config,
    mut tx_chan: TxRunner<'static, MTU>,
) {
    loop {
        let tx_fut = tx_chan.tx_buf().await;
        debug!("We shall send a packet");
        match send_ip_packet(&mut tun, &socket, config, tx_fut).await {
            Ok(_) => {
                debug!("Send packet successfully");
            }
            Err(e) => {
                #[cfg(feature = "defmt")]
                error!("{:?}", e);
            }
        }
        tx_chan.tx_done();
    }
}

/// Create a PPP embassy-net driver instance.
///
/// This returns two structs:
/// - a `Device` that you must pass to the `embassy-net` stack.
/// - a `Runner`. You must call `.run()` on it in a background task.
pub fn new<const N_RX: usize, const N_TX: usize>(
    state: &'_ mut State<N_RX, N_TX>,
) -> (Device<'_>, Runner<'_>) {
    let (runner, device) = ch::new(&mut state.ch_state, ch::driver::HardwareAddress::Ip);
    (device, Runner { ch: runner })
}

struct OnDrop<F: FnOnce()> {
    f: MaybeUninit<F>,
}

impl<F: FnOnce()> OnDrop<F> {
    fn new(f: F) -> Self {
        Self {
            f: MaybeUninit::new(f),
        }
    }
}

impl<F: FnOnce()> Drop for OnDrop<F> {
    fn drop(&mut self) {
        unsafe { self.f.as_ptr().read()() }
    }
}
