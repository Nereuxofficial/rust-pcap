use std::os::unix::io::AsRawFd;

use aya::{
    Ebpf,
    maps::{Array, MapData, RingBuf},
    programs::SocketFilter,
};
use libc::htons;
use log::{debug, warn};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::{Interest, unix::AsyncFd};

use crate::{
    EBPF_BYTES, ETH_P_ALL, build_sll_header, detect_ethertype, device::Device, ns_to_ts,
    packet::Packet, parse_ring_entry,
};

/// Bind a raw packet socket to a specific network interface by index.
///
/// When `ifindex` is provided the socket only receives packets from that
/// interface.  When it is `None` the socket is left unbound and receives
/// packets from all interfaces.
fn bind_to_interface(socket: &socket2::Socket, ifindex: u32) -> std::io::Result<()> {
    let addr = libc::sockaddr_ll {
        sll_family: libc::AF_PACKET as u16,
        sll_protocol: htons(ETH_P_ALL),
        sll_ifindex: ifindex as i32,
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen: 0,
        sll_addr: [0; 8],
    };

    // SAFETY: addr is a valid sockaddr_ll and its size is passed explicitly.
    let ret = unsafe {
        libc::bind(
            socket.as_raw_fd(),
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };

    if ret < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Statistics about the capture session.
#[derive(Debug, Clone, Hash, PartialEq, Eq, Default)]
pub struct Stats {
    /// Number of packets forwarded to user space.
    pub forwarded: u64,
    /// Number of packets dropped (e.g. due to ring buffer being full).
    pub dropped: u64,
}

/// Receives captured packets one at a time.
///
/// Implement this trait to handle packets however you like — print them,
/// forward them over the network, write them to a database, or anything else.
///
/// # Example
///
/// ```no_run
/// # #[tokio::main] async fn main() -> anyhow::Result<()> {
/// use rust_pcap::{capture::{Capture, PacketSink}, device::Device, packet::Packet};
///
/// struct Counter(u64);
///
/// impl PacketSink for Counter {
///     async fn handle(&mut self, _packet: Packet) -> anyhow::Result<()> {
///         self.0 += 1;
///         println!("packets so far: {}", self.0);
///         Ok(())
///     }
/// }
///
/// let mut capture = Capture::from_device(Device::any()).start().await?;
/// let mut counter = Counter(0);
/// loop {
///     let packet = capture.next_packet().await?;
///     counter.handle(packet).await?;
/// }
/// # Ok(()) }
/// ```
#[allow(async_fn_in_trait)]
pub trait PacketSink {
    /// Called once for every captured packet.
    async fn handle(&mut self, packet: Packet) -> anyhow::Result<()>;
}

pub struct Active {
    ebpf: Ebpf,
    stat_array: Array<MapData, u64>,
    packet_buffer: AsyncFd<RingBuf<MapData>>,
    _sockets: Vec<Socket>,
}

pub struct Inactive {
    pub devices: Vec<Device>,
}

/// Builder for a packet capture session.
///
/// # Examples
///
/// Capture all traffic on `eth0`:
/// ```no_run
/// # use rust_pcap::{capture::Capture, device::Device};
/// # #[tokio::main] async fn main() -> anyhow::Result<()> {
/// let dev = Device::lookup("eth0")?;
/// let mut capture = Capture::from_device(dev).start().await?;
///
/// while let Ok(packet) = capture.next_packet().await {
///     println!("Captured packet: {} bytes", packet.data.len());
/// }
/// # Ok(()) }
/// ```
///
/// Capture from all interfaces with a custom handler:
/// ```no_run
/// # use rust_pcap::{capture::{Capture, PacketSink}, device::Device, packet::Packet};
/// # struct MyHandler;
/// # impl PacketSink for MyHandler {
/// #     async fn handle(&mut self, _p: Packet) -> anyhow::Result<()> { Ok(()) }
/// # }
/// # #[tokio::main] async fn main() -> anyhow::Result<()> {
/// let mut capture = Capture::from_device(Device::any()).start().await?;
/// let mut handler = MyHandler;
///
/// while let Ok(packet) = capture.next_packet().await {
///     handler.handle(packet).await?;
/// }
/// # Ok(()) }
/// ```
pub struct Capture<State> {
    state: State,
}

impl Capture<Inactive> {
    /// Create a [`Capture`] targeting the given [`Device`].
    pub fn from_device(device: Device) -> Self {
        Self {
            state: Inactive {
                devices: vec![device],
            },
        }
    }

    /// Start capturing and deliver each packet to `sink`.
    ///
    /// Runs until the task is cancelled or an unrecoverable error occurs.
    pub async fn start(self) -> anyhow::Result<Capture<Active>> {
        let sockets: Vec<_> = self
            .state
            .devices
            .iter()
            .map(|device| {
                let socket = socket2::Socket::new(
                    Domain::PACKET,
                    Type::DGRAM,
                    Some(Protocol::from(htons(ETH_P_ALL) as i32)),
                )
                .map_err(|e| anyhow::anyhow!("failed to create socket: {e}"))?;

                if let Some(ifindex) = device.ifindex {
                    bind_to_interface(&socket, ifindex)
                        .map_err(|e| anyhow::anyhow!("failed to bind to {}: {e}", device.name))?;
                }
                Ok(socket)
            })
            .collect::<anyhow::Result<Vec<_>>>()?;

        Ok(Capture {
            state: Active::initialize(sockets)?,
        })
    }
}

impl Active {
    pub fn initialize(sockets: Vec<Socket>) -> anyhow::Result<Self> {
        // Bump the memlock rlimit for kernels that still use it.
        let rlim = libc::rlimit {
            rlim_cur: libc::RLIM_INFINITY,
            rlim_max: libc::RLIM_INFINITY,
        };
        let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
        if ret != 0 {
            debug!("remove limit on locked memory failed, ret is: {ret}");
        }

        let mut ebpf = aya::Ebpf::load(EBPF_BYTES).unwrap();

        let program: &mut SocketFilter = ebpf.program_mut("rust_pcap").unwrap().try_into()?;
        program.load()?;
        for socket in &sockets {
            program.attach(socket)?;
        }

        let ring_buf = RingBuf::try_from(ebpf.take_map("DATA").unwrap()).unwrap();
        let packet_buffer = AsyncFd::with_interest(ring_buf, Interest::READABLE).unwrap();
        let stat_array = Array::try_from(ebpf.take_map("COUNTERS").unwrap())?;
        Ok(Active {
            ebpf,
            stat_array,
            packet_buffer,
            _sockets: sockets,
        })
    }
}

impl Capture<Active> {
    /// Fetch the next captured packet.
    ///
    /// This method is asynchronous and will wait until a packet is available.
    pub async fn next_packet(&mut self) -> anyhow::Result<Packet> {
        loop {
            let mut guard = self.state.packet_buffer.readable_mut().await?;
            match guard.try_io(|inner| {
                let ringbuf_entry = inner
                    .get_mut()
                    .next()
                    .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::WouldBlock))?;

                let (timestamp_ns, packet_data) = parse_ring_entry(&ringbuf_entry);
                let protocol = detect_ethertype(packet_data);
                let mut data = build_sll_header(protocol).to_vec();
                data.extend_from_slice(packet_data);
                Ok((timestamp_ns, data))
            }) {
                Ok(Ok((timestamp_ns, data))) => {
                    let (ts_sec, ts_usec) = ns_to_ts(timestamp_ns);
                    return Ok(Packet {
                        ts_sec,
                        ts_usec,
                        incl_len: data.len() as u32,
                        orig_len: data.len() as u32,
                        data,
                    });
                }
                Ok(Err(e)) => {
                    if e.kind() != std::io::ErrorKind::WouldBlock {
                        warn!("Unexpected try_io error: {e:?}");
                        return Err(anyhow::anyhow!(e));
                    }
                    // If it's WouldBlock, we just fall through and loop
                }
                Err(_e) => {
                    // WouldBlock handled by try_io mechanism to clear ready flag.
                }
            }
        }
    }

    /// Stop capturing and unload the eBPF program.
    pub fn stop(mut self) -> anyhow::Result<()> {
        let program: &mut SocketFilter = self
            .state
            .ebpf
            .program_mut("rust_pcap")
            .unwrap()
            .try_into()?;
        program.unload()?;
        Ok(())
    }

    /// Fetch current packet counters from the eBPF map.
    pub fn fetch_stats(&mut self) -> anyhow::Result<Stats> {
        let stats = Stats {
            forwarded: self.state.stat_array.get(&0, 0).unwrap_or(0),
            dropped: self.state.stat_array.get(&1, 0).unwrap_or(0),
        };
        Ok(stats)
    }
}
