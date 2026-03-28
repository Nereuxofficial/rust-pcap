use std::os::unix::io::AsRawFd;

use aya::{maps::RingBuf, programs::SocketFilter};
use libc::htons;
use log::{debug, error, warn};
use socket2::{Domain, Protocol, Type};
use tokio::io::{Interest, unix::AsyncFd};

use crate::{
    EBPF_BYTES, ETH_P_ALL, build_sll_header, detect_ethertype, device::Device, ns_to_ts,
    packet::Packet, parse_ring_entry, pcap_writer::PcapWriter,
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

/// Builder for a packet capture session.
///
/// # Examples
///
/// Capture all traffic on `eth0` and write it to `capture.pcap`:
/// ```no_run
/// # use rust_pcap::{capture::Capture, device::Device};
/// # #[tokio::main] async fn main() -> anyhow::Result<()> {
/// let dev = Device::lookup("eth0")?;
/// Capture::from_device(dev).start("capture.pcap").await?;
/// # Ok(()) }
/// ```
///
/// Capture from all interfaces:
/// ```no_run
/// # use rust_pcap::{capture::Capture, device::Device};
/// # #[tokio::main] async fn main() -> anyhow::Result<()> {
/// Capture::from_device(Device::any()).start("capture.pcap").await?;
/// # Ok(()) }
/// ```
pub struct Capture {
    device: Device,
}

impl Capture {
    /// Create a [`Capture`] targeting the given [`Device`].
    pub fn from_device(device: Device) -> Self {
        Self { device }
    }

    /// Start capturing and stream packets into `filename` until the task is
    /// cancelled or an unrecoverable error occurs.
    pub async fn start(self, filename: &str) -> anyhow::Result<()> {
        // Bump the memlock rlimit for kernels that still use it.
        let rlim = libc::rlimit {
            rlim_cur: libc::RLIM_INFINITY,
            rlim_max: libc::RLIM_INFINITY,
        };
        let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
        if ret != 0 {
            debug!("remove limit on locked memory failed, ret is: {ret}");
        }

        let mut ebpf = aya::Ebpf::load(EBPF_BYTES)?;

        match aya_log::EbpfLogger::init(&mut ebpf) {
            Err(e) => {
                warn!("failed to initialize eBPF logger: {e}");
            }
            Ok(logger) => {
                let mut logger = AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
                tokio::task::spawn(async move {
                    loop {
                        let mut guard = logger.readable_mut().await.unwrap();
                        guard.get_inner_mut().flush();
                        guard.clear_ready();
                    }
                });
            }
        }

        let socket = socket2::Socket::new(
            Domain::PACKET,
            Type::DGRAM,
            Some(Protocol::from(htons(ETH_P_ALL) as i32)),
        )
        .map_err(|e| anyhow::anyhow!("failed to create socket: {e}"))?;

        if let Some(ifindex) = self.device.ifindex {
            bind_to_interface(&socket, ifindex)
                .map_err(|e| anyhow::anyhow!("failed to bind to {}: {e}", self.device.name))?;
        }

        let prog: &mut SocketFilter = ebpf.program_mut("rust_pcap").unwrap().try_into()?;
        prog.load()?;
        prog.attach(&socket)?;

        let ring_buf = RingBuf::try_from(ebpf.map_mut("DATA").unwrap()).unwrap();
        let mut packet_buffer = AsyncFd::with_interest(ring_buf, Interest::READABLE).unwrap();

        let file = tokio::fs::File::create(filename).await?;
        let mut file_writer = PcapWriter::new(file).await?;

        loop {
            let mut guard = packet_buffer.readable_mut().await?;
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
                    if let Err(e) = file_writer
                        .write(&Packet {
                            ts_sec,
                            ts_usec,
                            incl_len: data.len() as u32,
                            orig_len: data.len() as u32,
                            data,
                        })
                        .await
                    {
                        error!("Packet dropped: {e}");
                    }
                }
                Ok(Err(e)) => {
                    if e.kind() != std::io::ErrorKind::WouldBlock {
                        warn!("Unexpected try_io error: {e:?}");
                    }
                }
                Err(_e) => {
                    // WouldBlock handled by try_io mechanism to clear ready flag.
                }
            }
        }
    }
}
