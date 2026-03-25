pub mod packet;
pub mod pcap_writer;

use std::io::Error;

use aya::{maps::RingBuf, programs::SocketFilter};
use libc::htons;
use log::{debug, error, warn};
use socket2::{Domain, Protocol, Type};
use tokio::io::{Interest, unix::AsyncFd};

use crate::{packet::Packet, pcap_writer::PcapWriter};

const ETH_P_ALL: u16 = 0x003;

/// Start capturing packets and write them to the specified PCAP file.
pub async fn run_capture(filename: &str, ebpf_bytes: &[u8]) -> anyhow::Result<()> {
    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    let mut ebpf = aya::Ebpf::load(ebpf_bytes)?;

    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }

    let listener = socket2::Socket::new(
        Domain::PACKET,
        Type::DGRAM,
        Some(Protocol::from(htons(ETH_P_ALL) as i32)),
    )
    .map_err(|e| anyhow::anyhow!("failed to create socket: {e}"))?;

    let prog: &mut SocketFilter = ebpf.program_mut("rust_pcap").unwrap().try_into()?;
    prog.load()?;
    prog.attach(&listener)?;

    let ring_buf = RingBuf::try_from(ebpf.map_mut("DATA").unwrap()).unwrap();
    let mut packet_buffer = AsyncFd::with_interest(ring_buf, Interest::READABLE).unwrap();

    let mut file_writer = PcapWriter::new(filename).await.unwrap();

    loop {
        let mut guard = packet_buffer.readable_mut().await?;
        match guard.try_io(|inner| {
            let mut data = vec![];
            let ringbuf_entry = inner
                .get_mut()
                .next()
                .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::WouldBlock))?;

            let timestamp_ns = u64::from_le_bytes(*ringbuf_entry.first_chunk::<8>().unwrap());
            let len = u32::from_le_bytes(ringbuf_entry[8..12].try_into().unwrap());

            let packet_data = &ringbuf_entry[12..len as usize + 12];
            let protocol: u16 = if !packet_data.is_empty() && (packet_data[0] >> 4) == 4 {
                0x0800
            } else if !packet_data.is_empty() && (packet_data[0] >> 4) == 6 {
                0x86dd
            } else {
                0x0000
            };

            // Construct and append the 16-byte Linux SLL (Cooked Capture) header.
            data.extend_from_slice(&0u16.to_be_bytes()); // Packet type (0 = Unicast to host)
            data.extend_from_slice(&1u16.to_be_bytes()); // ARPHRD_ type (1 = Ethernet)
            data.extend_from_slice(&0u16.to_be_bytes()); // Link-layer address length (0)
            data.extend_from_slice(&[0u8; 8]); // Link-layer address (padded with 0s)
            data.extend_from_slice(&protocol.to_be_bytes()); // Protocol (EtherType)

            data.extend_from_slice(packet_data);
            Ok((timestamp_ns, data))
        }) {
            Ok(Ok((timestamp_ns, data))) => {
                if let Err(e) = file_writer
                    .write(&Packet {
                        ts_sec: (timestamp_ns / 1_000_000_000) as u32,
                        ts_usec: ((timestamp_ns % 1_000_000_000) / 1000) as u32,
                        incl_len: data.len() as u32,
                        orig_len: data.len() as u32,
                        data,
                    })
                    .await
                {
                    error!("Packet dropped: {e}");
                };
            }
            Ok(Err(e)) => {
                // Should only be WouldBlock
                debug!("try_io error: {e:?}");
            }
            Err(_e) => {
                // WouldBlock handled by try_io mechanism to clear ready flag
            }
        };
    }
}
