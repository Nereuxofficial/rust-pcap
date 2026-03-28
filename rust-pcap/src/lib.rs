pub mod packet;
pub mod pcap_writer;

use aya::{maps::RingBuf, programs::SocketFilter};
use libc::htons;
use log::{debug, error, warn};
use socket2::{Domain, Protocol, Type};
use tokio::io::{Interest, unix::AsyncFd};

use crate::{packet::Packet, pcap_writer::PcapWriter};

const ETH_P_ALL: u16 = 0x003;

static EBPF_BYTES: &[u8] = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/rust-pcap"));

/// Parse a ring buffer entry into a (timestamp_ns, packet_data) pair.
/// Entry layout: [timestamp: u64 LE][len: u32 LE][data: len bytes]
pub fn parse_ring_entry(buf: &[u8]) -> (u64, &[u8]) {
    let timestamp_ns = u64::from_le_bytes(*buf.first_chunk::<8>().unwrap());
    let len = u32::from_le_bytes(buf[8..12].try_into().unwrap()) as usize;
    (timestamp_ns, &buf[12..12 + len])
}

/// Detect the EtherType from the first byte of a raw IP packet.
pub fn detect_ethertype(data: &[u8]) -> u16 {
    if !data.is_empty() && (data[0] >> 4) == 4 {
        0x0800
    } else if !data.is_empty() && (data[0] >> 4) == 6 {
        0x86dd
    } else {
        0x0000
    }
}

/// Build a 16-byte Linux SLL (cooked capture) header for the given EtherType.
pub fn build_sll_header(protocol: u16) -> [u8; 16] {
    let mut header = [0u8; 16];
    header[0..2].copy_from_slice(&0u16.to_be_bytes()); // Packet type: unicast to host
    header[2..4].copy_from_slice(&1u16.to_be_bytes()); // ARPHRD type: Ethernet
    // [4..14] address length + padding: all zeros
    header[14..16].copy_from_slice(&protocol.to_be_bytes()); // EtherType
    header
}

/// Convert a nanosecond timestamp to (seconds, microseconds).
pub fn ns_to_ts(ns: u64) -> (u32, u32) {
    (
        (ns / 1_000_000_000) as u32,
        ((ns % 1_000_000_000) / 1000) as u32,
    )
}

/// Start capturing packets and write them to the specified PCAP file.
pub async fn run_capture(filename: &str) -> anyhow::Result<()> {
    let ebpf_bytes: &[u8] = EBPF_BYTES;
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
                };
            }
            Ok(Err(e)) => {
                // Should only be WouldBlock
                if e.kind() != std::io::ErrorKind::WouldBlock {
                    warn!("Unexpected try_io error: {e:?}");
                }
            }
            Err(_e) => {
                // WouldBlock handled by try_io mechanism to clear ready flag
            }
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ring_entry(ts_ns: u64, payload: &[u8]) -> Vec<u8> {
        let mut buf = vec![0u8; 12 + payload.len()];
        buf[0..8].copy_from_slice(&ts_ns.to_le_bytes());
        buf[8..12].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        buf[12..].copy_from_slice(payload);
        buf
    }

    #[test]
    fn parse_ring_entry_extracts_timestamp_and_data() {
        let payload = [0xAA, 0xBB, 0xCC];
        let buf = make_ring_entry(1_500_000_000_123, &payload);
        let (ts, data) = parse_ring_entry(&buf);
        assert_eq!(ts, 1_500_000_000_123);
        assert_eq!(data, &payload);
    }

    #[test]
    fn parse_ring_entry_empty_payload() {
        let buf = make_ring_entry(42, &[]);
        let (ts, data) = parse_ring_entry(&buf);
        assert_eq!(ts, 42);
        assert!(data.is_empty());
    }

    #[test]
    fn detect_ethertype_ipv4() {
        assert_eq!(detect_ethertype(&[0x45, 0x00, 0x00]), 0x0800);
        assert_eq!(detect_ethertype(&[0x40]), 0x0800); // version nibble = 4
    }

    #[test]
    fn detect_ethertype_ipv6() {
        assert_eq!(detect_ethertype(&[0x60, 0x00, 0x00]), 0x86dd);
        assert_eq!(detect_ethertype(&[0x6f]), 0x86dd); // version nibble = 6
    }

    #[test]
    fn detect_ethertype_unknown() {
        assert_eq!(detect_ethertype(&[0x50]), 0x0000); // version nibble = 5
        assert_eq!(detect_ethertype(&[0x00]), 0x0000);
        assert_eq!(detect_ethertype(&[]), 0x0000);
    }

    #[test]
    fn build_sll_header_layout() {
        let header = build_sll_header(0x0800);
        assert_eq!(header.len(), 16);
        assert_eq!(u16::from_be_bytes(header[0..2].try_into().unwrap()), 0x0000); // packet type
        assert_eq!(u16::from_be_bytes(header[2..4].try_into().unwrap()), 0x0001); // ARPHRD
        assert_eq!(&header[4..14], &[0u8; 10]); // address length + padding
        assert_eq!(
            u16::from_be_bytes(header[14..16].try_into().unwrap()),
            0x0800
        ); // EtherType
    }

    #[test]
    fn build_sll_header_ipv6_protocol() {
        let header = build_sll_header(0x86dd);
        assert_eq!(
            u16::from_be_bytes(header[14..16].try_into().unwrap()),
            0x86dd
        );
    }

    #[test]
    fn ns_to_ts_zero() {
        assert_eq!(ns_to_ts(0), (0, 0));
    }

    #[test]
    fn ns_to_ts_round_seconds() {
        assert_eq!(ns_to_ts(1_000_000_000), (1, 0));
        assert_eq!(ns_to_ts(2_000_000_000), (2, 0));
    }

    #[test]
    fn ns_to_ts_sub_second() {
        assert_eq!(ns_to_ts(500_000_000), (0, 500_000));
        assert_eq!(ns_to_ts(999_999_999), (0, 999_999));
    }

    #[test]
    fn ns_to_ts_mixed() {
        assert_eq!(ns_to_ts(1_500_000_000), (1, 500_000));
    }
}
