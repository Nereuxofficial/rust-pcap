mod packet;
mod pcap_writer;

use std::{io::Error, process::exit};

use aya::{maps::RingBuf, programs::SocketFilter};
use libc::htons;
use log::error;
#[rustfmt::skip]
use log::{debug, warn};
use socket2::{Domain, Protocol, Type};
use tokio::{
    io::{Interest, unix::AsyncFd},
    signal,
};

use crate::{packet::Packet, pcap_writer::PcapWriter};

const ETH_P_ALL: u16 = 0x003;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

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

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/rust-pcap"
    )))?;
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
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
    // Incorrect protocol here
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

    let mut file_writer = PcapWriter::new("file.pcap").await.unwrap();
    tokio::spawn(async move {
        let ctrl_c = signal::ctrl_c();
        println!("Waiting for Ctrl-C...");
        ctrl_c.await.unwrap();
        println!("Exiting...");
        exit(0);
    });

    loop {
        let mut guard = packet_buffer.readable_mut().await?;
        match guard.try_io(|inner| {
            let mut data = vec![];
            let ringbuf_entry = inner
                .get_mut()
                .next()
                .ok_or(Error::other("AsyncFd returned none despite being readable"))?;
            let len = u32::from_le_bytes(*ringbuf_entry.first_chunk::<4>().unwrap());

            let packet_data = &ringbuf_entry[4..len as usize + 4];
            let protocol: u16 = if !packet_data.is_empty() && (packet_data[0] >> 4) == 4 {
                0x0800
            } else if !packet_data.is_empty() && (packet_data[0] >> 4) == 6 {
                0x86dd
            } else {
                0x0000
            };

            data.extend_from_slice(&0u16.to_be_bytes());
            data.extend_from_slice(&1u16.to_be_bytes());
            data.extend_from_slice(&0u16.to_be_bytes());
            data.extend_from_slice(&[0u8; 8]);
            data.extend_from_slice(&protocol.to_be_bytes());

            data.extend_from_slice(packet_data);
            Ok(data)
        }) {
            Ok(Ok(data)) => {
                if let Err(e) = file_writer
                    .write(&Packet {
                        ts_sec: 0,
                        ts_usec: 0,
                        incl_len: data.len() as u32,
                        orig_len: data.len() as u32,
                        data,
                    })
                    .await
                {
                    error!("Packet dropped: {e}");
                };
            }
            Ok(e) => {
                //println!("Error getting ringbuf entry: {e:?}")
            }
            Err(e) => println!("Error reading from ringbuf: {e:?}"),
        };
    }

    Ok(())
}
