use aya::{
    maps::{HashMap, RingBuf},
    programs::SocketFilter,
};
use libc::htons;
#[rustfmt::skip]
use log::{debug, warn};
use socket2::{Domain, Protocol, Type};
use tokio::signal;

const ETH_P_ALL: u16 = 0x003;
struct PollFd<T>(T);
fn poll_fd<T>(t: T) -> PollFd<T> {
    PollFd(t)
}
impl<T> PollFd<T> {
    fn readable(&mut self) -> Guard<'_, T> {
        Guard(self)
    }
}
struct Guard<'a, T>(&'a mut PollFd<T>);

impl<T> Guard<'_, T> {
    fn inner_mut(&mut self) -> &mut T {
        let Guard(PollFd(t)) = self;
        t
    }
    fn clear_ready(&mut self) {}
}
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
    let mut poll = poll_fd(ring_buf);

    loop {
        let mut guard = poll.readable();
        let ring_buf = guard.inner_mut();
        while let Some(item) = ring_buf.next() {
            println!("Received item: {:?}", item.as_array::<256>().unwrap());
        }
        guard.clear_ready();
    }

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}
