#![no_std]
#![no_main]

use core::cmp::min;

use aya_ebpf::{
    macros::{map, socket_filter},
    maps::RingBuf,
    programs::SkBuffContext,
};
use aya_log_ebpf::{debug, info};

#[map]
static DATA: RingBuf = RingBuf::with_byte_size(4096 * 256, 0);

const CAPTURE_SIZE: usize = 256;

#[socket_filter]
pub fn rust_pcap(ctx: SkBuffContext) -> i64 {
    let protocol = ctx.skb.protocol();
    info!(&ctx, "received a packet of protocol {}", protocol);

    try_capture(&ctx);

    0
}

fn try_capture(ctx: &SkBuffContext) -> Result<(), i64> {
    // Check packet length first
    let len = unsafe { (*ctx.skb.skb).len };
    if len == 0 {
        return Err(-1);
    }

    let len = min(CAPTURE_SIZE as u32, len);

    let bytes = [0u8; CAPTURE_SIZE];
    let dst = bytes.as_ptr();

    let ret = unsafe {
        aya_ebpf::helpers::bpf_skb_load_bytes(ctx.skb.skb as *const _, 0, dst as *mut _, len as u32)
    };

    if ret < 0 {
        info!(&ctx, "failed to load bytes: {}", ret);
        return Err(ret as i64);
    }

    let Some(mut buf) = DATA.reserve_bytes(len as usize, 0) else {
        debug!(&ctx, "failed to reserve buffer");
        return Err(-1);
    };

    buf.copy_from_slice(&bytes);

    buf.submit(0);
    debug!(&ctx, "Submitted packet to buffer");
    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
