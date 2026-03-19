#![no_std]
#![no_main]

use core::{alloc::GlobalAlloc, cell::Cell};

use aya_ebpf::{
    helpers::generated::bpf_ktime_get_ns,
    macros::{map, socket_filter},
    maps::{HashMap, RingBuf},
    programs::SkBuffContext,
};
use aya_log_ebpf::{debug, info};

#[map]
static DATA: RingBuf = RingBuf::with_byte_size(4096 * 256, 0);

const BIGGER_THAN_ALL_MTUS: usize = 64 * 1024;

const CAPTURE_SIZE: usize = 128;

#[socket_filter]
pub fn rust_pcap(ctx: SkBuffContext) -> i64 {
    let _ = try_capture(&ctx);

    -1
}

fn try_capture(ctx: &SkBuffContext) -> Result<(), i64> {
    let timestamp_ns = unsafe { bpf_ktime_get_ns() };
    let protocol = ctx.skb.protocol();
    info!(&ctx, "received a packet of protocol {}", protocol);
    // Check packet length first
    let len = unsafe { (*ctx.skb.skb).len };
    if len == 0 {
        return Err(-1);
    }

    let Ok(byte_length) = ctx.load_bytes(0, &mut bytes) else {
        info!(&ctx, "failed to load bytes");
        return Err(-1);
    };

    if let Err(e) = DATA.output::<[u8]>(&bytes[..byte_length], 0) {
        info!(&ctx, "failed to output bytes: {}", e);
        return Err(-1);
    }

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
