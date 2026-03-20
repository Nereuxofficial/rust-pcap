#![no_std]
#![no_main]
use core::cmp::min;

use aya_ebpf::{
    macros::{map, socket_filter},
    maps::RingBuf,
    programs::SkBuffContext,
};
use aya_log_ebpf::debug;

#[map]
static DATA: RingBuf = RingBuf::with_byte_size(4096 * 4096, 0);

const MAX_PACKET_SIZE: usize = 64 * 1024;

#[socket_filter]
pub fn rust_pcap(ctx: SkBuffContext) -> i64 {
    match try_capture(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

fn try_capture(ctx: &SkBuffContext) -> Result<(), i64> {
    let len = min(unsafe { (*ctx.skb.skb).len } as usize, MAX_PACKET_SIZE);
    if len == 0 {
        return Err(-1);
    }

    let Some(mut buf) = DATA.reserve_bytes(MAX_PACKET_SIZE + 4, 0) else {
        return Err(-1);
    };

    let ptr = buf.as_mut_ptr();
    // Write len to the buffer
    unsafe {
        core::ptr::write(ptr as *mut u32, len as u32);
    }

    let ret = unsafe {
        aya_ebpf::helpers::bpf_skb_load_bytes(
            ctx.skb.skb as *const _,
            0,
            ptr.add(4) as *mut _,
            len as u32,
        )
    };

    if ret < 0 {
        debug!(&ctx, "bpf_skb_load_bytes failed: {}", ret);
        buf.discard(0);
        return Err(ret as i64);
    }

    buf.submit(0);
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
