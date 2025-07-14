#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::XskMap,
    programs::XdpContext,
};
// use aya_log_ebpf::info;

#[map]
static XSKS_MAP: XskMap = XskMap::with_max_entries(64, 0);

#[xdp]
pub fn nsave(ctx: XdpContext) -> u32 {
    match try_nsave(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_nsave(ctx: XdpContext) -> Result<u32, u32> {
    // let data_len = ctx.data_end() - ctx.data();
    // info!(
    //     &ctx,
    //     "Received a packet. queue id: {}, data_len: {}", queue_id, data_len
    // );

    // let queue_id = ctx.rx_queue_index(); 新版本可以这样获取queue_id
    let queue_id = unsafe { (*ctx.ctx).rx_queue_index };
    match XSKS_MAP.redirect(queue_id, 0) {
        Ok(_) => {
            // info!(
            //     &ctx,
            //     "redirected packet from queue {} to AF_XDP socket", queue_id
            // );
            Ok(xdp_action::XDP_REDIRECT)
        }
        Err(_) => {
            // info!(
            //     &ctx,
            //     "no AF_XDP socket found for queue {}, passing packet", queue_id
            // );
            Ok(xdp_action::XDP_PASS)
        }
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
