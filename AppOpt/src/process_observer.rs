//! IProcessObserver binder 回调 (手写 binder ioctl, 无 libbinder_ndk dlopen)。
//! 前台回调经 socketpair(SOCK_DGRAM) 发 [pid, uid] 8 字节给主线程 EV_FG。

use std::sync::atomic::{AtomicI32, Ordering};

use crate::binder_ioctl::{log_diag, observer_node, push_i32, push_utf16, Binder, BINDER_TYPE_BINDER};

/// 硬编码事务码: android.app.IActivityManager.registerProcessObserver
const TX_REGISTER_PROCESS_OBSERVER: u32 = 0x0d;
/// SurfaceFlinger.setRefreshRate (直连事务码 1035)
const TX_SET_REFRESH_RATE: u32 = 1035;

static FG_SEND_FD: AtomicI32 = AtomicI32::new(-1);

/// 注册 IProcessObserver (手写 binder ioctl) 并启动回调读取线程。
/// send_fd 为 fg 通道发送端; 回调 onForegroundActivitiesChanged → [pid, uid] 8 字节。
pub fn init_observer(send_fd: i32) -> bool {
    FG_SEND_FD.store(send_fd, Ordering::Release);
    log_diag("observer: init_observer start");

    let binder = match Binder::open() {
        Some(b) => b,
        None => { log_diag("observer: Binder::open FAIL"); return false; }
    };
    let am = match binder.get_service("activity") {
        Some(h) => h,
        None => { log_diag("observer: get_service(activity) FAIL"); return false; }
    };

    // parcel: [strict][this][desc "android.app.IActivityManager"][flat_binder_object(observer)]
    let mut data: Vec<u8> = Vec::new();
    push_i32(&mut data, 0); // strict_mode_policy
    push_i32(&mut data, 0); // this binder token
    push_utf16(&mut data, "android.app.IActivityManager");
    let obj_off = data.len();
    // flat_binder_object { type=BINDER_TYPE_BINDER, flags=0, binder=本地节点, cookie=0 }
    push_i32(&mut data, BINDER_TYPE_BINDER as i32);
    push_i32(&mut data, 0);
    data.extend_from_slice(&(observer_node() as u64).to_le_bytes());
    data.extend_from_slice(&0u64.to_le_bytes());
    let offsets = vec![obj_off as u64];

    if binder.transact_sync(am, TX_REGISTER_PROCESS_OBSERVER, &data, &offsets).is_none() {
        log_diag("observer: registerProcessObserver txn FAIL");
        return false;
    }
    log_diag("observer: registerProcessObserver OK");
    binder.run_observer(send_fd);
    true
}

/// binder 直连 SurfaceFlinger 设置刷新率 (手写 ioctl, 事务码 1035, 一个 i32 参数)。
pub fn set_refresh_rate_binder(mode: i32) -> bool {
    log_diag(&format!("refresh: set_refresh_rate_binder mode={}", mode));
    let binder = match Binder::open() {
        Some(b) => b,
        None => { log_diag("refresh: Binder::open FAIL"); return false; }
    };
    let sf = match binder.get_service("SurfaceFlinger") {
        Some(h) => h,
        None => { log_diag("refresh: get_service(SurfaceFlinger) FAIL"); return false; }
    };

    let mut data: Vec<u8> = Vec::new();
    push_i32(&mut data, 0); // strict_mode_policy
    push_i32(&mut data, 0); // this binder token
    push_utf16(&mut data, "android.ui.ISurfaceComposer");
    push_i32(&mut data, mode);

    match binder.transact_sync(sf, TX_SET_REFRESH_RATE, &data, &[]) {
        Some((reply, _)) => {
            // reply 首 i32 为异常码: 0 = 成功
            let ok = if reply.len() >= 4 {
                i32::from_le_bytes([reply[0], reply[1], reply[2], reply[3]]) == 0
            } else {
                false
            };
            log_diag(&format!("refresh: transact 1035 reply len={} ok={}", reply.len(), ok));
            ok
        }
        None => { log_diag("refresh: transact 1035 FAIL (no reply)"); false }
    }
}
