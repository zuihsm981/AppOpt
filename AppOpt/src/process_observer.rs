#![allow(dead_code)]
//! 前台事件通道 + SurfaceFlinger 刷新率直连 (binder_ndk 仅刷新率用; IProcessObserver 已移除)
//!
//! 触发分离/数据共享（参考 优化.md）：
//! 前台事件来源已改为内核 cgroup_attach_task 探针 (event_dispatch 直发), 本模块
//! 仅保留 SurfaceFlinger 刷新率 binder 直连。
//! 主线程据此查 uid 静态表并分发 CPU(按 uid 枚举)/刷新率(按包)线程。

use std::ffi::c_void;
use std::sync::{OnceLock};
use std::sync::atomic::{AtomicI32, Ordering};
use libc::{c_char, c_int, dlopen, dlsym, RTLD_LAZY};

// ── 硬编码事务码 ──

// ── FFI 函数指针类型 ──
type FnGetService = unsafe extern "C" fn(*const c_char) -> *mut c_void;
type FnClassDefine = unsafe extern "C" fn(
    *const c_char,
    Option<extern "C" fn(*mut c_void) -> *mut c_void>,
    Option<extern "C" fn(*mut c_void)>,
    Option<extern "C" fn(*mut c_void, u32, *mut c_void, *mut c_void) -> c_int>,
) -> *mut c_void;
type FnPrepareTx = unsafe extern "C" fn(*mut c_void, *mut *mut c_void) -> c_int;
type FnTransact = unsafe extern "C" fn(
    *mut c_void,       // binder
    u32,               // code
    *mut *mut c_void,  // in parcel (AParcel** — transact 会消费并置 null)
    *mut *mut c_void,  // out parcel (AParcel**)
    u32,               // flags
) -> c_int;
type FnParcelDelete = unsafe extern "C" fn(*mut c_void);
type FnReadI32 = unsafe extern "C" fn(*mut c_void, *mut i32) -> c_int;
type FnWriteI32 = unsafe extern "C" fn(*mut c_void, i32) -> c_int;
type FnAssociateClass = unsafe extern "C" fn(*mut c_void, *const c_void) -> bool;

struct BinderNdk {
    get_service: FnGetService,
    class_define: FnClassDefine,
    prepare_tx: FnPrepareTx,
    transact: FnTransact,
    parcel_delete: FnParcelDelete,
    write_int32: FnWriteI32,
    read_i32: FnReadI32,
    associate_class: FnAssociateClass,
}

static BINDER_NDK: OnceLock<Option<BinderNdk>> = OnceLock::new();

fn ndk() -> Option<&'static BinderNdk> {
    BINDER_NDK.get_or_init(|| unsafe {
        let lib = dlopen(b"libbinder_ndk.so\0".as_ptr() as *const c_char, RTLD_LAZY | libc::RTLD_GLOBAL);
        if lib.is_null() { return None; }

        let sym = |name: &str| -> *mut c_void {
            let c = std::ffi::CString::new(name).unwrap();
            dlsym(lib, c.as_ptr())
        };

        let p_get_service = sym("AServiceManager_getService");
        let p_class_define = sym("AIBinder_Class_define");
        let p_prepare_tx = sym("AIBinder_prepareTransaction");
        let p_transact = sym("AIBinder_transact");
        let p_parcel_delete = sym("AParcel_delete");
        let p_write_i32 = sym("AParcel_writeInt32");
        let p_read_i32 = sym("AParcel_readInt32");
        let p_associate = sym("AIBinder_associateClass");
        if p_get_service.is_null() || p_class_define.is_null()
            || p_prepare_tx.is_null() || p_transact.is_null() || p_parcel_delete.is_null()
            || p_write_i32.is_null() || p_read_i32.is_null() || p_associate.is_null()
        { return None; }
        
        Some(BinderNdk {
            get_service: std::mem::transmute(p_get_service),
            class_define: std::mem::transmute(p_class_define),
            prepare_tx: std::mem::transmute(p_prepare_tx),
            transact: std::mem::transmute(p_transact),
            parcel_delete: std::mem::transmute(p_parcel_delete),
            write_int32: std::mem::transmute(p_write_i32),
            read_i32: std::mem::transmute(p_read_i32),
            associate_class: std::mem::transmute(p_associate),
        })
    }).as_ref()
}

const STATUS_OK: c_int = 0;
const STATUS_UNKNOWN_TRANSACTION: c_int = -29;

struct SendClass(*mut c_void);
unsafe impl Send for SendClass {}
unsafe impl Sync for SendClass {}
// SurfaceFlinger 的 ISurfaceComposer 描述符：
// ISurfaceComposer.h 中 DECLARE_META_INTERFACE(SurfaceComposer) →
// IMPLEMENT_META_INTERFACE(SurfaceComposer, "android.ui.ISurfaceComposer")，
// 即旧版 C++ binder 接口注册的就是 android.ui.ISurfaceComposer
static SF_CLASS: OnceLock<SendClass> = OnceLock::new();

extern "C" fn on_create(_args: *mut c_void) -> *mut c_void { std::ptr::null_mut() }
extern "C" fn on_destroy(_user_data: *mut c_void) {}
extern "C" fn am_dummy_on_transact(_b: *mut c_void, _c: u32, _i: *mut c_void, _o: *mut c_void) -> c_int { STATUS_UNKNOWN_TRANSACTION }

/// SurfaceFlinger 的 ISurfaceComposer class（用于 binder 直连设置刷新率）
fn get_sf_class() -> *mut c_void {
    let ndk = match ndk() { Some(n) => n, None => return std::ptr::null_mut() };
    SF_CLASS.get_or_init(|| {
        let class = unsafe {
            (ndk.class_define)(
                b"android.ui.ISurfaceComposer\0".as_ptr() as *const c_char,
                Some(on_create), Some(on_destroy), Some(am_dummy_on_transact),
            )
        };
        SendClass(class)
    }).0
}

/// binder 直连 SurfaceFlinger 设置刷新率：事务码 1035，一个 int32 参数
/// （替代 `service call SurfaceFlinger 1035 i32 <mode>` 的 fork/exec 子进程方式）
/// 使用 ISurfaceComposer.h 确认的描述符 android.ui.ISurfaceComposer；
/// 失败返回 false，调用方可回退到 service 命令。
pub fn set_refresh_rate_binder(mode: i32) -> bool {
    let ndk = match ndk() { Some(n) => n, None => return false };

    let sf = unsafe { (ndk.get_service)(b"SurfaceFlinger\0".as_ptr() as *const c_char) };
    if sf.is_null() {
        return false;
    }

    let sf_class = get_sf_class();
    if sf_class.is_null() {
        return false;
    }
    if !unsafe { (ndk.associate_class)(sf, sf_class as *const c_void) } {
        return false;
    }

    let mut in_parcel: *mut c_void = std::ptr::null_mut();
    let prep_status = unsafe { (ndk.prepare_tx)(sf, &mut in_parcel) };
    if prep_status != STATUS_OK || in_parcel.is_null() {
        return false;
    }

    // 写入 int32 参数（刷新率模式：0=120Hz, 1=60Hz, 2=90Hz）
    let _ = unsafe { (ndk.write_int32)(in_parcel, mode) };

    let mut out_parcel: *mut c_void = std::ptr::null_mut();
    const TX_SET_REFRESH_RATE: u32 = 1035;
    let status =
        unsafe { (ndk.transact)(sf, TX_SET_REFRESH_RATE, &mut in_parcel, &mut out_parcel, 0) };

    // 检查 reply 异常码：服务端 enforceInterface/参数校验失败时视为失败
    let mut ok = status == STATUS_OK;
    if ok && !out_parcel.is_null() {
        let mut exception_code = 0i32;
        let _ = unsafe { (ndk.read_i32)(out_parcel, &mut exception_code) };
        if exception_code != 0 {
            ok = false;
        }
    }

    unsafe { (ndk.parcel_delete)(in_parcel) };
    if !out_parcel.is_null() {
        unsafe { (ndk.parcel_delete)(out_parcel) };
    }

    ok
}