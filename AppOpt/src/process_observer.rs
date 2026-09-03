#![allow(dead_code)]
//! IProcessObserver binder 回调实现（dlopen 运行时加载 libbinder_ndk.so）
//!
//! 触发分离/数据共享（参考 优化.md）：
//! Binder 回调只提取 pid，通过 socketpair(SOCK_DGRAM) 发送 pid（4 字节 i32），
//! 不再依赖 /data/system/packages.list / UID 映射表。
//! 刷新率模块从共享 ProcCache（PID_PKG）按 pid 查包名，热路径零文件 I/O。

use std::ffi::c_void;
use std::sync::{OnceLock};
use std::sync::atomic::{AtomicI32, Ordering};
use libc::{c_char, c_int, dlopen, dlsym, RTLD_LAZY};

// ── 硬编码事务码 ──
// 注册: IActivityManager.registerProcessObserver 的事务码 (AIDL 顺序, 各版本稳定)
const TX_REGISTER_PROCESS_OBSERVER: u32 = 0x0d;
// 回调: IProcessObserver.Stub 的 onTransact code, 按 AIDL 声明顺序从
// IBinder.FIRST_CALL_TRANSACTION(=1) 递增。注意顺序不可颠倒:
//   onForegroundActivitiesChanged 必须 = 1, 否则前台回调被误匹配到
//   PROCESS_STARTED 分支而丢失 (web 永远显示 launcher3 / 亲和性失效)。
const TX_ON_FG_ACTIVITIES_CHANGED: u32 = 0x01;
const TX_ON_FG_SERVICES_CHANGED: u32 = 0x02;
const TX_ON_PROCESS_DIED: u32 = 0x03;
const TX_ON_PROCESS_STARTED: u32 = 0x04; // Android 12+ 新增, 追加在末尾

// ── FFI 函数指针类型 ──
type FnGetService = unsafe extern "C" fn(*const c_char) -> *mut c_void;
type FnClassDefine = unsafe extern "C" fn(
    *const c_char,
    Option<extern "C" fn(*mut c_void) -> *mut c_void>,
    Option<extern "C" fn(*mut c_void)>,
    Option<extern "C" fn(*mut c_void, u32, *mut c_void, *mut c_void) -> c_int>,
) -> *mut c_void;
type FnBinderNew = unsafe extern "C" fn(*mut c_void, *mut c_void) -> *mut c_void;
type FnPrepareTx = unsafe extern "C" fn(*mut c_void, *mut *mut c_void) -> c_int;
type FnTransact = unsafe extern "C" fn(
    *mut c_void,       // binder
    u32,               // code
    *mut *mut c_void,  // in parcel (AParcel** — transact 会消费并置 null)
    *mut *mut c_void,  // out parcel (AParcel**)
    u32,               // flags
) -> c_int;
type FnParcelDelete = unsafe extern "C" fn(*mut c_void);
type FnWriteBinder = unsafe extern "C" fn(*mut c_void, *mut c_void) -> c_int;
type FnReadI32 = unsafe extern "C" fn(*mut c_void, *mut i32) -> c_int;
type FnWriteI32 = unsafe extern "C" fn(*mut c_void, i32) -> c_int;
type FnJoinThreadPool = unsafe extern "C" fn();
type FnStartThreadPool = unsafe extern "C" fn();
type FnAssociateClass = unsafe extern "C" fn(*mut c_void, *const c_void) -> bool;

struct BinderNdk {
    get_service: FnGetService,
    class_define: FnClassDefine,
    binder_new: FnBinderNew,
    prepare_tx: FnPrepareTx,
    transact: FnTransact,
    parcel_delete: FnParcelDelete,
    write_binder: FnWriteBinder,
    write_int32: FnWriteI32,
    read_i32: FnReadI32,
    join_thread_pool: FnJoinThreadPool,
    start_thread_pool: FnStartThreadPool,
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
        let p_binder_new = sym("AIBinder_new");
        let p_prepare_tx = sym("AIBinder_prepareTransaction");
        let p_transact = sym("AIBinder_transact");
        let p_parcel_delete = sym("AParcel_delete");
        let p_write_binder = sym("AParcel_writeStrongBinder");
        let p_write_i32 = sym("AParcel_writeInt32");
        let p_read_i32 = sym("AParcel_readInt32");
        let p_join = sym("ABinderProcess_joinThreadPool");
        let p_start = sym("ABinderProcess_startThreadPool");
        let p_associate = sym("AIBinder_associateClass");
        if p_get_service.is_null() || p_class_define.is_null() || p_binder_new.is_null()
            || p_prepare_tx.is_null() || p_transact.is_null() || p_parcel_delete.is_null()
            || p_write_binder.is_null() || p_write_i32.is_null()
            || p_read_i32.is_null() || p_join.is_null() || p_start.is_null() || p_associate.is_null()
        { return None; }
        
        Some(BinderNdk {
            get_service: std::mem::transmute(p_get_service),
            class_define: std::mem::transmute(p_class_define),
            binder_new: std::mem::transmute(p_binder_new),
            prepare_tx: std::mem::transmute(p_prepare_tx),
            transact: std::mem::transmute(p_transact),
            parcel_delete: std::mem::transmute(p_parcel_delete),
            write_binder: std::mem::transmute(p_write_binder),
            write_int32: std::mem::transmute(p_write_i32),
            read_i32: std::mem::transmute(p_read_i32),
            join_thread_pool: std::mem::transmute(p_join),
            start_thread_pool: std::mem::transmute(p_start),
            associate_class: std::mem::transmute(p_associate),
        })
    }).as_ref()
}

const STATUS_OK: c_int = 0;
const STATUS_UNKNOWN_TRANSACTION: c_int = -29;

// fg 事件通过 socketpair(SOCK_DGRAM) 传递 pid（4 字节 i32），
// 刷新率模块从共享 ProcCache（PID_PKG）按 pid 查包名，热路径零文件 I/O
static FG_SEND_FD: AtomicI32 = AtomicI32::new(-1);

struct SendClass(*mut c_void);
unsafe impl Send for SendClass {}
unsafe impl Sync for SendClass {}
static OBSERVER_CLASS: OnceLock<SendClass> = OnceLock::new();
static AM_CLASS: OnceLock<SendClass> = OnceLock::new();
// SurfaceFlinger 的 ISurfaceComposer 描述符：
// ISurfaceComposer.h 中 DECLARE_META_INTERFACE(SurfaceComposer) →
// IMPLEMENT_META_INTERFACE(SurfaceComposer, "android.ui.ISurfaceComposer")，
// 即旧版 C++ binder 接口注册的就是 android.ui.ISurfaceComposer
static SF_CLASS: OnceLock<SendClass> = OnceLock::new();

extern "C" fn on_create(_args: *mut c_void) -> *mut c_void { std::ptr::null_mut() }
extern "C" fn on_destroy(_user_data: *mut c_void) {}
extern "C" fn am_dummy_on_transact(_b: *mut c_void, _c: u32, _i: *mut c_void, _o: *mut c_void) -> c_int { STATUS_UNKNOWN_TRANSACTION }

/// onTransact 回调
extern "C" fn on_transact(
    _binder: *mut c_void,
    code: u32,
    in_parcel: *mut c_void,
    _out: *mut c_void,
) -> c_int {
    let ndk = match ndk() { Some(n) => n, None => return STATUS_UNKNOWN_TRANSACTION };

    // NDK 的 AIBinder_onTransact 内部已通过 checkInterface() 读取了 Interface Token
    // (strict_mode i32 + UTF-16 descriptor)，且不重置 parcel 位置
    // 因此这里直接从事务数据开始读取，不再重复读 token

    match code {
        TX_ON_PROCESS_STARTED => {
            // oneway 事务，无需读取数据
            STATUS_OK
        }
        TX_ON_FG_ACTIVITIES_CHANGED => {
            let mut pid = 0i32;
            let mut _uid = 0i32;
            let mut fg_val = 0i32;

            let _ = unsafe { (ndk.read_i32)(in_parcel, &mut pid) };
            let _ = unsafe { (ndk.read_i32)(in_parcel, &mut _uid) };
            let _ = unsafe { (ndk.read_i32)(in_parcel, &mut fg_val) };

            let fg = fg_val != 0;

            if fg && pid > 0 {
                // 触发分离：Binder 回调只传 pid（4 字节），包名由刷新率模块从共享
                // ProcCache（PID_PKG）按 pid 查询，热路径零 packages.list 文件 I/O。
                // 系统界面/未配置应用的白名单过滤在 refresh 侧完成（两道防线）。
                let fd = FG_SEND_FD.load(Ordering::Acquire);
                if fd >= 0 {
                    let _ = unsafe {
                        libc::send(fd, &pid as *const i32 as *const libc::c_void, 4, 0)
                    };
                }
            }
            STATUS_OK
        }
        TX_ON_FG_SERVICES_CHANGED => {
            let mut _pid = 0i32; let mut _uid = 0i32; let mut _st = 0i32;
            let _ = unsafe { (ndk.read_i32)(in_parcel, &mut _pid) };
            let _ = unsafe { (ndk.read_i32)(in_parcel, &mut _uid) };
            let _ = unsafe { (ndk.read_i32)(in_parcel, &mut _st) };
            STATUS_OK
        }
        TX_ON_PROCESS_DIED => {
            STATUS_OK
        }
        _ => { STATUS_UNKNOWN_TRANSACTION }
    }
}

fn get_observer_class() -> *mut c_void {
    let ndk = match ndk() { Some(n) => n, None => return std::ptr::null_mut() };
    OBSERVER_CLASS.get_or_init(|| {
        let class = unsafe {
            (ndk.class_define)(
                b"android.app.IProcessObserver\0".as_ptr() as *const c_char,
                Some(on_create), Some(on_destroy), Some(on_transact),
            )
        };
        SendClass(class)
    }).0
}

fn get_am_class() -> *mut c_void {
    let ndk = match ndk() { Some(n) => n, None => return std::ptr::null_mut() };
    AM_CLASS.get_or_init(|| {
        let class = unsafe {
            (ndk.class_define)(
                b"android.app.IActivityManager\0".as_ptr() as *const c_char,
                Some(on_create), Some(on_destroy), Some(am_dummy_on_transact),
            )
        };
        SendClass(class)
    }).0
}

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

pub fn init_observer(send_fd: i32) -> bool {
    FG_SEND_FD.store(send_fd, Ordering::Release);

    let ndk = match ndk() { Some(n) => n, None => return false };
    let class = get_observer_class();
    if class.is_null() { return false; }

    let observer = unsafe { (ndk.binder_new)(class, std::ptr::null_mut()) };
    if observer.is_null() { return false; }

    let am = unsafe { (ndk.get_service)(b"activity\0".as_ptr() as *const c_char) };
    if am.is_null() { return false; }

    let am_class = get_am_class();
    if am_class.is_null() { return false; }
    if !unsafe { (ndk.associate_class)(am, am_class as *const c_void) } {
        return false;
    }

    let mut in_parcel: *mut c_void = std::ptr::null_mut();
    let prep_status = unsafe { (ndk.prepare_tx)(am, &mut in_parcel) };
    if prep_status != STATUS_OK || in_parcel.is_null() {
        return false;
    }

    let _ = unsafe { (ndk.write_binder)(in_parcel, observer) };

    let mut out_parcel: *mut c_void = std::ptr::null_mut();
    let status = unsafe { (ndk.transact)(am, TX_REGISTER_PROCESS_OBSERVER, &mut in_parcel, &mut out_parcel, 0) };

    // 读取 reply 异常码以排空 parcel（不再输出日志）
    if status == STATUS_OK && !out_parcel.is_null() {
        let mut _exception_code = 0i32;
        let _ = unsafe { (ndk.read_i32)(out_parcel, &mut _exception_code) };
    }

    unsafe { (ndk.parcel_delete)(in_parcel) };
    if !out_parcel.is_null() { unsafe { (ndk.parcel_delete)(out_parcel) }; }

    if status == STATUS_OK {
        let start_fn = ndk.start_thread_pool;
        let join_fn = ndk.join_thread_pool;
        std::thread::spawn(move || {
            unsafe { start_fn(); }
            unsafe { join_fn(); }
        });
        true
    } else {
        false
    }
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