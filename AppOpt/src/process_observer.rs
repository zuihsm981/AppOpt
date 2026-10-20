//! ITaskStackListener binder 回调实现（dlopen 运行时加载 libbinder_ndk.so）
//!
//! 触发分离/数据共享（参考 优化.md）：
//! Binder 回调 onTaskMovedToFront 解析 RunningTaskInfo 的 effectiveUid,
//! 经 socketpair(SOCK_DGRAM) 发送 4 字节 uid; 主线程 EV_TASK 统一驱动
//! CPU / 刷新率 / vfc / srv / prop (IProcessObserver on_fg 驱动已移除)。

use std::ffi::c_void;
use std::sync::{OnceLock};
use std::sync::atomic::{AtomicI32, Ordering};
use libc::{c_char, c_int, dlopen, dlsym, RTLD_LAZY};

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
        // RTLD_LOCAL: 避免 libbinder_ndk 符号污染进程全局符号空间 (标准做法)
        let lib = dlopen(b"libbinder_ndk.so\0".as_ptr() as *const c_char, RTLD_LAZY | libc::RTLD_LOCAL);
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
            || p_read_i32.is_null()
            || p_join.is_null() || p_start.is_null() || p_associate.is_null()
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

struct SendClass(*mut c_void);
unsafe impl Send for SendClass {}
unsafe impl Sync for SendClass {}
static ATM_CLASS: OnceLock<SendClass> = OnceLock::new();
// SurfaceFlinger 的 ISurfaceComposer 描述符：
// ISurfaceComposer.h 中 DECLARE_META_INTERFACE(SurfaceComposer) →
// IMPLEMENT_META_INTERFACE(SurfaceComposer, "android.ui.ISurfaceComposer")，
// 即旧版 C++ binder 接口注册的就是 android.ui.ISurfaceComposer
static SF_CLASS: OnceLock<SendClass> = OnceLock::new();
// ITaskStackListener 本地 class (任务栈变化事件接收)
static TSL_CLASS: OnceLock<SendClass> = OnceLock::new();
/// TaskStackListener 事件通道写端: 解析出的 effectiveUid → 主线程 EV_TASK
static TASK_SEND_FD: AtomicI32 = AtomicI32::new(-1);

extern "C" fn on_create(_args: *mut c_void) -> *mut c_void { std::ptr::null_mut() }
extern "C" fn on_destroy(_user_data: *mut c_void) {}
extern "C" fn am_dummy_on_transact(_b: *mut c_void, _c: u32, _i: *mut c_void, _o: *mut c_void) -> c_int { STATUS_UNKNOWN_TRANSACTION }

/// IActivityTaskManager 本地 class (供 probe 直连 activity_task 时 associateClass)
fn get_atm_class() -> *mut c_void {
    let Some(ndk) = ndk() else { return std::ptr::null_mut() };
    ATM_CLASS.get_or_init(|| {
        let class = unsafe {
            (ndk.class_define)(
                b"android.app.IActivityTaskManager\0".as_ptr() as *const c_char,
                Some(on_create), Some(on_destroy), Some(am_dummy_on_transact),
            )
        };
        SendClass(class)
    }).0
}

/// SurfaceFlinger 的 ISurfaceComposer class（用于 binder 直连设置刷新率）
fn get_sf_class() -> *mut c_void {
    let Some(ndk) = ndk() else { return std::ptr::null_mut() };
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

/// ITaskStackListener 本地 class (任务栈变化事件接收)
fn get_tsl_class() -> *mut c_void {
    let Some(ndk) = ndk() else { return std::ptr::null_mut() };
    TSL_CLASS.get_or_init(|| {
        let class = unsafe {
            (ndk.class_define)(
                b"android.app.ITaskStackListener\0".as_ptr() as *const c_char,
                Some(on_create), Some(on_destroy), Some(tsl_on_transact),
            )
        };
        SendClass(class)
    }).0
}

/// ITaskStackListener 回调 onTransact: onTaskMovedToFront=0xb 参数 RunningTaskInfo
/// (readTypedObject → null 标志 + RunningTaskInfo.id + TaskInfo: userId/taskId/effectiveUid,
/// effectiveUid = null 标志后第 4 个 int),
/// 直接取 effectiveUid 发送到主线程 EV_TASK。
extern "C" fn tsl_on_transact(
    _binder: *mut c_void,
    code: u32,
    in_parcel: *mut c_void,
    _out: *mut c_void,
) -> c_int {
    let Some(ndk) = ndk() else { return STATUS_UNKNOWN_TRANSACTION };
    let mut uid = -1i32;
    match code {
        0x0b => {
            // onTaskMovedToFront(RunningTaskInfo):
            // [null 标志][RunningTaskInfo.id][TaskInfo.userId][taskId][effectiveUid]...
            // effectiveUid = null 标志后第 4 个 int
            let mut flag = 0i32;
            let _ = unsafe { (ndk.read_i32)(in_parcel, &mut flag) };
            if flag != 0 {
                let mut _id = 0i32;
                let _ = unsafe { (ndk.read_i32)(in_parcel, &mut _id) };
                let mut _user_id = 0i32;
                let _ = unsafe { (ndk.read_i32)(in_parcel, &mut _user_id) };
                let mut _task_id = 0i32;
                let _ = unsafe { (ndk.read_i32)(in_parcel, &mut _task_id) };
                let _ = unsafe { (ndk.read_i32)(in_parcel, &mut uid) };
            }
        }
        _ => {
            // onTaskStackChanged/onTaskFocusChanged 等: 无有效 uid 负载, 忽略
            return STATUS_OK;
        }
    }
    let fd = TASK_SEND_FD.load(Ordering::Acquire);
    if fd >= 0 && uid > 0 {
        let _ = unsafe {
            libc::send(fd, &uid as *const i32 as *const libc::c_void, 4, libc::MSG_DONTWAIT)
        };
    }
    STATUS_OK
}

/// 注册 ITaskStackListener (事务 0x2f): 任务前移 → effectiveUid → 主线程 EV_TASK
pub fn init_task_stack_listener(send_fd: i32) -> bool {
    TASK_SEND_FD.store(send_fd, Ordering::Release);
    let Some(ndk) = ndk() else { return false };
    let class = get_tsl_class();
    if class.is_null() {
        return false;
    }
    let listener = unsafe { (ndk.binder_new)(class, std::ptr::null_mut()) };
    if listener.is_null() {
        return false;
    }
    let am = unsafe { (ndk.get_service)(b"activity_task\0".as_ptr() as *const c_char) };
    if am.is_null() {
        return false;
    }
    let atm_class = get_atm_class();
    if atm_class.is_null() {
        return false;
    }
    if !unsafe { (ndk.associate_class)(am, atm_class as *const c_void) } {
        return false;
    }
    let mut in_parcel: *mut c_void = std::ptr::null_mut();
    if unsafe { (ndk.prepare_tx)(am, &mut in_parcel) } != STATUS_OK || in_parcel.is_null() {
        return false;
    }
    // writeStrongInterface(listener)
    let _ = unsafe { (ndk.write_binder)(in_parcel, listener) };
    let mut out_parcel: *mut c_void = std::ptr::null_mut();
    let status = unsafe { (ndk.transact)(am, 0x2f, &mut in_parcel, &mut out_parcel, 0) };
    unsafe { (ndk.parcel_delete)(in_parcel); }
    if status == STATUS_OK && !out_parcel.is_null() {
        let mut exc = 0i32;
        let _ = unsafe { (ndk.read_i32)(out_parcel, &mut exc) };
        unsafe { (ndk.parcel_delete)(out_parcel); }
        if exc == 0 {
            // binder 线程池: 原由 IProcessObserver 注册启动; on_fg 驱动移除后,
            // TaskStackListener 回调依赖此线程池 → 注册成功后在此启动
            let start_fn = ndk.start_thread_pool;
            let join_fn = ndk.join_thread_pool;
            std::thread::spawn(move || {
                unsafe { start_fn(); }
                unsafe { join_fn(); }
            });
            return true;
        }
        return false;
    }
    if !out_parcel.is_null() {
        unsafe { (ndk.parcel_delete)(out_parcel); }
    }
    false
}

/// binder 直连 SurfaceFlinger 设置刷新率：事务码 1035，一个 int32 参数
/// （替代 `service call SurfaceFlinger 1035 i32 <mode>` 的 fork/exec 子进程方式）
/// 使用 ISurfaceComposer.h 确认的描述符 android.ui.ISurfaceComposer；
/// 失败返回 false，调用方可回退到 service 命令。
pub fn set_refresh_rate_binder(mode: i32) -> bool {
    let Some(ndk) = ndk() else { return false };

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

