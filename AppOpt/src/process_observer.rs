#![allow(dead_code)]
//! IProcessObserver binder 回调实现（dlopen 运行时加载 libbinder_ndk.so）

use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::{LazyLock, Mutex, OnceLock};
use std::sync::atomic::{AtomicI32, Ordering};
use libc::{c_char, c_int, dlopen, dlsym, RTLD_LAZY};

// ── Android log ──
unsafe extern "C" {
    fn __android_log_write(prio: c_int, tag: *const c_char, text: *const c_char) -> c_int;
}
const LOG_TAG: &[u8] = b"AppOpt\0";
fn log(msg: &str) {
    let mut buf = vec![0u8; msg.len() + 1];
    buf[..msg.len()].copy_from_slice(msg.as_bytes());
    unsafe { __android_log_write(3, LOG_TAG.as_ptr() as *const c_char, buf.as_ptr() as *const c_char); }
}
macro_rules! alog { ($($a:tt)*) => { log(&format!($($a)*)) } }

// ── 硬编码事务码 ──
const TX_REGISTER_PROCESS_OBSERVER: u32 = 0x0d;
const TX_ON_PROCESS_STARTED: u32 = 0x01;
const TX_ON_FG_ACTIVITIES_CHANGED: u32 = 0x02;
const TX_ON_FG_SERVICES_CHANGED: u32 = 0x03;
const TX_ON_PROCESS_DIED: u32 = 0x04;

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
type FnWriteString = unsafe extern "C" fn(*mut c_void, *const c_char, i32) -> c_int;
type FnWriteBinder = unsafe extern "C" fn(*mut c_void, *mut c_void) -> c_int;
type FnWriteI32 = unsafe extern "C" fn(*mut c_void, i32) -> c_int;
type FnReadI32 = unsafe extern "C" fn(*mut c_void, *mut i32) -> c_int;
type FnReadString = unsafe extern "C" fn(
    *mut c_void,
    *mut c_void,
    Option<extern "C" fn(*mut c_void, *mut *mut c_char, i32) -> bool>,
) -> c_int;
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
    write_string: FnWriteString,
    write_binder: FnWriteBinder,
    write_i32: FnWriteI32,
    read_i32: FnReadI32,
    read_string: FnReadString,
    join_thread_pool: FnJoinThreadPool,
    start_thread_pool: FnStartThreadPool,
    associate_class: FnAssociateClass,
}

static BINDER_NDK: OnceLock<Option<BinderNdk>> = OnceLock::new();

fn ndk() -> Option<&'static BinderNdk> {
    BINDER_NDK.get_or_init(|| unsafe {
        let lib = dlopen(b"libbinder_ndk.so\0".as_ptr() as *const c_char, RTLD_LAZY | libc::RTLD_GLOBAL);
        if lib.is_null() { alog!("dlopen 失败"); return None; }
        alog!("dlopen 成功");

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
        let p_write_string = sym("AParcel_writeString");
        let p_write_binder = sym("AParcel_writeStrongBinder");
        let p_write_i32 = sym("AParcel_writeInt32");
        let p_read_i32 = sym("AParcel_readInt32");
        let p_read_string = sym("AParcel_readString");
        let p_join = sym("ABinderProcess_joinThreadPool");
        let p_start = sym("ABinderProcess_startThreadPool");
        let p_associate = sym("AIBinder_associateClass");
        if p_get_service.is_null() || p_class_define.is_null() || p_binder_new.is_null()
            || p_prepare_tx.is_null() || p_transact.is_null() || p_parcel_delete.is_null()
            || p_write_string.is_null() || p_write_binder.is_null() || p_write_i32.is_null()
            || p_read_i32.is_null() || p_read_string.is_null() || p_join.is_null() || p_start.is_null() || p_associate.is_null()
        { alog!("部分 dlsym 为 null"); return None; }
        
        alog!("所有 dlsym 成功");
        Some(BinderNdk {
            get_service: std::mem::transmute(p_get_service),
            class_define: std::mem::transmute(p_class_define),
            binder_new: std::mem::transmute(p_binder_new),
            prepare_tx: std::mem::transmute(p_prepare_tx),
            transact: std::mem::transmute(p_transact),
            parcel_delete: std::mem::transmute(p_parcel_delete),
            write_string: std::mem::transmute(p_write_string),
            write_binder: std::mem::transmute(p_write_binder),
            write_i32: std::mem::transmute(p_write_i32),
            read_i32: std::mem::transmute(p_read_i32),
            read_string: std::mem::transmute(p_read_string),
            join_thread_pool: std::mem::transmute(p_join),
            start_thread_pool: std::mem::transmute(p_start),
            associate_class: std::mem::transmute(p_associate),
        })
    }).as_ref()
}

const STATUS_OK: c_int = 0;
const STATUS_UNKNOWN_TRANSACTION: c_int = -29;

static PID_CACHE: LazyLock<Mutex<HashMap<i32, String>>> = LazyLock::new(|| Mutex::new(HashMap::new()));
static FG_EVENTFD: AtomicI32 = AtomicI32::new(-1);

struct SendClass(*mut c_void);
unsafe impl Send for SendClass {}
unsafe impl Sync for SendClass {}
static OBSERVER_CLASS: OnceLock<SendClass> = OnceLock::new();
static AM_CLASS: OnceLock<SendClass> = OnceLock::new();

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
    alog!("on_transact code=0x{:04x}", code);
    let ndk = match ndk() { Some(n) => n, None => return STATUS_UNKNOWN_TRANSACTION };

    // 读取 AIDL Interface Token (i32 strict mode + string descriptor)
    let mut strict_mode = 0i32;
    let sm_status = unsafe { (ndk.read_i32)(in_parcel, &mut strict_mode) };
    let token = read_string(in_parcel);
    alog!("  token: sm_status={} strict={} desc={:?}", sm_status, strict_mode, token);

    match code {
        TX_ON_PROCESS_STARTED => {
            let mut pid = 0i32;
            let mut process_uid = 0i32;
            let mut package_uid = 0i32;
            if unsafe { (ndk.read_i32)(in_parcel, &mut pid) } != STATUS_OK { return STATUS_UNKNOWN_TRANSACTION; }
            let _ = unsafe { (ndk.read_i32)(in_parcel, &mut process_uid) };
            let _ = unsafe { (ndk.read_i32)(in_parcel, &mut package_uid) };
            let package_name = read_string(in_parcel).unwrap_or_default();
            let _process_name = read_string(in_parcel).unwrap_or_default();
            alog!("onProcessStarted: pid={} pkg={} proc={}", pid, package_name, _process_name);
            PID_CACHE.lock().unwrap().insert(pid, package_name);
            STATUS_OK
        }
        TX_ON_FG_ACTIVITIES_CHANGED => {
            let mut pid = 0i32;
            let mut uid = 0i32;
            let mut fg_val = 0i32;

            let _ = unsafe { (ndk.read_i32)(in_parcel, &mut pid) };
            let _ = unsafe { (ndk.read_i32)(in_parcel, &mut uid) };
            let _ = unsafe { (ndk.read_i32)(in_parcel, &mut fg_val) };

            let fg = fg_val != 0;
            alog!("onFGChanged: pid={} uid={} fg={}", pid, uid, fg);

            if fg {
                let fd = FG_EVENTFD.load(Ordering::Acquire);
                alog!("  notifying eventfd={} pid={}", fd, pid);
                if fd >= 0 {
                    let val: u64 = pid as u64;
                    unsafe { libc::write(fd, &val as *const u64 as *const _, 8); }
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
            let mut pid = 0i32; let mut _uid = 0i32;
            let _ = unsafe { (ndk.read_i32)(in_parcel, &mut pid) };
            let _ = unsafe { (ndk.read_i32)(in_parcel, &mut _uid) };
            alog!("onProcessDied: pid={}", pid);
            PID_CACHE.lock().unwrap().remove(&pid);
            STATUS_OK
        }
        _ => { alog!("未知 code=0x{:04x}", code); STATUS_UNKNOWN_TRANSACTION }
    }
}

fn read_string(parcel: *mut c_void) -> Option<String> {
    let ndk = ndk()?;

    // 上下文：保存 allocator 分配的缓冲区指针和长度
    // AParcel_readString 流程：先调 allocator 分配 buffer → 再把字符串数据写入 buffer → 返回
    // allocator 返回 true=成功, false=失败(NDK 会返回 NO_MEMORY)
    struct StrCtx {
        buffer: *mut u8,
        length: i32,
    }

    extern "C" fn allocator(context: *mut c_void, buffer: *mut *mut c_char, length: i32) -> bool {
        let ctx = unsafe { &mut *(context as *mut StrCtx) };
        ctx.length = length;
        if length <= 0 {
            // 空字符串或 null，不需要分配
            return true;
        }
        // 分配 length + 1 字节（NDK 可能写入 null terminator）
        let buf = unsafe { libc::malloc((length as usize).saturating_add(1)) };
        if buf.is_null() {
            return false;
        }
        unsafe { *buffer = buf as *mut c_char; }
        ctx.buffer = buf as *mut u8;
        true
    }

    let mut ctx = StrCtx {
        buffer: std::ptr::null_mut(),
        length: 0,
    };
    let status = unsafe {
        (ndk.read_string)(parcel, &mut ctx as *mut _ as *mut c_void, Some(allocator))
    };
    alog!("  read_string: status={} length={} buf_null={}", status, ctx.length, ctx.buffer.is_null());

    let result = if status != STATUS_OK {
        None
    } else if ctx.length <= 0 || ctx.buffer.is_null() {
        Some(String::new())
    } else {
        let bytes =
            unsafe { std::slice::from_raw_parts(ctx.buffer, ctx.length as usize) };
        Some(String::from_utf8_lossy(bytes).into_owned())
    };

    if !ctx.buffer.is_null() {
        unsafe { libc::free(ctx.buffer as *mut libc::c_void) };
    }

    result
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

pub fn init_observer(eventfd: i32) -> bool {
    alog!("init_observer 开始, eventfd={}", eventfd);
    FG_EVENTFD.store(eventfd, Ordering::Release);
    
    let ndk = match ndk() { Some(n) => n, None => return false };
    let class = get_observer_class();
    if class.is_null() { return false; }
    
    let observer = unsafe { (ndk.binder_new)(class, std::ptr::null_mut()) };
    if observer.is_null() { return false; }
    alog!("observer=ok");
    
    let am = unsafe { (ndk.get_service)(b"activity\0".as_ptr() as *const c_char) };
    if am.is_null() { return false; }
    alog!("activity=ok");

    let am_class = get_am_class();
    if am_class.is_null() { return false; }
    let associated = unsafe { (ndk.associate_class)(am, am_class as *const c_void) };
    if !associated {
        alog!("associateClass for AM 失败");
        return false;
    }
    alog!("associateClass for AM = ok");
    
    // 【核心修复 2】：彻底删除 AParcel_create！
    // 让 prepare_tx 自动创建并正确关联 binder，避免 parcel is associated with binder object 报错
    let mut in_parcel: *mut c_void = std::ptr::null_mut();
    let prep_status = unsafe { (ndk.prepare_tx)(am, &mut in_parcel) };
    if prep_status != STATUS_OK || in_parcel.is_null() {
        alog!("prepareTransaction 失败: status={}", prep_status);
        return false;
    }
    alog!("prepareTransaction=ok");
    
    // NDK 的 prepareTransaction 已自动写入 Interface Token (UTF-16, 与 Java 端 enforceInterface 兼容)
    // 手动再写一次会导致双重 token → Java 端 readStrongBinder 读到第二个 token 而非 observer → 静默失败
    // 只需写入 observer binder 参数
    let _ = unsafe { (ndk.write_binder)(in_parcel, observer) };
    
    let mut out_parcel: *mut c_void = std::ptr::null_mut();
    let status = unsafe { (ndk.transact)(am, TX_REGISTER_PROCESS_OBSERVER, &mut in_parcel, &mut out_parcel, 0) };
    alog!("transact: status={}", status);
    
    // 检查 reply 中的异常码 (Java 端 enforceInterface/readStrongBinder 失败会返回异常)
    if status == STATUS_OK && !out_parcel.is_null() {
        let mut exception_code = 0i32;
        let _ = unsafe { (ndk.read_i32)(out_parcel, &mut exception_code) };
        alog!("reply exception_code={}", exception_code);
        if exception_code != 0 {
            alog!("服务端异常! 注册可能未生效");
        }
    }
    
    unsafe { (ndk.parcel_delete)(in_parcel) };
    if !out_parcel.is_null() { unsafe { (ndk.parcel_delete)(out_parcel) }; }
    
    if status == STATUS_OK {
        alog!("注册成功, 启动 binder 线程池");
        let start_fn = ndk.start_thread_pool;
        let join_fn = ndk.join_thread_pool;
        std::thread::spawn(move || {
            alog!("startThreadPool");
            unsafe { start_fn(); }
            alog!("joinThreadPool (阻塞)");
            unsafe { join_fn(); }
        });
        alog!("init_observer 完成");
        true
    } else {
        alog!("registerProcessObserver 失败 status={}", status);
        false
    }
}

pub fn get_package_name(pid: i32) -> Option<String> {
    PID_CACHE.lock().unwrap().get(&pid).cloned()
}