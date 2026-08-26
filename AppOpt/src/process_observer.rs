#![allow(dead_code)]
//! IProcessObserver binder 回调实现（dlopen 运行时加载 libbinder_ndk.so）
//!
//! 事务码硬编码：
//!   registerProcessObserver          = 0x0d
//!   onProcessStarted                 = 0x01
//!   onForegroundActivitiesChanged   = 0x02
//!   onForegroundServicesChanged      = 0x03
//!   onProcessDied                   = 0x04

use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::{LazyLock, Mutex, OnceLock};
use std::sync::atomic::{AtomicI32, Ordering};
use libc::{c_char, c_int, dlopen, dlsym, RTLD_LAZY};

// ── 硬编码事务码 ──
const TX_REGISTER_PROCESS_OBSERVER: u32 = 0x0d;
const TX_ON_PROCESS_STARTED: u32 = 0x01;
const TX_ON_FG_ACTIVITIES_CHANGED: u32 = 0x02;
const TX_ON_FG_SERVICES_CHANGED: u32 = 0x03;
const TX_ON_PROCESS_DIED: u32 = 0x04;

// ── FFI 类型 ──
type AIBinder = c_void;
type AIBinderClass = c_void;
type AParcel = c_void;

type FnGetService = unsafe extern "C" fn(*const c_char) -> *mut AIBinder;
type FnClassNew = unsafe extern "C" fn(
    *const c_char,
    Option<extern "C" fn(*mut c_void) -> *mut c_void>,
    Option<extern "C" fn(*mut c_void)>,
    Option<extern "C" fn(*mut AIBinder, u32, *const AParcel, *mut AParcel) -> c_int>,
) -> *mut AIBinderClass;
type FnBinderNew = unsafe extern "C" fn(*mut AIBinderClass, *mut c_void) -> *mut AIBinder;
type FnPrepareTx = unsafe extern "C" fn(*mut AIBinder, *mut *mut AParcel) -> c_int;
type FnTransact = unsafe extern "C" fn(*mut AIBinder, u32, *const AParcel, *mut *mut AParcel, u32) -> c_int;
type FnParcelDelete = unsafe extern "C" fn(*mut AParcel);
type FnWriteToken = unsafe extern "C" fn(*mut AParcel, *const c_char) -> c_int;
type FnWriteBinder = unsafe extern "C" fn(*mut AParcel, *mut AIBinder) -> c_int;
type FnReadI32 = unsafe extern "C" fn(*const AParcel, *mut i32) -> c_int;
type FnReadBool = unsafe extern "C" fn(*const AParcel, *mut bool) -> c_int;
type FnReadString = unsafe extern "C" fn(
    *const AParcel,
    *mut c_void,
    Option<extern "C" fn(*mut c_void, *const c_char, i32) -> c_int>,
) -> c_int;
type FnJoinThreadPool = unsafe extern "C" fn() -> c_int;

struct BinderNdk {
    get_service: FnGetService,
    class_new: FnClassNew,
    binder_new: FnBinderNew,
    prepare_tx: FnPrepareTx,
    transact: FnTransact,
    parcel_delete: FnParcelDelete,
    write_token: FnWriteToken,
    write_binder: FnWriteBinder,
    read_i32: FnReadI32,
    read_bool: FnReadBool,
    read_string: FnReadString,
    join_thread_pool: FnJoinThreadPool,
}

static BINDER_NDK: OnceLock<Option<BinderNdk>> = OnceLock::new();

fn ndk() -> Option<&'static BinderNdk> {
    BINDER_NDK.get_or_init(|| unsafe {
        eprintln!("刷新率dbg: dlopen libbinder_ndk.so ...");
        let lib = dlopen(b"libbinder_ndk.so\0".as_ptr() as *const c_char, RTLD_LAZY);
        if lib.is_null() {
            eprintln!("刷新率dbg: dlopen 失败");
            return None;
        }
        eprintln!("刷新率dbg: dlopen 成功, 开始 dlsym");

        let sym = |name: &[u8]| -> *mut c_void {
            let mut buf = [0u8; 64];
            let n = name.len().min(63);
            buf[..n].copy_from_slice(&name[..n]);
            buf[n] = 0;
            dlsym(lib, buf.as_ptr() as *const c_char)
        };

        let p_get_service = sym(b"AServiceManager_getService");
        let p_class_new = sym(b"AIBinder_Class_new");
        let p_binder_new = sym(b"AIBinder_new");
        let p_prepare_tx = sym(b"ABinder_prepareTransaction");
        let p_transact = sym(b"ABinder_transact");
        let p_parcel_delete = sym(b"AParcel_delete");
        let p_write_token = sym(b"AParcel_writeInterfaceToken");
        let p_write_binder = sym(b"AParcel_writeStrongBinder");
        let p_read_i32 = sym(b"AParcel_readInt32");
        let p_read_bool = sym(b"AParcel_readBool");
        let p_read_string = sym(b"AParcel_readString");
        let p_join = sym(b"ABinder_joinThreadPool");

        eprintln!(
            "刷新率dbg: dlsym 结果 get_service={} class_new={} binder_new={} prepare={} transact={} delete={} wtoken={} wbinder={} ri32={} rbool={} rstr={} join={}",
            p_get_service.is_null(), p_class_new.is_null(), p_binder_new.is_null(),
            p_prepare_tx.is_null(), p_transact.is_null(), p_parcel_delete.is_null(),
            p_write_token.is_null(), p_write_binder.is_null(),
            p_read_i32.is_null(), p_read_bool.is_null(), p_read_string.is_null(),
            p_join.is_null()
        );

        if p_get_service.is_null() || p_class_new.is_null() || p_binder_new.is_null()
            || p_prepare_tx.is_null() || p_transact.is_null() || p_parcel_delete.is_null()
            || p_write_token.is_null() || p_write_binder.is_null()
            || p_read_i32.is_null() || p_read_bool.is_null() || p_read_string.is_null()
            || p_join.is_null()
        {
            eprintln!("刷新率dbg: 部分 dlsym 为 null, 放弃");
            return None;
        }

        eprintln!("刷新率dbg: 所有 dlsym 成功");
        Some(BinderNdk {
            get_service: std::mem::transmute(p_get_service),
            class_new: std::mem::transmute(p_class_new),
            binder_new: std::mem::transmute(p_binder_new),
            prepare_tx: std::mem::transmute(p_prepare_tx),
            transact: std::mem::transmute(p_transact),
            parcel_delete: std::mem::transmute(p_parcel_delete),
            write_token: std::mem::transmute(p_write_token),
            write_binder: std::mem::transmute(p_write_binder),
            read_i32: std::mem::transmute(p_read_i32),
            read_bool: std::mem::transmute(p_read_bool),
            read_string: std::mem::transmute(p_read_string),
            join_thread_pool: std::mem::transmute(p_join),
        })
    }).as_ref()
}

const STATUS_OK: c_int = 0;
const STATUS_UNKNOWN_TRANSACTION: c_int = -29;

static PID_CACHE: LazyLock<Mutex<HashMap<i32, String>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static FG_EVENTFD: AtomicI32 = AtomicI32::new(-1);

struct SendClass(*mut AIBinderClass);
unsafe impl Send for SendClass {}
unsafe impl Sync for SendClass {}
static OBSERVER_CLASS: OnceLock<SendClass> = OnceLock::new();

/// onTransact 回调
extern "C" fn on_transact(
    _binder: *mut AIBinder,
    code: u32,
    in_parcel: *const AParcel,
    _out: *mut AParcel,
) -> c_int {
    eprintln!("刷新率dbg: on_transact 收到 code=0x{:04x}", code);

    let ndk = match ndk() {
        Some(n) => n,
        None => {
            eprintln!("刷新率dbg: on_transact ndk()=None");
            return STATUS_UNKNOWN_TRANSACTION;
        }
    };

    // 读取并丢弃 interface token (strict policy + work source + descriptor string)
    let mut tmp = 0i32;
    let s1 = unsafe { (ndk.read_i32)(in_parcel, &mut tmp) };
    let s2 = unsafe { (ndk.read_i32)(in_parcel, &mut tmp) };
    let s3 = read_string(in_parcel);
    eprintln!("刷新率dbg: interface token 读取 i32={} i32={} str={:?}", s1, s2, s3.as_deref().unwrap_or("(null)"));

    match code {
        TX_ON_PROCESS_STARTED => {
            eprintln!("刷新率dbg: 匹配 onProcessStarted");
            let mut pid = 0i32;
            let mut process_uid = 0i32;
            let mut package_uid = 0i32;
            if unsafe { (ndk.read_i32)(in_parcel, &mut pid) } != STATUS_OK {
                eprintln!("刷新率dbg: onProcessStarted read pid 失败");
                return STATUS_UNKNOWN_TRANSACTION;
            }
            let _ = unsafe { (ndk.read_i32)(in_parcel, &mut process_uid) };
            let _ = unsafe { (ndk.read_i32)(in_parcel, &mut package_uid) };
            let package_name = read_string(in_parcel).unwrap_or_default();
            let process_name = read_string(in_parcel).unwrap_or_default();
            eprintln!("刷新率dbg: onProcessStarted pid={} pkg={} proc={}", pid, package_name, process_name);
            PID_CACHE.lock().unwrap().insert(pid, package_name);
            STATUS_OK
        }
        TX_ON_FG_ACTIVITIES_CHANGED => {
            eprintln!("刷新率dbg: 匹配 onForegroundActivitiesChanged");
            let mut pid = 0i32;
            let mut uid = 0i32;
            let mut fg = false;
            let r1 = unsafe { (ndk.read_i32)(in_parcel, &mut pid) };
            let r2 = unsafe { (ndk.read_i32)(in_parcel, &mut uid) };
            let r3 = unsafe { (ndk.read_bool)(in_parcel, &mut fg) };
            eprintln!("刷新率dbg: onFGChanged pid={} uid={} fg={} (r={} {} {})", pid, uid, fg, r1, r2, r3);
            if fg {
                let fd = FG_EVENTFD.load(Ordering::Acquire);
                eprintln!("刷新率dbg: fg=true, eventfd={}, 写入 pid={}", fd, pid);
                if fd >= 0 {
                    let val: u64 = pid as u64;
                    unsafe { libc::write(fd, &val as *const u64 as *const _, 8); }
                }
            }
            STATUS_OK
        }
        TX_ON_FG_SERVICES_CHANGED => {
            eprintln!("刷新率dbg: 匹配 onForegroundServicesChanged");
            let mut _pid = 0i32;
            let mut _uid = 0i32;
            let mut _st = 0i32;
            let _ = unsafe { (ndk.read_i32)(in_parcel, &mut _pid) };
            let _ = unsafe { (ndk.read_i32)(in_parcel, &mut _uid) };
            let _ = unsafe { (ndk.read_i32)(in_parcel, &mut _st) };
            STATUS_OK
        }
        TX_ON_PROCESS_DIED => {
            eprintln!("刷新率dbg: 匹配 onProcessDied");
            let mut pid = 0i32;
            let mut _uid = 0i32;
            let _ = unsafe { (ndk.read_i32)(in_parcel, &mut pid) };
            let _ = unsafe { (ndk.read_i32)(in_parcel, &mut _uid) };
            eprintln!("刷新率dbg: onProcessDied pid={}", pid);
            PID_CACHE.lock().unwrap().remove(&pid);
            STATUS_OK
        }
        _ => {
            eprintln!("刷新率dbg: 未知 code=0x{:04x}, 返回 UNKNOWN_TRANSACTION", code);
            STATUS_UNKNOWN_TRANSACTION
        }
    }
}

fn read_string(parcel: *const AParcel) -> Option<String> {
    let ndk = ndk()?;
    let mut result: Option<String> = None;

    extern "C" fn allocator(context: *mut c_void, buffer: *const c_char, length: i32) -> c_int {
        let result = unsafe { &mut *(context as *mut Option<String>) };
        if buffer.is_null() || length < 0 {
            *result = None;
        } else {
            let bytes = unsafe { std::slice::from_raw_parts(buffer as *const u8, length as usize) };
            *result = Some(String::from_utf8_lossy(bytes).into_owned());
        }
        0
    }

    let _ = unsafe { (ndk.read_string)(parcel, &mut result as *mut _ as *mut c_void, Some(allocator)) };
    result
}

fn get_observer_class() -> *mut AIBinderClass {
    let ndk = match ndk() {
        Some(n) => n,
        None => return std::ptr::null_mut(),
    };
    OBSERVER_CLASS.get_or_init(|| {
        eprintln!("刷新率dbg: AIBinder_Class_new ...");
        let class = unsafe {
            (ndk.class_new)(
                b"android.app.IProcessObserver\0".as_ptr() as *const c_char,
                None,
                None,
                Some(on_transact),
            )
        };
        eprintln!("刷新率dbg: AIBinder_Class_new 返回 {}", if class.is_null() { "null" } else { "ok" });
        SendClass(class)
    }).0
}

pub fn init_observer(eventfd: i32) -> bool {
    eprintln!("刷新率dbg: init_observer 开始, eventfd={}", eventfd);
    FG_EVENTFD.store(eventfd, Ordering::Release);

    let ndk = match ndk() {
        Some(n) => n,
        None => {
            eprintln!("刷新率dbg: ndk()=None, 无法加载 libbinder_ndk.so");
            return false;
        }
    };

    let class = get_observer_class();
    if class.is_null() {
        eprintln!("刷新率dbg: class=null, 放弃");
        return false;
    }
    eprintln!("刷新率dbg: class=ok, 创建 AIBinder ...");
    let observer = unsafe { (ndk.binder_new)(class, std::ptr::null_mut()) };
    if observer.is_null() {
        eprintln!("刷新率dbg: AIBinder_new 返回 null");
        return false;
    }
    eprintln!("刷新率dbg: observer=ok, 获取 activity 服务 ...");

    let am = unsafe { (ndk.get_service)(b"activity\0".as_ptr() as *const c_char) };
    if am.is_null() {
        eprintln!("刷新率dbg: AServiceManager_getService(activity) 返回 null");
        return false;
    }
    eprintln!("刷新率dbg: activity 服务=ok, 构造事务 ...");

    let mut in_parcel: *mut AParcel = std::ptr::null_mut();
    let status = unsafe { (ndk.prepare_tx)(am, &mut in_parcel) };
    eprintln!("刷新率dbg: prepareTx status={} parcel_null={}", status, in_parcel.is_null());
    if status != STATUS_OK || in_parcel.is_null() {
        return false;
    }

    let r1 = unsafe { (ndk.write_token)(in_parcel, b"android.app.IActivityManager\0".as_ptr() as *const c_char) };
    let r2 = unsafe { (ndk.write_binder)(in_parcel, observer) };
    eprintln!("刷新率dbg: writeToken={} writeBinder={}", r1, r2);

    let code = TX_REGISTER_PROCESS_OBSERVER;
    let mut out_parcel: *mut AParcel = std::ptr::null_mut();
    eprintln!("刷新率dbg: transact code=0x{:04x} ...", code);
    let status = unsafe { (ndk.transact)(am, code, in_parcel, &mut out_parcel, 0) };
    eprintln!("刷新率dbg: transact status={}", status);

    unsafe { (ndk.parcel_delete)(in_parcel) };
    if !out_parcel.is_null() {
        unsafe { (ndk.parcel_delete)(out_parcel) };
    }

    if status == STATUS_OK {
        eprintln!("刷新率dbg: 注册成功, 启动 binder 线程池 ...");
        let join_fn = ndk.join_thread_pool;
        std::thread::spawn(move || {
            eprintln!("刷新率dbg: binder 线程池线程启动, 调用 ABinder_joinThreadPool");
            unsafe { join_fn(); }
            eprintln!("刷新率dbg: ABinder_joinThreadPool 返回 (不应发生)");
        });
        eprintln!("刷新率dbg: init_observer 完成");
        true
    } else {
        eprintln!("刷新率dbg: registerProcessObserver 失败 status={}", status);
        true
    }
}

pub fn get_package_name(pid: i32) -> Option<String> {
    let r = PID_CACHE.lock().unwrap().get(&pid).cloned();
    eprintln!("刷新率dbg: get_package_name({}) = {:?}", pid, r);
    r
}