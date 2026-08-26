#![allow(dead_code)]
//! IProcessObserver binder 回调实现
//! 直接 #[link(name = "binder_ndk")]，build.rs 生成 stub 供链接期使用
//! 运行时由系统 libbinder_ndk.so 提供真实实现

use std::collections::HashMap;
use std::ffi::{c_char, c_void};
use std::sync::{LazyLock, Mutex, OnceLock};
use std::sync::atomic::{AtomicI32, Ordering};
use libc::c_int;

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

// ── libbinder_ndk FFI（build.rs 生成 stub 供链接，运行时由系统库覆盖）──
#[link(name = "binder_ndk")]
unsafe extern "C" {
    fn AServiceManager_getService(instance: *const c_char) -> *mut c_void;
    fn AIBinder_Class_new(
        interfaceDescriptor: *const c_char,
        onCreate: Option<extern "C" fn(*mut c_void) -> *mut c_void>,
        onDestroy: Option<extern "C" fn(*mut c_void)>,
        onTransact: Option<extern "C" fn(*mut c_void, u32, *const c_void, *mut c_void) -> c_int>,
    ) -> *mut c_void;
    fn AIBinder_new(clazz: *mut c_void, args: *mut c_void) -> *mut c_void;
    fn ABinder_prepareTransaction(binder: *mut c_void, inParcel: *mut *mut c_void) -> c_int;
    fn ABinder_transact(
        binder: *mut c_void,
        code: u32,
        inParcel: *const c_void,
        outParcel: *mut *mut c_void,
        flags: u32,
    ) -> c_int;
    fn AParcel_delete(parcel: *mut c_void);
    fn AParcel_writeInterfaceToken(parcel: *mut c_void, interface: *const c_char) -> c_int;
    fn AParcel_writeStrongBinder(parcel: *mut c_void, binder: *mut c_void) -> c_int;
    fn AParcel_readInt32(parcel: *const c_void, value: *mut i32) -> c_int;
    fn AParcel_readBool(parcel: *const c_void, value: *mut bool) -> c_int;
    fn AParcel_readString(
        parcel: *const c_void,
        context: *mut c_void,
        allocator: Option<extern "C" fn(*mut c_void, *const c_char, i32) -> c_int>,
    ) -> c_int;
    fn ABinder_joinThreadPool() -> c_int;
}

const STATUS_OK: c_int = 0;
const STATUS_UNKNOWN_TRANSACTION: c_int = -29;

static PID_CACHE: LazyLock<Mutex<HashMap<i32, String>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static FG_EVENTFD: AtomicI32 = AtomicI32::new(-1);

struct SendClass(*mut c_void);
unsafe impl Send for SendClass {}
unsafe impl Sync for SendClass {}
static OBSERVER_CLASS: OnceLock<SendClass> = OnceLock::new();

/// onTransact 回调
extern "C" fn on_transact(
    _binder: *mut c_void,
    code: u32,
    in_parcel: *const c_void,
    _out: *mut c_void,
) -> c_int {
    alog!("on_transact code=0x{:04x}", code);

    // 读取并丢弃 interface token
    let mut tmp = 0i32;
    let s1 = unsafe { AParcel_readInt32(in_parcel, &mut tmp) };
    let s2 = unsafe { AParcel_readInt32(in_parcel, &mut tmp) };
    let s3 = read_string(in_parcel);
    alog!("token: i32={} i32={} str={:?}", s1, s2, s3.as_deref().unwrap_or("(null)"));

    match code {
        TX_ON_PROCESS_STARTED => {
            alog!("匹配 onProcessStarted");
            let mut pid = 0i32;
            let mut process_uid = 0i32;
            let mut package_uid = 0i32;
            if unsafe { AParcel_readInt32(in_parcel, &mut pid) } != STATUS_OK {
                return STATUS_UNKNOWN_TRANSACTION;
            }
            let _ = unsafe { AParcel_readInt32(in_parcel, &mut process_uid) };
            let _ = unsafe { AParcel_readInt32(in_parcel, &mut package_uid) };
            let package_name = read_string(in_parcel).unwrap_or_default();
            let process_name = read_string(in_parcel).unwrap_or_default();
            alog!("onProcessStarted: pid={} pkg={} proc={}", pid, package_name, process_name);
            PID_CACHE.lock().unwrap().insert(pid, package_name);
            STATUS_OK
        }
        TX_ON_FG_ACTIVITIES_CHANGED => {
            alog!("匹配 onForegroundActivitiesChanged");
            let mut pid = 0i32;
            let mut uid = 0i32;
            let mut fg = false;
            let r1 = unsafe { AParcel_readInt32(in_parcel, &mut pid) };
            let r2 = unsafe { AParcel_readInt32(in_parcel, &mut uid) };
            let r3 = unsafe { AParcel_readBool(in_parcel, &mut fg) };
            alog!("onFGChanged: pid={} uid={} fg={} (r={} {} {})", pid, uid, fg, r1, r2, r3);
            if fg {
                let fd = FG_EVENTFD.load(Ordering::Acquire);
                alog!("fg=true, eventfd={}, 写入 pid={}", fd, pid);
                if fd >= 0 {
                    let val: u64 = pid as u64;
                    unsafe { libc::write(fd, &val as *const u64 as *const _, 8); }
                }
            }
            STATUS_OK
        }
        TX_ON_FG_SERVICES_CHANGED => {
            alog!("匹配 onForegroundServicesChanged");
            let mut _pid = 0i32;
            let mut _uid = 0i32;
            let mut _st = 0i32;
            let _ = unsafe { AParcel_readInt32(in_parcel, &mut _pid) };
            let _ = unsafe { AParcel_readInt32(in_parcel, &mut _uid) };
            let _ = unsafe { AParcel_readInt32(in_parcel, &mut _st) };
            STATUS_OK
        }
        TX_ON_PROCESS_DIED => {
            alog!("匹配 onProcessDied");
            let mut pid = 0i32;
            let mut _uid = 0i32;
            let _ = unsafe { AParcel_readInt32(in_parcel, &mut pid) };
            let _ = unsafe { AParcel_readInt32(in_parcel, &mut _uid) };
            alog!("onProcessDied: pid={}", pid);
            PID_CACHE.lock().unwrap().remove(&pid);
            STATUS_OK
        }
        _ => {
            alog!("未知 code=0x{:04x}", code);
            STATUS_UNKNOWN_TRANSACTION
        }
    }
}

fn read_string(parcel: *const c_void) -> Option<String> {
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
    let _ = unsafe { AParcel_readString(parcel, &mut result as *mut _ as *mut c_void, Some(allocator)) };
    result
}

fn get_observer_class() -> *mut c_void {
    OBSERVER_CLASS.get_or_init(|| {
        alog!("AIBinder_Class_new ...");
        let class = unsafe {
            AIBinder_Class_new(
                b"android.app.IProcessObserver\0".as_ptr() as *const c_char,
                None,
                None,
                Some(on_transact),
            )
        };
        alog!("AIBinder_Class_new = {}", if class.is_null() { "null" } else { "ok" });
        SendClass(class)
    }).0
}

pub fn init_observer(eventfd: i32) -> bool {
    alog!("init_observer 开始, eventfd={}", eventfd);
    FG_EVENTFD.store(eventfd, Ordering::Release);

    let class = get_observer_class();
    if class.is_null() {
        alog!("class=null");
        return false;
    }

    alog!("AIBinder_new ...");
    let observer = unsafe { AIBinder_new(class, std::ptr::null_mut()) };
    if observer.is_null() {
        alog!("AIBinder_new = null");
        return false;
    }
    alog!("observer=ok");

    alog!("AServiceManager_getService(activity) ...");
    let am = unsafe { AServiceManager_getService(b"activity\0".as_ptr() as *const c_char) };
    if am.is_null() {
        alog!("getService(activity) = null");
        return false;
    }
    alog!("activity=ok");

    let mut in_parcel: *mut c_void = std::ptr::null_mut();
    let status = unsafe { ABinder_prepareTransaction(am, &mut in_parcel) };
    alog!("prepareTx: status={} parcel_null={}", status, in_parcel.is_null());
    if status != STATUS_OK || in_parcel.is_null() {
        return false;
    }

    let r1 = unsafe { AParcel_writeInterfaceToken(in_parcel, b"android.app.IActivityManager\0".as_ptr() as *const c_char) };
    let r2 = unsafe { AParcel_writeStrongBinder(in_parcel, observer) };
    alog!("writeToken={} writeBinder={}", r1, r2);

    let code = TX_REGISTER_PROCESS_OBSERVER;
    let mut out_parcel: *mut c_void = std::ptr::null_mut();
    alog!("transact code=0x{:04x} ...", code);
    let status = unsafe { ABinder_transact(am, code, in_parcel, &mut out_parcel, 0) };
    alog!("transact: status={}", status);

    unsafe { AParcel_delete(in_parcel) };
    if !out_parcel.is_null() {
        unsafe { AParcel_delete(out_parcel) };
    }

    if status == STATUS_OK {
        alog!("注册成功, 启动 binder 线程池 ...");
        std::thread::spawn(|| {
            alog!("binder 线程池启动, 调用 ABinder_joinThreadPool");
            unsafe { ABinder_joinThreadPool(); }
            alog!("ABinder_joinThreadPool 返回 (不应发生)");
        });
        alog!("init_observer 完成");
        true
    } else {
        alog!("registerProcessObserver 失败 status={}", status);
        true
    }
}

pub fn get_package_name(pid: i32) -> Option<String> {
    let r = PID_CACHE.lock().unwrap().get(&pid).cloned();
    alog!("get_package_name({}) = {:?}", pid, r);
    r
}