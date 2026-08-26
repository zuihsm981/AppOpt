#![allow(dead_code, non_snake_case, non_upper_case_globals)]
//! IProcessObserver binder 回调实现（dlopen 运行时加载 libbinder_ndk.so）
//!
//! libbinder_ndk.so 是 Android 系统库，NDK sysroot 中无链接用 stub，
//! 因此用 dlopen/dlsym 运行时加载，避免链接期 -lbinder_ndk 找不到的错误。

use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::{LazyLock, Mutex, OnceLock};
use std::sync::atomic::{AtomicI32, Ordering};
use libc::{c_char, c_int, dlopen, dlsym, RTLD_LAZY};

include!(concat!(env!("OUT_DIR"), "/aidl_transactions.rs"));

// ── FFI 类型 ──
type AIBinder = c_void;
type AIBinderClass = c_void;
type AParcel = c_void;

// ── 函数指针类型 ──
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

/// dlopen 加载的 libbinder_ndk 函数指针集合
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
}

static BINDER_NDK: OnceLock<Option<BinderNdk>> = OnceLock::new();

/// 加载 libbinder_ndk.so，返回函数指针集合的引用
fn ndk() -> Option<&'static BinderNdk> {
    BINDER_NDK.get_or_init(|| unsafe {
        let lib = dlopen(b"libbinder_ndk.so\0".as_ptr() as *const c_char, RTLD_LAZY);
        if lib.is_null() {
            return None;
        }

        let sym = |name: &[u8]| -> *mut c_void {
            let mut buf = [0u8; 64];
            let n = name.len().min(63);
            buf[..n].copy_from_slice(&name[..n]);
            buf[n] = 0;
            dlsym(lib, buf.as_ptr() as *const c_char)
        };

        let get_service: FnGetService = std::mem::transmute(sym(b"AServiceManager_getService"));
        let class_new: FnClassNew = std::mem::transmute(sym(b"AIBinder_Class_new"));
        let binder_new: FnBinderNew = std::mem::transmute(sym(b"AIBinder_new"));
        let prepare_tx: FnPrepareTx = std::mem::transmute(sym(b"ABinder_prepareTransaction"));
        let transact: FnTransact = std::mem::transmute(sym(b"ABinder_transact"));
        let parcel_delete: FnParcelDelete = std::mem::transmute(sym(b"AParcel_delete"));
        let write_token: FnWriteToken = std::mem::transmute(sym(b"AParcel_writeInterfaceToken"));
        let write_binder: FnWriteBinder = std::mem::transmute(sym(b"AParcel_writeStrongBinder"));
        let read_i32: FnReadI32 = std::mem::transmute(sym(b"AParcel_readInt32"));
        let read_bool: FnReadBool = std::mem::transmute(sym(b"AParcel_readBool"));
        let read_string: FnReadString = std::mem::transmute(sym(b"AParcel_readString"));

        if get_service.is_null() || class_new.is_null() || binder_new.is_null()
            || prepare_tx.is_null() || transact.is_null() || parcel_delete.is_null()
            || write_token.is_null() || write_binder.is_null()
            || read_i32.is_null() || read_bool.is_null() || read_string.is_null()
        {
            return None;
        }

        Some(BinderNdk {
            get_service, class_new, binder_new, prepare_tx, transact,
            parcel_delete, write_token, write_binder, read_i32, read_bool, read_string,
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
    let ndk = match ndk() {
        Some(n) => n,
        None => return STATUS_UNKNOWN_TRANSACTION,
    };

    // 读取并丢弃 interface token
    let mut tmp = 0i32;
    let _ = unsafe { (ndk.read_i32)(in_parcel, &mut tmp) };
    let _ = unsafe { (ndk.read_i32)(in_parcel, &mut tmp) };
    let _ = read_string(in_parcel);

    match code {
        c if c == aidl::IProcessObserver::TRANSACTION_onProcessStarted => {
            let mut pid = 0i32;
            let mut process_uid = 0i32;
            let mut package_uid = 0i32;
            if unsafe { (ndk.read_i32)(in_parcel, &mut pid) } != STATUS_OK {
                return STATUS_UNKNOWN_TRANSACTION;
            }
            let _ = unsafe { (ndk.read_i32)(in_parcel, &mut process_uid) };
            let _ = unsafe { (ndk.read_i32)(in_parcel, &mut package_uid) };
            let package_name = read_string(in_parcel).unwrap_or_default();
            let _ = read_string(in_parcel);
            PID_CACHE.lock().unwrap().insert(pid, package_name);
            STATUS_OK
        }
        c if c == aidl::IProcessObserver::TRANSACTION_onForegroundActivitiesChanged => {
            let mut pid = 0i32;
            let mut uid = 0i32;
            let mut fg = false;
            let _ = unsafe { (ndk.read_i32)(in_parcel, &mut pid) };
            let _ = unsafe { (ndk.read_i32)(in_parcel, &mut uid) };
            let _ = unsafe { (ndk.read_bool)(in_parcel, &mut fg) };
            if fg {
                let fd = FG_EVENTFD.load(Ordering::Acquire);
                if fd >= 0 {
                    let val: u64 = pid as u64;
                    unsafe { libc::write(fd, &val as *const u64 as *const _, 8); }
                }
            }
            STATUS_OK
        }
        c if c == aidl::IProcessObserver::TRANSACTION_onForegroundServicesChanged => {
            let mut _pid = 0i32;
            let mut _uid = 0i32;
            let mut _st = 0i32;
            let _ = unsafe { (ndk.read_i32)(in_parcel, &mut _pid) };
            let _ = unsafe { (ndk.read_i32)(in_parcel, &mut _uid) };
            let _ = unsafe { (ndk.read_i32)(in_parcel, &mut _st) };
            STATUS_OK
        }
        c if c == aidl::IProcessObserver::TRANSACTION_onProcessDied => {
            let mut pid = 0i32;
            let mut _uid = 0i32;
            let _ = unsafe { (ndk.read_i32)(in_parcel, &mut pid) };
            let _ = unsafe { (ndk.read_i32)(in_parcel, &mut _uid) };
            PID_CACHE.lock().unwrap().remove(&pid);
            STATUS_OK
        }
        _ => STATUS_UNKNOWN_TRANSACTION,
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
        let class = unsafe {
            (ndk.class_new)(
                b"android.app.IProcessObserver\0".as_ptr() as *const c_char,
                None,
                None,
                Some(on_transact),
            )
        };
        SendClass(class)
    }).0
}

pub fn init_observer(eventfd: i32) -> bool {
    FG_EVENTFD.store(eventfd, Ordering::Release);

    let ndk = match ndk() {
        Some(n) => n,
        None => {
            eprintln!("刷新率: 无法加载 libbinder_ndk.so");
            return false;
        }
    };

    let class = get_observer_class();
    if class.is_null() {
        eprintln!("刷新率: AIBinder_Class_new 失败");
        return false;
    }
    let observer = unsafe { (ndk.binder_new)(class, std::ptr::null_mut()) };
    if observer.is_null() {
        eprintln!("刷新率: AIBinder_new 失败");
        return false;
    }

    let am = unsafe { (ndk.get_service)(b"activity\0".as_ptr() as *const c_char) };
    if am.is_null() {
        eprintln!("刷新率: 无法获取 activity 服务");
        return false;
    }

    let mut in_parcel: *mut AParcel = std::ptr::null_mut();
    let status = unsafe { (ndk.prepare_tx)(am, &mut in_parcel) };
    if status != STATUS_OK || in_parcel.is_null() {
        eprintln!("刷新率: ABinder_prepareTransaction 失败 ({})", status);
        return false;
    }

    let _ = unsafe { (ndk.write_token)(in_parcel, b"android.app.IActivityManager\0".as_ptr() as *const c_char) };
    let _ = unsafe { (ndk.write_binder)(in_parcel, observer) };

    let code = aidl::IActivityManager::TRANSACTION_registerProcessObserver;
    let mut out_parcel: *mut AParcel = std::ptr::null_mut();
    let status = unsafe { (ndk.transact)(am, code, in_parcel, &mut out_parcel, 0) };

    unsafe { (ndk.parcel_delete)(in_parcel) };
    if !out_parcel.is_null() {
        unsafe { (ndk.parcel_delete)(out_parcel) };
    }

    if status == STATUS_OK {
        eprintln!("刷新率: IProcessObserver 已注册 (事务码 0x{:04x})", code);
        true
    } else {
        eprintln!("刷新率: registerProcessObserver 失败 ({})", status);
        true
    }
}

pub fn get_package_name(pid: i32) -> Option<String> {
    PID_CACHE.lock().unwrap().get(&pid).cloned()
}