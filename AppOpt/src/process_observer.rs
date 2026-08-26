//! IProcessObserver binder 回调实现（FFI 直连 libbinder_ndk.so）
//!
//! 不依赖 crates.io 的 binder crate（它不是 AOSP binder crate，缺少
//! Interface/Parcel/IBinder 等类型），也不使用 declare_binder_interface! 宏。
//!
//! TRANSACTION_* 常量由 build.rs 从 AIDL 文件编译时生成，事务码来源唯一。

use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::{LazyLock, Mutex, OnceLock};
use std::sync::atomic::{AtomicI32, Ordering};

use libc::{c_char, c_int};

// build.rs 从 AIDL 文件生成的 TRANSACTION_* 常量（模块名 aidl 避免与 trait 冲突）
include!(concat!(env!("OUT_DIR"), "/aidl_transactions.rs"));

// ── FFI 类型 ──
type AIBinder = c_void;
type AIBinderClass = c_void;
type AParcel = c_void;

// ── libbinder_ndk.so 函数声明 ──
#[link(name = "binder_ndk")]
unsafe extern "C" {
    fn AServiceManager_getService(instance: *const c_char) -> *mut AIBinder;
    fn AIBinder_Class_new(
        interfaceDescriptor: *const c_char,
        onCreate: Option<extern "C" fn(*mut c_void) -> *mut c_void>,
        onDestroy: Option<extern "C" fn(*mut c_void)>,
        onTransact: Option<extern "C" fn(*mut AIBinder, u32, *const AParcel, *mut AParcel) -> c_int>,
    ) -> *mut AIBinderClass;
    fn AIBinder_new(clazz: *mut AIBinderClass, args: *mut c_void) -> *mut AIBinder;
    fn ABinder_prepareTransaction(binder: *mut AIBinder, in_parcel: *mut *mut AParcel) -> c_int;
    fn ABinder_transact(
        binder: *mut AIBinder,
        code: u32,
        in_parcel: *const AParcel,
        out_parcel: *mut *mut AParcel,
        flags: u32,
    ) -> c_int;
    fn AParcel_delete(parcel: *mut AParcel);
    fn AParcel_writeInterfaceToken(parcel: *mut AParcel, interface: *const c_char) -> c_int;
    fn AParcel_writeStrongBinder(parcel: *mut AParcel, binder: *mut AIBinder) -> c_int;
    fn AParcel_readInt32(parcel: *const AParcel, value: *mut i32) -> c_int;
    fn AParcel_readBool(parcel: *const AParcel, value: *mut bool) -> c_int;
    fn AParcel_readString(
        parcel: *const AParcel,
        context: *mut c_void,
        allocator: Option<extern "C" fn(*mut c_void, *const c_char, i32) -> c_int>,
    ) -> c_int;
}

const STATUS_OK: c_int = 0;
const STATUS_UNKNOWN_TRANSACTION: c_int = -29;

// ── 状态 ──
static PID_CACHE: LazyLock<Mutex<HashMap<i32, String>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static FG_EVENTFD: AtomicI32 = AtomicI32::new(-1);

// ── AIBinder_Class 单例（线程安全 OnceLock）──
struct SendClass(*mut AIBinderClass);
unsafe impl Send for SendClass {}
unsafe impl Sync for SendClass {}

static OBSERVER_CLASS: OnceLock<SendClass> = OnceLock::new();

/// onTransact 回调：AMS 调用 IProcessObserver 方法时触发
extern "C" fn on_transact(
    _binder: *mut AIBinder,
    code: u32,
    in_parcel: *const AParcel,
    _out: *mut AParcel,
) -> c_int {
    // 读取并丢弃 interface token（strict policy + version + descriptor string）
    let mut tmp = 0i32;
    let _ = unsafe { AParcel_readInt32(in_parcel, &mut tmp) };
    let _ = unsafe { AParcel_readInt32(in_parcel, &mut tmp) };
    let _ = read_string(in_parcel);

    match code {
        c if c == aidl::IProcessObserver::TRANSACTION_onProcessStarted => {
            let mut pid = 0i32;
            let mut process_uid = 0i32;
            let mut package_uid = 0i32;
            if unsafe { AParcel_readInt32(in_parcel, &mut pid) } != STATUS_OK {
                return STATUS_UNKNOWN_TRANSACTION;
            }
            let _ = unsafe { AParcel_readInt32(in_parcel, &mut process_uid) };
            let _ = unsafe { AParcel_readInt32(in_parcel, &mut package_uid) };
            let package_name = read_string(in_parcel).unwrap_or_default();
            let _process_name = read_string(in_parcel);

            PID_CACHE.lock().unwrap().insert(pid, package_name);
            STATUS_OK
        }
        c if c == aidl::IProcessObserver::TRANSACTION_onForegroundActivitiesChanged => {
            let mut pid = 0i32;
            let mut uid = 0i32;
            let mut fg = false;
            let _ = unsafe { AParcel_readInt32(in_parcel, &mut pid) };
            let _ = unsafe { AParcel_readInt32(in_parcel, &mut uid) };
            let _ = unsafe { AParcel_readBool(in_parcel, &mut fg) };

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
            // 读取参数但不处理
            let mut _pid = 0i32;
            let mut _uid = 0i32;
            let mut _st = 0i32;
            let _ = unsafe { AParcel_readInt32(in_parcel, &mut _pid) };
            let _ = unsafe { AParcel_readInt32(in_parcel, &mut _uid) };
            let _ = unsafe { AParcel_readInt32(in_parcel, &mut _st) };
            STATUS_OK
        }
        c if c == aidl::IProcessObserver::TRANSACTION_onProcessDied => {
            let mut pid = 0i32;
            let mut _uid = 0i32;
            let _ = unsafe { AParcel_readInt32(in_parcel, &mut pid) };
            let _ = unsafe { AParcel_readInt32(in_parcel, &mut _uid) };

            PID_CACHE.lock().unwrap().remove(&pid);
            STATUS_OK
        }
        _ => STATUS_UNKNOWN_TRANSACTION,
    }
}

/// 从 Parcel 读取 UTF-8 字符串（通过 allocator 回调）
fn read_string(parcel: *const AParcel) -> Option<String> {
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

    let _ = unsafe {
        AParcel_readString(
            parcel,
            &mut result as *mut Option<String> as *mut c_void,
            Some(allocator),
        )
    };
    result
}

/// 获取或创建 IProcessObserver 的 AIBinder_Class 单例
fn get_observer_class() -> *mut AIBinderClass {
    OBSERVER_CLASS.get_or_init(|| {
        let class = unsafe {
            AIBinder_Class_new(
                b"android.app.IProcessObserver\0".as_ptr() as *const c_char,
                None,  // onCreate: 不需要
                None,  // onDestroy: 不需要
                Some(on_transact),
            )
        };
        SendClass(class)
    }).0
}

/// 初始化 IProcessObserver 并向 ActivityManagerService 注册
pub fn init_observer(eventfd: i32) -> bool {
    FG_EVENTFD.store(eventfd, Ordering::Release);

    // 1. 创建本地 binder 对象
    let class = get_observer_class();
    if class.is_null() {
        eprintln!("刷新率: AIBinder_Class_new 失败");
        return false;
    }
    let observer = unsafe { AIBinder_new(class, std::ptr::null_mut()) };
    if observer.is_null() {
        eprintln!("刷新率: AIBinder_new 失败");
        return false;
    }

    // 2. 获取 activity 服务
    let am = unsafe {
        AServiceManager_getService(b"activity\0".as_ptr() as *const c_char)
    };
    if am.is_null() {
        eprintln!("刷新率: 无法获取 activity 服务");
        return false;
    }

    // 3. 构造 registerProcessObserver 事务
    //    AIDL: void registerProcessObserver(in IProcessObserver observer);
    //    Parcel: interfaceToken + strongBinder
    let mut in_parcel: *mut AParcel = std::ptr::null_mut();
    let status = unsafe { ABinder_prepareTransaction(am, &mut in_parcel) };
    if status != STATUS_OK || in_parcel.is_null() {
        eprintln!("刷新率: ABinder_prepareTransaction 失败 ({})", status);
        return false;
    }

    let _ = unsafe {
        AParcel_writeInterfaceToken(in_parcel, b"android.app.IActivityManager\0".as_ptr() as *const c_char)
    };
    let _ = unsafe { AParcel_writeStrongBinder(in_parcel, observer) };

    // 4. 发送事务
    //    registerProcessObserver = FIRST_CALL_TRANSACTION(1) + 12 = 0x0d
    //    原代码错误使用 0x4e（removeContentProvider 的事务码）
    let code = aidl::IActivityManager::TRANSACTION_registerProcessObserver;
    let mut out_parcel: *mut AParcel = std::ptr::null_mut();
    let status = unsafe { ABinder_transact(am, code, in_parcel, &mut out_parcel, 0) };

    unsafe { AParcel_delete(in_parcel) };
    if !out_parcel.is_null() {
        unsafe { AParcel_delete(out_parcel) };
    }

    if status == STATUS_OK {
        eprintln!("刷新率: IProcessObserver 已注册 (事务码 0x{:04x})", code);
        true
    } else {
        eprintln!("刷新率: registerProcessObserver 失败 ({})", status);
        true // 不阻塞刷新率模块
    }
}

pub fn get_package_name(pid: i32) -> Option<String> {
    PID_CACHE.lock().unwrap().get(&pid).cloned()
}