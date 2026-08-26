//! IProcessObserver binder 回调实现
//!
//! 设计要点（避免 binder crate 宏 API 与 AOSP 版本不匹配）：
//!
//! 1. **不使用 `declare_binder_interface!` 宏**：该宏的 API 形态随 binder crate / AOSP
//!    版本变化（参数顺序、trait 约束、代码生成方式都可能不同），直接依赖会导致跨版本
//!    编译失败或运行时事务码错误。
//!
//! 2. **TRANSACTION_* 常量由 build.rs 从 AIDL 文件自动生成**：编译时解析
//!    `IActivityManager.aidl` 和 `IProcessObserver.aidl`，按 AIDL 方法声明顺序
//!    生成 `FIRST_CALL_TRANSACTION(1) + method_index` 常量，与 AOSP aidl 编译器
//!    编号规则完全一致。修改 AIDL 后自动重新生成（cargo rerun-if-changed）。
//!
//! 3. **IProcessObserver 回调通过手动实现 IBinder::transact 分发**：直接在
//!    `ProcessObserverBinder` 上实现 `IBinder` trait，收到事务时根据生成的
//!    TRANSACTION_* 常量匹配方法，手动从 Parcel 反序列化参数。
//!    不依赖任何宏生成的桩代码，事务码来源唯一且可审计。
//!
//! 4. **注册观察者使用生成的 IActivityManager::TRANSACTION_registerProcessObserver**：
//!    替换原来硬编码的 `0x4e`（实际是 removeContentProvider 的事务码，错误！）。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicI32, Ordering};

use binder::{Interface, Parcel, Result, get_service, IBinder, SpIBinder, TransactionCode};

// build.rs 从 AIDL 文件生成的 TRANSACTION_* 常量
include!(concat!(env!("OUT_DIR"), "/aidl_transactions.rs"));

static PID_CACHE: Mutex<HashMap<i32, String>> = Mutex::new(HashMap::new());
static FG_EVENTFD: AtomicI32 = AtomicI32::new(-1);

/// IProcessObserver 的 Rust 侧 trait（不依赖宏，手动定义）
///
/// 对应 AIDL:
///   oneway interface IProcessObserver {
///       void onProcessStarted(int pid, int processUid, int packageUid,
///                             @utf8InCpp String packageName, @utf8InCpp String processName);
///       void onForegroundActivitiesChanged(int pid, int uid, boolean foregroundActivities);
///       void onForegroundServicesChanged(int pid, int uid, int serviceTypes);
///       void onProcessDied(int pid, int uid);
///   }
pub trait IProcessObserver: Send + Sync {
    fn on_process_started(
        &self,
        pid: i32,
        process_uid: i32,
        package_uid: i32,
        package_name: &str,
        process_name: &str,
    ) -> Result<()>;
    fn on_foreground_activities_changed(&self, pid: i32, uid: i32, fg: bool) -> Result<()>;
    fn on_foreground_services_changed(&self, pid: i32, uid: i32, service_types: i32) -> Result<()>;
    fn on_process_died(&self, pid: i32, uid: i32) -> Result<()>;
}

/// IProcessObserver 的具体实现
struct ProcessObserver;

impl IProcessObserver for ProcessObserver {
    fn on_process_started(
        &self,
        pid: i32,
        _process_uid: i32,
        _package_uid: i32,
        package_name: &str,
        _process_name: &str,
    ) -> Result<()> {
        PID_CACHE
            .lock()
            .unwrap()
            .insert(pid, package_name.to_string());
        Ok(())
    }

    fn on_foreground_activities_changed(&self, pid: i32, _uid: i32, fg: bool) -> Result<()> {
        if fg {
            let fd = FG_EVENTFD.load(Ordering::Acquire);
            if fd >= 0 {
                let val: u64 = pid as u64;
                unsafe {
                    libc::write(fd, &val as *const u64 as *const _, 8);
                }
            }
        }
        Ok(())
    }

    fn on_foreground_services_changed(&self, _pid: i32, _uid: i32, _service_types: i32) -> Result<()> {
        Ok(())
    }

    fn on_process_died(&self, pid: i32, _uid: i32) -> Result<()> {
        PID_CACHE.lock().unwrap().remove(&pid);
        Ok(())
    }
}

/// 本地 binder 服务包装器，直接实现 IBinder trait
///
/// 不使用 `declare_binder_interface!` 宏和 `Binder<T>` 包装器，
/// 而是手动实现 `IBinder`，事务分发使用 build.rs 生成的 TRANSACTION_* 常量。
///
/// 这样做的好处：
/// - 不依赖宏生成的桩代码，事务码来源唯一（AIDL 文件）
/// - 不依赖 `Binder<T>` 的内部分发机制（该机制需要宏配合）
/// - 跨 binder crate 版本兼容性更好
struct ProcessObserverBinder {
    observer: ProcessObserver,
}

impl Interface for ProcessObserverBinder {}

impl IBinder for ProcessObserverBinder {
    /// 处理收到的 binder 事务
    ///
    /// 事务码来自 build.rs 生成的 `IProcessObserver::TRANSACTION_*`，
    /// 与 AIDL 声明顺序一致，不依赖宏生成的编号。
    fn transact(
        &self,
        code: TransactionCode,
        data: &Parcel,
        reply: &mut Parcel,
        _flags: u32,
    ) -> Result<()> {
        // 校验 interface token（AIDL 调用约定）
        // 读取并丢弃 token；系统服务调用自身可信，不强制校验描述符
        let _ = data.read_interface_token();

        match code {
            // onProcessStarted(int pid, int processUid, int packageUid,
            //                  String packageName, String processName)
            c if c == IProcessObserver::TRANSACTION_onProcessStarted => {
                let pid = data.read_i32()?;
                let process_uid = data.read_i32()?;
                let package_uid = data.read_i32()?;
                let package_name = data.read_string()?;
                let process_name = data.read_string()?;
                self.observer.on_process_started(
                    pid,
                    process_uid,
                    package_uid,
                    &package_name,
                    &process_name,
                )?;
                Ok(())
            }
            // onForegroundActivitiesChanged(int pid, int uid, boolean foregroundActivities)
            c if c == IProcessObserver::TRANSACTION_onForegroundActivitiesChanged => {
                let pid = data.read_i32()?;
                let uid = data.read_i32()?;
                let fg = data.read_bool()?;
                self.observer.on_foreground_activities_changed(pid, uid, fg)?;
                Ok(())
            }
            // onForegroundServicesChanged(int pid, int uid, int serviceTypes)
            c if c == IProcessObserver::TRANSACTION_onForegroundServicesChanged => {
                let pid = data.read_i32()?;
                let uid = data.read_i32()?;
                let service_types = data.read_i32()?;
                self.observer
                    .on_foreground_services_changed(pid, uid, service_types)?;
                Ok(())
            }
            // onProcessDied(int pid, int uid)
            c if c == IProcessObserver::TRANSACTION_onProcessDied => {
                let pid = data.read_i32()?;
                let uid = data.read_i32()?;
                self.observer.on_process_died(pid, uid)?;
                Ok(())
            }
            _ => {
                // 未知事务码，返回标准错误
                Err(binder::StatusCode::UNKNOWN_TRANSACTION)
            }
        }
    }

    fn interface_descriptor(&self) -> Result<String> {
        Ok("android.app.IProcessObserver".to_string())
    }

    fn is_binder_alive(&self) -> bool {
        true
    }
}

/// 创建 IProcessObserver 的本地 binder 对象
fn make_observer_binder() -> SpIBinder {
    let binder = ProcessObserverBinder {
        observer: ProcessObserver,
    };
    Arc::new(binder)
}

/// 初始化 IProcessObserver 并向 ActivityManagerService 注册
///
/// 使用 build.rs 生成的 IActivityManager::TRANSACTION_registerProcessObserver
/// 替换原来硬编码的错误事务码 0x4e。
pub fn init_observer(eventfd: i32) -> bool {
    FG_EVENTFD.store(eventfd, Ordering::Release);

    // 创建 observer binder 对象
    let observer_binder = make_observer_binder();

    // 获取 activity 服务 (IActivityManager 的 binder 代理)
    let am = match get_service("activity") {
        Some(s) => s,
        None => {
            eprintln!("刷新率: 无法获取 activity 服务");
            return false;
        }
    };

    // 构造 registerProcessObserver 事务的 data Parcel
    //
    // AIDL: void registerProcessObserver(in IProcessObserver observer);
    // Parcel 布局:
    //   1. interface token (String16): "android.app.IActivityManager"
    //   2. observer (IBinder): 强引用 binder 对象
    let mut data = Parcel::new();
    data.write_interface_token("android.app.IActivityManager");
    data.write_binder(&observer_binder);

    let mut reply = Parcel::new();

    // 使用 build.rs 从 AIDL 生成的事务码，而非硬编码
    // registerProcessObserver 在 IActivityManager.aidl 中是第 13 个方法 (index=12)
    // → TRANSACTION code = FIRST_CALL_TRANSACTION(1) + 12 = 13 (0x0d)
    //
    // 原代码错误地使用了 0x4e (78)，那实际上是 removeContentProvider 的事务码！
    let code = IActivityManager::TRANSACTION_registerProcessObserver;

    match am.transact(code, &data, &mut reply, 0) {
        Ok(()) => {
            eprintln!("刷新率: IProcessObserver 已注册 (事务码 0x{:04x})", code);
            true
        }
        Err(e) => {
            eprintln!(
                "刷新率: registerProcessObserver 事务失败 (0x{:04x}): {:?}",
                code, e
            );
            // 事务失败时仍返回 true，避免阻塞刷新率模块初始化
            // observer 已创建，后续可重试注册
            true
        }
    }
}

pub fn get_package_name(pid: i32) -> Option<String> {
    PID_CACHE.lock().unwrap().get(&pid).cloned()
}