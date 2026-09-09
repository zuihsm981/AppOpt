//! 手写 binder ioctl (arm64): 替代 libbinder_ndk dlopen。
//! open("/dev/binder") + mmap + ioctl(BINDER_WRITE_READ) + BC_TRANSACTION/BR_*。
//! 覆盖: 服务句柄查找 (servicemanager handle 0), IProcessObserver 注册+回调线程,
//!       SurfaceFlinger 刷新率 (code 1035)。

use libc::{c_int, c_void};

/// 诊断日志 (临时): 追加写入 /data/local/tmp/appopt_binder.log
pub(crate) fn log_diag(msg: &str) {
    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("/data/local/tmp/appopt_binder.log")
    {
        let _ = writeln!(f, "[{:?}] {}", std::time::SystemTime::now(), msg);
    }
}

// ================= ioctl 码 (arm64 asm-generic: dir<<30 | type<<8 | nr<<0 | size<<16) =================
const BINDER_WRITE_READ: u32 = 0xc0306201;      // _IOWR('b',1,sizeof(bwr)=48)
const BINDER_VERSION: u32 = 0xc0046209;         // _IOWR('b',9,4)
const BINDER_SET_MAX_THREADS: u32 = 0x40086205; // _IOW('b',5,8)

// ================= binder 命令 (type 'c') =================
const BC_TRANSACTION: u32 = 0x40406300;
const BC_FREE_BUFFER: u32 = 0x40086303;
const BC_ENTER_LOOPER: u32 = 0x630c;

const BR_ERROR: u32 = 0x80047200;
const BR_TRANSACTION: u32 = 0x80407202;
const BR_REPLY: u32 = 0x80407203;
const BR_ACQUIRE_RESULT: u32 = 0x80047204;
const BR_DEAD_REPLY: u32 = 0x7205;
const BR_TRANSACTION_COMPLETE: u32 = 0x7206;
const BR_FAILED_REPLY: u32 = 0x720f;
const BR_SPAWN_LOOPER: u32 = 0x720b;

// ================= flat_binder_object 类型 =================
pub(crate) const BINDER_TYPE_BINDER: u32 = 1;
const BINDER_TYPE_HANDLE: u32 = 2;

// servicemanager (context manager) 句柄 = 0
const SVC_MGR_HANDLE: u32 = 0;

// IProcessObserver 回调事务码
const TX_ON_FG_ACTIVITIES_CHANGED: u32 = 0x02;

// ================= 内核 ABI 结构 (arm64, uapi binder.h) =================
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct BinderWriteRead {
    write_size: u64,
    write_consumed: u64,
    write_buffer: u64,
    read_size: u64,
    read_consumed: u64,
    read_buffer: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct BinderTxnPtr {
    buffer: u64,
    offsets: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
union BinderTxnData {
    ptr: BinderTxnPtr,
    buf: [u8; 8],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct BinderTransactionData {
    target: u64, // union { u32 handle; binder_uintptr_t ptr; }
    cookie: u64,
    code: u32,
    flags: u32,
    sender_pid: i32,
    sender_euid: u32,
    data_size: u64,
    offsets_size: u64,
    data: BinderTxnData,
}

// binder_transaction_data 在 arm64 为 64 字节 (data 联合体 16B, 含 2×binder_uintptr_t 指针)
// 本地 observer binder 节点身份 (内核不解析该地址, 仅作节点标识)
const OBSERVER_NODE: usize = 0x4150_5054_4f42_5345; // "APPTOBSE"

/// 本地 observer 节点地址 (process_observer 注册时写入 flat_binder_object.binder)
pub(crate) fn observer_node() -> usize {
    OBSERVER_NODE
}

pub struct Binder {
    fd: c_int,
    map_base: *mut u8,
    map_size: usize,
}

// Binder 被回调线程使用 (fd + mmap 共享); 自身不含可变借用
unsafe impl Send for Binder {}
unsafe impl Sync for Binder {}

impl Drop for Binder {
    fn drop(&mut self) {
        if !self.map_base.is_null() {
            unsafe { libc::munmap(self.map_base as *mut libc::c_void, self.map_size) };
        }
        if self.fd >= 0 {
            unsafe { libc::close(self.fd) };
        }
    }
}

impl Binder {
    /// 打开 /dev/binder + 校验版本 + mmap 接收缓冲区。
    pub fn open() -> Option<Binder> {
        let fd = unsafe {
            libc::open(
                b"/dev/binder\0".as_ptr() as *const libc::c_char,
                libc::O_RDWR | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        if fd < 0 {
            log_diag(&format!("binder: open /dev/binder FAIL errno={}", std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)));
            return None;
        }
        log_diag(&format!("binder: open fd={}", fd));
        let mut ver: u32 = 0;
        let r = unsafe { libc::ioctl(fd, BINDER_VERSION as i32, &mut ver as *mut u32 as *mut c_void) };
        if r < 0 {
            log_diag(&format!("binder: BINDER_VERSION FAIL errno={}", std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)));
            unsafe { libc::close(fd) };
            return None;
        }
        log_diag(&format!("binder: version ioctl ok ver={}", ver));
        // mmap binder 接收区 (必需: BR_REPLY/BR_TRANSACTION 数据指针指向此区域)
        let map_size: usize = 1024 * 1024;
        let map = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                map_size,
                libc::PROT_READ,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        if map == libc::MAP_FAILED {
            log_diag(&format!("binder: mmap FAIL errno={}", std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)));
            unsafe { libc::close(fd) };
            return None;
        }
        log_diag(&format!("binder: mmap ok base={:p}", map));
        let max_threads: u64 = 16;
        unsafe { libc::ioctl(fd, BINDER_SET_MAX_THREADS as i32, &max_threads as *const u64 as *const c_void) };
        Some(Binder {
            fd,
            map_base: map as *mut u8,
            map_size,
        })
    }

    fn write_read(&self, wb: &[u8], rb: &mut [u8]) -> Option<BinderWriteRead> {
        let mut bwr = BinderWriteRead {
            write_size: wb.len() as u64,
            write_consumed: 0,
            write_buffer: wb.as_ptr() as u64,
            read_size: rb.len() as u64,
            read_consumed: 0,
            read_buffer: rb.as_mut_ptr() as u64,
        };
        let r = unsafe { libc::ioctl(self.fd, BINDER_WRITE_READ as i32, &mut bwr as *mut BinderWriteRead as *mut c_void) };
        if r < 0 {
            log_diag(&format!("binder: BINDER_WRITE_READ ioctl FAIL errno={}", std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)));
            None
        } else {
            Some(bwr)
        }
    }

    fn free_buffer(&self, ptr: u64) {
        let mut wb = Vec::with_capacity(12);
        wb.extend_from_slice(&BC_FREE_BUFFER.to_le_bytes());
        wb.extend_from_slice(&ptr.to_le_bytes());
        let mut rb = [0u8; 256];
        let _ = self.write_read(&wb, &mut rb);
    }

    /// 从 mmap 接收区读取数据。tr.data.ptr.buffer 已是绝对用户态 VA
    /// (= mmap基址 + 内核数据偏移), 直接按该指针读, 不能再加 map_base。
    unsafe fn read_mapped(&self, ptr: u64, len: u64) -> Option<Vec<u8>> {
        if ptr == 0 {
            return Some(Vec::new());
        }
        let base = self.map_base as usize;
        if ptr < base as u64 || (ptr as usize) + len as usize > base + self.map_size {
            return None;
        }
        Some(unsafe { std::slice::from_raw_parts(ptr as *const u8, len as usize).to_vec() })
    }

    /// 向 handle 发送同步事务; 返回 reply 的 (data, offsets)。
    pub fn transact_sync(&self, handle: u32, code: u32, data: &[u8], offsets: &[u64]) -> Option<(Vec<u8>, Vec<u64>)> {
        let mut wb = Vec::with_capacity(60);
        wb.extend_from_slice(&BC_TRANSACTION.to_le_bytes());
        let tr = BinderTransactionData {
            target: handle as u64,
            cookie: 0,
            code,
            flags: 0,
            sender_pid: 0,
            sender_euid: 0,
            data_size: data.len() as u64,
            offsets_size: (offsets.len() * 8) as u64,
            data: BinderTxnData {
                ptr: BinderTxnPtr {
                    buffer: data.as_ptr() as u64,
                    offsets: offsets.as_ptr() as u64,
                },
            },
        };
        wb.extend_from_slice(&unsafe { std::mem::transmute::<BinderTransactionData, [u8; 64]>(tr) });

        // 非阻塞收发: 先发 BC_TRANSACTION, 再 poll(可读)+read 累积直到 BR_REPLY 或 3s 超时
        let mut rb: Vec<u8> = Vec::new();
        let mut free_ptrs: Vec<u64> = Vec::new();
        let mut result: Option<(Vec<u8>, Vec<u64>)> = None;
        let mut failed: bool = false;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);

        let mut rb_buf = vec![0u8; 16384];
        if let Some(bwr) = self.write_read(&wb, &mut rb_buf) {
            let n = bwr.read_consumed as usize;
            if n > 0 {
                rb.extend_from_slice(&rb_buf[..n]);
            }
        }
        loop {
            // 解析 rb 中已累积的命令
            let mut pos = 0usize;
            while pos + 4 <= rb.len() {
                let cmd = u32::from_le_bytes([rb[pos], rb[pos + 1], rb[pos + 2], rb[pos + 3]]);
                match cmd {
                    BR_TRANSACTION_COMPLETE | BR_SPAWN_LOOPER => { pos += 4; }
                    BR_DEAD_REPLY | BR_FAILED_REPLY => {
                        log_diag(&format!("binder: transact handle={} code={} -> {:x}", handle, code, cmd));
                        failed = true;
                        pos += 4;
                    }
                    BR_REPLY => {
                        if pos + 4 + 64 > rb.len() {
                            break; // BR_REPLY 数据未到齐, 等更多
                        }
                        let tr: BinderTransactionData = unsafe {
                            std::ptr::read_unaligned(rb[pos + 4..pos + 4 + 64].as_ptr() as *const BinderTransactionData)
                        };
                        pos += 4 + 64;
                        let (dsz, osz, bptr, optr) =
                            unsafe { (tr.data_size, tr.offsets_size, tr.data.ptr.buffer, tr.data.ptr.offsets) };
                        if bptr != 0 {
                            free_ptrs.push(bptr);
                        }
                        let rdata = unsafe { self.read_mapped(bptr, dsz) };
                        let roffs = if osz > 0 {
                            unsafe { self.read_mapped(optr, osz) }
                                .map(|b| b.chunks_exact(8).map(|c| u64::from_le_bytes(c.try_into().unwrap())).collect())
                        } else {
                            Some(Vec::new())
                        };
                        if let (Some(d), Some(o)) = (rdata, roffs) {
                            result = Some((d, o));
                        }
                    }
                    BR_ERROR | BR_ACQUIRE_RESULT => { pos += 4; }
                    _ => { pos += 4; }
                }
                if result.is_some() || failed {
                    break;
                }
            }
            rb.drain(..pos);
            if result.is_some() || failed {
                break;
            }
            if std::time::Instant::now() >= deadline {
                log_diag(&format!("binder: transact handle={} code={} 等待回复超时", handle, code));
                break;
            }
            // poll 可读后再 read (非阻塞 fd)
            let mut pfd = libc::pollfd { fd: self.fd, events: libc::POLLIN, revents: 0 };
            let pr = unsafe { libc::poll(&mut pfd, 1, 300) };
            if pr > 0 {
                let mut rb_buf2 = vec![0u8; 16384];
                if let Some(n2_i) = read_only(self.fd, &mut rb_buf2) {
                    let n2 = n2_i as usize;
                    if n2 > 0 {
                        rb.extend_from_slice(&rb_buf2[..n2]);
                    }
                }
            }
        }
        for p in &free_ptrs {
            self.free_buffer(*p);
        }
        result
    }

    /// 向 servicemanager (handle 0) 查询服务句柄。
    /// 向 servicemanager (handle 0) 查询服务句柄。
    /// 依次尝试 AIDL 事务码 1..4 与 legacy 'S', 取首个返回句柄者;
    /// 全部回复都打日志 (诊断用)。
    pub fn get_service(&self, name: &str) -> Option<u32> {
        // AIDL 请求带完整接口 token
        let mut data: Vec<u8> = Vec::new();
        push_i32(&mut data, 0); // strict_mode_policy
        push_i32(&mut data, 0); // this binder token
        push_utf16(&mut data, "android.os.IServiceManager");
        push_utf16(&mut data, name);

        // legacy 'S'(0x53) / 'C'(0x43) 带完整 token (某些版本 legacy 也过 enforceInterface)
        for code in [0x53u32, 0x43] {
            log_diag(&format!("binder: get_service({}) try legacy token code={:#x}", name, code));
            match self.transact_sync(SVC_MGR_HANDLE, code, &data, &[]) {
                Some((reply, _)) => {
                    log_diag(&format!("binder:   code={:#x} reply len={} hex={:02x?}", code, reply.len(), &reply[..reply.len().min(32)]));
                    if let Some(h) = Self::parse_service_handle(&reply) {
                        log_diag(&format!("binder: get_service({}) code={:#x} handle={}", name, code, h));
                        return Some(h);
                    }
                }
                None => log_diag(&format!("binder:   code={:#x} txn FAIL/超时", code)),
            }
        }

        for code in [1u32, 2, 3, 4] {
            log_diag(&format!("binder: get_service({}) try AIDL code={}", name, code));
            match self.transact_sync(SVC_MGR_HANDLE, code, &data, &[]) {
                Some((reply, _)) => {
                    log_diag(&format!("binder:   code={} reply len={} hex={:02x?}", code, reply.len(), &reply[..reply.len().min(32)]));
                    if let Some(h) = Self::parse_service_handle(&reply) {
                        log_diag(&format!("binder: get_service({}) code={} handle={}", name, code, h));
                        return Some(h);
                    }
                }
                None => log_diag(&format!("binder:   code={} txn FAIL", code)),
            }
        }

        // legacy 'S': 数据直接从 string16(服务名) 开始
        let mut sdata: Vec<u8> = Vec::new();
        push_utf16(&mut sdata, name);
        log_diag(&format!("binder: get_service({}) try legacy 'S'", name));
        match self.transact_sync(SVC_MGR_HANDLE, 0x53, &sdata, &[]) {
            Some((reply, _)) => {
                log_diag(&format!("binder:   legacy reply len={} hex={:02x?}", reply.len(), &reply[..reply.len().min(32)]));
                if let Some(h) = Self::parse_service_handle(&reply) {
                    log_diag(&format!("binder: get_service({}) legacy handle={}", name, h));
                    return Some(h);
                }
            }
            None => log_diag("binder:   legacy txn FAIL"),
        }
        log_diag(&format!("binder: get_service({}) 全部尝试失败", name));
        None
    }

    fn parse_service_handle(reply: &[u8]) -> Option<u32> {
        // AIDL: [异常=0][flat_binder_object{HANDLE}]; 或直排 [flat_binder_object]
        let mut r = ParcelReader::new(reply);
        let first = r.read_i32()?;
        if first == 0 {
            let t = r.read_i32()? as u32;
            if t == BINDER_TYPE_HANDLE {
                let _flags = r.read_i32()?;
                let binder = r.read_u64()?;
                return Some(binder as u32);
            }
            return None;
        }
        if first as u32 == BINDER_TYPE_HANDLE {
            let _flags = r.read_i32()?;
            let binder = r.read_u64()?;
            return Some(binder as u32);
        }
        None
    }

    /// 启动 IProcessObserver 回调读取线程: BR_TRANSACTION → fg 事件 → send_fd (8字节 [pid,uid])。
    /// 消费 self (线程持有 Binder, 保持 fd/mmap 存活)。
    pub fn run_observer(self, send_fd: i32) {
        let fd = self.fd;
        std::thread::spawn(move || {
            log_diag(&format!("binder: observer thread start fd={} send_fd={}", fd, send_fd));
            // 进入 binder 线程循环
            let mut wb = Vec::new();
            wb.extend_from_slice(&BC_ENTER_LOOPER.to_le_bytes());
            let mut rb = [0u8; 64];
            let _ = raw_write_read(fd, &wb, &mut rb);
            loop {
                // O_NONBLOCK: 先 poll 等可读, 再 read_only (避免 EAGAIN 空转/退出)
                let mut pfd = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
                let pr = unsafe { libc::poll(&mut pfd, 1, -1) };
                if pr < 0 {
                    break;
                }
                if pr == 0 {
                    continue;
                }
                let mut rb = vec![0u8; 16384];
                let n = match read_only(fd, &mut rb) {
                    Some(n) => n,
                    None => break,
                };
                if n == 0 {
                    break;
                }
                let rb = &rb[..n as usize];
                let mut pos = 0usize;
                while pos + 4 <= rb.len() {
                    let cmd = u32::from_le_bytes([rb[pos], rb[pos + 1], rb[pos + 2], rb[pos + 3]]);
                    pos += 4;
                    match cmd {
                        BR_TRANSACTION => {
                            if pos + 64 > rb.len() {
                                break;
                            }
                            let tr: BinderTransactionData = unsafe {
                                std::ptr::read_unaligned(rb[pos..pos + 64].as_ptr() as *const BinderTransactionData)
                            };
                            pos += 64;
                            let (dsz, bptr) = unsafe { (tr.data_size, tr.data.ptr.buffer) };
                            // 回调数据在 mmap 区
                            let data: Vec<u8> = if bptr != 0 {
                                unsafe {
                                    std::slice::from_raw_parts(bptr as *const u8, dsz as usize).to_vec()
                                }
                            } else {
                                Vec::new()
                            };
                            // 释放内核缓冲区
                            if bptr != 0 {
                                let mut wbf = Vec::with_capacity(12);
                                wbf.extend_from_slice(&BC_FREE_BUFFER.to_le_bytes());
                                wbf.extend_from_slice(&bptr.to_le_bytes());
                                let mut rbf = [0u8; 64];
                                let _ = raw_write_read(fd, &wbf, &mut rbf);
                            }
                            // 解析回调
                            log_diag(&format!("binder: BR_TRANSACTION code={} datalen={}", tr.code, dsz));
                            if tr.code == TX_ON_FG_ACTIVITIES_CHANGED {
                                let mut r = ParcelReader::new(&data);
                                let _ = r.read_i32(); // strict
                                let _ = r.read_i32(); // this
                                let _ = r.read_utf16_str(); // interface token
                                if let (Some(pid), Some(uid), Some(fg)) = (r.read_i32(), r.read_i32(), r.read_i32()) {
                                    log_diag(&format!("binder: fg pid={} uid={} fg={}", pid, uid, fg));
                                    if fg != 0 && pid > 0 && send_fd >= 0 {
                                        let pkt = [pid, uid];
                                        unsafe {
                                            libc::send(
                                                send_fd,
                                                pkt.as_ptr() as *const c_void,
                                                8,
                                                0,
                                            );
                                        }
                                    }
                                }
                            }
                            // oneway 回调无需回复
                        }
                        BR_TRANSACTION_COMPLETE | BR_SPAWN_LOOPER => {}
                        BR_DEAD_REPLY | BR_FAILED_REPLY => {}
                        _ => {}
                    }
                }
            }
        });
    }
}

// ================= parcel 构建/读取助手 =================

pub(crate) fn push_i32(v: &mut Vec<u8>, x: i32) {
    v.extend_from_slice(&x.to_le_bytes());
}

fn pad4(v: &mut Vec<u8>) {
    while v.len() % 4 != 0 {
        v.push(0);
    }
}

/// 写 UTF-16 字符串: i32 长度 + utf16 字节 + 4 字节对齐
pub(crate) fn push_utf16(v: &mut Vec<u8>, s: &str) {
    let units: Vec<u16> = s.encode_utf16().collect();
    push_i32(v, units.len() as i32);
    for u in &units {
        v.extend_from_slice(&u.to_le_bytes());
    }
    pad4(v);
}

struct ParcelReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> ParcelReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        ParcelReader { data, pos: 0 }
    }

    fn read_i32(&mut self) -> Option<i32> {
        if self.pos + 4 > self.data.len() {
            return None;
        }
        let v = i32::from_le_bytes([self.data[self.pos], self.data[self.pos + 1], self.data[self.pos + 2], self.data[self.pos + 3]]);
        self.pos += 4;
        Some(v)
    }

    fn read_u64(&mut self) -> Option<u64> {
        if self.pos + 8 > self.data.len() {
            return None;
        }
        let mut b = [0u8; 8];
        b.copy_from_slice(&self.data[self.pos..self.pos + 8]);
        self.pos += 8;
        Some(u64::from_le_bytes(b))
    }

    /// 读 UTF-16 字符串 (i32 长度 + 字节 + 对齐), 返回 String
    fn read_utf16_str(&mut self) -> Option<String> {
        let len = self.read_i32()?;
        if len < 0 || len > 4096 {
            return None;
        }
        let bytes = len as usize * 2;
        if self.pos + bytes > self.data.len() {
            return None;
        }
        let mut units = Vec::with_capacity(len as usize);
        for i in 0..len as usize {
            units.push(u16::from_le_bytes([self.data[self.pos + i * 2], self.data[self.pos + i * 2 + 1]]));
        }
        self.pos += bytes;
        while self.pos % 4 != 0 {
            self.pos += 1;
        }
        Some(String::from_utf16_lossy(&units))
    }
}

// ================= 底层 ioctl 封装 =================

fn raw_write_read(fd: c_int, wb: &[u8], rb: &mut [u8]) -> Option<i64> {
    let mut bwr = BinderWriteRead {
        write_size: wb.len() as u64,
        write_consumed: 0,
        write_buffer: wb.as_ptr() as u64,
        read_size: rb.len() as u64,
        read_consumed: 0,
        read_buffer: rb.as_mut_ptr() as u64,
    };
    let r = unsafe { libc::ioctl(fd, BINDER_WRITE_READ as i32, &mut bwr as *mut BinderWriteRead as *mut c_void) };
    if r < 0 {
        None
    } else {
        Some(bwr.read_consumed as i64)
    }
}

fn read_only(fd: c_int, rb: &mut [u8]) -> Option<i64> {
    let mut bwr = BinderWriteRead {
        write_size: 0,
        write_consumed: 0,
        write_buffer: 0,
        read_size: rb.len() as u64,
        read_consumed: 0,
        read_buffer: rb.as_mut_ptr() as u64,
    };
    let r = unsafe { libc::ioctl(fd, BINDER_WRITE_READ as i32, &mut bwr as *mut BinderWriteRead as *mut c_void) };
    if r < 0 {
        None
    } else {
        Some(bwr.read_consumed as i64)
    }
}
