//! 手写 binder ioctl (arm64): 替代 libbinder_ndk dlopen。
//! open("/dev/binder") + mmap + ioctl(BINDER_WRITE_READ) + BC_TRANSACTION/BR_*。
//! 覆盖: 服务句柄查找 (servicemanager handle 0), IProcessObserver 注册+回调线程,
//!       SurfaceFlinger 刷新率 (code 1035)。

use libc::{c_int, c_void};

// ================= ioctl 码 (arm64: dir<<30 | 'b'<<22 | nr<<14 | size) =================
const BINDER_WRITE_READ: u32 = 0xc1884030;      // _IOWR('b',1,sizeof(bwr)=48)
const BINDER_VERSION: u32 = 0xc1882404;         // _IOWR('b',9,4)
const BINDER_SET_MAX_THREADS: u32 = 0x58814008; // _IOW('b',5,8)

// ================= binder 命令 (type 'c') =================
const BC_TRANSACTION: u32 = 0x58c00040;
const BC_FREE_BUFFER: u32 = 0x58c0c008;
const BC_ENTER_LOOPER: u32 = 0x18c03000;

const BR_ERROR: u32 = 0x98c00004;
const BR_TRANSACTION: u32 = 0x98c08040;
const BR_REPLY: u32 = 0x98c0c040;
const BR_ACQUIRE_RESULT: u32 = 0x98c10004;
const BR_DEAD_REPLY: u32 = 0x18c14000;
const BR_TRANSACTION_COMPLETE: u32 = 0x18c18000;
const BR_FAILED_REPLY: u32 = 0x18c3c000;
const BR_SPAWN_LOOPER: u32 = 0x18c2c000;

// ================= flat_binder_object 类型 =================
pub(crate) const BINDER_TYPE_BINDER: u32 = 1;
const BINDER_TYPE_HANDLE: u32 = 2;

// servicemanager (context manager) 句柄 = 0; getService 事务码 'S'
const SVC_MGR_HANDLE: u32 = 0;
const SVC_MGR_GET_SERVICE: u32 = 0x53;

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
                libc::O_RDWR | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return None;
        }
        let mut ver: u32 = 0;
        let r = unsafe { libc::ioctl(fd, BINDER_VERSION as i32, &mut ver as *mut u32 as *mut c_void) };
        if r < 0 {
            unsafe { libc::close(fd) };
            return None;
        }
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
            unsafe { libc::close(fd) };
            return None;
        }
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

    /// 从 mmap 接收区读取数据 (BR_REPLY/BR_TRANSACTION 的 data/offsets 指针)。
    unsafe fn read_mapped(&self, ptr: u64, len: u64) -> Option<Vec<u8>> {
        if ptr == 0 {
            return Some(Vec::new());
        }
        let base = self.map_base as usize;
        if len > self.map_size as u64 {
            return None;
        }
        Some(unsafe { std::slice::from_raw_parts((base + ptr as usize) as *const u8, len as usize).to_vec() })
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

        let mut rb = vec![0u8; 16384];
        let bwr = self.write_read(&wb, &mut rb)?;
        let n = bwr.read_consumed as usize;
        if n == 0 {
            return None;
        }
        let rb = &rb[..n];
        let mut pos = 0usize;
        let mut free_ptrs: Vec<u64> = Vec::new();
        let mut result: Option<(Vec<u8>, Vec<u64>)> = None;
        while pos + 4 <= rb.len() {
            let cmd = u32::from_le_bytes([rb[pos], rb[pos + 1], rb[pos + 2], rb[pos + 3]]);
            pos += 4;
            match cmd {
                BR_TRANSACTION_COMPLETE | BR_SPAWN_LOOPER => {}
                BR_DEAD_REPLY | BR_FAILED_REPLY => {
                    for p in &free_ptrs {
                        self.free_buffer(*p);
                    }
                    return None;
                }
                BR_REPLY => {
                    if pos + 64 > rb.len() {
                        break;
                    }
                    let tr: BinderTransactionData =
                        unsafe { std::ptr::read_unaligned(rb[pos..pos + 64].as_ptr() as *const BinderTransactionData) };
                    pos += 64;
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
                BR_ERROR | BR_ACQUIRE_RESULT => {
                    pos += 4;
                }
                _ => {}
            }
            if result.is_some() {
                break;
            }
        }
        for p in &free_ptrs {
            self.free_buffer(*p);
        }
        result
    }

    /// 向 servicemanager (handle 0) 查询服务句柄。
    pub fn get_service(&self, name: &str) -> Option<u32> {
        // parcel: [strict][this][desc "android.os.IServiceManager"][string16(name)]
        let mut data: Vec<u8> = Vec::new();
        push_i32(&mut data, 0);
        push_i32(&mut data, 0);
        push_utf16(&mut data, "android.os.IServiceManager");
        push_utf16(&mut data, name);
        let (reply, _offs) = self.transact_sync(SVC_MGR_HANDLE, SVC_MGR_GET_SERVICE, &data, &[])?;
        // reply (servicemanager 非 AIDL): 直接是 flat_binder_object{type=HANDLE},
        // 无 strict/this 头, 无异常码
        let mut r = ParcelReader::new(&reply);
        let t = r.read_i32()? as u32;
        let _flags = r.read_i32()?;
        let binder = r.read_u64()?;
        if t == BINDER_TYPE_HANDLE {
            Some(binder as u32)
        } else {
            None
        }
    }

    /// 启动 IProcessObserver 回调读取线程: BR_TRANSACTION → fg 事件 → send_fd (8字节 [pid,uid])。
    /// 消费 self (线程持有 Binder, 保持 fd/mmap 存活)。
    pub fn run_observer(self, send_fd: i32) {
        let fd = self.fd;
        let map_base = self.map_base as usize;
        std::thread::spawn(move || {
            // 进入 binder 线程循环
            let mut wb = Vec::new();
            wb.extend_from_slice(&BC_ENTER_LOOPER.to_le_bytes());
            let mut rb = [0u8; 64];
            let _ = raw_write_read(fd, &wb, &mut rb);
            loop {
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
                                    std::slice::from_raw_parts((map_base + bptr as usize) as *const u8, dsz as usize).to_vec()
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
                            if tr.code == TX_ON_FG_ACTIVITIES_CHANGED {
                                let mut r = ParcelReader::new(&data);
                                let _ = r.read_i32(); // strict
                                let _ = r.read_i32(); // this
                                let _ = r.read_utf16_str(); // interface token
                                if let (Some(pid), Some(uid), Some(fg)) = (r.read_i32(), r.read_i32(), r.read_i32()) {
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
