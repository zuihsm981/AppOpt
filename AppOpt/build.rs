use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    // 生成 stub C 文件——所有函数返回 0/null，仅用于链接期满足符号
    // 运行时由系统 libbinder_ndk.so 覆盖
    let stub_c = out_dir.join("binder_ndk_stub.c");
    std::fs::write(&stub_c, r#"
        void* AServiceManager_getService() { return 0; }
        void* AIBinder_Class_new() { return 0; }
        void* AIBinder_new() { return 0; }
        int ABinder_prepareTransaction() { return 0; }
        int ABinder_transact() { return 0; }
        void AParcel_delete() {}
        int AParcel_writeInterfaceToken() { return 0; }
        int AParcel_writeStrongBinder() { return 0; }
        int AParcel_readInt32() { return 0; }
        int AParcel_readBool() { return 0; }
        int AParcel_readString() { return 0; }
        int ABinder_joinThreadPool() { return 0; }
    "#).unwrap();

    // 查找 NDK clang
    let cc = env::var("CC_aarch64_linux_android")
        .or_else(|_| env::var("CC"))
        .unwrap_or_else(|_| "aarch64-linux-android29-clang".to_string());

    let so_path = out_dir.join("libbinder_ndk.so");
    let status = Command::new(&cc)
        .args(["-shared", "-o", so_path.to_str().unwrap(), stub_c.to_str().unwrap()])
        .status();

    match status {
        Ok(s) if s.success() => {
            println!("cargo:rustc-link-search=native={}", out_dir.display());
        }
        Ok(s) => {
            println!("cargo:warning=binder_ndk stub 编译失败: {:?}", s);
        }
        Err(e) => {
            println!("cargo:warning=找不到 NDK clang ({}): {}", cc, e);
        }
    }

    println!("cargo:rerun-if-changed=build.rs");
}