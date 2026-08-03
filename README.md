# AppOptR

#### 介绍
安卓应用 CPU 亲和性优化程序 - https://gitee.com/sutoliu/AppOpt 的Rust重构版

 **使用说明请参考** 

http://appopt.suto.top

### 模块说明

| 模块 | 功能 |
|------|------|
| `main.rs` | 程序入口，CLI 解析与 eBPF/proc 双模式主循环编排 |
| `config.rs` | 配置文件解析（块语法/语义核心名）、inotify 热加载与降级轮询 |
| `cpuset.rs` | CpuSet 位图、CPU 拓扑检测与 cpuset 目录管理 |
| `rule_match.rs` | 包名/线程名规则匹配与 comm 到包名映射 |
| `apply_affinity.rs` | 亲和性应用与 `/proc` 文件读取 |
| `cache.rs` | 统一进程缓存 |
| `ebpf_mode.rs` | eBPF 事件驱动 |
| `proc_mode.rs` | proc 轮询模式 |
| `AppOpt-ebpf` | eBPF 内核态：4 事件 tracepoint + 白名单前置过滤 |


#### 请作者喝奶茶

![请作者喝奶茶](%E8%AF%B7%E4%BD%9C%E8%80%85%E6%9D%AF%E5%A5%B6%E8%8C%B6.png)



### 基本语法

```ini
# 注释行（# 或 // 开头）

# 包名 = CPU范围                   → 匹配该包的所有线程
com.example.app=4-5

# 包名 { 线程名 = CPU范围 }          → 匹配该包的特定线程
com.example.game {
    main_thread=0-3
    render_*=4-5
    worker_?=6
}

# 紧凑单行：包名 { 线程名 } = CPU范围
com.example.app{heavy_thread}=6-7

# 块内同时放包级规则 + 线程规则
com.example.app=0-3 {
    bg_thread=4-5
}
```

### 线程名通配符

| 符号 | 含义 | 示例 |
|------|------|------|
| `*` | 匹配任意字符序列 | `render_*` 匹配 `render_thread`、`render_worker` |
| `?` | 匹配单个字符 | `worker_?` 匹配 `worker_1`、`worker_A` |
| `[范围]` | 匹配集合中任一字符 | `thread_[0-9]` 匹配 `thread_0` ~ `thread_9` |

### CPU 范围

```ini
0          # 单个 CPU
0-3        # 连续范围
0-3,5,7-8  # 逗号分隔
```

### 语义核心名（核心自适应）

规则中的 CPU 范围可使用语义名，自动展开为实际 CPU 编号：

| 语义名 | 含义 |
|--------|------|
| `e-core` | 能效小核（最低频率簇） |
| `p-core` | 性能中核（中间频率簇，多簇合并） |
| `hp-core` | 高性能大核（最高频率簇） |
| `all-core` | 所有核心 |

语义名可与数字范围混用，逗号分隔取并集后压缩为范围：

```ini
# 6+2 拓扑(高通8 Elite：e=0-5, hp=6-7)：e-core,p-core 展开为 0-5，hp-core 展开为 6-7
com.tencent.tmgp.sgame=e-core,p-core {
    UnityMain=hp-core
    UnityGfxDeviceW=p-core,hp-core
}
# 等价于
com.tencent.tmgp.sgame=0-5 {
    UnityMain=6-7
    UnityGfxDeviceW=6-7
}
```

分层规则：按 `cpuinfo_max_freq` 升序分组，首组为 `e-core`，末组为 `hp-core`，中间所有组合并为 `p-core`；仅两簇时 `p-core` 为空。

## 命令行参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `-c <file>` | 指定配置文件路径 | `./applist.conf` |
| `-s <seconds>` | 检查间隔（秒，≥1） | `2` |
| `-b <name>` | 指定 BASE_CPUSET 目录名（不可含 `/`） | `AppOpt` |
| `-v` | 显示版本信息 | — |
| `-h` | 显示帮助 | — |
