# AppOptR

#### 介绍
安卓应用 CPU 亲和性优化程序 - https://gitee.com/sutoliu/AppOpt Rust重构版

 **使用说明请参考** 

http://appopt.suto.top

#### 软件架构

| 模块 | 功能 |
|------|------|
| `main.rs` | 入口：CLI 解析、拓扑初始化、配置加载、主循环 |
| `config.rs` | 配置文件解析、`inotify` 热加载线程、配置重载 |
| `cpuset.rs` | `cpuset` 位图、CPU 拓扑初始化 |
| `rule_match.rs` | 规则匹配：包名精确匹配 + 线程名通配 |
| `apply_affinity.rs` | 线程缓存、亲和性应用 |
| `ebpf_mode.rs` | eBPF 事件驱动模式 |
| `proc_mode.rs` | proc 轮询模式  |
| `common.rs` | 常量、全局状态、工具函数 |
| `AppOpt-ebpf` | eBPF 内核态 |


 **请作者喝奶茶** 



![请作者喝奶茶](%E8%AF%B7%E4%BD%9C%E8%80%85%E6%9D%AF%E5%A5%B6%E8%8C%B6.png)