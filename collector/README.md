# collector

**网络流量采集器 / 威胁情报采集**，cyber-posture 平台的外视引擎。基于 Rust 构建，旁路监听网络流量元数据，输出结构化日志供 `form` 做关联分析。

## 职责

- **流量元数据采集**：会话五元组、协议识别、流量大小与时序、DNS / TLS SNI 等可观测要素。
- **外联行为识别**：可疑域名 / IP、异常协议、潜在 C2 通信特征。
- **横向移动可见性**：内部主机间会话拓扑。
- **威胁情报对接**：将本地观测与外部 IOC 源比对。

> 本组件采集的是 **元数据**，不做完整 payload 留存；详细告警/关联由 `form` 完成。

## 仓库形态

本目录是一个 **Cargo workspace**（Rust monorepo），各能力按 crate 拆分组织在 `crates/` 下。

```
collector/
├── Cargo.toml         # workspace 根
└── crates/            # 各子 crate（待添加）
```

## 新增 crate

```bash
cd collector
cargo new --lib crates/<crate-name>
# 然后在 collector/Cargo.toml 的 [workspace].members 中加入 "crates/<crate-name>"
```

## 构建 & 测试

```bash
cargo build --workspace
cargo test  --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all
```

## 计划中的初始 crate

> 仅作为规划占位，尚未实现。

- `collector-core`：捕获/解析调度内核。
- `collector-capture`：底层抓包后端（pcap / AF_PACKET / eBPF 适配层）。
- `collector-proto`：协议解析（DNS / HTTP / TLS SNI 等）。
- `collector-ioc`：威胁情报匹配。
- `collector-cli`：可执行二进制入口。
