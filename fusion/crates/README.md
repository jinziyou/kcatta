# fusion workspace crates

Rust workspace 成员索引。架构说明见 [`../docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md)，使用指南见 [`../README.md`](../README.md)。

crate 按 **4 个能力域 + 1 个共享底座**（4+1）分组——目录即域：`host/`、`flow/`、`malware/`、`runtime/`，外加顶层 `contract/` 底座。

## 分层与依赖（单向、无环）

```
+1 底座:   fusion-contract        (数据契约: AssetReport + FlowBatch, 零内部依赖, DAG 汇点)

runtime 域 (基础设施, 被各域依赖):
  fusion-runtime ──► fusion-contract     (Collector trait / ScanContext / run_scan_at)
  fusion-ingest  ──► fusion-contract     (POST AssetReport / FlowBatch → form)

host 域 (内视 → AssetReport):
  fusion-host-cli / fusion-remote (编排 bin)
      ├── fusion-asset                 (静态资产采集, 实现 Collector)
      ├── fusion-malware               (ClamAV; host 子能力, Vulnerability 汇入 AssetReport)
      ├── fusion-runtime ──► fusion-contract
      └── fusion-ingest

flow 域 (外视 → FlowBatch):
  fusion-flow  (lib + bin: fusion-flow / fusion-intel-sync)
      ├── capture + intel ──► fusion-contract
      └── fusion-ingest
```

> 编排器（各域 CLI）依赖各域实现与底座，但**没有任何 crate 反向依赖编排器**——故只做主机扫描的二进制不会牵入网络抓包依赖，纯 mock 演示也不牵 libpcap / HTTP。

## Crate 列表

| 域 | 目录 | 包名 | 说明 | 文档 |
| --- | --- | --- | --- | --- |
| 底座 | `contract/` | `fusion-contract` | 数据契约（Rust 镜像）：`AssetReport` + `FlowBatch` | [README](./contract/README.md) |
| runtime | `runtime/fusion-runtime/` | `fusion-runtime` | Collector 调度抽象与 `run_scan_at` | [README](./runtime/fusion-runtime/README.md) |
| runtime | `runtime/fusion-ingest/` | `fusion-ingest` | HTTP 上报 form（两种 envelope 泛型） | [README](./runtime/fusion-ingest/README.md) |
| host | `host/fusion-asset/` | `fusion-asset` | 静态文件系统资产发现（lib + bin） | [README](./host/fusion-asset/README.md) |
| host | `host/fusion-remote/` | `fusion-remote` | SSH / WinRM 远端 agent 扫描（lib + bin） | [README](./host/fusion-remote/README.md) |
| host | `host/fusion-host-cli/` | `fusion-host-cli` | 主机编排 CLI（bin: `fusion-host`，合并报告） | [README](./host/fusion-host-cli/README.md) |
| malware | `malware/` | `fusion-malware` | ClamAV 病毒查杀（host 子能力，独立 bin） | [README](./malware/README.md) |
| flow | `flow/` | `fusion-flow` | 流量捕获 + IOC 匹配 + 情报同步（lib + bin: `fusion-flow` / `fusion-intel-sync`） | [README](./flow/README.md) |

## 常用命令

```bash
# 全 workspace 测试
cargo test --workspace

# —— host 域 ——
# 静态资产扫描（独立二进制）
cargo run -p fusion-asset -- -r / -t all -o ./scan-out
# 合并 AssetReport（含 ClamAV 查杀）
cargo run -p fusion-host-cli --features full -- -r / --pretty
# 远端扫描
cargo run -p fusion-remote -- --ssh-host user@host --target all -o ./reports/

# —— flow 域 ——
# 抓包 + 威胁情报匹配 → FlowBatch（mock 默认）
cargo run -p fusion-flow -- --pretty
# 同步 IOC 情报库（abuse.ch Feodo）
cargo run -p fusion-flow --bin fusion-intel-sync -- --source feodo --out data/feeds/feodo.json
```
