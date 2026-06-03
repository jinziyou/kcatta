# probe workspace crates

Rust workspace 成员索引。架构说明见 [`../docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md)，使用指南见 [`../README.md`](../README.md)。

probe 按「主机（内视）+ 网络（外视）」两个领域拆分，二者共享 `probe-contract`（数据契约）
与 `probe-ingest`（上报客户端）。

## 依赖层次

```
共享: probe-contract  ◄──  probe-ingest  (POST AssetReport / FlowBatch → form)

主机域:
  probe-host-cli / probe-remote (bin)
      ├── probe-asset / probe-malware (domain)
      ├── probe-runtime ──► probe-contract
      └── probe-ingest
  probe-core (facade) ──► probe-runtime + probe-asset

网络域:
  probe-flow-cli / probe-intel-sync (bin)
      ├── probe-flow  (capture + intel) ──► probe-contract
      └── probe-ingest
```

## Crate 列表

| 领域 | 目录 | 包名 | 说明 | 文档 |
| --- | --- | --- | --- | --- |
| 共享 | `probe-contract/` | `probe-contract` | 数据契约（Rust 镜像）：`AssetReport` + `FlowBatch` | [README](./probe-contract/README.md) |
| 共享 | `probe-ingest/` | `probe-ingest` | HTTP 上报 form（两种 envelope 泛型） | [README](./probe-ingest/README.md) |
| 主机 | `probe-runtime/` | `probe-runtime` | Collector 调度与 `run_scan_at` | [README](./probe-runtime/README.md) |
| 主机 | `probe-asset/` | `probe-asset` | 静态文件系统资产发现 | [README](./probe-asset/README.md) |
| 主机 | `probe-malware/` | `probe-malware` | ClamAV 病毒查杀 | [README](./probe-malware/README.md) |
| 主机 | `probe-core/` | `probe-core` | 主机门面（`run_scan` / 默认计划） | [README](./probe-core/README.md) |
| 主机 | `probe-host-cli/` | `probe-host-cli` | 主机 CLI（bin: `probe-host`，合并报告） | [README](./probe-host-cli/README.md) |
| 主机 | `probe-remote/` | `probe-remote` | SSH 远端 agent 扫描 | [README](./probe-remote/README.md) |
| 网络 | `probe-flow/` | `probe-flow` | 流量捕获 + 威胁情报 IOC 匹配 | — |
| 网络 | `probe-intel-sync/` | `probe-intel-sync` | 拉取 IOC feed → 本地 JSON | — |
| 网络 | `probe-flow-cli/` | `probe-flow-cli` | 网络 CLI（bin: `probe-flow`） | — |

## 常用命令

```bash
# 全 workspace 测试
cargo test --workspace

# —— 主机域 ——
# 静态资产扫描（独立二进制）
cargo run -p probe-asset -- -r / -t all -o ./scan-out
# 合并 AssetReport
cargo run -p probe-host-cli --features full -- -r / --pretty
# 远端扫描
cargo run -p probe-remote -- --ssh-host user@host --target all -o ./reports/

# —— 网络域 ——
# 抓包 + 威胁情报匹配 → FlowBatch（mock 默认）
cargo run -p probe-flow-cli -- --pretty
# 同步 IOC 情报库（abuse.ch Feodo）
cargo run -p probe-intel-sync -- --source feodo --out data/feeds/feodo.json
```
