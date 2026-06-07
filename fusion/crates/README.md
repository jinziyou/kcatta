# fusion workspace crates

Rust workspace 成员索引。架构说明见 [`../docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md)，使用指南见 [`../README.md`](../README.md)。

fusion 按「主机（内视）+ 网络（外视）」两个领域拆分，二者共享 `fusion-contract`（数据契约）
与 `fusion-ingest`（上报客户端）。

## 依赖层次

```
共享: fusion-contract  ◄──  fusion-ingest  (POST AssetReport / FlowBatch → form)

主机域:
  fusion-host-cli / fusion-remote (bin)
      ├── fusion-asset / fusion-malware (domain)
      ├── fusion-runtime ──► fusion-contract
      └── fusion-ingest

网络域:
  fusion-flow-cli / fusion-intel-sync (bin)
      ├── fusion-flow  (capture + intel) ──► fusion-contract
      └── fusion-ingest
```

## Crate 列表

| 领域 | 目录 | 包名 | 说明 | 文档 |
| --- | --- | --- | --- | --- |
| 共享 | `fusion-contract/` | `fusion-contract` | 数据契约（Rust 镜像）：`AssetReport` + `FlowBatch` | [README](./fusion-contract/README.md) |
| 共享 | `fusion-ingest/` | `fusion-ingest` | HTTP 上报 form（两种 envelope 泛型） | [README](./fusion-ingest/README.md) |
| 主机 | `fusion-runtime/` | `fusion-runtime` | Collector 调度与 `run_scan_at` | [README](./fusion-runtime/README.md) |
| 主机 | `fusion-asset/` | `fusion-asset` | 静态文件系统资产发现 | [README](./fusion-asset/README.md) |
| 主机 | `fusion-malware/` | `fusion-malware` | ClamAV 病毒查杀 | [README](./fusion-malware/README.md) |
| 主机 | `fusion-host-cli/` | `fusion-host-cli` | 主机 CLI（bin: `fusion-host`，合并报告） | [README](./fusion-host-cli/README.md) |
| 主机 | `fusion-remote/` | `fusion-remote` | SSH 远端 agent 扫描 | [README](./fusion-remote/README.md) |
| 网络 | `fusion-flow/` | `fusion-flow` | 流量捕获 + 威胁情报 IOC 匹配 | [README](./fusion-flow/README.md) |
| 网络 | `fusion-intel-sync/` | `fusion-intel-sync` | 拉取 IOC feed → 本地 JSON | [README](./fusion-intel-sync/README.md) |
| 网络 | `fusion-flow-cli/` | `fusion-flow-cli` | 网络 CLI（bin: `fusion-flow`） | [README](./fusion-flow-cli/README.md) |

## 常用命令

```bash
# 全 workspace 测试
cargo test --workspace

# —— 主机域 ——
# 静态资产扫描（独立二进制）
cargo run -p fusion-asset -- -r / -t all -o ./scan-out
# 合并 AssetReport
cargo run -p fusion-host-cli --features full -- -r / --pretty
# 远端扫描
cargo run -p fusion-remote -- --ssh-host user@host --target all -o ./reports/

# —— 网络域 ——
# 抓包 + 威胁情报匹配 → FlowBatch（mock 默认）
cargo run -p fusion-flow-cli -- --pretty
# 同步 IOC 情报库（abuse.ch Feodo）
cargo run -p fusion-intel-sync -- --source feodo --out data/feeds/feodo.json
```
