# scanner workspace crates

Rust workspace 成员索引。架构说明见 [`../docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md)，使用指南见 [`../README.md`](../README.md)。

## 依赖层次

```
scanner-cli / scanner-remote (bin)
    ├── scanner-asset / scanner-malware (domain)
    ├── scanner-ingest
    └── scanner-runtime
            └── scanner-contract

scanner-core (facade)
    ├── scanner-runtime
    └── scanner-asset
```

## Crate 列表

| 目录 | 包名 | 说明 | 文档 |
| --- | --- | --- | --- |
| `scanner-contract/` | `scanner-contract` | 数据契约（Rust 镜像） | [README](./scanner-contract/README.md) |
| `scanner-runtime/` | `scanner-runtime` | Collector 调度与 `run_scan_at` | [README](./scanner-runtime/README.md) |
| `scanner-asset/` | `scanner-asset` | 静态文件系统资产发现 | [README](./scanner-asset/README.md) |
| `scanner-malware/` | `scanner-malware` | ClamAV 病毒查杀 | [README](./scanner-malware/README.md) |
| `scanner-ingest/` | `scanner-ingest` | HTTP 上报 form | [README](./scanner-ingest/README.md) |
| `scanner-core/` | `scanner-core` | 向后兼容门面 | [README](./scanner-core/README.md) |
| `scanner-cli/` | `scanner-cli` | 主 CLI（合并报告） | [README](./scanner-cli/README.md) |
| `scanner-remote/` | `scanner-remote` | SSH 远端 agent 扫描 | [README](./scanner-remote/README.md) |

## 常用命令

```bash
# 全 workspace 测试
cargo test --workspace

# 静态资产扫描（独立二进制）
cargo run -p scanner-asset -- -r / -t all -o ./scan-out

# 合并 AssetReport
cargo run -p scanner-cli --features full -- -r / --pretty

# 远端扫描
cargo run -p scanner-remote -- --ssh-host user@host --target all -o ./reports/
```
