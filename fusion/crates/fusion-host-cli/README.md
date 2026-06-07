# fusion-host-cli

posture 主机扫描 **主 CLI**：组装 Collector 计划、运行扫描、输出合并 `AssetReport` JSON，可选上报 form。

## 用法

```bash
# 完整报告 → stdout
cargo run -p fusion-host-cli -- -r / --pretty

# 写入文件
cargo run -p fusion-host-cli -- -r / --out report.json

# 静态分文件模式（等同 fusion-asset）
cargo run -p fusion-host-cli -- -r / -t all --asset-out ./scan-out

# 含 ClamAV（需 full feature）
cargo run -p fusion-host-cli --features full -- -r / --pretty

# 扫描后上报 form
cargo run -p fusion-host-cli --features ingest -- -r / --upload http://127.0.0.1:8000
```

## Features

| Feature | 说明 |
| --- | --- |
| `asset`（默认） | 静态资产采集 |
| `malware` | ClamAV 查杀 |
| `ingest` | `--upload` 上报 |
| `full` | `asset` + `malware` |

## 行为说明

- 指定 `--asset-out` 时进入 **静态分文件模式**，行为与 `fusion-asset` 一致，不输出合并 `AssetReport`。
- 未指定 `--asset-out` 时运行 Collector 计划，输出单个 `AssetReport` JSON。

完整参数见 [`../../README.md`](../../README.md)。
