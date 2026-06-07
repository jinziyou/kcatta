# fusion-runtime

扫描 **调度层**：定义 `Collector` trait、`ScanContext` 与 `run_scan_at`，将各领域采集器合并为 `AssetReport`。

## 核心 API

```rust
use fusion_runtime::{Collector, ScanContext, run_scan_at};

let collectors: Vec<Box<dyn Collector>> = /* from fusion-asset, fusion-malware, ... */;
let report = run_scan_at(&collectors, "/")?;
```

带额外项目根（语言包 venv / `node_modules`）：

```rust
run_scan_at_with(&collectors, "/", vec!["srv/app".into()])?;
```

## 模块

| 文件 | 内容 |
| --- | --- |
| `collector.rs` | `ScanContext`、`Collector`、`CollectorOutput` |
| `lib.rs` | `run_scan` / `run_scan_at` / `run_scan_at_with` |

## 契约测试

```bash
cargo test -p fusion-runtime
```

对照 `form/schemas-json/AssetReport.schema.json` 校验扫描输出。
