# scanner-core

**向后兼容门面**：重导出 `scanner-contract` / `scanner-runtime` 类型，并提供默认 v0 采集计划的便捷入口。

新代码建议直接依赖 `scanner-runtime` + 领域 crate；保留本 crate 以兼容早期集成。

## API

```rust
use scanner_core::{run_scan, run_scan_at, AssetReport};

let report = run_scan()?;           // 本机 `/`
let report = run_scan_at("/mnt/image")?;
```

等价于：

```rust
scanner_runtime::run_scan_at(&scanner_asset::default_collectors(), root)
```

## 契约测试

```bash
cargo test -p scanner-core
```
