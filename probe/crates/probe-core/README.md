# probe-core

**向后兼容门面**：重导出 `probe-contract` / `probe-runtime` 类型，并提供默认 v0 采集计划的便捷入口。

新代码建议直接依赖 `probe-runtime` + 领域 crate；保留本 crate 以兼容早期集成。

## API

```rust
use probe_core::{run_scan, run_scan_at, AssetReport};

let report = run_scan()?;           // 本机 `/`
let report = run_scan_at("/mnt/image")?;
```

等价于：

```rust
probe_runtime::run_scan_at(&probe_asset::default_collectors(), root)
```

## 契约测试

```bash
cargo test -p probe-core
```
