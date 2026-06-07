# fusion-ingest

将 [`AssetReport`](../../fusion-contract/src/lib.rs) POST 到 form 的 `/ingest/asset-report`、或将 [`FlowBatch`](../../fusion-contract/src/lib.rs) POST 到 `/ingest/flow-batch` 端点。

## API

```rust
use fusion_ingest::{upload_batch, upload_report};

upload_report(&report, "http://127.0.0.1:8000")?; // host AssetReport
upload_batch(&batch, "http://127.0.0.1:8000")?; // network FlowBatch
```

成功时 form 返回 `202 Accepted`。

## CLI 集成

`fusion-host-cli` 与 `fusion-remote` 在启用相应 feature / `--upload` 时调用本 crate。

```bash
cargo run -p fusion-host-cli --features ingest -- -r / --upload http://127.0.0.1:8000
```

## 依赖

使用 `reqwest` blocking client + rustls，默认超时 60 秒。
