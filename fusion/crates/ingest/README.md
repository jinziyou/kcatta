# fusion-ingest

阻塞式 HTTP 上报客户端，将检测产物 POST 到 form 的 ingest 端点。独立顶层 crate（`crates/ingest`），仅依赖 [`fusion-contract`](../contract)。

- 将 [`AssetReport`](../contract/src/lib.rs) POST 到 form 的 `/ingest/asset-report`；
- 将 [`FlowBatch`](../contract/src/lib.rs) POST 到 `/ingest/flow-batch`。

## API

```rust
use fusion_ingest::{upload_batch, upload_report};

upload_report(&report, "http://127.0.0.1:8000")?; // host AssetReport → /ingest/asset-report
upload_batch(&batch, "http://127.0.0.1:8000")?;    // network FlowBatch → /ingest/flow-batch
```

请求携带 `FORM_API_TOKEN` 环境变量作为 Bearer 鉴权头；form 返回 `202 Accepted` 视为成功。

## 调用方

由 `fusion`（`fusion-runtime`）的 `host` / `flow` 子命令在指定 `--upload URL` 时调用：

```bash
cargo run -p fusion-runtime -- host -r / -t all --upload http://127.0.0.1:8000
cargo run -p fusion-runtime -- flow --intel data/feeds/feodo.json --upload http://127.0.0.1:8000
```

## 依赖

`reqwest` blocking client + rustls，默认超时 60 秒。
