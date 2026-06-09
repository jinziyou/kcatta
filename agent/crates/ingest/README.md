# agent-ingest

阻塞式 HTTP 上报客户端，将检测产物 POST 到 fusion 的 ingest 端点。独立顶层 crate（`crates/ingest`），仅依赖 [`agent-contract`](../contract)。

- 将 [`AssetReport`](../contract/src/lib.rs) POST 到 fusion 的 `/ingest/asset-report`；
- 将 [`FlowBatch`](../contract/src/flow.rs) POST 到 `/ingest/flow-batch`；
- 将 [`GuardEventBatch`](../contract/src/guard.rs) POST 到 `/ingest/guard-event`。

## API

```rust
use agent_ingest::{upload_batch, upload_guard_batch, upload_report};

upload_report(&report, "http://127.0.0.1:8000")?;      // AssetReport     → /ingest/asset-report
upload_batch(&batch, "http://127.0.0.1:8000")?;        // FlowBatch       → /ingest/flow-batch
upload_guard_batch(&events, "http://127.0.0.1:8000")?; // GuardEventBatch → /ingest/guard-event
```

请求携带 `FUSION_API_TOKEN` 环境变量作为 Bearer 鉴权头；fusion 返回 `202 Accepted` 视为成功。

## 调用方

由 `posture-host` / `posture-flow` / `posture-guard` 在指定 `--upload URL` 时调用：

```bash
cargo run -p posture-host -- -r / -t all --upload http://127.0.0.1:8000
cargo run -p posture-flow -- capture --intel data/feeds/feodo.json --upload http://127.0.0.1:8000
cargo run -p posture-guard -- --upload http://127.0.0.1:8000
```

## 依赖

`reqwest` blocking client + rustls，默认超时 60 秒。
