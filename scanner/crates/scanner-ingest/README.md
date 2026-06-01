# scanner-ingest

将 [`AssetReport`](../scanner-contract/src/lib.rs) POST 到 form 的 `/ingest/asset-report` 端点。

## API

```rust
use scanner_ingest::upload_report;

upload_report(&report, "http://127.0.0.1:8000")?;
```

成功时 form 返回 `202 Accepted`。

## CLI 集成

`scanner-cli` 与 `scanner-remote` 在启用相应 feature / `--upload` 时调用本 crate。

```bash
cargo run -p scanner-cli --features ingest -- -r / --upload http://127.0.0.1:8000
```

## 依赖

使用 `reqwest` blocking client + rustls，默认超时 60 秒。
