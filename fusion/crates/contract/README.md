# fusion-contract

posture 扫描器 **数据契约** 的 Rust 实现。

## 权威来源

| 层级 | 路径 |
| --- | --- |
| Pydantic 模型 | `form/src/form/schemas/` |
| JSON Schema | `form/schemas-json/` |
| Rust 类型 | 本 crate `src/lib.rs` |

scanner / collector 产出的 JSON 必须能分别通过 `AssetReport.schema.json` / `FlowBatch.schema.json` 校验。

## 主要类型

- `HostInfo` — 主机描述
- `Asset` —  tagged union（`Package` / `Service` / `Port` / `Account` / `Credential`）
- `Vulnerability` — 风险项（含 ClamAV 命中）
- `AssetReport` — 一次采集周期的完整报告（scanner → form）
- `FlowBatch` / `FlowEvent` / `FlowProto` / `ThreatMatch` / `IndicatorType` — 网络流 envelope（collector → form）；定义在 `src/flow.rs`，由 `lib.rs` 重导出
- `Severity` — 主机 `Vulnerability` 与网络 `ThreatMatch` 共享的风险等级

## 使用

```toml
[dependencies]
fusion-contract = { path = "../contract" }
```

```rust
use fusion_contract::{AssetReport, HostInfo};
```

## 测试

契约一致性由 `fusion-host` 与 `fusion-flow` 的集成测试保证（`crates/host/tests/contract.rs` 校验 `AssetReport`、`crates/flow/tests/contract.rs` 校验 `FlowBatch`），本 crate 无独立测试。
