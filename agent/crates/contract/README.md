# agent-contract

kcatta 扫描器 **数据契约** 的 Rust 实现。

## 权威来源

| 层级 | 路径 |
| --- | --- |
| Pydantic 模型 | `analyzer/src/analyzer/schemas/` |
| JSON Schema | `analyzer/schemas-json/` |
| Rust 类型 | 本 crate `src/lib.rs` |

各能力产出的 JSON 必须能分别通过 `AssetReport.schema.json` / `TraceBatch.schema.json` /
`GuardEventBatch.schema.json` 校验。

## 主要类型

- `HostInfo` — 主机描述
- `Asset` —  tagged union（`Package` / `Service` / `Port` / `Account` / `Credential`）
- `Vulnerability` — 风险项（含内置查毒命中，`source = "kcatta-malware"`）
- `AssetReport` — 一次采集周期的完整报告（agent-host → analyzer）
- `TraceBatch` / `TraceEvent` / `TraceProto` / `ThreatMatch` / `IndicatorType` — 网络流 envelope（agent-trace → analyzer）；定义在 `src/flow.rs`
- `GuardEventBatch` / `GuardEvent`（`Fim`|`Malware`|`Process`|`Network`|`Ids`）/ `ActionTaken` / `Outcome` / `FimChange` — 实时防护 envelope（agent-guard → analyzer）；定义在 `src/guard.rs`
- `Severity`（三侧共享）/ `IndicatorType`（flow 与 guard 共享）

## 使用

```toml
[dependencies]
agent-contract = { path = "../contract" }
```

```rust
use agent_contract::{AssetReport, HostInfo};
```

## 测试

契约一致性由集成测试保证：`crates/host/tests/contract.rs`（`AssetReport`）、
`crates/trace/tests/contract.rs`（`TraceBatch`）、以及本 crate 的
`tests/guard_contract.rs`（`GuardEventBatch`）。
