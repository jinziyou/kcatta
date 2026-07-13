# agent-contract

kcatta agent 的 Rust 契约底座：既包含 analyzer-facing JSON wire 镜像，也包含 Collect/Detect/Respond
之间共享的 Rust 内部阶段类型。

## 权威来源

| 层级 | 路径 |
| --- | --- |
| Pydantic 模型 | `analyzer/src/analyzer/schemas/` |
| 公共 JSON Schema | `form/schemas-json/` |
| Rust wire 镜像 | 本 crate `src/{lib.rs,trace.rs,guard.rs}` |

各能力产出的 JSON 必须能分别通过 `AssetReport.schema.json` / `TraceBatch.schema.json` /
`GuardEventBatch.schema.json` 校验。

三个 envelope 都镜像可选的 `source_agent_id` / `source_target_id` provenance。Agent
生产者始终将它们留空，Serde 也不会把空值写到端点 payload；只有 Form 在认证 Agent 并完成
target 绑定后才能注入。Rust wire 接受并在拆分 chunk 时保留这两个字段，是为了完整镜像
Form→Analyzer 合同，不能把端点自行提交的同名值当作可信身份。

`Detection` 是例外：它定义在 `src/detection.rs`，是 Detect → Respond 的 Rust 内部 stage
contract，不实现 Serde，也不属于 analyzer Pydantic / JSON Schema wire。

## 主要类型

- `HostInfo` — 主机描述
- `Asset` —  tagged union（`Package` / `Service` / `Port` / `Account` / `Credential` / `Container`）
- `Vulnerability` — 风险项（含内置查毒命中，`source = "kcatta-malware"`）
- `AssetReport` — 一次采集周期的完整报告（agent-collect-host → Form → analyzer）
- `TraceBatch` / `TraceEvent` / `TraceProto` / `ThreatMatch` / `IndicatorType` — 网络流 envelope（agent-collect-trace → Form → analyzer）；定义在 `src/trace.rs`
- `GuardEventBatch` / `GuardEvent`（`Fim`|`Malware`|`Process`|`Network`|`Ids`）/ `ActionTaken` / `Outcome` / `FimChange` — 实时防护 envelope（agent-respond → Form → analyzer）；定义在 `src/guard.rs`
- `Detection` — 内部规范化检测事实；detect/respond re-export，由 detector 或实时 sensor adapter 产出、response pipeline 消费；定义在 `src/detection.rs`（非 wire）
- `Severity`（三侧共享）/ `IndicatorType`（trace 与 guard 共享）

## 使用

```toml
[dependencies]
agent-contract = { path = "../contract" }
```

```rust
use agent_contract::{AssetReport, HostInfo};
```

## 测试

契约一致性由集成测试保证：`crates/collect/host/tests/contract.rs`（`AssetReport`）、
`crates/collect/trace/tests/contract.rs`（`TraceBatch`）、以及本 crate 的
`tests/guard_contract.rs`（`GuardEventBatch`）。
