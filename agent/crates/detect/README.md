# agent-detect

Agent **detect** 层 umbrella：端上 finding / detection 逻辑（不含 CVE；CVE 在 Python
analyzer）。detect 不执行处置、不上传。内部阶段类型 `Detection` 物理定义在
`agent-contract`（非 Serde / 非 JSON wire），本 crate 产出并 re-export 它。

| 模块 | 说明 |
| --- | --- |
| [`malware`](malware/) | 独立 crate `agent-detect-malware`（本包 re-export） |
| [`host`](src/host.rs) | 组合 malware / posture / secrets，返回 host `Vulnerability` finding |
| [`posture`](src/posture.rs) | sshd / shadow / SUID 配置风险 |
| [`secrets`](src/secrets.rs) | 密钥与 token 泄露检测 |
| [`ioc`](src/ioc.rs) | `ThreatFeed` 加载 / 匹配 / enrich |
| [`network`](src/network.rs) | collected `TraceEvent` → IOC enrich + `Detection::Network/Ids`（含轻量 IDS 规则） |
| [`Detection`](../contract/src/detection.rs) | contract 定义的内部阶段事实；本 crate 的 detector 产出/re-export，respond pipeline 消费（FIM/behavior adapter 可在部署 crate 规范化） |

新编排代码直接调用 `agent_detect::host::detect`、`agent_detect::ioc::ThreatFeed::enrich` 或
`agent_detect::network::detect`。其中前者适合组装 host finding，IOC enrich 适合仍输出
`TraceBatch` 的 CLI / agentd；network detector 同时产出供 Respond 消费的 IOC/IDS `Detection`。
`agent-collect-host` 的 `DetectOpts` / `run_detect_at` / `run_scan_with_detect`，以及
`agent-collect-trace` 的 `ThreatFeed` re-export / `enrich_batch` / `run_capture_with_detect`，仍为
CLI 和旧调用方保留兼容组合能力。`agent-respond` 的 network sensor 只捕获并调用本 crate detector；
IOC/IDS 规则不属于 respond。respond 再消费返回的 `Detection` 完成 decide / safety / action / report。

**未迁入**：CycloneDX SBOM（仍在 `collect/host`，由包资产派生；见 REFACTOR-PIPELINE「后续」）。

见 [`../../docs/REFACTOR-PIPELINE.md`](../../docs/REFACTOR-PIPELINE.md)。
