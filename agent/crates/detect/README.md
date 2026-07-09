# agent-detect

Agent **detect** 层 umbrella：端上 finding 引擎（不含 CVE；CVE 在 Python analyzer）。

| 模块 | 说明 |
| --- | --- |
| [`malware`](malware/) | 独立 crate `agent-detect-malware`（本包 re-export） |
| [`posture`](src/posture.rs) | sshd / shadow / SUID 配置风险 |
| [`secrets`](src/secrets.rs) | 密钥与 token 泄露检测 |
| [`ioc`](src/ioc.rs) | `ThreatFeed` 加载 / 匹配 / enrich（trace 经 `agent_collect_trace::ThreatFeed` re-export） |

消费者：`agent-collect-host` detect phase（`DetectOpts` / `run_detect_at`）；`agent-collect-trace` `enrich_batch` /
`intel::sync`；`agent-respond` on-access（`scan_bytes`）。

**未迁入**：CycloneDX SBOM（仍在 `collect/host`，由包资产派生；见 REFACTOR-PIPELINE「后续」）。

见 [`../../docs/REFACTOR-PIPELINE.md`](../../docs/REFACTOR-PIPELINE.md)。
