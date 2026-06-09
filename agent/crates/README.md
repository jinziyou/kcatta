# agent workspace crates

Rust workspace 成员索引。架构说明见 [`../docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md)，
使用指南见 [`../README.md`](../README.md)。

agent 分为**三大能力**，**一个能力 = 一个目录 = 一个 crate**（lib + bin 同处一个 crate，
无嵌套子 crate）；三者共享 `agent-contract`（数据契约）+ `agent-ingest`（上报）+
`agent-cli-common`（CLI 底座）。

| 类别 | 目录 | 包名 | 说明 |
| --- | --- | --- | --- |
| 底座 | `contract/` | `agent-contract` | 数据契约（fusion `schemas-json` 镜像）：`AssetReport` + `FlowBatch` + `GuardEventBatch` + 共享 `Severity`/`IndicatorType`。零内部依赖（DAG 汇点）。 |
| 底座 | `ingest/` | `agent-ingest` | 阻塞 HTTP 上报：`upload_report` / `upload_batch` / `upload_guard_batch`，`FUSION_API_TOKEN` Bearer，202 成功。 |
| 底座 | `cli-common/` | `agent-cli-common` | 共享 CLI 底座：JSON 输出 sink + 阻塞 HTTP client。零内部依赖、无领域逻辑。 |
| **主机静态文件检测** | `host/` | `posture-host` | lib（主机检测 + **内置签名/哈希查毒**，被 guard on-access 复用）+ bin `posture-host` → `AssetReport`。 |
| **流量检测** | `flow/` | `posture-flow` | lib（capture mock/pcap + IOC 匹配，被 guard network 复用）+ bin `posture-flow`（`capture`/`intel-sync`）→ `FlowBatch`。 |
| **实时防护** | `guard/` | `posture-guard` | lib（传感器 + detect→decide→respond→report 流水线 + 安全）+ bin `posture-guard` → `GuardEventBatch`。 |

## 分层与依赖（单向、无环；bin 与 lib 同 crate，capability crate 互为 lib 依赖）

```
底座:  agent-contract   (数据契约: AssetReport + FlowBatch + GuardEventBatch, 零内部依赖)
       agent-cli-common (输出 + HTTP, 零内部依赖)

       agent-contract ◄── agent-ingest    (POST 三种 envelope → fusion)
       agent-contract ◄── posture-host    (主机检测 + 内置查毒)
       agent-contract ◄── posture-flow    (capture + IOC 匹配 + feed 解析)
       agent-contract ◄── posture-guard ◄── posture-host(onaccess, 复用 malware) + posture-flow(network, 复用 capture)
```

> guard 通过 feature 可选依赖：`onaccess → posture-host`（复用其 `malware` 模块），`network → posture-flow`（复用 capture + `ThreatFeed`）。默认 guard（fim+behavior）不牵入二者，保持精简。

## Feature 速查

- `posture-host`：无 feature；`--malware` 始终可用（内置签名引擎，仅 std+sha2，无外部守护进程）。
- `posture-flow`：`default=[]`；`pcap`（实时抓包，否则 mock）。
- `posture-guard`：`default=[fim,behavior]`；`onaccess`（→ posture-host）；`network`（→ posture-flow）；`ids`（→ network）；`pcap`（→ posture-flow/pcap）；`all`。

## 常用命令

```bash
cargo test --workspace                              # 全 workspace（含三契约校验 + 内置查毒）
cargo test -p posture-guard --features all          # guard 全传感器（无需 root）

# 主机静态文件检测（--malware 内置签名引擎，可 --malware-signatures 加载额外签名）
cargo run -p posture-host -- -r / -t all -o ./scan-out
cargo run -p posture-host -- -r / --malware --pretty

# 流量检测
cargo run -p posture-flow -- capture --pretty
cargo run -p posture-flow -- intel-sync --source feodo --out data/feeds/feodo.json

# 实时防护（默认 monitor，无需 root）
cargo run -p posture-guard -- --stdout
```

## 边界

`posture-host` / `posture-flow` **只采集**；CVE 判定 / 跨源关联在 **fusion** 侧。
**`posture-guard` 是唯一会端上主动处置的能力**（可逆隔离 / 网络阻断 / 阻断打开），默认
monitor 关闭、受安全否决保护。跨机投放（`fusion-scan`，Python）属于 fusion。

## 契约校验测试

- [`scan/tests/contract.rs`](./scan/tests/contract.rs) —— `AssetReport`。
- [`flow/tests/contract.rs`](./flow/tests/contract.rs) —— `FlowBatch`。
- [`contract/tests/guard_contract.rs`](./contract/tests/guard_contract.rs) —— `GuardEventBatch`。
