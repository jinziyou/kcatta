# agent workspace crates

Rust workspace 成员索引。架构说明见 [`../docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md)，
使用指南见 [`../README.md`](../README.md)。

**5 个 crate**：1 个数据契约底座 + 3 个能力（一个能力 = 一个目录 = 一个 crate，lib+bin 同处）
+ 1 个统一入口 `agent`。**上报模型**：三个能力独立运行**只产出结果文件**，不上报；
**只有 `agent <cap> --upload` 才上报 analyzer**（ingest 能力内置于 `agent`）。

| 类别 | 目录 | 包名 | 说明 |
| --- | --- | --- | --- |
| 底座 | `contract/` | `agent-contract` | 数据契约（analyzer `schemas-json` 镜像）：`AssetReport` + `FlowBatch` + `GuardEventBatch` + 共享 `Severity`/`IndicatorType`。零内部依赖（DAG 汇点）。 |
| **主机静态文件检测** | `host/` | `agent-host` | lib（主机检测 + **内置签名/哈希查毒**，被 guard on-access 复用 + `cli` 模块）+ bin `agent-host` → 写 `AssetReport` 文件。 |
| **流量检测** | `flow/` | `agent-flow` | lib（capture mock/pcap + IOC 匹配，被 guard network 复用 + `cli` 模块）+ bin `agent-flow`（`capture`/`intel-sync`）→ 写 `FlowBatch` 文件。 |
| **实时防护** | `guard/` | `agent-guard` | lib（传感器 + detect→decide→respond→report + 安全 + `cli` 模块）+ bin `agent-guard` → 本地 NDJSON/stdout。 |
| 统一入口 | `agent/` | `agent` | umbrella：`agent host\|flow\|guard` 进程内分发到各能力 `cli`；**内置 ingest**（`--upload` 才上报 analyzer）。 |

## 分层与依赖（单向、无环；bin 与 lib 同 crate）

依赖 DAG 见 [`../docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md)。

- 各能力的 CLI（Args + run）放在各 lib 的 `pub mod cli`；三个独立 bin 与 umbrella `agent` 共用，不重复、不 shell-out。
- 能力 `run` 只**产出**结果（host/flow 返回 envelope 供 agent 上报；guard 把事件写本地 sink）。上报由 agent 注入：host/flow 拿返回值 POST；guard 由 agent 注入一个 `ReportSink`（analyzer sink）。
- guard 经 feature 可选依赖 `agent-host`(onaccess) / `agent-flow`(network)，默认（fim+behavior）不牵入。

## Feature 速查

- `agent-host`：无 feature；`--malware` 始终可用（内置签名引擎，仅 std+sha2，无外部守护进程）。
- `agent-flow`：`default=[]`；`pcap`（实时抓包，否则 mock）。
- `agent-guard`：`default=[fim,behavior]`；`onaccess`（→ agent-host）；`network`（→ agent-flow）；`ids`；`pcap`；`all`。
- `agent`：`pcap`/`onaccess`/`network`/`ids`/`full` 转发到对应能力 crate。

## 常用命令

```bash
cargo test --workspace                              # 全 workspace（含三契约校验 + 内置查毒）
cargo test -p agent-guard --features all          # guard 全传感器（无需 root）

# 独立运行：只产出结果文件，不上报
cargo run -p agent-host -- -r / -t all -o ./scan-out
cargo run -p agent-host -- -r / --malware --pretty
cargo run -p agent-flow -- capture --pretty
cargo run -p agent-guard -- --stdout

# 统一 agent：可 --upload 上报 analyzer
cargo run -p agent -- host -r / --malware --upload http://127.0.0.1:8000
cargo run -p agent -- flow --upload http://127.0.0.1:8000 capture
cargo run -p agent -- guard --upload http://127.0.0.1:8000
```

## 边界

`agent-host` / `agent-flow` **只采集**；CVE 判定 / 跨源关联在 **analyzer** 侧。
**`agent-guard` 是唯一会端上主动处置的能力**（可逆隔离 / 网络阻断 / 阻断打开），默认
monitor 关闭、受安全否决保护。**上报只发生在 `agent --upload`**；跨机投放（`analyzer-scan`，Python）属于 analyzer。

## 契约校验测试

- [`host/tests/contract.rs`](./host/tests/contract.rs) —— `AssetReport`。
- [`flow/tests/contract.rs`](./flow/tests/contract.rs) —— `FlowBatch`。
- [`contract/tests/guard_contract.rs`](./contract/tests/guard_contract.rs) —— `GuardEventBatch`。
