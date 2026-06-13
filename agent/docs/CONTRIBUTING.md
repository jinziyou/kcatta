# agent 开发指南

面向在 `kcatta/agent` workspace 内贡献代码的说明。

## 环境

- Rust stable（`rustup default stable`）
- 可选：`x86_64-unknown-linux-musl` target（精简主机扫描静态二进制）
- 可选：`libpcap-dev`（编译 / 测试 `pcap` feature；CI 已安装）

```bash
cd agent
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

## 架构速查

详见 [`ARCHITECTURE.md`](./ARCHITECTURE.md)。三大能力，**一个能力 = 一个目录 = 一个 crate**
（lib + bin 同处一个 crate，无嵌套子 crate），共享数据契约 + 上报 + CLI 底座：

| 目录 / 包名 | 职责 |
| --- | --- |
| `contract` / `agent-contract` | 数据契约：`AssetReport` + `FlowBatch` + `GuardEventBatch` + 共享 `Severity`/`IndicatorType`。零内部依赖。 |
| `host` / `agent-host` | 主机检测 + 内置签名查毒（`malware` 模块）+ CLI（`cli` 模块）+ `agent-host` 二进制。只写文件。 |
| `flow` / `agent-flow` | 捕获 + IOC 匹配 + feed 解析（lib 无 reqwest）+ CLI（`cli`，含 `intel-sync` 的 HTTP 下载）+ `agent-flow` 二进制。只写文件。 |
| `guard` / `agent-guard` | 实时防护引擎 + CLI（`cli` 模块）+ `agent-guard` 守护进程。写本地 NDJSON/stdout。 |
| `agent` / `agent` | umbrella：`agent host`/`flow`/`guard` 分发到各能力 `cli`；**内置 ingest**（`src/ingest.rs`），`--upload` 才上报 analyzer。 |

各能力的 CLI（`Args` + `run`）放在各 lib 的 `pub mod cli`，三个独立 bin 与 umbrella `agent` 共用——
新增/修改 CLI 改 `crates/<cap>/src/cli.rs`，三处入口（独立 bin、`agent <cap>`、本能力测试）自动一致。
**能力只采集、不上报**：`host`/`flow` 的 `run` 返回 envelope（供 agent 上报）；`guard` 经注入的 `ReportSink`
上报。

依赖 DAG（单向无环，5 crate）见 [`ARCHITECTURE.md`](./ARCHITECTURE.md)。

**原则**：`agent-host` / `agent-flow` 只采集；CVE 判定与跨源关联在 analyzer 侧。
**`agent-guard` 是唯一会端上主动处置的能力**（默认 monitor、受安全否决保护）。跨机投放由
analyzer 的 `analyzer-scan`（Python）负责（投放 `agent-host`）。

## 新增采集器（主机静态检测）

采集器落在 `agent-host` 的 lib：

1. 实现 [`Collector`](../crates/host/src/collector.rs)。
2. 若产出新 asset 类型，**先**扩展 analyzer Pydantic → 生成 JSON Schema → 更新 [`agent-contract`](../crates/contract/src/lib.rs)。
3. 编排进 `default_collectors()`（`crates/host/src/lib.rs`）。
4. 在 [`crates/host/tests/contract.rs`](../crates/host/tests/contract.rs) 补充 `AssetReport` 校验。

Host collector 必须排首位（后续依赖 `ctx.host_id`）。内部分层：`collectors/` · `sources/` · `walk/` · `platform/` · `malware`（内置查毒）。

### 扩展内置查毒

`crates/host/src/malware.rs`：`SignatureSet` 支持 `Sha256` 与 `Bytes` 规则；新增规则类型在此扩展（命中走 `match_file` / `scan_bytes`）。引擎纯 `std`+`sha2`，无外部守护进程；`scan_bytes` 被 guard on-access 复用。

## 新增情报源（流量检测）

1. 在 [`crates/flow/src/intel/sync/`](../crates/flow/src/intel/sync) 实现 feed 适配器（参考 `feodo.rs`，只解析字节）。
2. 在 `agent-flow` 的 `intel-sync` 子命令（`crates/flow/src/cli.rs`）`--source` 分发中接入；HTTP 下载用本地 `http_get_text`（reqwest）。
3. 产出对齐 `ThreatFeed` 的本地 JSON。

## 新增传感器（实时防护）

传感器落在 `crates/guard/src/sensors/`，实现 [`Sensor`](../crates/guard/src/sensors/mod.rs) trait（自有线程、向 `mpsc` 推 `Detection`、轮询 `shutdown`）：

1. 新增 `Detection` 变体（`event.rs`）与契约事件（先扩展 analyzer `guard_event.py` → JSON Schema → `agent-contract/src/guard.rs`）。
2. 实现传感器，按 `#[cfg(all(target_os = "linux", feature = "..."))]` 门控；在 `build_sensors` 挂接。
3. 新处置动作：扩展 `decide::Action`、`respond` 执行，**并先在 `respond::safety` 加否决规则**，再补单元测试（safety 测试防自伤，最高优先级）。
4. 在 `report::build_event` 补 `Detection → GuardEvent` 映射。

syscall 一律走安全的 `nix` 封装，不写 `unsafe`。

## 数据契约

| 步骤 | 位置 |
| --- | --- |
| 编辑模型 | `analyzer/src/analyzer/schemas/`（guard 在 `guard_event.py`） |
| 生成 JSON Schema | `analyzer-export-schemas` → `analyzer/schemas-json/` |
| Rust 镜像 | `contract/src/{lib.rs, flow.rs, guard.rs}` |
| 校验 | `cargo test -p agent-host` / `-p agent-flow` / `-p agent-contract`（guard） |

CI 经 `git diff --exit-code schemas-json/` 守护跨语言漂移。

## 代码风格

- workspace `rustfmt` / `clippy`（`unsafe_code = deny`）。
- `missing_docs = "warn"`（`clippy -D warnings` 升级为错误，公共项均需文档）；`agent-contract` 为 `deny`。

## 测试

| 类型 | 位置 | 运行 |
| --- | --- | --- |
| 主机契约 | `crates/host/tests/contract.rs` | `cargo test -p agent-host` |
| 网络契约 | `crates/flow/tests/contract.rs` | `cargo test -p agent-flow` |
| 实时防护契约 | `crates/contract/tests/guard_contract.rs` | `cargo test -p agent-contract` |
| 内置查毒 | `crates/host/src/malware.rs`（`#[cfg(test)]`） | `cargo test -p agent-host` |
| guard 流水线 / 安全 | `crates/guard/src/*` | `cargo test -p agent-guard --features all`（无需 root） |

端到端验证：

```bash
cargo run -p agent-host -- -r / --pretty                                   # 合并 AssetReport
cargo run -p agent-host -- -r / --malware --pretty                         # 含内置查毒
cargo run -p agent-flow -- capture --pretty                                # FlowBatch（mock）
cargo run -p agent-guard -- --stdout                                       # 实时防护（monitor 默认）
```

## 二进制与 feature

| crate（= 能力目录） | features |
| --- | --- |
| `agent-host` | 无（`--malware` 始终可用，内置签名引擎） |
| `agent-flow` | `default = []`；`pcap` |
| `agent-guard` | `default = [fim, behavior]`；`onaccess`（→ agent-host）；`network`（→ agent-flow）；`ids`；`pcap`；`all` |

```bash
cargo build -p agent-host --target x86_64-unknown-linux-musl --release   # 精简主机扫描
cargo build -p agent-flow --no-default-features                          # 精简流量检测
cargo build -p agent-guard --no-default-features --features fim          # 精简实时防护（仅 FIM）
cargo build -p agent-flow --features pcap                                # 实时抓包
```

## 文档维护

修改公共 API 或 CLI 参数时同步更新：对应 crate `README.md`、`agent/README.md`、必要时
`docs/ARCHITECTURE.md`。
