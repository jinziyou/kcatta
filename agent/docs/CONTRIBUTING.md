# agent 开发指南

面向在 `kcatta/agent` workspace 内贡献代码的说明。

## 环境

- Rust stable（`rustup default stable`）
- 可选：`x86_64-unknown-linux-musl` target（精简主机扫描静态二进制）
- 可选：`libpcap-dev`（编译 / 测试 `pcap` feature；CI 已安装）
- 可选（eBPF）：nightly + `rust-src` + `cargo install bpf-linker`（仅当编译 `ebpf` feature 时需要，见下文）

```bash
cd agent
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

## 架构速查

详见 [`ARCHITECTURE.md`](./ARCHITECTURE.md)。三大能力（host/trace/guard）+ 数据契约底座（contract）+ agentd 编排入口 + eBPF 支撑 crate，**一个 crate = 一个目录**
（lib + bin 同处一个 crate，无嵌套子 crate），共享数据契约 + 上报 + CLI 底座：

| 目录 / 包名 | 职责 |
| --- | --- |
| `contract` / `agent-contract` | 数据契约：`AssetReport` + `TraceBatch`（`events` 网络五元组 + `file_events` + `process_events`）+ `GuardEventBatch` + 共享 `FileOp`/`ProcessEventType`/`Severity`/`IndicatorType`。零内部依赖。 |
| `host` / `agent-host` | 主机静态资产扫描（包/SBOM/服务/账户/凭据/容器）+ 内置签名查毒（`malware` 模块）+ CLI（`cli` 模块）+ `agent-host` 二进制。编程入口 `run_scan_at()`。只写文件。 |
| `trace` / `agent-trace` | 追踪：网络流经 mock(默认)/pcap(feature) 抓包 + IOC 匹配 → `TraceBatch.events`；启用 `ebpf` feature 后挂接 exec/exit + openat tracepoint，从 ring buffer 排空到 `file_events`/`process_events`。CLI（`cli`，含 `intel-sync` 的 HTTP 下载）+ `agent-trace` 二进制。lib 无 reqwest，只写文件。 |
| `guard` / `agent-guard` | 实时防护引擎（sensor → detect → decide → respond → report）+ CLI（`cli` 模块）+ `agent-guard` 守护进程。写本地 NDJSON/stdout，可选注入 analyzer sink。 |
| `agentd` / `agentd` | umbrella + 编排器：`agentd host`/`trace`/`guard` 分发到各能力 `cli`，以及 `agentd run --config`（编排守护进程）；**内置 ingest**（`src/ingest.rs`），`--upload` 才上报 analyzer。 |
| `ebpf-common` / `ebpf-common` | no_std 共享 `#[repr(C)]` POD 事件结构（`ExecEvent`/`ExitEvent`/`FileEvent`，bytemuck `Pod`），经 ring buffer 内核→用户态传递。普通 workspace 成员。 |
| `trace-ebpf` / `trace-ebpf` | no_std / bpf target：内核 tracepoint 程序（`trace_exec`/`trace_exit`/`trace_openat` → `EVENTS` RingBuf）。GPL 许可。 |
| `guard-ebpf` / `guard-ebpf` | no_std / bpf target：内核 `cgroup_sock_addr` 程序（`guard_connect4`/`guard_connect6`，按 `BLOCKED_V4`/`V6` 拒绝目的 IP）。 |

各能力的 CLI（`Args` + `run`）放在各 lib 的 `pub mod cli`，三个独立 bin 与 umbrella `agentd` 共用——
新增/修改 CLI 改 `crates/<cap>/src/cli.rs`，三处入口（独立 bin、`agentd <cap>`、本能力测试）自动一致。
**能力只采集、不上报**：`host`/`trace` 的 `run` 返回 envelope（供 agentd 上报）；`guard` 经注入的 `ReportSink`
上报。上报统一由 agentd 拥有（`--upload` 或 `agentd run`）。

依赖 DAG（单向无环）见 [`ARCHITECTURE.md`](./ARCHITECTURE.md)。要点：`agent-host`/`agent-trace`/`agent-guard`/`agentd`
依赖 `agent-contract`；`agent-guard` 依赖 `agent-host`(onaccess) + `agent-trace`(network)；`agent-trace` 启用
`ebpf` 时依赖 `ebpf-common` 并经 build.rs 嵌入 `trace-ebpf`，`agent-guard` 经 build.rs 嵌入 `guard-ebpf`；
`trace-ebpf` 依赖 `ebpf-common`，`guard-ebpf` 无 `ebpf-common` 依赖。

**原则**：`agent-host` / `agent-trace` 只采集；CVE 判定与跨源关联在 analyzer 侧。
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

## 新增情报源（网络追踪）

1. 在 [`crates/trace/src/intel/sync/`](../crates/trace/src/intel/sync) 实现 feed 适配器（参考 `feodo.rs`，只解析字节）。
2. 在 `agent-trace` 的 `intel-sync` 子命令（`crates/trace/src/cli.rs`）`--source` 分发中接入；HTTP 下载用本地 `http_get_text`（reqwest）。
3. 产出对齐 `ThreatFeed` 的本地 JSON。

## 新增传感器（实时防护）

传感器落在 `crates/guard/src/sensors/`，实现 [`Sensor`](../crates/guard/src/sensors/mod.rs) trait（自有线程、向 `mpsc` 推 `Detection`、轮询 `shutdown`）：

1. 新增 `Detection` 变体（`event.rs`）与契约事件（先扩展 analyzer `guard_event.py` → JSON Schema → `agent-contract/src/guard.rs`）。
2. 实现传感器，按 `#[cfg(all(target_os = "linux", feature = "..."))]` 门控；在 `build_sensors` 挂接。
3. 新处置动作：扩展 `decide::Action`、`respond` 执行，**并先在 `respond::safety` 加否决规则**，再补单元测试（safety 测试防自伤，最高优先级）。
4. 在 `report::build_event` 补 `Detection → GuardEvent` 映射。

syscall 一律走安全的 `nix` 封装，不写 `unsafe`。netblock 处置在 `ebpf` feature 下优先用内核
cgroup connect4/6 阻断器（`BLOCKED_V4`/`V6` map），加载/挂接失败时回退 `nft`；cgroup-connect 不需要 `CONFIG_BPF_LSM`。

## 编译 eBPF 程序

两个 `*-ebpf` crate 是 workspace 成员，但**排除在 `default-members` 之外**，宿主 `cargo build`/`cargo test`
不会编译它们。它们仅在 `agent-trace`/`agent-guard` 开启 `ebpf` feature 时，由对应 crate 的 build.rs 编译：
`rustup run nightly cargo build -Z build-std=core --target bpfel-unknown-none` + bpf-linker，再经
`include_bytes_aligned!` 内嵌。

- 构建时：nightly + `rust-src` + `cargo install bpf-linker`。
- 运行时：CAP_BPF/root + BTF 内核（trace）、cgroup-v2（guard）。
- 工具链缺失时 build.rs 输出空 stub + 警告，保证 CI `--all-features` 仍绿（届时 eBPF 后端在运行期报错，用户态回退 pcap/mock 或 nft）。
- `ebpf` 为 opt-in，**不在** musl 部署构建中（部署侧投放 agent-host/agent-trace/agentd；guard 以 onaccess/network/ids 运行）。

## 数据契约

| 步骤 | 位置 |
| --- | --- |
| 编辑模型 | `analyzer/src/analyzer/schemas/`（guard 在 `guard_event.py`） |
| 生成 JSON Schema | `analyzer-export-schemas` → `analyzer/schemas-json/` |
| Rust 镜像 | `contract/src/{lib.rs, trace.rs, guard.rs}` |
| 校验 | `cargo test -p agent-host` / `-p agent-trace` / `-p agent-contract`（guard） |

CI 经 `git diff --exit-code schemas-json/` 守护跨语言漂移。

## 代码风格

- workspace `rustfmt` / `clippy`（`unsafe_code = deny`）。
- `missing_docs = "warn"`（`clippy -D warnings` 升级为错误，公共项均需文档）；`agent-contract` 为 `deny`。

## 测试

| 类型 | 位置 | 运行 |
| --- | --- | --- |
| 主机契约 | `crates/host/tests/contract.rs` | `cargo test -p agent-host` |
| 网络/文件/进程契约 | `crates/trace/tests/contract.rs` | `cargo test -p agent-trace` |
| 实时防护契约 | `crates/contract/tests/guard_contract.rs` | `cargo test -p agent-contract` |
| 内置查毒 | `crates/host/src/malware.rs`（`#[cfg(test)]`） | `cargo test -p agent-host` |
| guard 流水线 / 安全 | `crates/guard/src/*` | `cargo test -p agent-guard --features all`（无需 root） |

`*-ebpf` 不在 `default-members`，`cargo test --workspace` 不编译它们；eBPF 代码路径需 nightly 工具链
+ 特权方可端到端验证。

端到端验证：

```bash
cargo run -p agent-host -- -r / --pretty                                   # 合并 AssetReport
cargo run -p agent-host -- -r / --malware --pretty                         # 含内置查毒
cargo run -p agent-trace -- capture --pretty                               # TraceBatch（mock 网络）
cargo run -p agent-trace --features ebpf -- capture --ebpf --pretty        # 含 eBPF 文件/进程事件（需特权）
cargo run -p agent-guard -- --stdout                                       # 实时防护（monitor 默认）
cargo run -p agentd -- run --config run.json                               # 编排守护进程（定时扫描 + 抓包 + 上报）
```

## 二进制与 feature

| crate（= 能力目录） | features |
| --- | --- |
| `agent-host` | 无（`--malware` 始终可用，内置签名引擎） |
| `agent-trace` | `default = []`；`pcap`；`ebpf`（exec/exit + openat tracepoint，内嵌 trace-ebpf） |
| `agent-guard` | `default = [fim, behavior]`；`onaccess`（→ agent-host）；`network`（→ agent-trace）；`ids`；`pcap`；`ebpf`（cgroup connect4/6 netblock，内嵌 guard-ebpf，回退 nft）；`all` |

```bash
cargo build -p agent-host --target x86_64-unknown-linux-musl --release   # 精简主机扫描
cargo build -p agent-trace --no-default-features                         # 精简网络追踪
cargo build -p agent-guard --no-default-features --features fim          # 精简实时防护（仅 FIM）
cargo build -p agent-trace --features pcap                               # 实时抓包
cargo build -p agent-trace --features ebpf                               # eBPF 文件/进程追踪（需 nightly + bpf-linker）
cargo build -p agent-guard --features ebpf                               # eBPF netblock（需 nightly + bpf-linker）
```

## 文档维护

修改公共 API 或 CLI 参数时同步更新：对应 crate `README.md`、`agent/README.md`、必要时
`docs/ARCHITECTURE.md`。
