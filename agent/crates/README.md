# agent workspace crates

Rust workspace 成员索引。架构说明见 [`../docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md)，
使用指南见 [`../README.md`](../README.md)。

**三大能力（host/trace/guard）+ 数据契约底座（contract）+ agentd 编排入口 + eBPF 支撑 crate**：1 个数据契约底座
+ 3 个能力（一个能力 = 一个目录 = 一个 crate，lib+bin 同处）+ 1 个统一入口兼编排器 `agentd`，外加 1 个 eBPF 支撑 crate `agent-ebpf`（共享类型 lib + 两个内核 bin）。**上报模型**：三个能力独立运行
**只采集、产出本地结果**，不自行上报；**上报由 `agentd` 拥有**（`agentd <cap> --upload` 或 `agentd run`，ingest 内置于 `agentd`）。

| 类别 | 目录 | 包名 | 说明 |
| --- | --- | --- | --- |
| 底座 | `contract/` | `agent-contract` | 数据契约（analyzer Pydantic schema 镜像）：`AssetReport` + `TraceBatch`（`events` 网络五元组 / `file_events` / `process_events`）+ `GuardEventBatch`，及 `FileOp`/`ProcessEventType`/`ThreatMatch`/`IndicatorType`/`Severity`。零内部依赖（DAG 汇点）。 |
| **主机静态文件检测** | `host/` | `agent-host` | lib（主机静态资产扫描：包/SBOM/服务/账号/凭据/容器（含嵌套 rootfs 扫描）+ **内置签名/哈希查毒**，被 guard on-access 复用 + `cli` 模块；程序入口 `run_scan_at()`）+ bin `agent-host` → 写 `AssetReport`。 |
| **追踪** | `trace/` | `agent-trace` | lib（网络流：mock(默认)/pcap(feature) 抓包 + 威胁情报 IOC 匹配 → `TraceBatch.events`；启用 **`ebpf` feature** 时加载 eBPF tracer，挂 exec/exit + openat tracepoint，从 ring buffer 排空 → `file_events`/`process_events`；HTTP-free，被 guard network 复用 + `cli` 模块）+ bin `agent-trace`（`capture [--ebpf [--ebpf-duration N]]`/`intel-sync`）→ 写 `TraceBatch`。 |
| **实时防护** | `guard/` | `agent-guard` | lib（传感器（默认 fim+behavior，可选 onaccess→agent-host、network/ids→agent-trace）+ detect→decide→respond（隔离/netblock/kill，均安全否决 + monitor 默认）→ report → `GuardEventBatch`；启用 **`ebpf` feature** 时 netblock 走内核 cgroup connect4/6 eBPF blocker（`BLOCKED_V4`/`V6` map），加载/挂载失败回退 nft；+ `cli` 模块）+ bin `agent-guard` → 本地 NDJSON/stdout。 |
| 统一入口/编排 | `agentd/` | `agentd` | umbrella：`agentd host\|trace\|guard` 进程内分发到各能力 `cli`（`--upload <URL>` 才上报 analyzer）；**`agentd run --config <json>`** 编排守护进程：按 `interval_secs` 调度 host 扫描 + trace 抓包并上传，`guard.enabled` 时后台线程监管 guard 流式上报，支持 SIGINT/Ctrl-C 优雅退出、失败周期记录后重试。**内置 ingest**（`/ingest/asset-report`、`/ingest/trace-batch`、`/ingest/guard-event`，202 Accepted）。 |
| eBPF 支撑 | `ebpf/` | `agent-ebpf` | 单 crate，含一个共享类型 lib（lib name `agent_ebpf`，Apache-2.0，`no_std`，dep bytemuck：内核→用户态经 ring buffer 传递的共享 `#[repr(C)]` POD 事件结构 `ExecEvent`/`ExitEvent`/`FileEvent`，bytemuck `Pod`；被 agent-trace 用户态加载器在 `ebpf` feature 下依赖并宿主编译）+ 两个内核 bin（GPL-2.0，`no_std`+`no_main`，bpf target，`required-features=["ebpf"]`，**排除于 default-members**）：bin `trace-ebpf`（tracepoint `trace_exec`/`trace_exit`/`trace_openat` → `EVENTS` RingBuf）、bin `guard-ebpf`（`cgroup_sock_addr` 程序 `guard_connect4`/`guard_connect6` 按 `BLOCKED_V4`/`V6` 拒绝目的 IP）。`aya-ebpf` 为 crate `ebpf` feature 下的可选依赖。由 agent-trace/agent-guard 的 build.rs 在 `ebpf` feature 下分别编译对应 bin 并 `include_bytes_aligned!` 嵌入。整 crate license `Apache-2.0 AND GPL-2.0`。 |

## 分层与依赖（单向、无环；bin 与 lib 同 crate）

依赖 DAG 见 [`../docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md)。

- 各能力的 CLI（Args + run）放在各 lib 的 `pub mod cli`；三个独立 bin 与 umbrella `agentd` 共用，不重复、不 shell-out。
- 能力 `run` 只**采集/产出**结果（host/trace 返回 envelope 供 agentd 上报；guard 把事件写本地 sink）。上报由 agentd 注入：host/trace 拿返回值 POST；guard 由 agentd 注入一个 `ReportSink`（analyzer sink）。
- guard 经 feature 可选依赖 `agent-host`(onaccess) / `agent-trace`(network)，默认（fim+behavior）不牵入。
- `agent-ebpf` 是 workspace **成员**但**排除于 `default-members`**（其两个内核 bin 仅 bpf target），宿主 `cargo build`/`cargo test` 永不编译它们；其共享类型 lib 在 agent-trace `--features ebpf` 时随之宿主编译。两个内核 bin 仅由 agent-trace/agent-guard 的 build.rs 在 `ebpf` feature 下用 `rustup run nightly cargo build -Z build-std=core --target bpfel-unknown-none` + bpf-linker 编译并嵌入。工具链缺失时 build.rs 产出空 stub + 警告（CI `--all-features` 仍绿，运行期 eBPF 后端报错、用户态回退 pcap/mock 或 nft）。

## Feature 速查

- `agent-host`：无 feature；`--malware` 始终可用（内置签名引擎，仅 std+sha2，无外部守护进程）。
- `agent-trace`：`default=[]`；`pcap`（实时抓包，否则 mock）；`ebpf`（加载 eBPF tracer，新增 file/process 流，feature-gated + 需特权，缺工具链时优雅回退）。
- `agent-guard`：`default=[fim,behavior]`；`onaccess`（→ agent-host）；`network`（→ agent-trace）；`ids`；`pcap`；`ebpf`（cgroup-connect netblock，失败回退 nft）；`all`。
- `agentd`：`pcap`/`onaccess`/`network`/`ids`/`ebpf`/`full` 转发到对应能力 crate。
- eBPF 构建/运行要求：构建期 nightly + rust-src + `cargo install bpf-linker`；运行期 CAP_BPF/root + BTF 内核（trace）、cgroup-v2（guard）。`ebpf` opt-in，不在 musl 部署构建内（部署只发 agent-host/agent-trace/agentd；guard 以 onaccess/network/ids 运行）。eBPF 不需要 `CONFIG_BPF_LSM`（cgroup-connect，非 LSM）。

## 常用命令

```bash
cargo test --workspace                              # 全 workspace（含三契约校验 + 内置查毒；agent-ebpf 内核 bin 不参与）
cargo test -p agent-guard --features all            # guard 全传感器（无需 root）
cargo build -p agent-trace --features ebpf          # 编译 eBPF tracer（需 nightly + bpf-linker）

# 独立运行：只采集/产出本地结果，不上报
cargo run -p agent-host -- -r / -t all -o ./scan-out
cargo run -p agent-host -- -r / --malware --pretty
cargo run -p agent-trace -- capture --pretty
cargo run -p agent-trace --features ebpf -- capture --ebpf --ebpf-duration 30
cargo run -p agent-guard -- --stdout

# 统一 agentd：可 --upload 上报 analyzer，或 run 编排守护
cargo run -p agentd -- host -r / --malware --upload http://127.0.0.1:8000
cargo run -p agentd -- trace --upload http://127.0.0.1:8000 capture
cargo run -p agentd -- guard --upload http://127.0.0.1:8000
cargo run -p agentd -- run --config ./run.json
```

## 边界

`agent-host` / `agent-trace` **只采集**；CVE 判定 / 跨源关联在 **analyzer** 侧。trace 的连续追踪 = 网络（pcap/mock）+ 文件操作 + 进程调用（后两者由 feature-gated 的 eBPF 提供）。
**`agent-guard` 是唯一会端上主动处置的能力**（可逆隔离 / 网络阻断 / 阻断打开），默认
monitor 关闭、受安全否决保护。三能力本地**只采集、绝不自行上报**；**上报由 `agentd` 拥有**（`--upload` 或 `agentd run`）；跨机投放（`analyzer-scan`，Python）属于 analyzer。

## 契约校验测试

- [`host/tests/contract.rs`](./host/tests/contract.rs) —— `AssetReport`。
- [`trace/tests/contract.rs`](./trace/tests/contract.rs) —— `TraceBatch`。
- [`contract/tests/guard_contract.rs`](./contract/tests/guard_contract.rs) —— `GuardEventBatch`。
