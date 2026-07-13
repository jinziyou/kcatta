# agent workspace crates

Rust workspace 成员索引。架构说明见 [`../docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md)，
使用指南见 [`../README.md`](../README.md)。

> **SOC 布局**：`Collect → Detect → Respond`，`agentd` 为 composition/control plane；目录为
> `crates/{agentd,collect/*,detect/*,respond}`。
> 权威说明 [`../docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md)；迁移史
> [`../docs/REFACTOR-PIPELINE.md`](../docs/REFACTOR-PIPELINE.md)。部署 / package：
> `agent-collect-host` / `agent-collect-trace` / `agent-respond`；`agentd` 子命令
> `collect-host` / `collect-trace` / `respond`（别名 `host` / `trace` / `guard`）。

**collect / detect / respond + contract + agentd + eBPF**。**上报模型**：能力独立运行只产出本地结果；**上报由 `agentd` 拥有**。

| 类别 | 目录 | 包名 | 说明 |
| --- | --- | --- | --- |
| 底座 | `contract/` | `agent-contract` | 三种 analyzer wire envelope + 非 Serde/非 JSON wire 的内部 `Detection` 阶段类型。零内部依赖。 |
| **detect（P0）** | `detect/malware/` | `agent-detect-malware` | 签名/哈希查毒引擎。被 host / guard onaccess 复用。 |
| **detect** | `detect/` | `agent-detect` | host finding / IOC + 轻量 IDS；产出/re-export contract `Detection`，re-export malware。 |
| **collect** | [`collect/host/`](collect/host/) | `agent-collect-host` | `FilesystemSource` → 零到多组 `HostInfo` / `Asset`；CLI/兼容 façade 可另步 detect。 |
| **collect** | [`collect/trace/`](collect/trace/) | `agent-collect-trace` | `NetworkSource` / `EbpfSource` → 零到多组网络/文件/进程事件；CLI/兼容 façade 可另步 IOC detect。 |
| **respond** | `respond/` | `agent-respond` | 消费/re-export contract `Detection`，执行 decide/respond/report。 |
| 统一入口/编排 | `agentd/` | `agentd` | umbrella：`agentd collect-host\|collect-trace\|respond` 进程内分发到各能力 `cli`（`--upload <URL>` 才上报 Form）；**`agentd run --config <json>`** 编排守护进程：按 `interval_secs` 调度 host 扫描 + trace 抓包并上传，`guard.enabled` 时后台线程监管 guard 流式上报，支持 SIGINT/Ctrl-C 优雅退出、失败周期记录后重试。**内置 ingest client**（Form 的 `/ingest/asset-report`、`/ingest/trace-batch`、`/ingest/guard-event`，202 Accepted）。 |
| eBPF 支撑 | `ebpf/` | `agent-ebpf` | 共享 POD lib（`ExecEvent`/`ExitEvent`/`FileEvent`/`NetEvent`）+ 两个 bpf-target bin：`trace-ebpf`（进程/文件 tracepoints + cgroup-skb network telemetry）与 `guard-ebpf`（cgroup connect4/6 netblock）；排除于 default-members，由能力 build.rs 按 feature 编译嵌入。 |

## 分层与依赖（单向、无环；bin 与 lib 同 crate）

依赖 DAG 见 [`../docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md)。

- 各能力的 CLI（Args + run）放在各 lib 的 `pub mod cli`；三个独立 bin 与 umbrella `agentd` 共用，不重复、不 shell-out。
- 核心 `Source` API 只采集；能力 CLI 可在本地显式组合 detect 后产出 envelope。上报由 agentd
  注入：host/trace 拿返回值 POST；respond 由 agentd 注入一个 `ReportSink`（Form sink）。
- CLI 是 composition/control plane，不是信息来源。为兼容现有调用方，collect crates 仍保留
  collect→detect 便利 façade，所以 Cargo DAG 并不承诺 `collect-*` 完全不依赖 `agent-detect`。
- respond 默认只依赖 contract；feature `onaccess`/`network` 才启用可选 detect 引擎，network 还
  依赖 `agent-collect-trace`。
- `agent-ebpf` 是 workspace **成员**但**排除于 `default-members`**（其两个内核 bin 仅 bpf target），宿主 `cargo build`/`cargo test` 永不编译它们；其共享类型 lib 在 agent-collect-trace `--features ebpf` 时随之宿主编译。工具链缺失时 build.rs 产出空 stub + 警告，使 CI `--all-features` 仍绿；文件/进程 `EbpfSource` 运行时报错，eBPF network 仅在编入 pcap 时回退真实 pcap、否则报错，respond netblock 回退 nft。

## Feature 速查

- `agent-detect-malware`：无 feature；签名/哈希引擎（std+sha2+aho-corasick）。
- `agent-collect-host`：无 feature；`--malware` 由 CLI 调用 `agent_detect::host`（旧 `DetectOpts` façade 保留）。
- `agent-collect-trace`：`default=[]`；`pcap`；`winnet`（连接表）；`ebpf`（既提供
  `NetworkSource` 的 cgroup-skb backend，也提供 file/process `EbpfSource`）。
- `agent-respond`：`default=[fim,behavior]`，只需 contract `Detection`；`onaccess` 启用 detect
  malware；`network`（→ agent-collect-trace + detect network）；`ids`；`pcap`；`ebpf`
  （cgroup-connect netblock，失败回退 nft）；`all`。
- `agentd`：`pcap`/`winnet`/`onaccess`/`network`/`ids`/`ebpf`/`full` 转发到对应能力 crate。
- eBPF 构建/运行要求：构建期 nightly + rust-src + `cargo install bpf-linker`；运行期 CAP_BPF/root + BTF 内核（trace）、cgroup-v2（guard）。`ebpf` opt-in，不在 musl 部署构建内（部署只发 agent-collect-host/agent-collect-trace/agentd；guard 以 onaccess/network/ids 运行）。eBPF 不需要 `CONFIG_BPF_LSM`（cgroup-connect，非 LSM）。

## 常用命令

```bash
cargo test --workspace                              # 全 workspace（含三契约校验 + 内置查毒；agent-ebpf 内核 bin 不参与）
cargo test -p agent-respond --features all            # guard 全传感器（无需 root）
cargo build -p agent-collect-trace --features ebpf          # 编译 eBPF tracer（需 nightly + bpf-linker）

# 独立运行：产出本地结果，不上报
cargo run -p agent-collect-host -- -r / -t all -o ./scan-out
cargo run -p agent-collect-host -- -r / --malware --pretty
cargo run -p agent-collect-trace -- capture --pretty
cargo run -p agent-collect-trace --features ebpf -- capture --ebpf --ebpf-duration 30
cargo run -p agent-respond -- --stdout

# 统一 agentd：生产上报到 :10443（先设置 FORM_AGENT_CERT/KEY/CA），或 run 编排守护
cargo run -p agentd -- collect-host -r / --malware --upload https://agents.example:10443
cargo run -p agentd -- collect-trace --upload https://agents.example:10443 capture
cargo run -p agentd -- respond --upload https://agents.example:10443
cargo run -p agentd -- run --config ./run.json
```

## 边界

`agent-collect-host` / `agent-collect-trace` 的**核心 Source 只采集**，但独立 CLI 与兼容 façade
可组合端上 detect；CVE 判定 / 跨源关联仍在 **analyzer** 侧。trace 的连续追踪 = 网络
（显式 mock 或 live pcap/eBPF/连接表）+ 文件操作 + 进程调用（后两者由 feature-gated 的 eBPF 提供）。
**`agent-respond` 是唯一会端上主动处置的能力**（可逆隔离 / 网络阻断 / 阻断打开），默认
monitor 不动作。deny-open/quarantine/netblock/kill 均经过显式 gate、阈值与 safety；on-access
`allow_block_open` 默认关，错误/否决/超大文件 fail-open，预执行结果不会在 pipeline 二次处置。
三能力本地**绝不自行上报**；
**上报由 `agentd` 拥有**（`--upload` 或 `agentd run`），目标只能是 Form；跨机投放属于 Form。

## 契约校验测试

- [`host/tests/contract.rs`](./host/tests/contract.rs) —— `AssetReport`。
- [`trace/tests/contract.rs`](./trace/tests/contract.rs) —— `TraceBatch`。
- [`contract/tests/guard_contract.rs`](./contract/tests/guard_contract.rs) —— `GuardEventBatch`。
