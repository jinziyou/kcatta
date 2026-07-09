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

权威：[`ARCHITECTURE.md`](./ARCHITECTURE.md)（流水线四层）。迁移史：[`REFACTOR-PIPELINE.md`](./REFACTOR-PIPELINE.md)。

| 层 | 目录 / 包名 | 职责 |
| --- | --- | --- |
| 契约 | `contract` / `agent-contract` | `AssetReport` + `TraceBatch` + `GuardEventBatch`；零内部依赖 |
| detect | `detect/malware` / `agent-detect-malware` | 签名查毒引擎 |
| detect | `detect` / `agent-detect` | posture / secrets / IOC（`ThreatFeed`）；re-export malware |
| collect | `collect/host` / `agent-collect-host` | **按来源**采主机 → **资产**（`Asset`/`HostInfo`）+ CLI/bin；SBOM 由包资产导出 |
| collect | `collect/trace` / `agent-collect-trace` | **按来源**捕获；编排 `capture_batch`→`enrich_batch`；intel-sync；可选 eBPF |
| respond | `respond` / `agent-respond` | sensors → decide → respond → report |
| 编排 | `agentd` / `agentd` | CLI 分发 + `run` + **唯一 ingest** |
| 内核 | `ebpf` / `agent-ebpf` | 共享 POD lib + `trace-ebpf` / `guard-ebpf`（不在 default-members） |

**用语**：「analyzer」仅指 Python 服务；端上称 **detect**。上报仅 **agentd**。处置仅 **respond**（默认 monitor）。

CLI 在各 lib 的 `pub mod cli`；独立 bin 与 `agentd` 共用。依赖 DAG 见 ARCHITECTURE。  
部署 / package / bin 主名 `agent-collect-host` / `agent-collect-trace` / `agent-respond`；
`agentd` 子命令别名 `host` / `trace` / `guard`。

## 新增采集器（主机静态检测）

采集器落在 `agent-collect-host` 的 lib：

1. 实现 [`Collector`](../crates/collect/host/src/collector.rs)。
2. 若产出新 asset 类型，**先**扩展 analyzer Pydantic → 生成 JSON Schema → 更新 [`agent-contract`](../crates/contract/src/lib.rs)。
3. 编排进 `default_collectors()`（`crates/collect/host/src/lib.rs`）。
4. 在 [`crates/collect/host/tests/contract.rs`](../crates/collect/host/tests/contract.rs) 补充 `AssetReport` 校验。

Host collector 必须排首位（后续依赖 `ctx.host_id`）。资产 Collector 进 `default_collectors` / `build_asset_plan`；finding 只走 `DetectOpts` / `run_detect_at`（`CollectorOutput` 无 finding 变体）。

### 扩展内置查毒

引擎在 [`crates/detect/malware`](../crates/detect/malware/)（`agent-detect-malware`）。`SignatureSet` 支持 `Sha256` 与 `Bytes` 规则；新增规则类型在此扩展。host 侧适配器：`crates/collect/host/src/malware.rs`。`scan_bytes` 被 guard on-access 直接依赖。

## 新增情报源（网络追踪）

1. 在 [`crates/collect/trace/src/intel/sync/`](../crates/collect/trace/src/intel/sync) 实现 feed 适配器（参考 `feodo.rs`，只解析字节 → `FeedIndicator`）。
2. 在 `agent-collect-trace` 的 `intel-sync` 子命令（`crates/collect/trace/src/cli.rs`）`--source` 分发中接入；HTTP 下载用本地 `http_get_text`（reqwest）。
3. 经 `ThreatFeed::from_feed_indicators`（`agent_detect::ioc`，本 crate re-export）写出本地 JSON。

## 新增传感器（实时防护）

传感器落在 `crates/respond/src/sensors/`，实现 [`Sensor`](../crates/respond/src/sensors/mod.rs) trait（自有线程、向 `mpsc` 推 `Detection`、轮询 `shutdown`）：

1. 新增 `Detection` 变体（`event.rs`）与契约事件（先扩展 analyzer `guard_event.py` → JSON Schema → `agent-contract/src/guard.rs`）。
2. 实现传感器，按 `#[cfg(all(target_os = "linux", feature = "..."))]` 门控；在 `build_sensors` 挂接。
3. 新处置动作：扩展 `decide::Action`、`respond` 执行，**并先在 `respond::safety` 加否决规则**，再补单元测试（safety 测试防自伤，最高优先级）。
4. 在 `report::build_event` 补 `Detection → GuardEvent` 映射。

syscall 一律走安全的 `nix` 封装，不写 `unsafe`。netblock 处置在 `ebpf` feature 下优先用内核
cgroup connect4/6 阻断器（`BLOCKED_V4`/`V6` map），加载/挂接失败时回退 `nft`；cgroup-connect 不需要 `CONFIG_BPF_LSM`。

## 编译 eBPF 程序

合一的 `agent-ebpf` crate（`crates/ebpf`）是 workspace 成员，但**排除在 `default-members` 之外**，其 bin
（`trace-ebpf`/`guard-ebpf`，均 `required-features = ["ebpf"]`）仅在 bpf target 下编译，宿主 `cargo build`/
`cargo test` 不会编译它们（仅在 `agent-collect-trace --features ebpf` 时把共享 lib 透传宿主编译）。两个 bin 仅在
`agent-collect-trace`/`agent-respond` 开启 `ebpf` feature 时，由对应 crate 的 build.rs 编译：
`rustup run nightly cargo build --package agent-ebpf --bin <trace-ebpf|guard-ebpf> --features ebpf -Z build-std=core --target bpfel-unknown-none` + bpf-linker，再经
`include_bytes_aligned!` 内嵌。

- 构建时：nightly + `rust-src` + `cargo install bpf-linker`。
- 运行时：CAP_BPF/root + BTF 内核（trace）、cgroup-v2（guard）。
- 工具链缺失时 build.rs 输出空 stub + 警告，保证 CI `--all-features` 仍绿（届时 eBPF 后端在运行期报错，用户态回退 pcap/mock 或 nft）。
- `ebpf` 为 opt-in，**不在** musl 部署构建中（部署侧投放 agent-collect-host/agent-collect-trace/agentd；guard 以 onaccess/network/ids 运行）。

## 数据契约

| 步骤 | 位置 |
| --- | --- |
| 编辑模型 | `analyzer/src/analyzer/schemas/`（guard 在 `guard_event.py`） |
| 生成 JSON Schema | `analyzer-export-schemas` → `analyzer/schemas-json/` |
| Rust 镜像 | `contract/src/{lib.rs, trace.rs, guard.rs}` |
| 校验 | `cargo test -p agent-collect-host` / `-p agent-collect-trace` / `-p agent-contract`（guard） |

CI 经 `git diff --exit-code schemas-json/` 守护跨语言漂移。

## 代码风格

- workspace `rustfmt` / `clippy`（`unsafe_code = deny`）。
- `missing_docs = "warn"`（`clippy -D warnings` 升级为错误，公共项均需文档）；`agent-contract` 为 `deny`。

## 测试

| 类型 | 位置 | 运行 |
| --- | --- | --- |
| 主机契约 | `crates/collect/host/tests/contract.rs` | `cargo test -p agent-collect-host` |
| 网络/文件/进程契约 | `crates/collect/trace/tests/contract.rs` | `cargo test -p agent-collect-trace` |
| 实时防护契约 | `crates/contract/tests/guard_contract.rs` | `cargo test -p agent-contract` |
| 内置查毒 | `crates/detect/malware`（单元测试） | `cargo test -p agent-detect-malware` |
| guard 流水线 / 安全 | `crates/respond/src/*` | `cargo test -p agent-respond --features all`（无需 root） |

`agent-ebpf` 不在 `default-members`，其 bin（`trace-ebpf`/`guard-ebpf`）仅 bpf target，`cargo test --workspace`
不编译它们；eBPF 代码路径需 nightly 工具链 + 特权方可端到端验证。

端到端验证：

```bash
cargo run -p agent-collect-host -- -r / --pretty                                   # 合并 AssetReport
cargo run -p agent-collect-host -- -r / --malware --pretty                         # 含内置查毒
cargo run -p agent-collect-trace -- capture --pretty                               # TraceBatch（mock 网络）
cargo run -p agent-collect-trace --features ebpf -- capture --ebpf --pretty        # 含 eBPF 文件/进程事件（需特权）
cargo run -p agent-respond -- --stdout                                       # 实时防护（monitor 默认）
cargo run -p agentd -- run --config run.json                               # 编排守护进程（定时扫描 + 抓包 + 上报）
```

## 二进制与 feature

| crate（= 能力目录） | features |
| --- | --- |
| `agent-collect-host` | 无（`--malware` 始终可用，内置签名引擎） |
| `agent-collect-trace` | `default = []`；`pcap`；`ebpf`（exec/exit + openat tracepoint，内嵌 trace-ebpf） |
| `agent-respond` | `default = [fim, behavior]`；`onaccess`（→ agent-collect-host）；`network`（→ agent-collect-trace）；`ids`；`pcap`；`ebpf`（cgroup connect4/6 netblock，内嵌 guard-ebpf，回退 nft）；`all` |

```bash
cargo build -p agent-collect-host --target x86_64-unknown-linux-musl --release   # 精简主机扫描
cargo build -p agent-collect-trace --no-default-features                         # 精简网络追踪
cargo build -p agent-respond --no-default-features --features fim          # 精简实时防护（仅 FIM）
cargo build -p agent-collect-trace --features pcap                               # 实时抓包
cargo build -p agent-collect-trace --features ebpf                               # eBPF 文件/进程追踪（需 nightly + bpf-linker）
cargo build -p agent-respond --features ebpf                               # eBPF netblock（需 nightly + bpf-linker）
```

## 文档维护

修改公共 API 或 CLI 参数时同步更新：对应 crate `README.md`、`agent/README.md`、必要时
`docs/ARCHITECTURE.md`。
