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
bash scripts/check-soc-boundaries.sh
```

## 架构速查

权威：[`ARCHITECTURE.md`](./ARCHITECTURE.md)（流水线四层）。迁移史：[`REFACTOR-PIPELINE.md`](./REFACTOR-PIPELINE.md)。

| 层 | 目录 / 包名 | 职责 |
| --- | --- | --- |
| 契约 | `contract` / `agent-contract` | 三种 wire envelope + 非 Serde 内部 `Detection`；零内部依赖 |
| detect | `detect/malware` / `agent-detect-malware` | 签名查毒引擎 |
| detect | `detect` / `agent-detect` | host finding / IOC / network IDS；产出并 re-export contract `Detection` |
| collect | `collect/host` / `agent-collect-host` | `FilesystemSource` → 零到多组 `HostInfo` / `Asset` |
| collect | `collect/trace` / `agent-collect-trace` | `NetworkSource` / `EbpfSource` → 零到多组网络/文件/进程事件 |
| respond | `respond` / `agent-respond` | 消费并 re-export contract `Detection` → decide → respond → report |
| 编排 | `agentd` / `agentd` | CLI 分发 + `run` + **唯一 ingest** |
| 内核 | `ebpf` / `agent-ebpf` | 共享 POD lib + `trace-ebpf` / `guard-ebpf`（不在 default-members） |

**用语**：「analyzer」仅指 Python 服务；端上称 **detect**。上报仅 **agentd**。处置仅 **respond**（默认 monitor）。

CLI 在各 lib 的 `pub mod cli`；独立 bin 与 `agentd` 共用。依赖 DAG 见 ARCHITECTURE。  
部署 / package / bin 主名 `agent-collect-host` / `agent-collect-trace` / `agent-respond`；
`agentd` 主子命令 `collect-host` / `collect-trace` / `respond`，兼容别名 `host` / `trace` / `guard`。

CLI / `agentd` 是 composition/control plane，不是信息来源。核心 collect API 不产生 finding；但为保持
CLI 与现有调用方兼容，collect packages 仍有 `run_scan_with_detect` / `enrich_batch` 等 façade，故
Cargo 层面可以依赖 detect。不要用 package 依赖替代 Source/Detection 的阶段归属判断。
`Detection` 物理定义在 contract 以瘦身默认 respond，但语义上仍是 Detect→Respond 的内部阶段契约。

## 新增 Source / reader（Collect）

两条 collect 核心接口都允许一轮成功返回 `Vec<SourceResult>`（零到多组结果）。新增代码先判断它读的
是一个新信息来源，还是已有来源内部的 reader：

1. 新来源实现 host 或 trace 的 `Source`，返回 `Result<Vec<SourceResult>>`；没有事实可返回空 Vec。
2. 同一底层来源的新解析器放入已有 Source。例如 dpkg/apk/服务/账户都属于
   [`FilesystemSource`](../crates/collect/host/src/sources/filesystem.rs)，不是按 `Asset` 变体再建 Source。
3. trace 网络后端归 [`NetworkSource`](../crates/collect/trace/src/sources/network.rs)，由
   `CaptureConfig` 选择 mock/pcap/eBPF network/winnet；内核文件/进程观测归 feature-gated
   [`EbpfSource`](../crates/collect/trace/src/sources/ebpf.rs)。两种 eBPF 路径不要混为同一 Source。
4. 若产出新 wire 类型，**先**扩展 analyzer Pydantic → 生成 JSON Schema → 更新
   [`agent-contract`](../crates/contract/src/lib.rs)。
5. 补 Source 的零结果、多结果与顺序测试，以及 host/trace 契约测试。trace 顺序断言只能针对
   同类 stream；wire 没有跨 network/file/process 的全局顺序。

host 默认计划为 `default_sources()` 中的单一 `FilesystemSource`，它先发 `Host`，再发多个非空
`Assets` 批次。旧 `Collector` / `CollectorOutput` / `default_collectors()` 只为兼容保留。finding
新代码走 `agent_detect::host::detect`；不要增加 detect `SourceResult`。

### 扩展内置查毒

引擎在 [`crates/detect/malware`](../crates/detect/malware/)（`agent-detect-malware`）。`SignatureSet`
支持 `Sha256` 与 `Bytes` 规则；新增规则类型在此扩展。host 组合入口在
[`agent_detect::host`](../crates/detect/src/host.rs)；`scan_bytes` 被 respond on-access 直接依赖。

## 新增情报源（网络追踪）

1. 在 [`crates/collect/trace/src/intel/sync/`](../crates/collect/trace/src/intel/sync) 实现 feed 适配器（参考 `feodo.rs`，只解析字节 → `FeedIndicator`）。
2. 在 `agent-collect-trace` 的 `intel-sync` 子命令（`crates/collect/trace/src/cli.rs`）`--source` 分发中接入；HTTP 下载用本地 `http_get_text`（reqwest）。
3. 经 `ThreatFeed::from_feed_indicators`（直接从 `agent_detect::ioc` 导入）写出本地 JSON。

网络 IOC/IDS 规则落在 [`agent_detect::network`](../crates/detect/src/network.rs)。respond network
sensor 只负责 `agent-collect-trace` capture、调用 detector、把返回的 `Detection` 送入流水线；新增
IDS 规则及顺序测试不要写回 `respond/src/sensors/network.rs`。

## 新增传感器（实时防护）

传感器落在 `crates/respond/src/sensors/`，实现 [`Sensor`](../crates/respond/src/sensors/mod.rs) trait（自有线程、向 `mpsc` 推 `SensorEvent`、轮询 `shutdown`）：

1. 新增 [`agent-contract::Detection`](../crates/contract/src/detection.rs) 变体。该类型无 Serde、
   不生成 JSON Schema；若报告 wire 也要新增 kind/字段，再先扩展 analyzer `guard_event.py` → JSON
   Schema → `agent-contract/src/guard.rs`。detect/respond 只 re-export，不要另定义一份。
2. 可复用的匹配/规则优先放 `agent-detect`，sensor 只读事实并调用窄 API；仅部署专用的 FIM/behavior
   轻量规范化可留在 adapter。按平台/feature 门控并在 `build_sensors` 挂接；配置启用但能力不可用、
   或零有效 watch/mark 必须返回错误，不能健康 idle。
3. 新处置动作：扩展 `decide::Action`、`respond` 执行，**并先在 `respond::safety` 加否决规则**，再补单元测试（safety 测试防自伤，最高优先级）。
4. 在 `report::build_event` 补 `Detection → GuardEvent` 映射。

OS API 一律走安全 wrapper（Linux `nix`；Windows FIM/shutdown 用 `notify`/`ctrlc`），不写
`unsafe`。netblock 处置在 `ebpf` feature 下优先用内核
cgroup connect4/6 阻断器（`BLOCKED_V4`/`V6` map），加载/挂接失败时回退 `nft`；cgroup-connect 不需要 `CONFIG_BPF_LSM`。

on-access 同步 `FAN_DENY` 是“必须在 kernel permission hook 内立即执行”的特殊动作，但仍必须
经过 `allow_block_open`、mode、severity threshold 与 `safety::veto`。新增同步动作要沿用
`SensorEvent.pre_applied`，让 pipeline 只报告准确结果而不重复执行普通 Action；失败路径必须尝试
`FAN_ALLOW`；若 allow 写失败必须让 sensor fatal。覆盖 gate-off、阈值、safety、deny/allow
write-failure 与旧配置缺字段测试。

## 编译 eBPF 程序

合一的 `agent-ebpf` crate（`crates/ebpf`）是 workspace 成员，但**排除在 `default-members` 之外**，其 bin
（`trace-ebpf`/`guard-ebpf`，均 `required-features = ["ebpf"]`）仅在 bpf target 下编译，宿主 `cargo build`/
`cargo test` 不会编译它们（仅在 `agent-collect-trace --features ebpf` 时把共享 lib 透传宿主编译）。两个 bin 仅在
`agent-collect-trace`/`agent-respond` 开启 `ebpf` feature 时，由对应 crate 的 build.rs 编译：
`rustup run nightly cargo build --package agent-ebpf --bin <trace-ebpf|guard-ebpf> --features ebpf -Z build-std=core --target bpfel-unknown-none` + bpf-linker，再经
`include_bytes_aligned!` 内嵌。

- 构建时：nightly + `rust-src` + `cargo install bpf-linker`。
- 运行时：CAP_BPF/root + BTF 内核（trace）、cgroup-v2（guard）。
- 工具链缺失时 build.rs 输出空 stub + 警告，保证 CI `--all-features` 仍绿。文件/进程
  `--ebpf` 会在运行期报错；network `--net-ebpf` 仅在编译 pcap 时回退真实 pcap，否则报错；
  respond netblock 回退 nft。live capture 不允许回退 synthetic mock。
- `ebpf` 为 opt-in，**不在** musl 部署构建中（部署侧投放 agent-collect-host/agent-collect-trace/agentd；guard 以 onaccess/network/ids 运行）。

## 数据契约

| 步骤 | 位置 |
| --- | --- |
| 编辑模型 | `analyzer/src/analyzer/schemas/`（guard 在 `guard_event.py`） |
| 发布 JSON Schema | `form-export-schemas` → `form/schemas-json/` |
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
| SOC 分层守卫 | collect core / contract Detection 单定义 / agentd 显式编排 | `bash scripts/check-soc-boundaries.sh` |

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
| `agent-collect-trace` | `default = []`；`pcap`；`winnet`（连接表）；`ebpf`（cgroup-skb network + exec/exit/openat `EbpfSource`，内嵌 trace-ebpf） |
| `agent-respond` | `default = [fim, behavior]`，只需 contract；`onaccess`（→ 可选 detect malware）；`network`（→ 可选 detect + agent-collect-trace）；`ids`；`pcap`；`ebpf`（cgroup connect4/6 netblock，内嵌 guard-ebpf，回退 nft）；`all` |

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
