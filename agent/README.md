# agent

kcatta 的端点组件（Rust workspace）。逻辑上按流水线四层 **agentd · collect · detect · respond**
组织；部署上仍提供 `agent-collect-host` / `agent-collect-trace` / `agent-respond` / `agentd` 二进制（包名过渡期不变）。
详见 [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)。

| 层 / 角色 | 目录 · 包名 | 产出 / 职责 |
| --- | --- | --- |
| 契约 | `crates/contract` · `agent-contract` | `AssetReport` / `TraceBatch` / `GuardEventBatch`（Python analyzer schema 镜像） |
| detect | `crates/detect` · `agent-detect`；`detect/malware` · `agent-detect-malware` | posture / secrets / 查毒（**不是** Python analyzer） |
| collect | `crates/collect/host` · `agent-collect-host`；`collect/trace` · `agent-collect-trace` | 主机事实 / 网络捕获（`capture_batch`） |
| respond | `crates/respond` · `agent-respond` | 实时防护 + 可选主动处置（默认 monitor） |
| 编排 | `crates/agentd` · `agentd` | CLI 分发 + `run` + **唯一上报** |
| eBPF | `crates/ebpf` · `agent-ebpf` | 内核程序支撑（feature-gated） |

边界：collect 路径不上报；CVE/跨源关联在 Python **analyzer**；端上处置仅 respond；上报仅 agentd。

## 三种运行方式（与上报模型）

**上报模型**：三个能力**独立运行只产出本地结果文件，从不上报**；**只有统一 `agentd <cap> --upload <URL>`（主子命令 `collect-host` / `collect-trace` / `respond`，兼容别名 `host` / `trace` / `guard`）或 `agentd run` 才上报 analyzer**（ingest 能力内置于 `agentd`，见 `crates/agentd/src/ingest.rs`）。
ingest 端点：`/ingest/asset-report`、`/ingest/trace-batch`、`/ingest/guard-event`（受理返回 `202 Accepted`）。
上报客户端环境变量：`ANALYZER_API_TOKEN`（Bearer 令牌，可选）、`ANALYZER_UPLOAD_TIMEOUT`（HTTP 上传超时秒数，默认 60）。

1. **三独立二进制**（最精简、纯本地采集）：`agent-collect-host` / `agent-collect-trace` / `agent-respond` 各自单独构建、部署、运行，结果落文件/stdout/本地 NDJSON。
2. **统一 `agentd` 命令**（umbrella）：单一二进制 `agentd`，主子命令 `collect-host` / `collect-trace` / `respond` 在进程内分发到三能力（短别名 `host` / `trace` / `guard` 保留给旧脚本），共用各能力 lib 的 `cli` 模块；额外提供 `--upload` 上报 analyzer。**`agentd run --config <json>`** 则是编排守护进程：按 `interval_secs` 周期调度 host 扫描（→ `AssetReport`）+ trace 捕获（→ `TraceBatch`）并各自上报；若 `guard.enabled` 则在后台线程常驻 guard 推送 `GuardEventBatch`；SIGINT / Ctrl-C 优雅退出，单次失败的周期记录后下一拍重试。
3. **由 analyzer 调度**：`analyzer-scan --capability {host|trace|guard}` 经 SSH 远程投放——host/trace 投精简 bin、一次性拉回结果由 analyzer 入库；guard 投 `agentd` 二进制并以 `agentd respond --upload` 常驻推送。

```bash
agent-collect-host -r / --malware --pretty                       # 方式1：独立二进制（只产出文件，不上报）
agentd collect-host -r / --malware --upload http://analyzer:10068      # 方式2：统一命令 + 上报 analyzer
agentd run --config /etc/kcatta/agentd.json                   # 方式2：编排守护进程（周期 host+trace，可选常驻 guard）
analyzer-scan --ssh-host root@H --capability host -o out --upload http://analyzer:10068   # 方式3：analyzer 调度
analyzer-scan --ssh-host root@H --capability guard --upload http://analyzer:10068          #       （guard 常驻，投 agentd）
```

## 部署构建（静态 musl —— 方式3 analyzer 投放的产物）

analyzer 远程投放（`analyzer-scan` / admin 触发）需要**静态链接**的二进制，才能在任意 Linux 目标机上直接运行
（不受目标 glibc 版本影响）。这层由 agent 项目拥有，从仓库根用一条命令产出：

```bash
make build-agent-deploy         # x86_64：输出到 agent/target/x86_64-unknown-linux-musl/release/
make build-agent-deploy-arm64   # aarch64：输出到 agent/target/aarch64-unknown-linux-musl/release/（需 cross）
# 每个架构产出三件（analyzer 按目标 uname -m 自动选对应架构）：
#   agent-collect-host   —— host 能力（精简）
#   agent-collect-trace  —— trace 能力（精简，mock 网络后端；不含 pcap，不含 ebpf）
#   agentd       —— umbrella（--features onaccess,network,ids；guard 用它常驻）
```

- **x86_64**：需 musl C 工具链（agent-collect-host 的内置 SQLite、TLS 的 ring 走 C/asm）：Debian/Ubuntu `sudo apt-get install -y musl-tools`；纯 Rust 子集（如 `agent-respond --features fim`）无需。
- **aarch64**：用 `cross`（`cargo install cross`，docker 化工具链,自带 C 交叉编译，省去手配 musl 交叉 gcc）。
- **多架构自动选择**：analyzer 部署时探测目标 `uname -m`（x86_64/amd64 → x86_64，aarch64/arm64 → aarch64），从 `ANALYZER_AGENT_TARGET_DIR`（默认 `../agent/target`）下取 `<triple>/release/<bin>`。`--agent-binary` 可显式覆盖。
- **pcap / ebpf 不进部署 bin**：libpcap 是动态 C 库，eBPF 需 build-time nightly 工具链 + runtime 特权/BTF；实时抓包与内核追踪属目标侧能力，部署构建用 mock 网络后端、不开 `ebpf`（deploy 仅 host/trace/agentd；guard 以 onaccess/network/ids 常驻）。
- **CI**：`agent (musl deploy build)` 与 `agent (musl deploy build, arm64)` 两个 job 分别构建并上传 `agent-musl-x86_64` / `agent-musl-aarch64` 制品。

## 架构概览

一个 workspace，7 个常规 crate + 1 个 eBPF crate：1 个数据契约底座 + detect 引擎（P0）+ 三大能力（lib+bin 同处）+
1 个统一入口 `agentd`（内置 ingest）+ eBPF 支撑 `agent-ebpf`，全部位于 `crates/`（无嵌套 workspace；`detect/malware` 为子目录 crate）：

```
agent/crates/
├── contract/              # agent-contract：数据契约。零内部依赖
├── detect/malware/        # agent-detect-malware：查毒引擎（P0）
├── detect/                # agent-detect：posture / secrets（P2；re-export malware）
├── collect/host/          # agent-collect-host：主机采集 + detect 适配器（P1）
├── collect/trace/         # agent-collect-trace：capture_batch + enrich（P1/P2）
├── respond/               # agent-respond：实时防护 / 处置（P1）
├── agentd/                # agentd：umbrella + ingest
└── ebpf/                  # agent-ebpf：共享 POD lib + bin trace-ebpf / guard-ebpf
```

> `agent-ebpf` 是 workspace **成员**但**不在 `default-members`**（其内核 bin 仅限 bpf 目标）——host 工具链的
> `cargo build` / `cargo test` 永远不编译其 bin（共享事件结构 lib 仍会在 `agent-collect-trace --features ebpf`
> 时被 host 编译进用户态加载器）。两个内核 bin `trace-ebpf` / `guard-ebpf` 仅由 `agent-collect-trace` / `agent-respond`
> 的 `build.rs` 在各自 `ebpf` feature 打开时，经 `rustup run nightly cargo build -Z build-std=core
> --target bpfel-unknown-none` + bpf-linker 编译为 bpf 字节码，并用 `include_bytes_aligned!` 内嵌。
> 工具链缺失时 `build.rs` 产出空桩 + 警告，使 CI `--all-features` 仍绿（eBPF 后端改为运行时报错，
> 用户态回退到 pcap/mock 或 nft）。

**依赖方向**（单向无环）：

```
agent-contract ◄── agent-detect-malware
agent-contract ◄── agent-collect-host ◄── agent-detect-malware
agent-contract ◄── agent-collect-trace   （+ feature ebpf 时依赖 agent-ebpf；经 build.rs 内嵌 bin trace-ebpf）
agent-contract ◄── agent-respond ◄── agent-detect-malware(onaccess) + agent-collect-trace(network)
agentd ◄── agent-collect-host + agent-collect-trace + agent-respond + agent-contract
agent-ebpf：共享事件结构 lib + 内核 bin trace-ebpf / guard-ebpf
```

完整 DAG 见 [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)。

**流水线重构**：P0–P3 及后续编排两步已落地。部署 / package / bin 主名：
`agent-collect-host` / `agent-collect-trace` / `agent-respond`；`agentd` 子命令
`collect-host` / `collect-trace` / `respond`（别名 `host` / `trace` / `guard`）。见
[`docs/REFACTOR-PIPELINE.md`](docs/REFACTOR-PIPELINE.md)。

guard 经 feature 可选依赖 `agent-detect-malware`（onaccess）/ `agent-collect-trace`（network）：默认
fim+behavior 不牵入查毒 / libpcap。**恶意软件检测**在 `agent-detect-malware`；host 经
detect phase（`DetectOpts`）调用，guard on-access 直接依赖同一引擎。

## feature / 构建矩阵

| feature | 所属 crate | 作用 | 构建/运行要求 |
| --- | --- | --- | --- |
| `pcap` | agent-collect-trace / agent-respond | 实时抓包网络后端（替代默认 mock） | `libpcap-dev`（动态 C 库） |
| `ebpf` | agent-collect-trace | 加载 `trace-ebpf`，挂 exec/exit + openat tracepoint，drain ring buffer → `file_events` / `process_events` | build：nightly + rust-src + bpf-linker；run：CAP_BPF/root + BTF 内核 |
| `ebpf` | agent-respond | netblock 改用内核 cgroup connect4/6 阻断（`guard-ebpf`，BLOCKED_V4/V6 maps），load/attach 失败回退 nft | build：nightly + rust-src + bpf-linker；run：CAP_BPF/root + cgroup-v2 |
| `fim` / `behavior` / `onaccess` / `network` / `ids` / `all` | agent-respond | guard 传感器选择（默认 fim+behavior；`all` 不含 `ebpf`） | onaccess 需 CAP_SYS_ADMIN；network/ids 复用 agent-collect-trace |

eBPF 全程 **opt-in + 特权 + 优雅回退**：未开 `ebpf` 或工具链/内核条件不满足时，用户态自动退回 pcap/mock（trace）或 nft（guard）。
`guard-ebpf` 走 cgroup-connect（**不需要 `CONFIG_BPF_LSM`**，非 LSM 程序）。eBPF **不进** musl 部署构建。

## 构建 & 测试

**工具链 / MSRV**：本 workspace 的 `rust-version = "1.96"`（见 `Cargo.toml` 的 `[workspace.package]`）——
`rustc` / `cargo` **需 ≥ 1.96**。这是因为 `agent-collect-host` 内置 SQLite 的 `rusqlite 0.40` / `libsqlite3-sys 0.38`
用到 `cfg_select`（stable since rustc 1.96），更旧的 Rust 会编译失败。装/升级：
`rustup toolchain install stable && rustup update`，用 `rustc --version` 确认 ≥ 1.96。eBPF 内核 bin 另需 nightly（见下）。

本地验证速查（CI 同款，从 `agent/` 目录执行）：

```bash
cd agent
cargo check  --workspace                             # 快速类型检查（不产出二进制）
cargo build --workspace
cargo test  --workspace                              # 含契约校验 + 内置查毒测试（不编译 *-ebpf）
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all
cargo build --release                                # release 产物（default-members；不含 *-ebpf 内核 bin）

cargo test  -p agent-respond --features all            # guard 全传感器（无需 root，不含 ebpf）
cargo build -p agent-collect-trace --features pcap           # 实时抓包网络后端（需 libpcap-dev）
cargo build -p agent-collect-trace --features ebpf           # eBPF 进程/文件追踪（需 nightly + rust-src + bpf-linker）
cargo build -p agent-respond --features ebpf           # eBPF cgroup-connect netblock（需 nightly + rust-src + bpf-linker）
```

eBPF 构建前置：`rustup toolchain install nightly` + `rustup component add rust-src --toolchain nightly` + `cargo install bpf-linker`。

## 主机静态文件检测（agent-collect-host）

产出 `AssetReport`；`--malware` 追加内置签名查毒；容器/镜像资产默认启用（Docker/Podman/containerd/k8s 静态元数据 + 容器 merged rootfs 内资产），可用 `--no-container-assets` / `--no-image-assets` 关闭。程序化入口 `run_scan_at()`。

```bash
cargo run -p agent-collect-host -- -r / --pretty                                # 合并 AssetReport
cargo run -p agent-collect-host -- -r / -t all -o ./scan-out                    # 分文件 JSON
cargo run -p agent-collect-host -- -r / --malware --pretty                      # 含内置查毒
cargo run -p agent-collect-host -- -r / --malware --malware-signatures sigs.json --pretty
cargo run -p agentd -- collect-host -r / -t all --upload http://127.0.0.1:10068   # 上报 analyzer（统一 agentd）
cargo run -p agent-collect-host -- -r / --container-asset-targets packages,services --pretty  # 容器/镜像资产默认启用；此处仅收窄容器内扫描类别
```

旗标：`-r/--root`、`--image`、`-t/--target {host|packages|sbom|services|accounts|credentials|identity|all}`、
`--project-root`、`--windows-packages {full|apps}`、`--malware`、`--malware-jobs`、
`--malware-signatures PATH`、`--malware-scan-deps`、`--no-posture`、`--secrets`、`--no-container-assets`、`--no-image-assets`、`--container-asset-targets {packages|services|accounts|credentials|all}`、`--max-containers N`、`--max-images N`、`--include-stopped-containers`、`--pretty`、`--report-out`。

- 内置查毒：每个文件读入（限大小）→ SHA-256 + 字节子串匹配签名集；内置 EICAR 测试签名，
  额外签名经 `--malware-signatures`（JSON：`sha256` / `bytes` 规则）加载。命中 → `Vulnerability`
  （`source = "kcatta-malware"`，severity critical）。**简单可用，后续可扩展（YARA 风格规则、更大的库）**。
- Linux 包覆盖 dpkg / apk / rpm / PyPI / npm；Windows 主机/服务/账户/已装程序来自注册表。SBOM 输出 CycloneDX 1.6。**CVE 检测集中在 analyzer**。

```bash
# 精简静态二进制（musl，不牵 trace/guard）
cargo build -p agent-collect-host --target x86_64-unknown-linux-musl --release
```

> 跨机投放 / 调用 / 取回由 analyzer 的 `analyzer-scan`（Python）负责（投放 `agent-collect-host`，调用其单命令）。

## 追踪（agent-collect-trace）

两个子命令：`capture`（网络捕获 → IOC 匹配 → `TraceBatch`，可叠加 eBPF 进程/文件事件）与 `intel-sync`（拉 IOC feed）。
网络后端为 `mock`（默认）/ `pcap`（feature），填充 `TraceBatch.events`（5 元组 + IOC 命中）；
开 `ebpf` feature 后，挂 exec/exit + openat tracepoint，将 ring buffer 事件汇入 `file_events` / `process_events`。库本身不含 HTTP。

```bash
cargo run -p agent-collect-trace -- capture --pretty                                       # mock 网络后端
cargo run -p agentd -- collect-trace --upload http://127.0.0.1:10068 capture --intel data/feeds/feodo.json
sudo cargo run -p agent-collect-trace --features pcap -- capture --pcap --iface eth0 --duration 30 --pretty
sudo cargo run -p agent-collect-trace --features ebpf -- capture --ebpf --ebpf-duration 10 --pretty  # +进程/文件事件（需 CAP_BPF/root + BTF）
cargo run -p agent-collect-trace -- intel-sync --source feodo --out data/feeds/feodo.json
```

## 实时防护（agent-respond）

长驻守护：实时检测 → 决策 → 处置 → 上报。**默认安全**（monitor、零破坏性动作），
启用 enforce + 单动作开关后才处置，受多重安全否决保护。上报 `GuardEventBatch`（本地 NDJSON + 可选注入的 analyzer sink）。

```bash
cargo run -p agent-respond -- --stdout                                    # monitor 默认，无需 root
cargo run -p agentd -- respond --config /etc/kcatta/guard.json --upload http://127.0.0.1:10068
cargo build -p agent-respond --no-default-features --features fim         # 精简：仅 FIM
cargo build -p agent-respond --features all                               # 全传感器（+pcap 需 libpcap；不含 ebpf）
cargo build -p agent-respond --features ebpf                              # netblock 用内核 cgroup-connect（回退 nft）
```

机制（Linux）：`fim`（inotify，默认）、`behavior`（/proc，默认）、`onaccess`（fanotify + 复用
`agent-collect-host` 内置查毒，需 `CAP_SYS_ADMIN`）、`network`/`ids`（复用 `agent-collect-trace` 捕获 + `ThreatFeed`）。
处置：可逆隔离（永不删除、不碰系统前缀 / 运行中-mmap 文件）、网络阻断（默认 nft；`ebpf` feature 下走内核
cgroup connect4/6 阻断器，load/attach 失败回退 nft）、阻断打开（FAN_DENY）；`kill` 仅搭骨架默认关闭。
所有 syscall 走安全的 `nix` 封装，满足 `unsafe_code = "deny"`。

## 数据契约

| 层级 | 路径 |
| --- | --- |
| Pydantic（权威） | `analyzer/src/analyzer/schemas/`（含 `guard_event.py`） |
| JSON Schema | `analyzer/schemas-json/`（含 `GuardEventBatch.schema.json`） |
| Rust 镜像 | `agent-contract`（三种 envelope：`AssetReport` / `TraceBatch`{`events` + `file_events` + `process_events`} / `GuardEventBatch`，共享 `Severity`/`IndicatorType`/`FileOp`/`ProcessEventType`） |
| 校验测试 | `host/tests/contract.rs`、`trace/tests/contract.rs`、`contract/tests/guard_contract.rs` |

## 开发文档

| 文档 | 说明 |
| --- | --- |
| [`../ARCHITECTURE.md`](../ARCHITECTURE.md) | **仓库级**架构综述（agent / analyzer / admin 如何协同、数据契约、关键不变量）——本组件在整体中的位置 |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | **组件级**：三大能力 + 契约底座 + agentd 入口 + eBPF 支撑 crate 模型、各域架构、guard 流水线、扩展指南 |
| [`docs/CONTRIBUTING.md`](docs/CONTRIBUTING.md) | 开发环境、测试、新增采集器 / 传感器流程 |
| [`crates/README.md`](crates/README.md) | Workspace crate 索引 |
