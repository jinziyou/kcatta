# agent

posture 的采集组件，基于 Rust workspace 构建。用**两个正交维度**描述能力，而非互相替代：

| 维度 | 回答的问题 | 取值 |
| --- | --- | --- |
| **数据域** | 采什么、fusion 怎么分析 | **主机**（内视 → `AssetReport`）· **网络**（外视 → `FlowBatch`） |
| **运行模式** | 怎么跑、多久采一次 | **周期性**（按需 / cron 快照）· **持续性**（长驻 / 流式近实时） |

职责边界为 **只采集、不分析**：CVE 判定与跨源关联集中在 **fusion** 侧；agent 只产出标准化 envelope 并上报。

### 能力矩阵（数据域 × 运行模式）

|  | 周期性（快照 / 批处理） | 持续性（长驻 / 流式） |
| --- | --- | --- |
| **主机** | `agent host`（资产盘点 + 可选 ClamAV） | *规划中*（配置漂移、文件监听等） |
| **网络** | `agent flow`（mock 批跑）、`agent intel-sync`（定时拉 feed） | `agent flow --pcap` 长时抓包 / 可扩展为 daemon |

当前实现以 **主机周期性盘点 + 网络可周期可持续** 为主；crate 划分按**数据域**（主机 / 网络），运行模式由部署方式（cron、一次性 CLI、长驻进程）决定。所有能力统一从单一二进制 `agent` 的子命令进入。

| 数据域 | 视角 | 采集内容 | 子命令 | 典型运行模式 |
| --- | --- | --- | --- | --- |
| 主机（agent-host） | 内视 | 主机信息、已装包、CycloneDX SBOM、服务 / 账户 / 凭证指纹、ClamAV 命中 | `agent host` | 周期性 |
| 网络（agent-flow） | 外视 | 流量元数据（会话 / 协议 / 外联）、威胁情报 IOC 命中 | `agent flow`、`agent intel-sync` | 周期性 + 持续性 |

## 架构概览

5 个**扁平** crate，位于 `crates/` 下，每个目录就是一个 crate（不再有目录套子 crate）：

```
agent/crates/
├── contract/    # agent-contract：数据契约（AssetReport + FlowBatch，共享 Severity）。零内部依赖，DAG 汇点
├── ingest/      # agent-ingest：阻塞式 HTTP 上报客户端 → fusion（仅依赖 contract）
├── host/        # agent-host：全部主机检测（纯库）+ Collector/run_scan 调度抽象 + ClamAV（malware feature）
├── flow/        # agent-flow：网络流捕获 + 威胁情报 IOC 匹配 + IOC feed 解析（纯库）
└── runtime/     # agent-runtime：`agent` 编排二进制（bin 名 agent），子命令调度各域模块
```

各 crate 职责：

| 目录 / 包名 | 职责 |
| --- | --- |
| `contract` / `agent-contract` | 数据契约：`AssetReport` + `FlowBatch` + 共享 `Severity`（fusion `schemas-json` 的 Rust 镜像）。零内部依赖。 |
| `ingest` / `agent-ingest` | 阻塞式 HTTP 上报客户端 → fusion：`upload_report`（`AssetReport` → `/ingest/asset-report`）、`upload_batch`（`FlowBatch` → `/ingest/flow-batch`），带 `FUSION_API_TOKEN` Bearer，202 视为成功。仅依赖 contract。 |
| `host` / `agent-host` | 全部主机检测（纯库）：静态资产发现（packages / services / accounts / credentials / SBOM / platform / walk / sources）+ 主机域调度抽象（`Collector` trait、`ScanContext`、`CollectorOutput`、`WindowsPackageProfile`、`run_scan` / `run_scan_at*`）+ ClamAV INSTREAM 查杀（`malware` feature 后的 `MalwareCollector`）。仅依赖 contract。features：`default = []`；`malware`。 |
| `flow` / `agent-flow` | 网络流域纯库：capture（默认 mock，`pcap` feature 实时）+ 威胁情报 IOC 匹配（`ThreatFeed`）+ IOC feed 字节解析器（`intel::sync::feodo`）。不含 CLI / HTTP / ingest。仅依赖 contract。features：`default = []`；`pcap`。 |
| `runtime` / `agent-runtime` | `agent` 编排二进制（bin 名 `agent`），通过子命令调度各域模块。依赖 contract、ingest、host（可选）、flow（可选）、reqwest（可选）。features：`default = [host, flow]`；`host`；`flow`；`malware → host/malware`；`pcap → flow/pcap`；`full = [host, flow, malware]`。 |

**分层与依赖方向**（单向、无环）：契约底座 ← 各域实现 ← 编排器。

```
contract ← ingest
contract ← host
contract ← flow
{contract, ingest, host, flow} ← runtime
```

- `agent-contract` 是依赖 DAG 的唯一汇点（零内部依赖），被所有域依赖——故独立保留为底座，不归入任一域。
- `agent-ingest`、`agent-host`、`agent-flow` 都只依赖 `agent-contract`，三者之间互不依赖。
- 编排只发生在 `agent-runtime`（`agent` 二进制），且各域模块经 feature 门控：只做主机扫描的精简 agent（`--no-default-features --features host`）不会牵入网络 / pcap 依赖，反之亦然。
- **malware 是 host 域的可选采集器**：在 `host` 的 `malware` feature 后，`MalwareCollector` 产出 `Vulnerability`，经 `run_scan` 合并进 host 的 `AssetReport.vulnerabilities`（无独立 envelope），且要求 host collector 先跑填充 `host_id`。

> `Collector` trait（位于 `agent-host` 的 `crate::collector`）指「一类资产采集单元」，与网络组件无关——网络组件为 `agent-flow`，不再与之同名。

## 构建 & 测试

```bash
cd agent
cargo build --workspace
cargo test  --workspace                                 # 含跨语言契约验证（mock 后端）
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all

# 启用 pcap 实时抓包（需 libpcap-dev，Debian/Ubuntu: apt install libpcap-dev）
cargo build -p agent-runtime --features pcap
cargo test  -p agent-flow    --features pcap --lib       # 含 parse 单元测试
```

## 主机域（agent host / 内视 · 周期性）

`agent host` 产出 `AssetReport`，当前均为**周期性 / 按需**批扫（本机、挂载盘）；尚未提供长驻 agent。

```bash
# 本机合并资产报告 → stdout
cargo run -p agent-runtime -- host -r / --pretty

# 分文件静态扫描（host.json / packages.json / sbom.cyclonedx.json …）
cargo run -p agent-runtime -- host -r / -t all -o ./scan-out

# 含 ClamAV 查杀（需本机 clamd + freshclam 库）
cargo run -p agent-runtime --features full -- host -r / --malware --pretty

# 扫描 + 上报 fusion
cargo run -p agent-runtime -- host -r / -t all --upload http://127.0.0.1:8000
```

旗标：`-r/--root`、`-t/--target {host|packages|sbom|services|accounts|credentials|identity|all}`、`--project-root`、`--windows-packages {full|apps}`、`--malware`、`--malware-jobs`、`--clamd-socket`。

- 输出模式：带 `-o DIR` → 分文件 JSON（`host.json` / `packages.json` / `sbom.cyclonedx.json` / `services.json` / `accounts.json` / `credentials.json`，经 `run_static_scan`，`--malware` 时另写 `malware.json`）；不带 `-o` → 合并 `AssetReport` 到 stdout（`--pretty`）/ 文件（`--report-out FILE`）/ fusion（`--upload URL`，`--malware` 命中并入 `vulnerabilities`）。
- **Linux**：软件包覆盖 dpkg / apk / rpm / PyPI / npm，各带 OSV `ecosystem`，供 fusion CVE 匹配。
- **Windows**：主机 / 服务 / 账户 / 已装程序来自注册表（离线 hive 或本机 HKLM）；PyPI / npm 来自常见安装路径；SSH 指纹来自 `Users/*/.ssh` 与 `ProgramData/ssh`；IP/MAC 来自 SYSTEM 注册表。
- SBOM 输出 CycloneDX 1.6（带 `purl`）；agent 只出 SBOM，**CVE 检测集中在 fusion**。
- ClamAV 命中 → `Vulnerability`（`source = "clamav"`）。

### Windows 扫描

支持三种场景：

| 场景 | 命令示例 | 数据来源 |
| --- | --- | --- |
| WSL / Linux 挂载 Windows 盘 | `cargo run -p agent-runtime -- host -r /mnt/c -t all -o ./win-out` | `Windows/System32/config/{SOFTWARE,SYSTEM,SAM}` 离线 hive |
| Windows 本机 | `cargo run -p agent-runtime -- host -t all -o ./scan-out` | 默认 `%SystemDrive%\`，走 live HKLM |
| 磁盘镜像挂载 | `cargo run -p agent-runtime -- host -r /path/to/mount -t all -o ./out` | 离线 hive（需包含 config 目录） |

```bash
# 交叉编译 Windows 二进制（在 Windows 上本机扫描）
rustup target add x86_64-pc-windows-msvc
cargo build -p agent-runtime --target x86_64-pc-windows-msvc --release

# 精简主机 agent（不牵 flow/pcap）：产物为单一 agent 二进制
rustup target add x86_64-unknown-linux-musl
cargo build -p agent-runtime --no-default-features --features host,malware \
  --target x86_64-unknown-linux-musl --release
```

> Windows 已装程序使用 `source = windows-uninstall | windows-winget | windows-cbs | windows-appx | windows-chocolatey`，并附带 `ecosystem = Windows:10/11`（与 Linux 发行版 ecosystem 对齐，供 fusion OSV 匹配）。

> **远端投放 / 采集已上移到 fusion**：跨机投放（上传到待测机器、调用 `agent`、取回结果）现在由 fusion 的 `fusion-scan`（Python 实现）负责；`agent-runtime` 只调度本机 / 目标机上的进程内模块。

## 网络域（agent flow / 外视 · 周期性 + 持续性）

`agent flow` 产出 `FlowBatch`：**周期性**（mock 批跑、intel-sync 定时更新 IOC）与**持续性**（pcap 长时抓包）均可。capture → IOC 匹配 → `FlowBatch`。

```bash
# Mock（默认，无需 root / libpcap）：抓包 → 威胁情报 IOC 匹配 → FlowBatch
cargo run -p agent-runtime -- flow --pretty
cargo run -p agent-runtime -- flow --intel examples/threat-feed.json --upload http://127.0.0.1:8000

# Pcap 实时抓包（需 --features pcap + libpcap + 通常 root）
cargo build -p agent-runtime --features pcap
sudo cargo run -p agent-runtime --features pcap -- flow --pcap --iface eth0 --duration 30 \
  --bpf "tcp port 443" --pretty
```

旗标：`--pretty`、`-o/--out FILE`、`--intel PATH`、`--upload URL`、`--mock`（默认）、`--pcap`（需 pcap feature）、`--iface`、`--duration`、`--bpf`、`--list-devices`。

- 威胁情报 IOC 匹配（IP / 域名 / JA3）在 flow 域内完成（**初步处理**），命中以 `ThreatMatch` 注入对应 `FlowEvent.threat_intel`，fusion 据此直接做告警关联。
- 域名匹配大小写不敏感且父域命中子域（`a.b.evil` 命中 `evil`）。

### 情报库自动同步（agent intel-sync）

与 fusion 的 `fusion-osv-sync` 同样 **离线友好**：同步是独立、可定时的步骤；采集时 `--intel` 只读本地 JSON，匹配不联网。

```bash
cargo run -p agent-runtime -- intel-sync --source feodo --out data/feeds/feodo.json
cargo run -p agent-runtime -- flow --intel data/feeds/feodo.json --upload http://127.0.0.1:8000
```

旗标：`--source NAME`（可重复，必填）、`-o/--out`、`--feodo-url`、`--timeout`。

abuse.ch Feodo Tracker 每条 IP 映射为 `type=ip`、`category=c2`、`severity=high`、`source=abuse.ch-feodo`。

## 数据契约

| 层级 | 路径 |
| --- | --- |
| Pydantic（权威） | `fusion/src/fusion/schemas/` |
| JSON Schema | `fusion/schemas-json/`（共 6 个；agent 镜像其中 `AssetReport.schema.json` / `FlowBatch.schema.json`） |
| Rust 镜像 | `agent-contract`（同时持有两种 envelope，共享 `Severity`） |
| 校验测试 | [`crates/host/tests/contract.rs`](crates/host/tests/contract.rs)（`AssetReport`）、[`crates/flow/tests/contract.rs`](crates/flow/tests/contract.rs)（`FlowBatch`） |

新增字段流程：先改 fusion 端 Pydantic 模型 → `fusion-export-schemas` 重生成 JSON Schema → 在 `agent-contract` 加对应 Rust 字段 → `cargo test` 验证。

## 开发文档

| 文档 | 说明 |
| --- | --- |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | 双轴模型、Collector / Flow 架构、扩展指南 |
| [`docs/CONTRIBUTING.md`](docs/CONTRIBUTING.md) | 开发环境、测试、新增采集器流程 |
| [`crates/README.md`](crates/README.md) | Workspace crate 索引 |
