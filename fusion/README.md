# fusion

posture 的采集探针，基于 Rust workspace 构建。用**两个正交维度**描述能力，而非互相替代：

| 维度 | 回答的问题 | 取值 |
| --- | --- | --- |
| **数据域** | 采什么、form 怎么分析 | **主机**（内视 → `AssetReport`）· **网络**（外视 → `FlowBatch`） |
| **运行模式** | 怎么跑、多久采一次 | **周期性**（按需 / cron 快照）· **持续性**（长驻 / 流式近实时） |

职责边界为 **只采集、不分析**：CVE 判定与跨源关联集中在 **form** 侧；fusion 只产出标准化 envelope 并上报。

### 能力矩阵（数据域 × 运行模式）

|  | 周期性（快照 / 批处理） | 持续性（长驻 / 流式） |
| --- | --- | --- |
| **主机** | `fusion-asset`、`fusion-host`、`fusion-malware`、`fusion-remote`（SSH / WinRM 投放） | *规划中*（配置漂移、文件监听等） |
| **网络** | `fusion-flow-cli` mock 批跑、`fusion-intel-sync` 定时拉 feed | `fusion-flow-cli --pcap` 长时抓包 / 可扩展为 daemon |

当前实现以 **主机周期性盘点 + 网络可周期可持续** 为主；crate 划分仍按**数据域**（主机 / 网络），运行模式由部署方式（cron、一次性 CLI、长驻进程）决定。

| 数据域 | 视角 | 采集内容 | 主二进制 | 典型运行模式 |
| --- | --- | --- | --- | --- |
| 主机（fusion-host） | 内视 | 主机信息、已装包、CycloneDX SBOM、服务 / 账户 / 凭证指纹、ClamAV 命中 | `fusion-host`、`fusion-asset`、`fusion-malware`、`fusion-remote` | 周期性 |
| 网络（fusion-flow） | 外视 | 流量元数据（会话 / 协议 / 外联）、威胁情报 IOC 命中 | `fusion-flow`、`fusion-intel-sync` | 周期性 + 持续性 |

## 架构概览

```
fusion/crates/
├── fusion-contract/      # 数据契约（Rust 镜像）：AssetReport + FlowBatch，共享 Severity
├── fusion-ingest/        # 上报客户端：POST AssetReport / FlowBatch → form（共享 HTTP + 鉴权）
├── fusion-runtime/       # 主机采集调度：Collector trait、ScanContext、run_scan_at
├── fusion-asset/         # 主机静态资产发现 + bin
├── fusion-malware/       # ClamAV INSTREAM 查杀 + bin
├── fusion-host-cli/      # 主机 CLI（bin: fusion-host）
├── fusion-remote/        # SSH 投放 fusion-asset、远端执行、回传 JSON + bin
├── fusion-flow/          # 网络流量捕获 + 威胁情报匹配（库）
├── fusion-intel-sync/    # 拉取 IOC feed → 本地 JSON（bin）
└── fusion-flow-cli/      # 网络 CLI（bin: fusion-flow）
```

依赖方向：`fusion-asset/...` 领域 crate → `fusion-runtime`/`fusion-flow` → `fusion-contract`；
`fusion-ingest` 仅依赖 `fusion-contract`，对两种 envelope 泛型上报，故 `fusion-remote` 等只做
主机扫描的二进制不会牵入网络抓包依赖。

> 命名上 `fusion-runtime` 内部的 `Collector` trait 指「一类资产采集单元」，与网络组件无关——
> 网络组件现为 `fusion-flow`，不再与之同名。

## 构建 & 测试

```bash
cd fusion
cargo build --workspace
cargo test  --workspace                                 # 含跨语言契约验证（mock 后端）
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all

# 启用 pcap 实时抓包（需 libpcap-dev，Debian/Ubuntu: apt install libpcap-dev）
cargo build -p fusion-flow-cli --features pcap
cargo test  -p fusion-flow --features pcap --lib         # 含 parse 单元测试
```

## 主机域（fusion-host / 内视 · 周期性）

主机域产出 `AssetReport`，当前均为**周期性 / 按需**批扫（本机、挂载盘、远端 SSH/WinRM）；尚未提供长驻 agent。

```bash
# 本机完整资产报告 → stdout
cargo run -p fusion-host-cli -- -r / --pretty

# 分文件静态扫描（host.json / packages.json / sbom.cyclonedx.json …）
cargo run -p fusion-asset -- -r / -t all -o ./scan-out

# 含 ClamAV 查杀（需本机 clamd + freshclam 库）
cargo run -p fusion-host-cli --features full -- -r / --pretty

# 扫描 + 上报 form
cargo run -p fusion-host-cli --features ingest -- -r / -t all --upload http://127.0.0.1:8000
```

- 静态扫描对象：`host | packages | sbom | services | accounts | credentials | identity | all`。
- **Linux**：软件包覆盖 dpkg / apk / rpm / PyPI / npm，各带 OSV `ecosystem`，供 form CVE 匹配。
- **Windows**：主机 / 服务 / 账户 / 已装程序来自注册表（离线 hive 或本机 HKLM）；PyPI / npm 来自常见安装路径；SSH 指纹来自 `Users/*/.ssh` 与 `ProgramData/ssh`；IP/MAC 来自 SYSTEM 注册表。
- SBOM 输出 CycloneDX 1.6（带 `purl`）；fusion 只出 SBOM，**CVE 检测集中在 form**。
- `fusion-malware` 命中 → `Vulnerability`（`source = "clamav"`）。

### Windows 扫描

支持三种场景：

| 场景 | 命令示例 | 数据来源 |
| --- | --- | --- |
| WSL / Linux 挂载 Windows 盘 | `cargo run -p fusion-asset -- -r /mnt/c -t all -o ./win-out` | `Windows/System32/config/{SOFTWARE,SYSTEM,SAM}` 离线 hive |
| Windows 本机 | `cargo run -p fusion-asset -- -t all -o ./scan-out` | 默认 `%SystemDrive%\`，走 live HKLM |
| 磁盘镜像挂载 | `cargo run -p fusion-asset -- -r /path/to/mount -t all -o ./out` | 离线 hive（需包含 config 目录） |

```bash
# 交叉编译 Windows 二进制（在 Windows 上本机扫描）
rustup target add x86_64-pc-windows-msvc
cargo build -p fusion-asset --target x86_64-pc-windows-msvc --release
```

> Windows 已装程序使用 `source = windows-uninstall | windows-winget | windows-cbs | windows-appx | windows-chocolatey`，并附带 `ecosystem = Windows:10/11`（与 Linux 发行版 ecosystem 对齐，供 form OSV 匹配）。

### 远端扫描（fusion-remote）

通过 SSH 投放**静态** `fusion-asset` 到目标主机、就地扫描、回传 JSON。`fusion-asset` 内含
bundled SQLite（C）：musl 静态需 musl C 编译器（`apt install musl-tools`）；若无，用原生
工具链做 static-glibc，并以 `--asset-binary` 指定其路径：

```bash
# 方式 A：musl 静态（需 musl-gcc）
rustup target add x86_64-unknown-linux-musl
cargo build -p fusion-asset --target x86_64-unknown-linux-musl --release

# 方式 B：static-glibc（用原生 gcc，无需额外 C 工具链）
RUSTFLAGS="-C target-feature=+crt-static" \
  cargo build -p fusion-asset --target x86_64-unknown-linux-gnu --release

SCDR_SSH_PASSWORD='...' cargo run -p fusion-remote -- \
    --ssh-host root@10.22.0.243 --target all \
    --output ./reports/10.22.0.243/ --upload http://127.0.0.1:8000
```

## 网络域（fusion-flow / 外视 · 周期性 + 持续性）

网络域产出 `FlowBatch`：**周期性**（mock 批跑、intel-sync 定时更新 IOC）与**持续性**（pcap 长时抓包）均可。

```bash
# Mock（默认，无需 root / libpcap）：抓包 → 威胁情报 IOC 匹配 → FlowBatch
cargo run -p fusion-flow-cli -- --pretty
cargo run -p fusion-flow-cli -- --intel examples/threat-feed.json --upload http://127.0.0.1:8000

# Pcap 实时抓包（需 --features pcap + libpcap + 通常 root）
cargo build -p fusion-flow-cli --features pcap
sudo cargo run -p fusion-flow-cli --features pcap -- --pcap --iface eth0 --duration 30 \
  --bpf "tcp port 443" --pretty
```

- 威胁情报 IOC 匹配（IP / 域名 / JA3）在 fusion-flow 侧完成（**初步处理**），命中以
  `ThreatMatch` 注入对应 `FlowEvent.threat_intel`，form 据此直接做告警关联。
- 域名匹配大小写不敏感且父域命中子域（`a.b.evil` 命中 `evil`）。

### 情报库自动同步（fusion-intel-sync）

与 form 的 `form-osv-sync` 同样 **离线友好**：同步是独立、可定时的步骤；采集时 `--intel`
只读本地 JSON，匹配不联网。

```bash
cargo run -p fusion-intel-sync -- --source feodo --out data/feeds/feodo.json
cargo run -p fusion-flow-cli -- --intel data/feeds/feodo.json --upload http://127.0.0.1:8000
```

abuse.ch Feodo Tracker 每条 IP 映射为 `type=ip`、`category=c2`、`severity=high`、
`source=abuse.ch-feodo`。

## 数据契约

| 层级 | 路径 |
| --- | --- |
| Pydantic（权威） | `form/src/form/schemas/` |
| JSON Schema | `form/schemas-json/`（`AssetReport.schema.json` / `FlowBatch.schema.json`） |
| Rust 镜像 | `fusion-contract`（同时持有两种 envelope，共享 `Severity`） |
| 校验测试 | `fusion-runtime/tests/contract.rs`、`fusion-flow/tests/contract.rs` |

新增字段流程：先改 form 端 Pydantic 模型 → `form-export-schemas` 重生成 JSON Schema →
在 `fusion-contract` 加对应 Rust 字段 → `cargo test` 验证。

## 开发文档

| 文档 | 说明 |
| --- | --- |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | 双轴模型、Collector / Flow 架构、扩展指南 |
| [`docs/CONTRIBUTING.md`](docs/CONTRIBUTING.md) | 开发环境、测试、新增采集器流程 |
| [`crates/README.md`](crates/README.md) | Workspace crate 索引 |
