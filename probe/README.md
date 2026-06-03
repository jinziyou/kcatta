# probe

cyber-posture 的采集探针 —— 「主机 + 网络」双维度。基于 Rust workspace 构建。

职责边界为 **只采集、不分析**：CVE 判定与关联分析集中在 **form** 侧，probe 只产出标准化的
`AssetReport`（主机）与 `FlowBatch`（网络）并上报。

| 领域 | 视角 | 采集内容 | 主二进制 |
| --- | --- | --- | --- |
| 主机（probe-host） | 内视 | 主机信息、已装包、CycloneDX SBOM、服务 / 账户 / 凭证指纹、ClamAV 命中 | `probe-host`、`probe-asset`、`probe-malware`、`probe-remote` |
| 网络（probe-flow） | 外视 | 流量元数据（会话 / 协议 / 外联）、威胁情报 IOC 命中 | `probe-flow`、`probe-intel-sync` |

## 架构概览

```
probe/crates/
├── probe-contract/      # 数据契约（Rust 镜像）：AssetReport + FlowBatch，共享 Severity
├── probe-ingest/        # 上报客户端：POST AssetReport / FlowBatch → form（共享 HTTP + 鉴权）
├── probe-runtime/       # 主机采集调度：Collector trait、ScanContext、run_scan_at
├── probe-asset/         # 主机静态资产发现 + bin
├── probe-malware/       # ClamAV INSTREAM 查杀 + bin
├── probe-core/          # 主机门面（run_scan / 默认采集计划）
├── probe-host-cli/      # 主机 CLI（bin: probe-host）
├── probe-remote/        # SSH 投放 probe-asset、远端执行、回传 JSON + bin
├── probe-flow/          # 网络流量捕获 + 威胁情报匹配（库）
├── probe-intel-sync/    # 拉取 IOC feed → 本地 JSON（bin）
└── probe-flow-cli/      # 网络 CLI（bin: probe-flow）
```

依赖方向：`probe-asset/...` 领域 crate → `probe-runtime`/`probe-flow` → `probe-contract`；
`probe-ingest` 仅依赖 `probe-contract`，对两种 envelope 泛型上报，故 `probe-remote` 等只做
主机扫描的二进制不会牵入网络抓包依赖。

> 命名上 `probe-runtime` 内部的 `Collector` trait 指「一类资产采集单元」，与网络组件无关——
> 网络组件现为 `probe-flow`，不再与之同名。

## 构建 & 测试

```bash
cd probe
cargo build --workspace
cargo test  --workspace                                 # 含跨语言契约验证（mock 后端）
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all

# 启用 pcap 实时抓包（需 libpcap-dev，Debian/Ubuntu: apt install libpcap-dev）
cargo build -p probe-flow-cli --features pcap
cargo test  -p probe-flow --features pcap --lib         # 含 parse 单元测试
```

## 主机域（probe-host / 内视）

```bash
# 本机完整资产报告 → stdout
cargo run -p probe-host-cli -- -r / --pretty

# 分文件静态扫描（host.json / packages.json / sbom.cyclonedx.json …）
cargo run -p probe-asset -- -r / -t all -o ./scan-out

# 含 ClamAV 查杀（需本机 clamd + freshclam 库）
cargo run -p probe-host-cli --features full -- -r / --pretty

# 扫描 + 上报 form
cargo run -p probe-host-cli --features ingest -- -r / -t all --upload http://127.0.0.1:8000
```

- 静态扫描对象：`host | packages | sbom | services | accounts | credentials | identity | all`。
- 软件包覆盖 dpkg / apk / rpm / PyPI / npm，各带 OSV `ecosystem`，供 form CVE 匹配。
- SBOM 输出 CycloneDX 1.6（带 `purl`）；probe 只出 SBOM，**CVE 检测集中在 form**。
- `probe-malware` 命中 → `Vulnerability`（`source = "clamav"`）。

### 远端扫描（probe-remote）

通过 SSH 投放**静态** `probe-asset` 到目标主机、就地扫描、回传 JSON。`probe-asset` 内含
bundled SQLite（C）：musl 静态需 musl C 编译器（`apt install musl-tools`）；若无，用原生
工具链做 static-glibc，并以 `--asset-binary` 指定其路径：

```bash
# 方式 A：musl 静态（需 musl-gcc）
rustup target add x86_64-unknown-linux-musl
cargo build -p probe-asset --target x86_64-unknown-linux-musl --release

# 方式 B：static-glibc（用原生 gcc，无需额外 C 工具链）
RUSTFLAGS="-C target-feature=+crt-static" \
  cargo build -p probe-asset --target x86_64-unknown-linux-gnu --release

SCDR_SSH_PASSWORD='...' cargo run -p probe-remote -- \
    --ssh-host root@10.22.0.243 --target all \
    --output ./reports/10.22.0.243/ --upload http://127.0.0.1:8000
```

## 网络域（probe-flow / 外视）

```bash
# Mock（默认，无需 root / libpcap）：抓包 → 威胁情报 IOC 匹配 → FlowBatch
cargo run -p probe-flow-cli -- --pretty
cargo run -p probe-flow-cli -- --intel examples/threat-feed.json --upload http://127.0.0.1:8000

# Pcap 实时抓包（需 --features pcap + libpcap + 通常 root）
cargo build -p probe-flow-cli --features pcap
sudo cargo run -p probe-flow-cli --features pcap -- --pcap --iface eth0 --duration 30 \
  --bpf "tcp port 443" --pretty
```

- 威胁情报 IOC 匹配（IP / 域名 / JA3）在 probe-flow 侧完成（**初步处理**），命中以
  `ThreatMatch` 注入对应 `FlowEvent.threat_intel`，form 据此直接做告警关联。
- 域名匹配大小写不敏感且父域命中子域（`a.b.evil` 命中 `evil`）。

### 情报库自动同步（probe-intel-sync）

与 form 的 `form-osv-sync` 同样 **离线友好**：同步是独立、可定时的步骤；采集时 `--intel`
只读本地 JSON，匹配不联网。

```bash
cargo run -p probe-intel-sync -- --source feodo --out data/feeds/feodo.json
cargo run -p probe-flow-cli -- --intel data/feeds/feodo.json --upload http://127.0.0.1:8000
```

abuse.ch Feodo Tracker 每条 IP 映射为 `type=ip`、`category=c2`、`severity=high`、
`source=abuse.ch-feodo`。

## 数据契约

| 层级 | 路径 |
| --- | --- |
| Pydantic（权威） | `form/src/form/schemas/` |
| JSON Schema | `form/schemas-json/`（`AssetReport.schema.json` / `FlowBatch.schema.json`） |
| Rust 镜像 | `probe-contract`（同时持有两种 envelope，共享 `Severity`） |
| 校验测试 | `probe-runtime/tests/contract.rs`、`probe-core/tests/contract.rs`、`probe-flow/tests/contract.rs` |

新增字段流程：先改 form 端 Pydantic 模型 → `form-export-schemas` 重生成 JSON Schema →
在 `probe-contract` 加对应 Rust 字段 → `cargo test` 验证。

## 开发文档

| 文档 | 说明 |
| --- | --- |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | 主机采集 Collector 模型、扩展指南 |
| [`docs/CONTRIBUTING.md`](docs/CONTRIBUTING.md) | 开发环境、测试、新增采集器流程 |
| [`crates/README.md`](crates/README.md) | Workspace crate 索引 |
