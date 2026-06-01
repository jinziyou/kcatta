# scanner

主机端 **资产与风险扫描器**，[cyber-posture](../README.md) 平台的内视引擎。基于 Rust workspace 构建。

## 目录

- [职责边界](#职责边界)
- [快速开始](#快速开始)
- [架构概览](#架构概览)
- [Workspace 成员](#workspace-成员)
- [静态资产扫描（scanner-asset）](#静态资产扫描scanner-asset)
- [病毒查杀（scanner-malware）](#病毒查杀scanner-malware)
- [合并 AssetReport（scanner-cli）](#合并-assetreportscanner-cli)
- [远端扫描（scanner-remote）](#远端扫描scanner-remote)
- [构建与测试](#构建与测试)
- [数据契约](#数据契约)
- [开发文档](#开发文档)

## 职责边界

| 组件 | 职责 |
| --- | --- |
| **scanner** | 采集：主机信息、已装包、CycloneDX SBOM、服务/账户/凭证、ClamAV 恶意文件命中 |
| **form** | CVE / 包漏洞识别：对上报 SBOM 与包清单做 OSV 匹配；scanner **不内置**漏洞扫描引擎 |

## 快速开始

```bash
cd scanner

# 本机完整资产报告 → stdout
cargo run -p scanner-cli -- -r / --pretty

# 分文件静态扫描
cargo run -p scanner-asset -- -r / -t all -o ./scan-out

# 全 workspace 测试
cargo test --workspace
```

## 架构概览

详细设计见 [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)。

```
scanner/crates/
├── scanner-contract/     # 数据契约（Rust 镜像）
├── scanner-runtime/      # Collector 调度 + run_scan_at
├── scanner-asset/        # 静态资产发现 + bin
├── scanner-malware/      # ClamAV 查杀 + bin
├── scanner-ingest/       # POST /ingest/asset-report
├── scanner-core/         # 门面 run_scan() / run_scan_at()
├── scanner-cli/          # 主 CLI
└── scanner-remote/       # SSH 远端 agent + bin
```

依赖方向：**domain → runtime → contract**。

## Workspace 成员

Crate 索引与常用命令见 [`crates/README.md`](crates/README.md)。

| Crate | 说明 |
| --- | --- |
| `scanner-contract` | 与 `form/schemas-json/` 对齐的 Rust 类型 |
| `scanner-runtime` | `Collector` trait、`ScanContext`、`run_scan_at` |
| `scanner-asset` | 静态文件扫描（包、SBOM、服务、账户、凭证） |
| `scanner-malware` | ClamAV `INSTREAM` 病毒查杀 |
| `scanner-ingest` | HTTP 上报 form |
| `scanner-core` | 向后兼容门面 |
| `scanner-cli` | 组装计划、输出/上报 `AssetReport` |
| `scanner-remote` | SSH 投放静态二进制、远端执行、回传 JSON |

### 当前能力（v0）

- **按功能域拆分的 workspace**：契约 / 调度 / 资产 / 恶意代码 / 上报 / 远端
- **`scanner-asset` 静态扫描**：挂载目录读 `etc/`、`var/lib/dpkg/status`、`proc/net/*` 等
- **多生态软件包**：dpkg / apk / rpm / PyPI / npm，各带 OSV `ecosystem`
- **主机配置**：systemd / SysV 服务、`/etc/passwd`、SSH 公钥指纹
- **CycloneDX SBOM**：`sbom.cyclonedx.json`（带 `purl`，供 form CVE 匹配）
- **`scanner-malware`**：ClamAV 命中 → `Vulnerability`（`source = "clamav"`）
- **`scanner-ingest`**：`POST /ingest/asset-report`
- **`scanner-remote`**：SSH 远端扫描 + 可选 `--upload`
- **跨语言契约验证**：对照 `form/schemas-json/AssetReport.schema.json`

## 静态资产扫描（scanner-asset）

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `--root` / `-r` | `/` | 扫描挂载目录（磁盘镜像根、chroot、本机） |
| `--target` / `-t` | `host` | `host` \| `packages` \| `sbom` \| `services` \| `accounts` \| `credentials` \| `identity` \| `all` |
| `--output` / `-o` | `.` | 写出 JSON 的目录 |
| `--project-root` | （无） | 额外项目目录（相对 `--root`），递归扫 venv / `node_modules`，可重复 |

| 扫描对象 | 输出文件 | 数据来源（相对 root） |
| --- | --- | --- |
| `host` | `host.json` | `etc/hostname`, `etc/os-release`, `proc/version` |
| `packages` | `packages.json` | dpkg / apk / rpm / PyPI / npm |
| `services` | `services.json` | systemd unit + SysV `init.d` |
| `accounts` | `accounts.json` | `/etc/passwd` |
| `credentials` | `credentials.json` | SSH 公钥 / `authorized_keys`（`SHA256:` 指纹） |
| `identity` | 以上三个 | |
| `sbom` | `sbom.cyclonedx.json` | 已装包 + `etc/os-release` → CycloneDX 1.6 |
| `all` | 以上全部 | |

```bash
# 独立二进制
cargo run -p scanner-asset -- -r / -t host -o ./scan-out
cargo run -p scanner-asset -- -r /mnt/image -t all -o ./scan-out

# 采集项目本地语言包
cargo run -p scanner-asset -- -r / -t packages \
    --project-root srv/app --project-root opt/svc -o ./scan-out

# 经 scanner-cli 分文件模式
cargo run -p scanner-cli -- -r / -t all --asset-out ./scan-out
```

> **语言包项目根**：packages 采集会在 `--root` 下自动发现项目目录（深度上限 10）——
> 遇到 `package.json`（跳过 `node_modules` 内）、`pyproject.toml` 或 `requirements.txt`
> 时把其所在目录当作 project-root。`--project-root` 可额外指定，与自动发现合并去重。

### CycloneDX SBOM（`-t sbom`）

输出 CycloneDX 1.6 JSON，每个包带 Package URL（`purl`）。本地可用 trivy 对照验证：

```bash
cargo run -p scanner-asset -- -r / -t sbom -o ./scan-out
trivy sbom ./scan-out/sbom.cyclonedx.json
```

> scanner 只产出 SBOM；**CVE 检测集中在 form 侧**。

## 病毒查杀（scanner-malware）

基于 ClamAV `clamd`：遍历文件，`INSTREAM` 流式扫描，命中 → `Vulnerability`（`severity = critical`、`source = "clamav"`）。

前置：目标主机已安装 ClamAV，签名库已 `freshclam` 更新。

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `--root` / `-r` | `/` | 扫描挂载目录 |
| `--path` / `-p` | 整个 root | 限定子路径（可多次） |
| `--clamd-socket` / `--clamd-host` | 自动探测 | `clamd` 地址 |
| `--max-file-size` | 32 MiB | 超过则跳过 |
| `--jobs` / `-j` | CPU 核数 | 并行 worker |
| `--scan-media` | 关 | 默认跳过 png/mp4/woff2 等媒体 |
| `--include-pseudo-fs` | 关 | 默认跳过 proc/sys/dev/run |
| `--output` / `-o` | `.` | 写出 `malware.json` |

```bash
cargo run -p scanner-malware -- -r / -p home -p tmp -o ./scan-out
cargo run -p scanner-cli --features full -- -r / --pretty
```

## 合并 AssetReport（scanner-cli）

```bash
cargo run -p scanner-cli -- -r / --pretty
cargo run -p scanner-cli -- -r /mnt/image --out report.json
cargo run -p scanner-cli --features ingest -- -r / -t all --upload http://127.0.0.1:8000
```

| Feature | 说明 |
| --- | --- |
| `asset`（默认） | 静态资产 |
| `malware` | ClamAV |
| `ingest` | `--upload` |
| `full` | `asset` + `malware` |

## 远端扫描（scanner-remote）

通过 SSH 投放静态 `scanner-asset` 到目标主机、就地扫描、回传 JSON。详见 [`crates/scanner-remote/README.md`](crates/scanner-remote/README.md)。

```bash
rustup target add x86_64-unknown-linux-musl
cargo build -p scanner-asset --target x86_64-unknown-linux-musl --release

SCDR_SSH_PASSWORD='...' cargo run -p scanner-remote -- \
    --ssh-host root@10.22.0.243 \
    --target all \
    --output ./reports/10.22.0.243/ \
    --upload http://127.0.0.1:8000
```

## 构建与测试

```bash
cd scanner
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo doc --no-deps --workspace --open   # 本地 API 文档
```

## 数据契约

| 层级 | 路径 |
| --- | --- |
| Pydantic（权威） | `form/src/form/schemas/` |
| JSON Schema | `form/schemas-json/` |
| Rust 类型 | `scanner-contract` |
| 校验测试 | `scanner-runtime/tests/contract.rs` |

分文件 JSON（`packages.json` 等）使用同一契约类型序列化（`packages.json` 为 `Asset[]`）。

## 开发文档

| 文档 | 说明 |
| --- | --- |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | 组件关系、Collector 模型、扩展指南 |
| [`docs/CONTRIBUTING.md`](docs/CONTRIBUTING.md) | 开发环境、测试、新增采集器流程 |
| [`crates/README.md`](crates/README.md) | Workspace crate 索引 |
