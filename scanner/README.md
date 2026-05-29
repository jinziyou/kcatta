# scanner

主机端 **资产与风险扫描器**，cyber-posture 平台的内视引擎。基于 Rust 构建。

## 当前状态（v0）

已落地：

- **按功能域拆分的 workspace**：契约 / 调度 / 资产发现 / 漏洞&恶意代码占位 / 上报占位
- **`scanner-asset` 静态文件扫描**：对挂载目录（默认 `/`）读 `etc/`、`var/lib/dpkg/status`、`proc/net/*` 等
- **`scanner-malware` 病毒查杀**：基于 ClamAV（`clamd`）对目录树做 `INSTREAM` 流式扫描，命中映射为 `Vulnerability`（`source = "clamav"`）
- **扫描参数**：`--root` 挂载目录、`--target` 扫描对象（默认 `host`）
- **多生态软件包采集**：`packages.json` 含 dpkg / apk / rpm(OS)、Python(`PyPI`)、npm(`npm`)包，各自带 OSV `ecosystem`（如 `Debian:12`/`Alpine:v3.18`/`Rocky Linux:9`/`PyPI`/`npm`），供 form 按**包级生态**在同一主机上混合匹配；语言包除全局位置外，`--project-root` 可递归采集项目本地 venv / `node_modules`，且 packages 采集会**自动发现**含 `package.json`/`pyproject.toml`/`requirements.txt` 的项目目录
- **CycloneDX SBOM 导出**：`sbom.cyclonedx.json`（带 deb `purl`，供 form/trivy 做 CVE 检测）
- **`Collector` + `run_scan_at(root)`**：合并为完整 `AssetReport`（`scanner-cli` stdout / `--out`）
- **跨语言契约验证**：对照 `form/schemas-json/AssetReport.schema.json`

尚未落地：

- rpm 旧版后端（Berkeley DB `Packages` / ndb；当前仅支持 RHEL8+/Fedora 的 sqlite `rpmdb.sqlite`）
- service / account / credential 采集
- `scanner-vuln` 真实引擎
- `scanner-ingest` HTTP 上报

## 仓库形态

```
scanner/crates/
├── scanner-contract/
├── scanner-runtime/        # ScanContext.scan_root + run_scan_at
├── scanner-asset/          # 静态资产扫描 + 二进制 scanner-asset
├── scanner-vuln|ingest/
├── scanner-malware/        # ClamAV 病毒查杀 + 二进制 scanner-malware
├── scanner-core/           # 门面 run_scan() / run_scan_at()
├── scanner-cli/
└── scanner-remote/         # agent 模式远端扫描（SSH 投放 scanner-asset）+ 二进制
```

## 静态资产扫描（scanner-asset）

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `--root` / `-r` | `/` | 扫描挂载目录（磁盘镜像根、chroot、本机） |
| `--target` / `-t` | `host` | `host` \| `packages` \| `sbom` \| `all` |
| `--output` / `-o` | `.` | 写出 JSON 的目录 |
| `--project-root` | （无） | 额外项目目录（相对 `--root`），递归扫 venv / 项目 `node_modules`，可重复 |

| 扫描对象 | 输出文件 | 数据来源（相对 root） |
| --- | --- | --- |
| `host` | `host.json` | `etc/hostname`, `etc/os-release`, `proc/version` |
| `packages` | `packages.json` | dpkg `var/lib/dpkg/status`、apk `lib/apk/db/installed`、rpm `var/lib/rpm/rpmdb.sqlite`(+`etc/os-release`)、Python 全局 `*/site-packages/*.dist-info`、npm 全局 `*/node_modules/*/package.json`、自动发现的项目目录（见下）及 `--project-root` 下的 venv / `node_modules`(递归) |
| `sbom` | `sbom.cyclonedx.json` | `var/lib/dpkg/status` + `etc/os-release` |
| `all` | 以上三个 | |

```bash
# 独立二进制
cargo run -p scanner-asset -- -r / -t host -o ./scan-out
cargo run -p scanner-asset -- -r /mnt/image -t all -o ./scan-out

# 采集项目本地语言包（venv / node_modules），--project-root 可重复
cargo run -p scanner-asset -- -r / -t packages --project-root srv/app --project-root opt/svc -o ./scan-out

# 经 scanner-cli（需 --asset-out）
cargo run -p scanner-cli -- -r / -t all --asset-out ./scan-out
```

> **语言包项目根**：packages 采集会在 `--root` 下自动发现项目目录（深度上限 10）——
> 遇到 `package.json`（跳过 `node_modules` 内）、`pyproject.toml` 或 `requirements.txt`
> 时把其所在目录当作 project-root。`--project-root` 可额外指定目录（可重复），与自动发现合并去重。
> 仅影响 Python/npm；OS 包（dpkg/apk/rpm）不受影响。递归扫描 venv / `node_modules` 有深度上限。

### CycloneDX SBOM（`-t sbom`）

输出标准 [CycloneDX](https://cyclonedx.org/) 1.6 JSON，每个 dpkg 包一个
`library` 组件并带 Package URL（`purl`，形如
`pkg:deb/<distro>/<name>@<version>?arch=<arch>&distro=<id>-<version_id>`）。
该文件可直接交给 trivy 做 CVE 检测（漏洞匹配依赖 `purl`）：

```bash
cargo run -p scanner-asset -- -r / -t sbom -o ./scan-out
trivy sbom ./scan-out/sbom.cyclonedx.json
```

> 设计取向：scanner 只产出 SBOM 清单，CVE 检测集中在 form 侧（中心一份漏洞库、
> 可对历史清单回溯匹配）；详见仓库根 `trivy/` 与 form 的检测模块规划。

## 病毒查杀（scanner-malware）

基于 ClamAV 的 `clamd` 守护进程：遍历挂载目录下的文件，逐个以 `INSTREAM`
协议（长度前缀分块 + 零长度终止）流式传给 `clamd`，命中的文件映射为
`Vulnerability`（`severity = critical`、`source = "clamav"`、`vuln_id` 为签名名、
`evidence` 含文件路径）。无需 `libclamav` 链接，只需一个可达的 `clamd`。

前置：目标主机已安装并运行 ClamAV，签名库已 `freshclam` 更新。

`clamd` 地址按以下顺序自动探测，可用参数 / 环境变量覆盖：
`CLAMD_SOCKET` → `CLAMD_HOST` → 常见 Unix socket（`/run/clamav/clamd.ctl` 等）
→ TCP `127.0.0.1:3310`。

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `--root` / `-r` | `/` | 扫描挂载目录 |
| `--path` / `-p` | 整个 root | 限定子路径（可多次；相对 root 或绝对路径） |
| `--clamd-socket` | 自动探测 | `clamd` Unix socket 路径 |
| `--clamd-host` | 自动探测 | `clamd` TCP `host[:port]` |
| `--max-file-size` | 32 MiB | 超过则跳过（受限于 `clamd` 的 `StreamMaxLength`） |
| `--include-pseudo-fs` | 关 | 默认跳过 `proc`/`sys`/`dev`/`run` |
| `--output` / `-o` | `.` | 写出 `malware.json`（`Vulnerability[]`） |

```bash
# 独立二进制：扫描 /home 与 /tmp，结果写入 ./scan-out/malware.json
cargo run -p scanner-malware -- -r / -p home -p tmp -o ./scan-out

# 指定远端 clamd（TCP）
cargo run -p scanner-malware -- -r /mnt/image --clamd-host 10.0.0.5:3310 -o ./scan-out

# 经 scanner-cli 纳入合并报告（命中进入 AssetReport.vulnerabilities）
cargo run -p scanner-cli --features full -- -r / --pretty
```

## 合并 AssetReport（scanner-cli）

```bash
cargo run -p scanner-cli -- -r / --pretty              # 完整报告 → stdout
cargo run -p scanner-cli -- -r /mnt/image --out report.json
```

## 远端扫描（scanner-remote，agent 模式）

通过 SSH 把静态编译的 `scanner-asset` 投放到目标主机、就地扫描、回传 JSON，
完成后清理。目标主机只需 SSH 可达 + 一个可写目录，无需快照 / NBD / 内核模块。
首次给一次密码自动装公钥，之后免密。

```bash
# 先一次性编出静态二进制（纯 Rust，无需 musl-gcc）
rustup target add x86_64-unknown-linux-musl
cargo build -p scanner-asset --target x86_64-unknown-linux-musl --release

# 首次：提供密码（装公钥后丢弃），之后免密
SCDR_SSH_PASSWORD='...' cargo run -p scanner-remote -- \
    --ssh-host root@10.22.0.243 \
    --target all \
    --output ./reports/10.22.0.243/
```

详细要求与兼容性说明见
[`crates/scanner-remote/README.md`](crates/scanner-remote/README.md)。

## 构建 & 测试

```bash
cd scanner
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

## 数据契约

- Rust 类型：`scanner-contract`
- 完整报告校验：`scanner-runtime` / `scanner-core` 集成测试
- 分文件 JSON 使用同一契约类型序列化（`packages.json` 为 `Asset[]`）
