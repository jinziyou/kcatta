# scanner

主机端 **资产与风险扫描器**，cyber-posture 平台的内视引擎。基于 Rust 构建。

## 当前状态（v0）

已落地：

- **按功能域拆分的 workspace**：契约 / 调度 / 资产发现 / 漏洞&恶意代码占位 / 上报占位
- **`scanner-asset` 静态文件扫描**：对挂载目录（默认 `/`）读 `etc/`、`var/lib/dpkg/status`、`proc/net/*` 等
- **扫描参数**：`--root` 挂载目录、`--target` 扫描对象（默认 `host`）
- **分资产 JSON 输出**：`host.json`、`packages.json`（不采集端口）
- **`Collector` + `run_scan_at(root)`**：合并为完整 `AssetReport`（`scanner-cli` stdout / `--out`）
- **跨语言契约验证**：对照 `form/schemas-json/AssetReport.schema.json`

尚未落地：

- rpm / apk 等非 dpkg 包管理器
- service / account / credential 采集
- `scanner-vuln` / `scanner-malware` 真实引擎
- `scanner-ingest` HTTP 上报

## 仓库形态

```
scanner/crates/
├── scanner-contract/
├── scanner-runtime/        # ScanContext.scan_root + run_scan_at
├── scanner-asset/          # 静态资产扫描 + 二进制 scanner-asset
├── scanner-vuln|malware|ingest/
├── scanner-core/           # 门面 run_scan() / run_scan_at()
├── scanner-cli/
├── scanner-snapshot-contract/  # 远端快照后端契约 (RemoteExec / SnapshotBackend)
├── scanner-snapshot-lvm/       # LVM 快照后端实现
└── scanner-remote/             # agentless 远端扫描编排 + scanner-remote 二进制
```

## 静态资产扫描（scanner-asset）

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `--root` / `-r` | `/` | 扫描挂载目录（磁盘镜像根、chroot、本机） |
| `--target` / `-t` | `host` | `host` \| `packages` \| `all` |
| `--output` / `-o` | `.` | 写出 JSON 的目录 |

| 扫描对象 | 输出文件 | 数据来源（相对 root） |
| --- | --- | --- |
| `host` | `host.json` | `etc/hostname`, `etc/os-release`, `proc/version` |
| `packages` | `packages.json` | `var/lib/dpkg/status` |
| `all` | 以上两个 | |

```bash
# 独立二进制
cargo run -p scanner-asset -- -r / -t host -o ./scan-out
cargo run -p scanner-asset -- -r /mnt/image -t all -o ./scan-out

# 经 scanner-cli（需 --asset-out）
cargo run -p scanner-cli -- -r / -t all --asset-out ./scan-out
```

## 合并 AssetReport（scanner-cli）

```bash
cargo run -p scanner-cli -- -r / --pretty              # 完整报告 → stdout
cargo run -p scanner-cli -- -r /mnt/image --out report.json
```

## 远端 agentless 扫描（scanner-remote）

通过 SSH 在远端建 LVM 快照、用 `qemu-nbd` 暴露、隧道到扫描端挂载，再调
`scanner-asset`。目标主机无需安装 agent；远端账户用白名单 sudoers。

```bash
cargo run -p scanner-remote -- \
    --ssh-host scdr@10.0.1.23 \
    --ssh-identity ~/.ssh/scdr_ed25519 \
    --lv /dev/vg0/root \
    --freeze-mount / \
    --target all \
    --output ./reports/10.0.1.23/
```

详细要求、sudoers 模板与运维约定见
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
