# fusion-asset

**静态文件系统**资产发现：对挂载目录（磁盘镜像、chroot、`/` 或 Windows 卷）读取 Linux FHS 路径或 Windows 注册表 hive，产出分文件 JSON 或通过 `Collector` 接口并入 `AssetReport`。

## 二进制

```bash
# Linux
cargo run -p fusion-asset -- -r / -t all -o ./scan-out

# Windows 盘（WSL 挂载）
cargo run -p fusion-asset -- -r /mnt/c -t all -o ./win-out
```

| `-t` 目标 | 输出 |
| --- | --- |
| `host` | `host.json` |
| `packages` | `packages.json` |
| `sbom` | `sbom.cyclonedx.json` |
| `services` / `accounts` / `credentials` | 对应 JSON |
| `identity` | 以上三个 |
| `all` | 全部 |

## 库 API

```rust
use fusion_asset::{default_collectors, discover_project_roots, run_static_scan, ScanOptions, ScanTarget};

// Collector 计划（供 fusion-runtime）
let plan = default_collectors();

// 静态分文件扫描
run_static_scan(&ScanOptions { root, target, project_roots }, &output_dir)?;
```

## 目录结构

```
src/
├── collectors/         # 语义层 facade（Collector trait + OS 分派）
├── sources/            # 第 2 类：固定路径采集
│   ├── host.rs, services.rs, accounts.rs, credentials.rs
│   └── packages/       # dpkg, apk, rpm, pypi, npm
├── walk/               # 第 3 类：有界遍历 + pattern registry
│   ├── engine.rs, policy.rs, markers.rs, registry.rs
│   └── handlers/       # pypi, npm, ssh_home
├── platform/           # 第 1 类：OS 检测 + Windows 后端
│   ├── mod.rs
│   └── windows/        # 注册表 hive / HKLM 采集
├── sbom.rs             # CycloneDX 1.6 导出
├── scan.rs             # run_static_scan API
└── root.rs             # scan_root 路径辅助
```

## 软件包生态

| 来源 | OSV ecosystem 示例 |
| --- | --- |
| dpkg | `Debian:12`、`Ubuntu:22.04` |
| apk | `Alpine:v3.18` |
| rpm | `Rocky Linux:9` |
| PyPI / npm | `PyPI` / `npm` |
| WinGet / CBS / Uninstall / AppX / Chocolatey | `Windows:10` / `Windows:11` |

详细参数见 [`../../README.md`](../../README.md#静态资产扫描fusion-asset)。
