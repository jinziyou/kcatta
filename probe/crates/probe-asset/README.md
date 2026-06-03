# probe-asset

**静态文件系统**资产发现：对挂载目录（磁盘镜像、chroot 或 `/`）读取 `etc/`、`var/lib/dpkg/status` 等，产出分文件 JSON 或通过 `Collector` 接口并入 `AssetReport`。

## 二进制

```bash
cargo run -p probe-asset -- -r / -t all -o ./scan-out
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
use probe_asset::{default_collectors, run_static_scan, ScanOptions, ScanTarget};

// Collector 计划（供 probe-runtime）
let plan = default_collectors();

// 静态分文件扫描
run_static_scan(&ScanOptions { root, target, project_roots }, &output_dir)?;
```

## 目录结构

```
src/
├── collectors/       # Host / Packages / Services / Accounts / Credentials
│   └── packages/     # dpkg, apk, rpm, pypi, npm
├── discover.rs       # 自动发现 project-root（package.json 等）
├── sbom.rs           # CycloneDX 1.6 导出
├── scan.rs           # run_static_scan API
└── root.rs           # scan_root 路径辅助
```

## 软件包生态

| 来源 | OSV ecosystem 示例 |
| --- | --- |
| dpkg | `Debian:12`、`Ubuntu:22.04` |
| apk | `Alpine:v3.18` |
| rpm | `Rocky Linux:9` |
| PyPI / npm | `PyPI` / `npm` |

详细参数见 [`../../README.md`](../../README.md#静态资产扫描probe-asset)。
