# fusion-host

**全部主机检测**（纯库）。读取一个**挂载目录**（磁盘镜像、chroot、`/` 或 Windows 卷），
产出分文件 JSON 或并入 [`AssetReport`](../contract/src/lib.rs)。本 crate 同时拥有**主机域调度抽象**——
[`Collector`](src/collector.rs) trait、`ScanContext`、`CollectorOutput`、`run_scan`/`run_scan_at*`——
由 `fusion` 编排二进制（`fusion-runtime`）驱动。可选地（`malware` feature）携带 ClamAV `INSTREAM` 查杀。

边界：fusion-host **只采集**。CVE 判定与跨源关联在 **form** 侧；OSV `ecosystem` 标签即为喂给 form 的输入。

仅依赖 [`fusion-contract`](../contract)（DAG 单向无环）。

## 两种使用方式

| 模式 | API | 产物 |
| --- | --- | --- |
| 分文件 JSON | [`run_static_scan`](src/scan.rs) | `host.json`、`packages.json`、`sbom.cyclonedx.json`、`services.json`、`accounts.json`、`credentials.json` |
| 合并报告 | `default_collectors` + [`run_scan_at`](src/scan_runner.rs) | 合并的 [`AssetReport`](../contract/src/lib.rs) |

```rust
use fusion_host::{default_collectors, run_scan_at, run_static_scan, ScanOptions, ScanTarget};

// 1) 静态分文件扫描
run_static_scan(&ScanOptions { root, target, project_roots, windows_packages: Default::default() }, &output_dir)?;

// 2) 合并 AssetReport（fusion-runtime 走此路径）
let plan = default_collectors();          // host → packages → services → accounts → credentials
let report = run_scan_at(&plan, &root)?;
```

启用 `malware` feature 后，把 [`MalwareCollector`](src/malware/mod.rs) **追加在包采集之后**加入计划，
即可在合并报告中并入 ClamAV 查杀结果（落到 `vulnerabilities`）。

## CLI（`fusion host` 子命令）

本 crate 不含独立二进制；唯一二进制 `fusion` 来自 [`fusion-runtime`](../runtime)。

```bash
# Linux：合并 AssetReport 到 stdout
cargo run -p fusion-runtime -- host -r / --pretty

# 分文件 JSON
cargo run -p fusion-runtime -- host -r / -t all -o ./scan-out

# 含 ClamAV
cargo run -p fusion-runtime --features full -- host -r / --malware --pretty

# 扫描并上报到 form
cargo run -p fusion-runtime -- host -r / -t all --upload http://127.0.0.1:8000

# Windows 盘（WSL 挂载）
cargo run -p fusion-runtime -- host -r /mnt/c -t all -o ./win-out
```

`-t` 目标 → 分文件模式下的输出：

| `-t` 目标 | 输出 |
| --- | --- |
| `host` | `host.json` |
| `packages` | `packages.json` |
| `sbom` | `sbom.cyclonedx.json` |
| `services` / `accounts` / `credentials` | 对应 JSON |
| `identity` | 上述三个 |
| `all` | 全部 |

`--malware`：合并模式 → 并入 `vulnerabilities`；分文件模式 → 另写 `malware.json`。
其余旗标见根文档「主机域」一节。

## 内部分层

```
src/
├── lib.rs              # 公开 API 汇出 + default_collectors()
├── collector.rs        # Collector trait、ScanContext、CollectorOutput、WindowsPackageProfile
├── scan_runner.rs      # run_scan / run_scan_at* —— 组装 collector 计划 → AssetReport
├── scan.rs             # run_static_scan API（ScanOptions / ScanTarget / ScanOutput）
├── collectors/         # 语义层 Collector facade（按 OS 分派并合并输出）
│   ├── host.rs, services.rs, accounts.rs, credentials.rs, mod.rs
│   └── packages/        # PackagesCollector facade（编排 sources/packages + walk）
├── sources/            # 固定路径采集（FHS 文件、包数据库）
│   ├── host.rs, services.rs, accounts.rs, credentials.rs, mod.rs
│   └── packages/       # dpkg, apk, rpm, pypi, npm
├── walk/               # 有界目录遍历 + pattern handler（PyPI / npm / SSH home）
│   ├── engine.rs, policy.rs, markers.rs, registry.rs, mod.rs
├── platform/           # OS 检测（mod.rs: detect / OsFamily）
│   └── windows/         # Windows 注册表 hive / live HKLM 后端（host/packages/services/accounts/registry/…）
├── sbom.rs             # CycloneDX 1.6 导出
├── root.rs             # scan_root 路径辅助
└── malware/            # feature `malware`：ClamAV INSTREAM 查杀（MalwareCollector）
    ├── clamav.rs, scan.rs, mod.rs
```

## 软件包生态

| 来源 | OSV ecosystem 示例 |
| --- | --- |
| dpkg | `Debian:12`、`Ubuntu:22.04` |
| apk | `Alpine:v3.18` |
| rpm | `Rocky Linux:9` |
| PyPI / npm | `PyPI` / `npm` |
| WinGet / CBS / Uninstall / AppX / Chocolatey | `Windows:10` / `Windows:11` |

## features

| feature | 默认 | 作用 |
| --- | --- | --- |
| `malware` | 否 | 编译 `malware/` 模块，启用 ClamAV `INSTREAM` 查杀（`MalwareCollector`），无需额外第三方 crate |

## 契约校验

- [`tests/contract.rs`](tests/contract.rs) —— 产出对 `AssetReport` schema 的校验。

详细参数见 [根文档](../../README.md) 的「主机域」一节，整体架构见 [`docs/ARCHITECTURE.md`](../../docs/ARCHITECTURE.md)。
