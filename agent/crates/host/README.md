# posture-host

posture 的**主机静态文件检测**能力：一个 crate = lib（主机检测 + 内置查毒，被 guard 的
on-access 复用）+ `posture-host` 二进制。产出 `AssetReport`。

边界：**只采集**。CVE 判定与跨源关联在 **fusion** 侧；OSV `ecosystem` 标签即为喂给 fusion 的输入。

## 输出形态

- **分文件 JSON**（`-o DIR`）：`host.json` / `packages.json` / `sbom.cyclonedx.json` /
  `services.json` / `accounts.json` / `credentials.json`；`--malware` 另写 `malware.json`。
- **合并 `AssetReport`**（不带 `-o`）：stdout（`--pretty`）/ `--report-out FILE` / `--upload URL`。

## 内置恶意软件引擎（`malware` 模块）

无 ClamAV、无外部守护进程：每个文件读入（限大小）→ SHA-256 + 字节子串匹配 `SignatureSet`
（`Sha256` 与 `Bytes` 两类规则）。内置 EICAR 测试签名，额外签名经 `--malware-signatures`
（JSON `{sha256:[{name,hex}], bytes:[{name,hex_pattern}]}`）加载。命中映射为
`Vulnerability`（`source = "posture-malware"`，critical）。`scan_bytes()` 供 guard on-access 复用。
**简单可用，后续可扩展**（YARA 风格规则、更大签名库）。

## 命令

```bash
cargo run -p posture-host -- -r / --pretty                                # 合并 AssetReport
cargo run -p posture-host -- -r / -t all -o ./scan-out                    # 分文件 JSON
cargo run -p posture-host -- -r / --malware --pretty                      # 含内置查毒
cargo run -p posture-host -- -r / --malware --malware-signatures sigs.json --pretty
cargo run -p posture-host -- -r / -t all --upload http://127.0.0.1:8000   # 上报 fusion
# 精简静态二进制（不牵 flow/guard）
cargo build -p posture-host --target x86_64-unknown-linux-musl --release
```

旗标：`-r/--root`、`-t/--target {host|packages|sbom|services|accounts|credentials|identity|all}`、
`--project-root`、`--windows-packages {full|apps}`、`--malware`、`--malware-jobs`、
`--malware-signatures PATH`、`--pretty`、`--report-out`、`--upload`。

## Windows 扫描

| 场景 | 命令 | 数据来源 |
| --- | --- | --- |
| WSL/Linux 挂载 Windows 盘 | `posture-host -r /mnt/c -t all -o ./win-out` | 离线 hive（`config/{SOFTWARE,SYSTEM,SAM}`） |
| Windows 本机 | `posture-host -t all -o ./scan-out` | 默认 `%SystemDrive%\`，live HKLM |
| 磁盘镜像挂载 | `posture-host -r /path/to/mount -t all -o ./out` | 离线 hive |

```bash
cargo build -p posture-host --target x86_64-pc-windows-msvc --release
```

> 跨机投放 / 调用 / 取回由 fusion 的 `fusion-scan`（Python）负责（投放 `posture-host`，调用其单命令）。

契约校验：[`tests/contract.rs`](tests/contract.rs)（`AssetReport`）。
