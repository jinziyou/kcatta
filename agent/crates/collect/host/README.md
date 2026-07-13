# agent-collect-host

kcatta 的 **collect/host** 能力：核心 lib 按信息来源读取主机事实，`agent-collect-host` CLI
负责组合 collect、可选 detect 与输出。wire 仍为 `AssetReport`；现有 CLI 参数不变。查毒引擎在
[`agent-detect-malware`](../../detect/malware/)，host 检测编排归
[`agent-detect::host`](../../detect/src/host.rs)；respond on-access 直接依赖 detect，不经本 crate。

边界：核心 collect 只产资产侧事实；malware / posture / secrets 由 `agent_detect::host::detect`
另步产生 finding。`DetectOpts` / `run_detect_at` / `run_scan_with_detect` 是保留给现有调用方的
兼容组合 façade，因此本 Cargo package 仍依赖 detect；这不表示检测逻辑属于信息来源。
CVE 与跨源关联在 **analyzer**；OSV `ecosystem` 标签喂给 analyzer。

## Source 模型（零到多结果）

`Source::collect(&mut ScanContext) -> anyhow::Result<Vec<SourceResult>>` 是核心接口：一个来源一次可返回零到多组
结果，当前结果类型为 `Host(HostInfo)` 与 `Assets(Vec<Asset>)`。默认计划
`default_sources()` 只有一个 `FilesystemSource`；它从同一扫描根读取 host、packages、services、
ports、accounts、credentials、containers，并按非空类别发出多个资产批次。`run_scan_at*` 同时接受
`Vec<Box<dyn Source>>` 与 `Vec<Box<dyn Collector>>`，按来源与结果顺序将批次折叠为一个
`AssetReport`。聚合计划必须先发出且只能发出一个 `Host`：`Host` 前的 `Assets` 和第二个 `Host`
都会被拒绝。

旧 `Collector::collect(...) -> Result<CollectorOutput>` 的单结果签名保留不变，并通过 blanket
adapter 作为单结果 `Source` 执行。`default_collectors()` 也保留原来的七步计划：host、packages、
services、ports、accounts、credentials、containers；`default_sources()` 则采用一个聚合后的
`FilesystemSource`。CLI 是 composition/control plane，不是 `filesystem` 并列的信息来源。

## 输出形态

- **分文件 JSON**（`-o DIR`）：`host.json` / `packages.json` / `sbom.cyclonedx.json` /
  `services.json` / `accounts.json` / `credentials.json`；`--malware` 另写 `malware.json`。
- **合并 `AssetReport`**（不带 `-o`）：stdout（`--pretty`）/ `--report-out FILE`。

## 恶意软件扫描（引擎在 `agent-detect-malware`）

引擎 crate：[`../../detect/malware`](../../detect/malware/)，由 `agent_detect::host::DetectOptions`
编排（`--malware` / `agentd run`）；旧 `DetectOpts` 名称仅为兼容别名。无 ClamAV、无外部守护进程：
每个文件读入（限大小）→ SHA-256 + 字节子串匹配 `SignatureSet`。内置 EICAR；额外签名经
`--malware-signatures` 加载。命中映射为 `Vulnerability`（`source = "kcatta-malware"`）。

## 主机 posture 检测（默认开）

引擎：`agent_detect::posture`。读 `sshd_config` / `/etc/shadow` / SUID-SGID，产
`source="posture"` 的 `Vulnerability`（锚 `host_id`）。**仅 host 扫描**（`--image` 排除）；
`--no-posture` 关闭。

## Secret 泄露检测（`--secrets` opt-in）

引擎：`agent_detect::secrets`。遍历找泄露机密；产 `source="secret"` 的 `Vulnerability`。
明文 secret 不离开主机。**仅 host 扫描**；opt-in。

## 命令

```bash
cargo run -p agent-collect-host -- -r / --pretty                                # 合并 AssetReport
cargo run -p agent-collect-host -- -r / -t all -o ./scan-out                    # 分文件 JSON
cargo run -p agent-collect-host -- -r / --malware --pretty                      # 含内置查毒
cargo run -p agent-collect-host -- -r / --malware --malware-signatures sigs.json --pretty
cargo run -p agent-collect-host -- --image img.tar -t all --pretty             # 扫描容器镜像（静态）
# 独立 bin 只产出文件、不上报；上报用统一 agent：
# cargo run -p agentd -- collect-host -r / --upload https://agents.example:10443  # 生产需 FORM_AGENT_CERT/KEY/CA
```

见 [`../../../docs/ARCHITECTURE.md`](../../../docs/ARCHITECTURE.md)。
