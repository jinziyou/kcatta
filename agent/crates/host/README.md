# agent-host

kcatta 的**主机静态文件检测**能力：一个 crate = lib（主机检测 + 内置查毒，被 guard 的
on-access 复用）+ `agent-host` 二进制。产出 `AssetReport`。

边界：**只采集**。CVE 判定与跨源关联在 **analyzer** 侧；OSV `ecosystem` 标签即为喂给 analyzer 的输入。

## 输出形态

- **分文件 JSON**（`-o DIR`）：`host.json` / `packages.json` / `sbom.cyclonedx.json` /
  `services.json` / `accounts.json` / `credentials.json`；`--malware` 另写 `malware.json`。
- **合并 `AssetReport`**（不带 `-o`）：stdout（`--pretty`）/ `--report-out FILE`。

## 内置恶意软件引擎（`malware` 模块）

无 ClamAV、无外部守护进程：每个文件读入（限大小）→ SHA-256 + 字节子串匹配 `SignatureSet`
（`Sha256` 与 `Bytes` 两类规则）。内置 EICAR 测试签名，额外签名经 `--malware-signatures`
（JSON `{sha256:[{name,hex}], bytes:[{name,hex_pattern}]}`）加载。命中映射为
`Vulnerability`（`source = "kcatta-malware"`，critical）。`scan_bytes()` 供 guard on-access 复用。
**简单可用，后续可扩展**（YARA 风格规则、更大签名库）。

## 主机 posture 检测（`PostureCollector`，默认开）

读 `sshd_config` / `/etc/shadow` / SUID-SGID 二进制,把 misconfig 产为 `source="posture"`
的 `Vulnerability`（host 级,锚 `host_id`；非新 Asset,直接复用关联/去重/告警链）。**刻意低误报**：
仅显式风险值（缺省安全的现代默认从不报）。规则：sshd `PermitRootLogin yes`(high)/`PermitEmptyPasswords yes`(crit)/
加性 MD5 `MACs`(med)、shadow 空密码(crit/med 按可达性)/MD5·DES 弱哈希(med)、SUID 世界可写(crit)/GTFOBins 类(high)。
sshd 解析遵循 **first-occurrence-wins + `Match` 作用域 + `Include`/drop-in 展平**。空库/不可读文件静默零结果。
**仅 host 扫描跑**（`--image`/nested 容器结构性排除,以免误归属到宿主）；`--no-posture` 关闭。

## Secret 泄露检测（`SecretsCollector`，`--secrets` opt-in）

遍历文件系统找泄露的机密:明文私钥(PEM)、AWS access key(AKIA/ASIA + 邻近 secret)、
GitHub/Slack/Stripe-live token、keystore 文件(.p12/.pfx/.jks 按名零读取)、已知凭据文件
(.aws/credentials、.npmrc、.git-credentials、.pypirc)。产 `source="secret"` 的 `Vulnerability`。
**确定性低误报、无 regex（aho-corasick 锚定前缀 + 手写校验，无 ReDoS）**:仅高置信结构化机密,
已砍高熵/JWT/连接串/`.env`/公开类 key;docs/tests/example/占位符路径与文件名排除。
**铁律——明文 secret 绝不离开主机**:上传字段(`vuln_id`/`evidence`)只含类型、相对路径、行号、
不可逆指纹(sha256 截断)或掩码(`AKIA****<last4>`)。复用 malware 的 walk(skip_dirs/媒体/二进制嗅探,
≤1 MiB)。**仅 host 扫描跑**（`--image`/nested 排除）;opt-in（成本/隐私敏感）。

## 命令

```bash
cargo run -p agent-host -- -r / --pretty                                # 合并 AssetReport
cargo run -p agent-host -- -r / -t all -o ./scan-out                    # 分文件 JSON
cargo run -p agent-host -- -r / --malware --pretty                      # 含内置查毒
cargo run -p agent-host -- -r / --malware --malware-signatures sigs.json --pretty
cargo run -p agent-host -- --image img.tar -t all --pretty             # 扫描容器镜像（静态）
# 独立 bin 只产出文件、不上报；上报用统一 agent：
cargo run -p agentd -- host -r / -t all --upload http://127.0.0.1:10068   # 上报 analyzer
# 精简静态二进制（不牵 trace/guard）
cargo build -p agent-host --target x86_64-unknown-linux-musl --release
```

旗标：`-r/--root`、`--image ARCHIVE`、`-t/--target {host|packages|sbom|services|accounts|credentials|identity|all}`、
`--project-root`、`--windows-packages {full|apps}`、`--malware`、`--malware-jobs`、
`--malware-signatures PATH`、`--no-posture`（关闭主机 posture 检测）、`--secrets`（开启 secret 泄露扫描）、`--pretty`、`--report-out`；容器/镜像相关：`--no-container-assets`、
`--no-image-assets`、`--container-asset-targets`、`--max-containers`、`--max-images`、
`--include-stopped-containers`。

## 容器 / 镜像资产「无感知」自动采集

扫描主机时若**检测到容器运行时**（`/var/lib/docker`、`/var/lib/containers`、containerd
快照、k8s manifest 等静态痕迹），自动一并采集容器内与本地镜像的资产——无需任何旗标，
非容器主机上零开销（采集器自然空跑）。两类产物：

- **容器内资产**（nested）：进入每个容器的合并 rootfs，按 `--container-asset-targets`
  采集包/服务/账户/凭据（默认 包+服务），结果 stamp 到所属容器 `asset_id`。
- **本地镜像资产**（`kind=image`）：枚举 Docker `overlay2` / Podman `overlay` 存储里的镜像
  （含**已拉取但从未运行**的镜像），从磁盘上的层 `diff` 目录静态组装出合并 rootfs（处理
  `.wh.` 与 overlayfs 字符设备 whiteout），采集其软件包并 stamp 到镜像 `asset_id` —— 镜像里的
  漏洞包因此同样进入 analyzer 的 CVE 判定。每张镜像另产出一条 `kind=image` 资产行（名称/标签/运行时/镜像 ID）。

```bash
agent-host -r / -t host --pretty                 # 默认即自动采集容器 + 镜像资产
agent-host -r / --no-container-assets --pretty   # 关闭容器/镜像采集
agent-host -r / --no-image-assets --pretty       # 只扫容器内资产，不枚举镜像
agent-host -r / --max-images 8 --pretty          # 限制每次组装/扫描的镜像数（默认 32）
```

镜像层目录读取经 `resolve_under_root` 路径规范化，恶意存储树无法越权读出扫描根之外；
组装时上层目录覆盖下层 symlink，避免被构造的软链接重定向写出 rootfs。
containerd **镜像**枚举因元数据在 boltdb 暂不支持（containerd **容器**仍由 nested 覆盖）。

## 容器镜像扫描（`--image`，基于静态文件）

`--image <ARCHIVE>` 直接解析一个 `docker save` / OCI 镜像归档（`.tar`，可 gzip），把各层按
`manifest.json` 的 `Layers` 顺序叠加、处理 OCI whiteout（`.wh.<name>` 删除、`.wh..wh..opq`
清空目录）组装出**合并 rootfs**，再走与 `--root` 完全相同的采集器——**全程不运行容器**，纯静态文件采集。

```bash
docker save alpine:latest -o alpine.tar
agent-host --image alpine.tar -t all --pretty        # apk 包 / 账户 / 服务 / 凭据…
```

层内路径经规范化（剥离 `..`、绝对前缀），恶意层无法越权写出 rootfs 之外。`--image` 与 `-r/--root` 互斥。

## Windows 扫描

| 场景 | 命令 | 数据来源 |
| --- | --- | --- |
| WSL/Linux 挂载 Windows 盘 | `agent-host -r /mnt/c -t all -o ./win-out` | 离线 hive（`config/{SOFTWARE,SYSTEM,SAM}`） |
| Windows 本机 | `agent-host -t all -o ./scan-out` | 默认 `%SystemDrive%\`，live HKLM |
| 磁盘镜像挂载 | `agent-host -r /path/to/mount -t all -o ./out` | 离线 hive |

```bash
cargo build -p agent-host --target x86_64-pc-windows-msvc --release
```

> 跨机投放 / 调用 / 取回由 analyzer 的 `analyzer-scan`（Python）负责（投放 `agent-host`，调用其单命令）。

契约校验：[`tests/contract.rs`](tests/contract.rs)（`AssetReport`）。
