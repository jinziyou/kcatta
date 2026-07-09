# agent-collect-host

kcatta 的 **collect/host** 能力：一个 crate = lib（按来源采主机**资产** + detect 编排）+
`agent-collect-host` 二进制。产出 `AssetReport`。查毒引擎在 [`agent-detect-malware`](../../detect/malware/)；
guard on-access 直接依赖该引擎，不经本 crate。

边界：collect 只产资产；malware / posture / secrets 经 `DetectOpts` / `run_detect_at` 另步合并
finding。CVE 与跨源关联在 **analyzer**；OSV `ecosystem` 标签喂给 analyzer。

## 输出形态

- **分文件 JSON**（`-o DIR`）：`host.json` / `packages.json` / `sbom.cyclonedx.json` /
  `services.json` / `accounts.json` / `credentials.json`；`--malware` 另写 `malware.json`。
- **合并 `AssetReport`**（不带 `-o`）：stdout（`--pretty`）/ `--report-out FILE`。

## 恶意软件扫描（引擎在 `agent-detect-malware`）

引擎 crate：[`../../detect/malware`](../../detect/malware/)。本 crate `malware` 模块 re-export
引擎 API；编排走 `DetectOpts.malware`（`--malware` / `agentd run`）。无 ClamAV、无外部守护进程：
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
# cargo run -p agentd -- collect-host -r / --upload http://analyzer:8080
```

见 [`../../../docs/ARCHITECTURE.md`](../../../docs/ARCHITECTURE.md)。
