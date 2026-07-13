# agent 架构

> **权威说明**（P0–P4 已落地）。迁移过程与历史决策见 [`REFACTOR-PIPELINE.md`](./REFACTOR-PIPELINE.md)。

kcatta 的端点组件。逻辑上按 SOC 循环 **Collect → Detect → Respond** 组织，`agentd` 是
composition/control plane；部署上提供 `agent-collect-host` / `agent-collect-trace` /
`agent-respond` 独立二进制。现有 CLI 与 wire envelope 保持不变。

## 流水线四层

| 层 | 目录 | 包名 | 职责 | 禁止 |
| --- | --- | --- | --- | --- |
| **agentd** | `crates/agentd/` | `agentd` | 调度、`run`、spool、**唯一上报**（ingest） | 内嵌采集/检测实现 |
| **collect** | `crates/collect/{host,trace}/` | `agent-collect-host` / `agent-collect-trace` | **按信息来源**读系统 → 资产侧事实 / 未检测观测 | finding / `Vulnerability` / IOC 标注；改系统状态；HTTP 上报 |
| **detect** | `crates/detect/` · `detect/malware/` | `agent-detect` / `agent-detect-malware` | 消费事实 → finding / IOC 标注 / `Detection` | CVE/OSV（属 Python **analyzer**）；处置；上报 |
| **respond** | `crates/respond/` | `agent-respond` | 消费 `Detection` → decide → safety → actions → report | 全量主机扫描实现；绕过 safety；默认 enforce |

底座：`crates/contract`（`agent-contract`）既持有 analyzer-facing wire，也持有非 Serde 的内部
`Detection` 阶段类型。内核支撑：`crates/ebpf`（`agent-ebpf`）。

> **命名**：「analyzer」**仅**指 Python 服务（CVE / 跨源关联 / ingest API）。端上检测层称 **detect**。  
> **处置**：仅 respond（`agent-respond`）可改系统状态；默认 monitor + safety 否决。

```
collect（按来源）──事实──► detect（按引擎）──finding / Detection──► respond（可选）
                              │
                              ▼
                    AssetReport / TraceBatch / GuardEventBatch
                              │
                              ▼
                         agentd ingest ──► Form ──► Python analyzer
```

### collect 原则（锁定）

1. **按信息来源划分** Source（当前：host 的 `FilesystemSource`；trace 的 `NetworkSource` 与
   feature-gated `EbpfSource`）。dpkg/apk 等是 filesystem 内 reader，不是独立来源；CLI 是
   composition/control plane，也不是来源。**不**按 `Asset` 枚举变体拆 crate。
2. **Source 零到多结果**：`Source::collect` 返回 `Result<Vec<SourceResult>>`。成功时一个来源一轮
   可无结果，也可发出多组异构结果；host 为 `Host` / `Assets`，trace 为网络 / 文件 / 进程事件组。
   trace variant 分别折叠到三个 Vec，只保证每个同类 stream 内的 source/result/event 顺序，不定义
   跨 stream 全局顺序。
3. **输出是事实**：主机路径以 `Asset` / `HostInfo` 为准，trace 路径以未 enrich 的观测事件为准；
   **不**在核心 collect 路径写入引擎语义 `Vulnerability` 或 IOC `ThreatMatch`。
4. **编排在控制面**：`collect → detect → 合并 envelope` 由 `agentd` / 能力 CLI 完成，detect
   适配器不应伪装成 Source。

**编排**：host 新路径为 `default_sources` + `run_scan_at*` → `agent_detect::host::detect` → 合并
`vulnerabilities`；`agentd run` 已显式使用该顺序。trace 新路径为 source plan + `capture_sources` →
`agent_detect::ioc::ThreatFeed::enrich`；CLI 与 `agentd run` 同样按显式两步收敛。

`Collector` / `CollectorOutput` / `default_collectors`、host `DetectOpts` / `run_scan_with_detect`，以及
trace `capture_batch` / `enrich_batch` / `run_capture_with_detect` 均保留兼容行为。因 CLI 与 façade
和核心 lib 同 package，Cargo 仍可能存在 collect → detect 依赖；阶段边界以 Source 输出和显式调用
为准，不以 package 是否依赖 detect 推断。

CI 的 `scripts/check-soc-boundaries.sh` 守护三个可机械校验的边界：collect core 不调用 detect、
`Detection` 只在 `agent-contract` 定义且由 detect/respond re-export、`agentd run` 不调用
collect-owned detect 便利 façade。

| 点 | 状态 |
| --- | --- |
| host / trace collect vs detect 两步 | **已落地** |
| Source 零到多结果；filesystem/network/eBPF 按来源 | **已落地** |
| contract 单定义 `Detection`；detect/respond re-export；detector/sensor adapter 产出，pipeline 消费 | **已落地** |
| 过渡 detect `Collector` 适配器 | **已删除** |
| SBOM | 留 host：由包资产派生导出 |
| package / 部署主名切换 | **已完成** |

周期路径：collect（事实）→ detect（finding / 标注）→ 写文件 / 交 agentd 上报（不经 respond）。
实时路径：respond.sensors 读取事实 → detect 窄 API或轻量 adapter 规范化 → decide → actions → report
→（agentd 注入的 durable outbox sink）。network/onaccess 调 detect；FIM/behavior 的部署专用规则仍在
sensor adapter 内，这是实时 composition 的明确例外。

## 部署二进制（能力轴）

| 部署主名 | 目录 / 包 | 视角 / envelope | 模式 |
| --- | --- | --- | --- |
| `agent-collect-host` | `collect/host` · `agent-collect-host` | 内视 → `AssetReport` | 周期 |
| `agent-collect-trace` | `collect/trace` · `agent-collect-trace` | 外视 → `TraceBatch` | 周期 + 持续 |
| `agent-respond` | `respond` · `agent-respond` | 端内 → `GuardEventBatch` | 持续 |
| `agentd` | `agentd` | 编排 + ingest | 单命令 / 长驻 |

跨机投放（`form-scan` / Form worker）与 musl deploy 使用上表主名。`agentd` 子命令主名为 `collect-host` / `collect-trace` / `respond`（兼容别名 `host` / `trace` / `guard`）。

```
  [周期] FilesystemSource ─► host detect ─► AssetReport 文件
  [周期|持续] NetworkSource [+ EbpfSource] ─► IOC detect ─► TraceBatch
  [持续] detect/sensors ─► agent-contract::Detection ─► respond ─► 本地 NDJSON/stdout
                            └──── 独立运行不上报 ────┘
                                              │
            agentd <cap> --upload / agentd run ──► Form ingest ──► Python analyzer
```

## Crate 依赖 DAG（单向无环）

```
agent-contract（wire + Detection）◄── agent-detect-malware ◄── agent-detect（host/ioc/network）
       ▲                    ▲                    ▲
       │                    │                    │
agent-collect-host ─────────┘      agent-collect-trace ──► agent-detect
                                             │
                                             └── ebpf feature ──► agent-ebpf
agent-respond ──► agent-contract；onaccess/network feature ──► agent-detect
                                   network feature ──► agent-collect-trace
agentd ──► collect-host + collect-trace + detect + respond + contract（ingest）

agent-ebpf：共享 POD lib + bin trace-ebpf / guard-ebpf
```

- **领域逻辑在 lib，CLI 在 lib（`pub mod cli`）**：独立 bin 与 `agentd` 共用；bin 为薄壳。
- **Detection 阶段契约**：物理类型只定义在 `agent-contract::Detection`，不实现 Serde、不是 JSON
  wire；`agent-detect` 产出并 re-export，`agent-respond` 消费并 re-export。这样 respond 默认
  fim+behavior 不需链接 detect 引擎，只有 onaccess/network feature 启用可选 `agent-detect`。
- **detect 逻辑**：`agent-detect-malware` 提供签名/哈希；`agent-detect` 提供 host 编排、posture /
  secrets、`ioc::ThreatFeed` 与 `network::detect`（IOC + IDS）。collect 中没有 detect Source，respond
  中没有网络 IDS 规则副本。
- **sbom**：暂留 `collect/host`（`sbom.rs` 直接调用 `collect_packages` / platform distro / deb 源）。拆到 detect 需先抽出包清单纯函数 API，否则 detect→host 环依赖；见 REFACTOR-PIPELINE §后续。
- **trace**：`capture_sources` 只采集；`ThreatFeed::enrich`（detect）另步标注；兼容
  `capture_batch` / `enrich_batch` / `run_capture_with_detect` 保留，`--no-intel` 可跳过 detect。
  `intel::sync` 仍在 collect/trace，但解析结果类型来自 detect。
- **eBPF**：opt-in。`NetworkSource` 的 eBPF network 后端失败时仅在 pcap feature 存在时回退
  真实 pcap，否则返回错误（不回退 synthetic mock）；独立文件/进程 `EbpfSource` 失败会返回
  本轮错误（fallback 需移除该 Source）；respond netblock 失败回退 nft。
- **包名 / 部署 bin**：`agent-collect-host` / `agent-collect-trace` / `agent-respond` / `agentd`（Makefile musl + Form 投放）。

## 三种运行方式

1. **独立二进制**：`agent-collect-host` / `agent-collect-trace` / `agent-respond` 各自构建部署（按 feature 裁剪）。
2. **统一 `agentd`**：子命令 `collect-host`/`collect-trace`/`respond`（保留短别名）+
   `agentd run` 编排守护；`--upload` 才上报。
3. **Form 调度**：`form-scan --capability {host|trace|guard}` 或 Form worker 经 SSH/WinRM 投放。

---

# 主机静态文件检测（agent-collect-host · 内视 · 周期性）

## agent-collect-host 命令

```
agent-collect-host [-r ROOT] [-t TARGET] [输出旗标] [--malware ...]
```

| 旗标 | 说明 |
| --- | --- |
| `-r` / `--root` | 挂载根或本机 `/`（`scan_root`） |
| `-t` / `--target` | `host` / `packages` / `sbom` / `services` / `accounts` / `credentials` / `containers` / `identity` / `all` |
| `--malware` / `--malware-jobs` / `--malware-signatures PATH` | 内置签名查毒 + 并发 + 额外签名 |
| `-o DIR` / `--pretty` / `--report-out FILE` | 输出 |

输出两种形态：**分文件 JSON**（`-o DIR`：`host.json` / `packages.json` / … ，`--malware` 另写 `malware.json`）与**合并 `AssetReport`**（不带 `-o`：stdout / `--report-out`）。

## Source 模型

`agent-collect-host` 的核心 lib：`Source` 共享 `ScanContext`，每轮返回零到多
`SourceResult::{Host,Assets}`，`run_scan_at*` 展平为资产侧 `AssetReport`。默认
`FilesystemSource` 从同一扫描根发出 host 与 packages/services/ports/accounts/credentials/
containers（+ 可选 nested/images）多个非空批次。

新组合代码随后调用 `agent_detect::host::detect` 写入 `vulnerabilities`（`--malware` / 默认 posture /
`--secrets`）。旧 `Collector` 名、`DetectOpts` / `run_detect_at` / `run_scan_with_detect` 仍兼容。

内部分层：`sources/filesystem`（信息来源）· `collectors/`（旧类别 façade / reader 组装）·
`detect_phase`（兼容别名）· `walk/` · `platform/`。

## 恶意软件引擎（`agent-detect-malware`）

引擎在 `crates/detect/malware`（P0 已抽出）。替代 ClamAV：无外部守护进程。每个文件读入（限 `DEFAULT_MAX_FILE_SIZE`）→ SHA-256 + 字节子串匹配 `SignatureSet`。内置 EICAR；额外签名经 `--malware-signatures` 加载。命中映射为 `Vulnerability`（`source = "kcatta-malware"`）。`scan_bytes` 供 guard on-access 与 host detect phase 复用。

---

# 追踪：网络 + 文件 + 进程（agent-collect-trace · 外视 · 周期 + 持续）

`agent-collect-trace` 的来源计划以 `NetworkSource` 为基线；其 `CaptureConfig` 可选择 mock、pcap、
eBPF cgroup-skb network 或 winnet 连接表（Windows IP Helper / Linux `/proc`）。`ebpf` feature 还可
叠加独立 `EbpfSource`（内核态文件操作与进程调用）。一个 Source 可返回零到多
`SourceResult::{NetworkEvents,FileEvents,ProcessEvents}`；`capture_sources` 按顺序折叠到
`TraceBatch.events` / `file_events` / `process_events`；顺序保证限于各同类 Vec。Source/capture core
不含 HTTP，`cli::intel-sync` 使用 reqwest 下载 feed。

两个子命令：

- `capture`：source plan → `capture_sources` → 可选 `ThreatFeed::enrich` → `TraceBatch`（写
  stdout / `-o`）。mock 缺省使用 demo feed；live 后端只在显式 `--intel` 时 enrich。
  **无 `--upload`**——上报经 `agentd collect-trace --upload`
  或 `agentd run`。
- `intel-sync`：下载 IOC feed → 本地 JSON。旗标 `--source NAME`（必填，可重复；`feodo`|`sslbl`|`threatfox`）/ `-o` / `--feodo-url` / `--sslbl-url` / `--threatfox-url` / `--timeout`。`feodo`=IP C2、`sslbl`=JA3 指纹、`threatfox`=域名+ip:port；多 source 按 `(type,value)` 去重合并。下载在 `http_get_text` 单点封顶 64 MiB 防恶意源 OOM。

## 网络后端 + IOC 富化

捕获：`NetworkSource` / `EbpfSource` → `capture_sources` 产出未 enrich 事实；`capture_batch` 是单
`NetworkSource` 兼容便利入口。
富化：`agent_detect::ioc::ThreatFeed::enrich`（IP / 域名父域 / JA3）；根级 `ThreatFeed` re-export
与 `enrich_batch` 为兼容 façade。
编排：CLI / `agentd run` / respond network 显式 collect → detect；`run_capture_with_detect` 保留。
`--no-intel` 跳过 enrich。
Source/capture core **不含 reqwest**；`intel-sync` 的 HTTP 下载在同 package 的 `cli`，feed 字节
解析在 `intel::sync`（产出 `FeedIndicator` → `ThreatFeed`）。

## eBPF 追踪后端（feature `ebpf` · 特权）

启用 `ebpf` feature 后，`capture --ebpf` 加载 `trace-ebpf` 的进程 exec/exit 与文件
open/unlink/rename tracepoints（后两类 best-effort），把 `ExecEvent` / `ExitEvent` / `FileEvent` 经
`EVENTS` ring buffer 排空到 `TraceBatch.file_events` / `process_events`。`--ebpf-duration N`
控制采样窗口；`--net-ebpf` 则使用同一内核对象的 cgroup-skb network 程序产生 `NetEvent`。

运行期需 **CAP_BPF/root + 带 BTF 的内核**。显式加入文件/进程 `EbpfSource` 后，加载失败会令本轮
`capture_sources` 返回错误，不会保留前面已采的 network batch；要运行 network-only 计划需省略
`--ebpf`。另一个 `--net-ebpf` 选择的是 `NetworkSource` 的 cgroup-skb 后端，失败时只在编入
pcap 时回退真实 pcap；否则本轮返回错误，绝不产生 synthetic mock。

---

# 实时防护（agent-respond · 端内 · 持续）

长驻守护进程，agent 中唯一允许改变系统状态的能力：**实时检测 → 决策 → 处置 → 上报**。

## 流水线

```
detect/sensor ──agent-contract::Detection──► decide ──Action──► respond(+safety+ledger) ──► report ──GuardEventBatch──► Form / 本地 NDJSON
 (N 线程)              (policy)           (可逆隔离/网络阻断/kill/...)    (批量+定时+critical 立即)
```

- `Detection` 是 `agent-contract` 的非 wire 内部阶段类型，detect/respond re-export；detector 或
  实时 sensor adapter 产出，response pipeline 消费。每个传感器一个长驻线程，向
  `std::sync::mpsc` 通道推送 `SensorEvent` 并轮询 `shutdown` 退出。
- **decide**：monitor 恒为 `None`；enforce 下按「单动作开关 ∧ 严重度阈值」选动作。
- **respond**：普通 Action 先过 `safety` 否决，再查幂等 ledger，最后执行；同步 deny-open 在
  fanotify hook 内经过等价 gate/safety 后执行，并以 `pre_applied` 结果进入 pipeline。
- **report**：`Detection` + 结果 → 契约 `GuardEvent`，按 `batch_max` / `flush_secs` 聚为 `GuardEventBatch`，critical 立即 flush；sink 含 analyzer 上报 + 本地 NDJSON 审计 + stdout。
- 优雅停机：Linux 用 `signalfd`、Windows 用安全的 `ctrlc` wrapper 置 `shutdown`；Supervisor
  最多 500ms 检查 token，传感器退出后最终 drain/report（Linux fanotify 标记随 fd 关闭移除）。

## 机制（按平台 / feature gated）

| Feature | 默认 | 实现 | 产出 |
| --- | --- | --- | --- |
| `fim` | ✓ | Linux inotify；Windows `notify`/ReadDirectoryChangesW；SHA-256 | `FileIntegrityEvent` |
| `behavior` | ✓ | `/proc` 轮询规则（exe-deleted-running、shell→网络工具） | `ProcessEvent` |
| `onaccess` | | fanotify + `agent_detect::malware::scan_bytes`（经 `/proc/self/fd/N`，错误 fail-open） | `MalwareEvent` |
| `network` / `ids` | | trace capture → `agent_detect::network::detect`（IOC enrich + 轻量 IDS） | `NetworkEvent` / `IdsEvent` |

## 主动处置与安全

默认 `mode = monitor` + 各动作开关全关。deny-open / quarantine / netblock / kill 仅当
`enforce ∧ 开关开 ∧ 严重度≥阈值 ∧ 安全不否决` 时触发：

- **阻断打开**（on-access `FAN_DENY`）、**可逆隔离**（移入 vault + `chmod 000` + manifest，
  **永不删除**）、**网络阻断**、**kill**（仅搭骨架、默认关闭）。
- **网络阻断后端**：默认 `nft` drop；启用 `ebpf` feature 时改用内核 **cgroup connect4/6 阻断器**（`agent-ebpf`（`crates/ebpf`）的 `guard-ebpf` bin `guard_connect4` / `guard_connect6`，从 `BLOCKED_V4` / `BLOCKED_V6` map 拒绝目的 IP），加载/挂载出错则自动回退到 `nft`。该路径**不需要 CONFIG_BPF_LSM**（是 cgroup-connect 而非 LSM），运行期需 CAP_BPF/root + cgroup-v2。
- **安全否决**（`respond/safety`）：关键路径 / 系统前缀 ELF / 运行中-mmap 文件 / vault 自身 /
  PID 1 / 自身 / 回环地址全部拒绝；普通 responder Action 再由**幂等 ledger** 防抖动。
- on-access 只有 `mode=enforce ∧ response.allow_block_open`（默认 `false`）时订阅权限事件；签名
  命中后再过 severity threshold 与文件 safety veto。错误、空/超大、未授权或否决均
  **fail-open**（`FAN_ALLOW`）；`FAN_DENY` 写失败立即尝试 allow。同步动作通过
  `SensorEvent.pre_applied` 上报 `BlockedOpen/Success|Failure`，pipeline 不会二次 quarantine。

Linux syscall（fanotify / inotify / signalfd / kill）走安全的 `nix` 封装；Windows FIM / shutdown
分别走安全的 `notify` / `ctrlc` wrapper，满足工作区 `unsafe_code = "deny"`。

## 配置（JSON，缺省即安全默认）

`--config /etc/kcatta/guard.json`（缺失则用默认）。字段：`mode`、`host_id`、各传感器开关与路径（`onaccess.signatures` 加载额外查毒签名）、`response`（`allow_block_open`/`allow_quarantine`/`allow_netblock`、`severity_threshold`、`critical_paths`、`vault_dir`）、`report`（`audit_log`/`audit_max_bytes`/`stdout`/`batch_max`/`flush_secs`）。所有动作 gate 默认关；旧 JSON 缺 `allow_block_open` 时仍解析为 `false`。CLI `--detect-only` / `--stdout` 覆盖配置（`--upload` 仅存在于 `agentd respond`，由 agent 注入 Form sink）。

本地 NDJSON 审计默认上限 64 MiB。Unix 要求父目录/日志分别为 effective-UID owner 的 `0700`/
`0600`，拒绝 symlink、额外 hardlink、group/world 可写对象及不可信祖先，并以 `O_NOFOLLOW` 打开；
旧 `0755`/`0644` 专用目录仅在完整验证后通过 fd 收紧。独占文件锁内执行长度预算检查、原地轮转、
追加与 `sync_data`；达到上限时保留最新完整 batch，且只告警一次。Windows/其它无法验证
owner-only DACL 与 reparse ancestry 的平台不创建本地
审计文件、明确告警；Form/stdout sink 不受影响，无其它 sink 时自动回退 stdout，因此不会阻断默认
启动。

## 跨平台 seam

FIM 与 `Supervisor` 已支持 Linux / Windows：Linux 后端为 inotify + signalfd，Windows 为
ReadDirectoryChangesW（经 `notify`）+ `ctrlc`。behavior / onaccess / network sensors 与 Linux 主动
处置仍按平台 gate；其他平台的 Supervisor 返回不支持。未来 ETW / minifilter / WFP 可复用同一
Detection / Respond 流水线与 wire。

---

# eBPF 构建（build.rs + bpf-linker + default-members 排除 + 优雅 stub）

eBPF 内核程序与共享类型合并到**一个 crate `agent-ebpf`（`crates/ebpf`）**——一个共享类型 lib（host 编译）+ 两个内核 bin（bpf-target-only）。该 crate 是 workspace **成员但被 `default-members` 排除**（因其 bin 仅在 bpf target 编译）——因此宿主侧 `cargo build` / `cargo test` 永远不会编译两个内核 bin（`aya-ebpf` 由 crate 的 `ebpf` feature 门控、bin 的 `required-features = ["ebpf"]` 进一步保证宿主构建不触碰它），普通 CI 与本机开发不受 BPF 工具链牵连；其共享类型 lib 仍随 `agent-collect-trace --features ebpf` 在宿主侧被传递编译。

- **lib `agent_ebpf`（`crates/ebpf`，no_std，Apache-2.0，仅依赖 `bytemuck`）**：内核 ↔ 用户态经 ring buffer 传递的共享 `#[repr(C)]` POD 事件结构（`ExecEvent` / `ExitEvent` / `FileEvent` / `NetEvent`，`bytemuck` Pod）；agent-collect-trace 用户态 loader 经 `ebpf` feature 依赖它（可选）。
- **bin `trace-ebpf`（no_std + no_main，bpf target，GPL-2.0，`required-features = ["ebpf"]`）**：进程/文件 tracepoints 与 cgroup-skb ingress/egress network telemetry，共用 `EVENTS` RingBuf。
- **bin `guard-ebpf`（no_std + no_main，bpf target，GPL-2.0，`required-features = ["ebpf"]`）**：内核 `cgroup_sock_addr` 程序（`guard_connect4` / `guard_connect6`，依 `BLOCKED_V4` / `BLOCKED_V6` 拒绝目的 IP；不用 `agent_ebpf` 共享类型）。

> crate license：`Apache-2.0 AND GPL-2.0`（Apache 的共享类型 lib + GPL 的两个内核 bin）。

两个内核 bin 只由 `agent-collect-trace` / `agent-respond` 的 `build.rs` 在各自 `ebpf` feature 打开时编译：经
`cargo build --package agent-ebpf --bin <trace-ebpf|guard-ebpf> --features ebpf --target bpfel-unknown-none`（nightly + `rust-src` + `bpf-linker`），再以 `include_bytes_aligned!` 内嵌进对应能力 crate。

**构建 stub**：若 nightly 工具链 / bpf-linker 缺失，`build.rs` 产出一个空 stub 对象并打印
warning，使 CI `--all-features` 仍然绿。运行期文件/进程 `EbpfSource` 会报错；eBPF network
backend 仅在编译 pcap 时回退真实 pcap，否则报错；respond netblock 回退 `nft`。

构建期需求：nightly + `rust-src` + `cargo install bpf-linker`。运行期需求：trace 需 CAP_BPF/root + 带 BTF 的内核；guard 需 CAP_BPF/root + cgroup-v2。`ebpf` feature **opt-in**，**不**进 musl 部署构建——部署只发 `agent-collect-host` / `agent-collect-trace` / `agentd`，guard 以 onaccess/network/ids 形态运行。

---

# `agentd run` 编排守护

除 `agentd collect-host|collect-trace|respond` 子命令在进程内分发到各能力 `cli`（并以 `--upload <URL>` POST Form）外，`agentd` 提供端点内编排守护：

```
agentd run --config <json>
```

加载一份 JSON `RunConfig`，按 `interval_secs` 周期：

- host 显式执行 `default_sources/run_scan_at_with_opts`（collect）→
  `agent_detect::host::detect`（detect）→ 合并 `AssetReport`；
- trace 显式执行 source capture（collect）→ 可选的配置文件 `trace.intel` IOC enrich（detect）→
  `TraceBatch`；未配置 feed 时保持 collect-only，绝不套用 demo IOC；两种 envelope 各自上传；
- 若 `guard.enabled`，在后台线程内运行 Respond，持续流式上报 `GuardEventBatch`；它通过
  `Supervisor::run_with_shutdown` 与周期 Collect/Detect 共用一个 shutdown token；
- Respond 提前退出会停止整个 SOC 循环；收到 SIGINT / SIGTERM / Ctrl-C 也置位同一 token；
- Guard batch 先进入 durable FIFO outbox 再异步上传；停机顺序为停止传感器 → final drain/report →
  join Respond/uploader → 有界尝试一个 spool item，其余留待下次启动，避免丢末批或按 backlog 长度卡住；
- 某次周期失败仅记录日志并在下一周期重试，不中断守护。

---

# 共享底座

## 数据契约（agent-contract）

`agent-contract` 零内部依赖，持有三种 analyzer-facing envelope 及一个内部阶段类型：

- 主机：`AssetReport` / `HostInfo` / `Asset` / `Vulnerability`
- 追踪：`TraceBatch`（`events: Vec<TraceEvent>`（网络 5 元组）/ `file_events: Vec<FileTraceEvent>` / `process_events: Vec<ProcessTraceEvent>`）/ `TraceProto` / `FileOp` / `ProcessEventType` / `ThreatMatch` / `IndicatorType`
- 实时防护：`GuardEventBatch` / `GuardEvent`（`Fim` | `Malware` | `Process` | `Network` | `Ids` 内部标签联合）/ `ActionTaken` / `Outcome` / `FimChange`
- provenance：三种 envelope 均带可选 `source_agent_id` / `source_target_id`。Agent
  本地产出时保持缺省并从 JSON 省略；Form 在认证入口覆盖/注入后才形成可信来源绑定，任何
  envelope chunk 都必须原样继承该绑定。
- 三侧共享 `Severity`；guard 与 trace 共享 `IndicatorType`。
- 内部阶段：`Detection`（`crates/contract/src/detection.rs`），不实现 Serde，不属于 Pydantic /
  JSON Schema wire；由 detect/respond re-export。

| 层级 | 路径 |
| --- | --- |
| 权威来源 | `analyzer/src/analyzer/schemas/`（guard 在 `guard_event.py`） |
| 公共 JSON Schema | `form/schemas-json/`（含 `GuardEventBatch.schema.json`） |
| Rust wire 镜像 | `crates/contract/src/{lib.rs, trace.rs, guard.rs}` |
| Rust 内部阶段类型 | `crates/contract/src/detection.rs`（无 Serde / JSON Schema） |
| 校验测试 | `crates/collect/host/tests/contract.rs`、`crates/collect/trace/tests/contract.rs`、`crates/contract/tests/guard_contract.rs` |

新增字段：先改 analyzer Pydantic / Form 控制模型 → `form-export-schemas` 重生成 Form 公共契约 → 在 `agent-contract` 加 Rust 字段 → `cargo test`。CI 守护公共 schema 漂移。

## 上报客户端（agent 内置 ingest）

ingest 能力**内置于 `agentd`**（`crates/agentd/src/ingest.rs`，不再是独立 crate）：阻塞 HTTP，对三种 envelope `upload_report` → `/ingest/asset-report`、`upload_batch` → `/ingest/trace-batch`、`upload_guard_batch` → `/ingest/guard-event`。共享 `post_json`：超时（默认 60s，可经 `FORM_UPLOAD_TIMEOUT` 秒数覆盖）、`202 Accepted` 为成功。新 Agent 同时配置 `FORM_AGENT_CERT` / `FORM_AGENT_KEY` / `FORM_AGENT_CA`，以 per-Agent mTLS 访问 Form 专用 `:10443` listener；三变量不完整时 fail-closed，TLS 只信任显式私有 CA 且不跟随 redirect。`FORM_AGENT_TOKEN` / `FORM_INGEST_TOKEN` bearer 仅保留 mixed/legacy 兼容。驻留进程可热加载轮换后的 TLS material；401/403 会保留 durable spool 并停止本轮 drain。**只有 `agentd <cap> --upload` 或 `agentd run`** 调用它：host/trace 用 `run` 返回的 envelope POST，guard 由 agent 注入一个 `FormGuardSink`（impl `agent_respond::ReportSink`）。Form 再把已认证且绑定 target/canonical host provenance 的 telemetry 送入 analyzer。

## 上报模型（能力本地运行、agentd 才上报）

三个能力独立运行只产出本地结果——collect 的核心 Source 只采集，但 host/trace CLI 可组合端上
detect；`agent-respond` 写本地 NDJSON/stdout。它们**从不上报**，也不依赖任何 HTTP 上报客户端。
上报只发生在统一 `agentd`（ingest 内置，见上节；经 `--upload` 或 `agentd run`）。

---

# 代表性命令

```sh
# 主机静态文件检测
cargo run -p agent-collect-host -- -r / --pretty
cargo run -p agent-collect-host -- -r / -t all -o ./scan-out
cargo run -p agent-collect-host -- -r / --malware --pretty
cargo run -p agentd -- collect-host -r / -t all --upload https://agents.example:10443  # 需 FORM_AGENT_CERT/KEY/CA

# 追踪（网络 + 文件 + 进程）
cargo run -p agent-collect-trace -- capture --pretty
sudo cargo run -p agent-collect-trace --features pcap -- capture --pcap --iface eth0 --duration 30 --pretty
cargo build -p agent-collect-trace --features ebpf                    # 需 nightly + rust-src + bpf-linker
sudo cargo run -p agent-collect-trace --features ebpf -- capture --ebpf --ebpf-duration 30 --pretty
cargo run -p agent-collect-trace -- intel-sync --source feodo --out data/feeds/feodo.json

# 实时防护
cargo run -p agent-respond -- --stdout
cargo build -p agent-respond --features ebpf                    # cgroup-connect 网络阻断（出错回退 nft）
cargo run -p agentd -- respond --config /etc/kcatta/guard.json --upload https://agents.example:10443  # 需 FORM_AGENT_CERT/KEY/CA

# 编排守护（周期 collect-host+collect-trace 上传 + 可选 respond）
cargo run -p agentd -- run --config /etc/kcatta/run.json

# 精简独立构建（证「各自独立且可独立运行」）
cargo build -p agent-collect-host --target x86_64-unknown-linux-musl --release
cargo build -p agent-collect-trace --no-default-features
cargo build -p agent-respond --no-default-features --features fim
```

详见 [`CONTRIBUTING.md`](./CONTRIBUTING.md)。
