# agent 架构

kcatta 的端点组件。agent 分为**三大能力** + **一个 eBPF 支撑 crate**，**一个能力 = 一个目录 = 一个 crate**
（lib + bin 同处一个 crate，无嵌套子 crate），各能力可单独部署、单独运行；三者共享数据
契约与上报底座。eBPF 路径全程 **feature-gated + 需特权**，工具链/内核缺失时优雅降级。

| 能力 | crate（目录） | 观测对象 / envelope | 边界 |
| --- | --- | --- | --- |
| **主机静态文件检测** | `agent-host`（`crates/host/`） | 内视 → `AssetReport` | 只采集 |
| **追踪（网络 + 文件 + 进程）** | `agent-trace`（`crates/trace/`） | 外视 → `TraceBatch` | 只采集 |
| **实时防护** | `agent-guard`（`crates/guard/`） | 端内实时事件 → `GuardEventBatch` | **检测 + 端上主动处置 + 上报** |

> CVE 判定与跨源关联在 **analyzer** 侧；`agent-host` / `agent-trace` 只产出标准化 envelope。
> **`agent-guard` 是唯一会在端上主动处置的能力**（可逆隔离 / 网络阻断 / 阻断打开 / kill），默认
> monitor 关闭、受多重安全否决保护。跨机投放（`analyzer-scan`，Python）属于 analyzer。

```
  [周期] 主机静态扫描 ──► agent-host  → host 域 (+--malware 内置查毒)              ──► 写 AssetReport 文件
  [周期|持续] 追踪      ──► agent-trace → 网络流 (mock | pcap) + intel-sync          ──► 写 TraceBatch.events
                                       └─[--ebpf]─► 内核 tracepoint(exec/exit/openat) ──► TraceBatch.file_events / process_events
  [持续] 实时防护       ──► agent-guard → guard 域 (fim/onaccess/behavior/network/ids) ──► 本地 NDJSON/stdout
                            └──── 独立运行：只产出本地结果，不上报 ────┘
                                              │
            agentd <cap> --upload / agentd run ──►  agent 内置 ingest  ──►  /ingest/{asset-report, trace-batch, guard-event}  →  analyzer
```

## Crate 结构与依赖 DAG（5 个常规 crate + 1 个 eBPF 支撑 crate；单向无环；lib+bin 同 crate）

```
底座:  agent-contract     (AssetReport + TraceBatch{events,file_events,process_events} + GuardEventBatch + 共享 Severity/IndicatorType, 零内部依赖)

       agent-contract ◄── agent-host      (主机检测 + 内置签名查毒; 只写文件)
       agent-contract ◄── agent-trace      (capture + IOC 匹配 + feed 解析; lib 无 reqwest, 只写文件)
                              └─[feature ebpf]─◄ agent-ebpf（共享类型 lib） ; build.rs 内嵌 trace-ebpf bin
       agent-contract ◄── agent-guard ◄── agent-host(onaccess, 复用 malware) + agent-trace(network, 复用 capture)
                              └─[feature ebpf]─ build.rs 内嵌 guard-ebpf bin（guard-ebpf bin 不用 agent-ebpf 共享类型）
       agentd (umbrella, crates/agentd) ◄── agent-host + agent-trace + agent-guard + agent-contract
                          └── 内置 ingest 模块 (reqwest): --upload / run 时 upload_report/batch/guard_batch → analyzer

eBPF 支撑:  agent-ebpf (crates/ebpf)         一个 crate = 共享类型 lib + 两个内核 bin
            ├ lib agent_ebpf (no_std, Apache-2.0)   #[repr(C)] POD: ExecEvent/ExitEvent/FileEvent, bytemuck Pod
            ├ bin trace-ebpf (no_std, GPL-2.0)       内核 tracepoint exec/exit/openat → EVENTS RingBuf（用 agent_ebpf 类型）
            └ bin guard-ebpf (no_std, GPL-2.0)       cgroup connect4/6 阻断器（不用 agent_ebpf 共享类型）
```

> `cli-common` / `agent-ingest` 已移除：JSON 输出 / HTTP 下载内联进各能力 `cli`；上报（ingest）内置进 `agentd`。
> **上报路径**：`agentd <cap> --upload` 单次上报，或 `agentd run` 编排守护周期上报；host/trace 把 `run` 返回的 envelope POST，guard 由 agent 注入一个 analyzer `ReportSink`。

- **领域逻辑在 lib，CLI 也在 lib（`pub mod cli`）**：各能力的 `Args + run` 放在 lib 的 `cli` 模块，三个独立 bin 与 umbrella `agentd` 共用同一套逻辑；bin 是薄壳。guard 经 feature 可选依赖 host/trace，默认（fim+behavior）不牵入。
- **恶意软件检测自实现**（`agent-host` 的 `malware` 模块）：签名/哈希引擎，仅 `std`+`sha2`，无 ClamAV / 外部守护进程；guard on-access 复用同一引擎（`scan_bytes`）。
- **eBPF 是可选后端**：网络追踪默认仍走 pcap/mock，`ebpf` feature 额外引入内核态文件/进程事件；guard 的网络阻断在 `ebpf` feature 下用内核 cgroup-connect 阻断器，否则用 `nft`。两条 eBPF 路径任一加载/挂载失败都优雅回退。
- **命名**：底座库 `agent-*`，三大能力 lib 名 `agent_host`/`agent_trace`/`agent_guard`（bin 同名）；umbrella `agentd`（bin `agentd`）；eBPF 支撑 crate `agent-ebpf`（lib 名 `agent_ebpf` + 两个 bin `trace-ebpf` / `guard-ebpf`）（产品标识/包名统一 `kcatta`）。

## 三种运行方式

1. **三独立二进制**：`agent-host` / `agent-trace` / `agent-guard` 各自单独构建、部署、运行（最精简，按 feature 裁剪）。
2. **统一 `agentd` 命令**：`crates/agentd` 产出单一 `agentd` 二进制，子命令 `host`/`trace`/`guard` 在进程内分发到各能力 lib 的 `cli` 模块（与独立 bin 共用逻辑）；外加 `agentd run` 编排守护（见下）。
3. **analyzer 调度**：`analyzer-scan --capability {host|trace|guard}` 经 SSH 远程投放——host/trace 一次性拉回结果，guard 部署为常驻守护推送 analyzer。

---

# 主机静态文件检测（agent-host · 内视 · 周期性）

## agent-host 命令

```
agent-host [-r ROOT] [-t TARGET] [输出旗标] [--malware ...]
```

| 旗标 | 说明 |
| --- | --- |
| `-r` / `--root` | 挂载根或本机 `/`（`scan_root`） |
| `-t` / `--target` | `host` / `packages` / `sbom` / `services` / `accounts` / `credentials` / `containers` / `identity` / `all` |
| `--malware` / `--malware-jobs` / `--malware-signatures PATH` | 内置签名查毒 + 并发 + 额外签名 |
| `-o DIR` / `--pretty` / `--report-out FILE` | 输出 |

输出两种形态：**分文件 JSON**（`-o DIR`：`host.json` / `packages.json` / … ，`--malware` 另写 `malware.json`）与**合并 `AssetReport`**（不带 `-o`：stdout / `--report-out`）。

## Collector 模型

`agent-host` 的 lib 把全部主机检测收纳在纯库里。一次扫描周期内各 `Collector` 共享 `ScanContext`（`scan_root` / `host_id` / `project_roots`），`Collector::collect` 返回 `CollectorOutput`（`Host` / `Assets` / `Vulnerabilities`），`run_scan_at` 顺序执行并合并为 `AssetReport`。默认计划：`HostCollector` → `PackagesCollector` → `ServicesCollector` → `AccountsCollector` → `CredentialsCollector`；`--malware` 追加 `MalwareCollector`，命中并入 `vulnerabilities`。`run_scan_at()` 是程序化入口（agentd 周期扫描即调用之）。

内部分层：`collectors/`（资产语义）· `sources/`（固定路径）· `walk/`（有界遍历）· `platform/`（OS / Windows 注册表）· `malware`（内置查毒引擎）。

## 内置恶意软件引擎（malware 模块）

替代 ClamAV：无外部守护进程、无 `libclamav`。每个文件读入（限 `DEFAULT_MAX_FILE_SIZE`）→ SHA-256 + 字节子串匹配 `SignatureSet`（`Sha256` 与 `Bytes` 两类规则）。内置 EICAR 测试签名；额外签名经 `--malware-signatures`（JSON `{sha256:[{name,hex}], bytes:[{name,hex_pattern}]}`）加载。命中映射为 `Vulnerability`（`source = "kcatta-malware"`）。`scan_bytes(&SignatureSet, &[u8])` 供 guard on-access 复用。**简单可用，后续可扩展**（YARA 风格规则、更大签名库）。

---

# 追踪：网络 + 文件 + 进程（agent-trace · 外视 · 周期 + 持续）

`agent-trace` 的追踪以**网络流**为基线（pcap/mock 后端），`ebpf` feature 再叠加**内核态文件操作与进程调用**事件——三类事件分别落在 `TraceBatch` 的 `events` / `file_events` / `process_events`。lib **不含 HTTP**。

两个子命令：

- `capture`：capture → IOC 匹配 → `TraceBatch`（写 stdout / `-o`）。旗标 `--mock`(默认) / `--pcap`（需 `pcap` feature）/ `--iface` / `--duration` / `--bpf` / `--intel PATH` / `--ebpf` / `--ebpf-duration N` / `--pretty` / `-o`。**无 `--upload`**——上报经 `agentd trace --upload` 或 `agentd run`。
- `intel-sync`：下载 IOC feed → 本地 JSON。旗标 `--source NAME`（必填，可重复；`feodo`|`sslbl`|`threatfox`）/ `-o` / `--feodo-url` / `--sslbl-url` / `--threatfox-url` / `--timeout`。`feodo`=IP C2、`sslbl`=JA3 指纹、`threatfox`=域名+ip:port；多 source 按 `(type,value)` 去重合并。下载在 `http_get_text` 单点封顶 64 MiB 防恶意源 OOM。

## 网络后端 + IOC 富化

捕获后端 `mock`（默认）与 `pcap`（feature）返回同一 `Vec<TraceEvent>`（网络 5 元组）。`ThreatFeed::enrich` 对本地 IOC 库匹配（IP / 域名父域 / JA3），命中以 `ThreatMatch` 注入 `TraceEvent.threat_intel`。lib **不含 reqwest**——`intel-sync` 的 HTTP 下载在 bin 的 `cli` 里（本地 `http_get_text`），feed 字节解析在 lib 的 `intel::sync`。

## eBPF 追踪后端（feature `ebpf` · 特权）

启用 `ebpf` feature 后，`capture --ebpf` 加载 `agent-ebpf`（`crates/ebpf`）的 `trace-ebpf` bin 内核程序，挂载 **进程 exec/exit** 与 **文件 openat**（`trace_exec` / `trace_exit` / `trace_openat`）tracepoint，把内核侧的 `ExecEvent` / `ExitEvent` / `FileEvent`（`agent_ebpf` lib 的 `#[repr(C)]` POD）经 `EVENTS` ring buffer 排空到用户态，解析为 `TraceBatch.file_events` / `process_events`（`FileOp` / `ProcessEventType` 枚举）。`--ebpf-duration N` 控制采样窗口。

运行期需 **CAP_BPF/root + 带 BTF 的内核**；加载失败时优雅降级——网络流仍走 pcap/mock，file/process 事件为空。

---

# 实时防护（agent-guard · 端内 · 持续）

长驻守护进程，agent 中唯一突破「只采集」边界的能力：**实时检测 → 决策 → 处置 → 上报**。

## 流水线

```
sensor ──Detection──► decide ──Action──► respond(+safety+ledger) ──► report ──GuardEventBatch──► analyzer / 本地 NDJSON
 (N 线程)              (policy)           (可逆隔离/网络阻断/kill/...)    (批量+定时+critical 立即)
```

- 每个传感器一个长驻线程，向有界 `std::sync::mpsc` 推 `Detection`，轮询 `shutdown` 退出。
- **decide**：monitor 恒为 `None`；enforce 下按「单动作开关 ∧ 严重度阈值」选动作。
- **respond**：先过 `safety` 否决，再查幂等 ledger，最后执行；产出 `(action_taken, outcome)`。
- **report**：`Detection` + 结果 → 契约 `GuardEvent`，按 `batch_max` / `flush_secs` 聚为 `GuardEventBatch`，critical 立即 flush；sink 含 analyzer 上报 + 本地 NDJSON 审计 + stdout。
- 优雅停机：`signalfd` 接 SIGINT/SIGTERM → 置 `shutdown` → 传感器退出（fanotify 标记随 fd 关闭移除）→ 末批 flush。

## 机制（Linux，feature-gated）

| Feature | 默认 | 实现 | 产出 |
| --- | --- | --- | --- |
| `fim` | ✓ | inotify 监听关键目录 + SHA-256 | `FileIntegrityEvent` |
| `behavior` | ✓ | `/proc` 轮询规则（exe-deleted-running、shell→网络工具） | `ProcessEvent` |
| `onaccess` | | fanotify `FAN_OPEN_PERM` + 复用 `agent-host` 内置查毒（经 `/proc/self/fd/N`，fail-open） | `MalwareEvent` |
| `network` / `ids` | | 复用 `agent-trace` 短窗捕获 + `ThreatFeed` 匹配 / 内置端口签名 | `NetworkEvent` / `IdsEvent` |

## 主动处置与安全

默认 `mode = monitor` + 各动作开关全关。动作仅当 `enforce ∧ 开关开 ∧ 严重度≥阈值 ∧ 安全不否决` 时触发：

- **可逆隔离**（移入 vault + `chmod 000` + manifest，**永不删除**）、**网络阻断**、**阻断打开**（on-access `FAN_DENY`）、**kill**（仅搭骨架、默认关闭）。
- **网络阻断后端**：默认 `nft` drop；启用 `ebpf` feature 时改用内核 **cgroup connect4/6 阻断器**（`agent-ebpf`（`crates/ebpf`）的 `guard-ebpf` bin `guard_connect4` / `guard_connect6`，从 `BLOCKED_V4` / `BLOCKED_V6` map 拒绝目的 IP），加载/挂载出错则自动回退到 `nft`。该路径**不需要 CONFIG_BPF_LSM**（是 cgroup-connect 而非 LSM），运行期需 CAP_BPF/root + cgroup-v2。
- **安全否决**（`respond/safety`）：关键路径 / 系统前缀 ELF / 运行中-mmap 文件 / vault 自身 / PID 1 / 自身 / 回环地址全部拒绝；**幂等 ledger** 防抖动。
- on-access **fail-open**（出错 / 超大 → `FAN_ALLOW`），绝不卡死系统。

所有 syscall（fanotify / inotify / signalfd / kill）走安全的 `nix` 封装，满足工作区 `unsafe_code = "deny"`（无任何 `#[allow(unsafe_code)]`）。

## 配置（JSON，缺省即安全默认）

`--config /etc/kcatta/guard.json`（缺失则用默认）。字段：`mode`、`host_id`、各传感器开关与路径（`onaccess.signatures` 加载额外查毒签名）、`response`（`allow_quarantine`/`allow_netblock`、`severity_threshold`、`critical_paths`、`vault_dir`）、`report`（`audit_log`/`stdout`/`batch_max`/`flush_secs`）。CLI `--detect-only` / `--stdout` 覆盖配置（`--upload` 仅存在于 `agentd guard`，由 agent 注入 analyzer sink）。

## 跨平台 seam

传感器与处置实现 `#[cfg(target_os = "linux")]`；非 Linux 编译为 stub（`Supervisor::run` 返回「仅支持 Linux」）。Windows v2 可在同一流水线下补 ETW / minifilter / WFP，契约与上层不变。

---

# eBPF 构建（build.rs + bpf-linker + default-members 排除 + 优雅 stub）

eBPF 内核程序与共享类型合并到**一个 crate `agent-ebpf`（`crates/ebpf`）**——一个共享类型 lib（host 编译）+ 两个内核 bin（bpf-target-only）。该 crate 是 workspace **成员但被 `default-members` 排除**（因其 bin 仅在 bpf target 编译）——因此宿主侧 `cargo build` / `cargo test` 永远不会编译两个内核 bin（`aya-ebpf` 由 crate 的 `ebpf` feature 门控、bin 的 `required-features = ["ebpf"]` 进一步保证宿主构建不触碰它），普通 CI 与本机开发不受 BPF 工具链牵连；其共享类型 lib 仍随 `agent-trace --features ebpf` 在宿主侧被传递编译。

- **lib `agent_ebpf`（`crates/ebpf`，no_std，Apache-2.0，仅依赖 `bytemuck`）**：内核 ↔ 用户态经 ring buffer 传递的共享 `#[repr(C)]` POD 事件结构（`ExecEvent` / `ExitEvent` / `FileEvent`，`bytemuck` Pod）；agent-trace 用户态 loader 经 `ebpf` feature 依赖它（可选）。
- **bin `trace-ebpf`（no_std + no_main，bpf target，GPL-2.0，`required-features = ["ebpf"]`）**：内核 tracepoint 程序（`trace_exec` / `trace_exit` / `trace_openat` → `EVENTS` `RingBuf`，用 `agent_ebpf` 共享类型）。
- **bin `guard-ebpf`（no_std + no_main，bpf target，GPL-2.0，`required-features = ["ebpf"]`）**：内核 `cgroup_sock_addr` 程序（`guard_connect4` / `guard_connect6`，依 `BLOCKED_V4` / `BLOCKED_V6` 拒绝目的 IP；不用 `agent_ebpf` 共享类型）。

> crate license：`Apache-2.0 AND GPL-2.0`（Apache 的共享类型 lib + GPL 的两个内核 bin）。

两个内核 bin 只由 `agent-trace` / `agent-guard` 的 `build.rs` 在各自 `ebpf` feature 打开时编译：经
`cargo build --package agent-ebpf --bin <trace-ebpf|guard-ebpf> --features ebpf --target bpfel-unknown-none`（nightly + `rust-src` + `bpf-linker`），再以 `include_bytes_aligned!` 内嵌进对应能力 crate。

**优雅 stub**：若 nightly 工具链 / bpf-linker 缺失，`build.rs` 产出一个空 stub 对象并打印 warning，使 CI `--all-features` 仍然绿（eBPF 后端此时在**运行期**报错，用户态退回 pcap/mock 或 `nft`）。

构建期需求：nightly + `rust-src` + `cargo install bpf-linker`。运行期需求：trace 需 CAP_BPF/root + 带 BTF 的内核；guard 需 CAP_BPF/root + cgroup-v2。`ebpf` feature **opt-in**，**不**进 musl 部署构建——部署只发 `agent-host` / `agent-trace` / `agentd`，guard 以 onaccess/network/ids 形态运行。

---

# `agentd run` 编排守护

除 `agentd host|trace|guard` 子命令在进程内分发到各能力 `cli`（并以 `--upload <URL>` POST analyzer）外，`agentd` 提供编排守护：

```
agentd run --config <json>
```

加载一份 JSON `RunConfig`，按 `interval_secs` 周期：

- 调度一次 host 扫描（→ `AssetReport`）+ 一次 trace capture（→ `TraceBatch`），各自上传；
- 若 `guard.enabled`，在后台线程内监管 guard，持续流式上报 `GuardEventBatch`；
- 收到 SIGINT / Ctrl-C 时优雅停机；
- 某次周期失败仅记录日志并在下一周期重试，不中断守护。

---

# 共享底座

## 数据契约（agent-contract）

`analyzer/schemas-json/` 的 Rust 镜像（analyzer Pydantic 的 Rust 镜像），零内部依赖，持有三种 envelope：

- 主机：`AssetReport` / `HostInfo` / `Asset` / `Vulnerability`
- 追踪：`TraceBatch`（`events: Vec<TraceEvent>`（网络 5 元组）/ `file_events: Vec<FileTraceEvent>` / `process_events: Vec<ProcessTraceEvent>`）/ `TraceProto` / `FileOp` / `ProcessEventType` / `ThreatMatch` / `IndicatorType`
- 实时防护：`GuardEventBatch` / `GuardEvent`（`Fim` | `Malware` | `Process` | `Network` | `Ids` 内部标签联合）/ `ActionTaken` / `Outcome` / `FimChange`
- 三侧共享 `Severity`；guard 与 trace 共享 `IndicatorType`。

| 层级 | 路径 |
| --- | --- |
| 权威来源 | `analyzer/src/analyzer/schemas/`（guard 在 `guard_event.py`） |
| JSON Schema | `analyzer/schemas-json/`（含 `GuardEventBatch.schema.json`） |
| Rust 镜像 | `crates/contract/src/{lib.rs, trace.rs, guard.rs}` |
| 校验测试 | `crates/host/tests/contract.rs`、`crates/trace/tests/contract.rs`、`crates/contract/tests/guard_contract.rs` |

新增字段：先改 analyzer Pydantic → `analyzer-export-schemas` 重生成 → 在 `agent-contract` 加 Rust 字段 → `cargo test`。CI 经 `git diff --exit-code schemas-json/` 守护漂移。

## 上报客户端（agent 内置 ingest）

ingest 能力**内置于 `agentd`**（`crates/agentd/src/ingest.rs`，不再是独立 crate）：阻塞 HTTP，对三种 envelope `upload_report` → `/ingest/asset-report`、`upload_batch` → `/ingest/trace-batch`、`upload_guard_batch` → `/ingest/guard-event`。共享 `post_json`：超时（默认 60s，可经 `ANALYZER_UPLOAD_TIMEOUT` 秒数覆盖）、`ANALYZER_API_TOKEN` Bearer、`202 Accepted` 为成功。**只有 `agentd <cap> --upload` 或 `agentd run`** 调用它：host/trace 用 `run` 返回的 envelope POST，guard 由 agent 注入一个 `AnalyzerGuardSink`（impl `agent_guard::ReportSink`）。

## 上报模型（能力只采集、agent 才上报）

三个能力**独立运行只产出本地结果**——`agent-host`/`agent-trace` 写 JSON 文件/stdout，`agent-guard` 写本地 NDJSON/stdout——**从不上报**，也不依赖任何 HTTP 上报客户端。上报只发生在统一 `agentd`（ingest 内置，见上节；经 `--upload` 或 `agentd run`）。

---

# 代表性命令

```sh
# 主机静态文件检测
cargo run -p agent-host -- -r / --pretty
cargo run -p agent-host -- -r / -t all -o ./scan-out
cargo run -p agent-host -- -r / --malware --pretty
cargo run -p agentd -- host -r / -t all --upload http://127.0.0.1:10068

# 追踪（网络 + 文件 + 进程）
cargo run -p agent-trace -- capture --pretty
sudo cargo run -p agent-trace --features pcap -- capture --pcap --iface eth0 --duration 30 --pretty
cargo build -p agent-trace --features ebpf                    # 需 nightly + rust-src + bpf-linker
sudo cargo run -p agent-trace --features ebpf -- capture --ebpf --ebpf-duration 30 --pretty
cargo run -p agent-trace -- intel-sync --source feodo --out data/feeds/feodo.json

# 实时防护
cargo run -p agent-guard -- --stdout
cargo build -p agent-guard --features ebpf                    # cgroup-connect 网络阻断（出错回退 nft）
cargo run -p agentd -- guard --config /etc/kcatta/guard.json --upload http://127.0.0.1:10068

# 编排守护（周期 host+trace 上传 + 可选 guard 监管）
cargo run -p agentd -- run --config /etc/kcatta/run.json

# 精简独立构建（证「各自独立且可独立运行」）
cargo build -p agent-host --target x86_64-unknown-linux-musl --release
cargo build -p agent-trace --no-default-features
cargo build -p agent-guard --no-default-features --features fim
```

详见 [`CONTRIBUTING.md`](./CONTRIBUTING.md)。
