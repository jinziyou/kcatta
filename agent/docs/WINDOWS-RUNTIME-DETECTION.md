# Windows 用户态运行时检测 — 路线② 设计

> [`WINDOWS-SUPPORT.md`](WINDOWS-SUPPORT.md) §三方案 B / §四路线② 的详细设计。**纯设计，未写代码**——
> 目的是先把信号选型、契约映射、crate 结构、依赖、权限、构建/CI、分期与未决决策摆清，确认可行/匹配
> 你们环境后再实现。
>
> ⚠️ **本仓库当前为 Linux 开发/CI 环境，无法编译/运行/验证这些 `cfg(windows)` 代码**（连 windows-msvc
> 交叉工具链都未配置）。实现前必须先打通 Windows 构建链路（§7），否则零回归保护。

## 0. 目的与边界

- 给 Windows 端点加**运行时检测**：trace（网络流量）+ guard（FIM / 进程行为），**纯用户态、无内核驱动**。
- **复用既有数据契约**（`TraceBatch` / `GuardEventBatch`）→ analyzer / admin **零改动**；agent 侧只新增“采集源”。
- **非目标**（留路线③/后续）：内核驱动（minifilter / kernel callbacks）、on-access 查毒、内核级网络阻断、
  guard **主动处置**（Windows 上路线②先 monitor-only，只检测+上报）。

## 1. 现状锚点（为什么能“只换采集源”）

| 复用点 | 代码出处 | 说明 |
| --- | --- | --- |
| 数据契约平台中立 | `crates/contract`（`guard.rs` / `trace.rs`） | `GuardEvent`(Fim/Malware/Process/Network/Ids)、`TraceEvent`/`FileTraceEvent`/`ProcessTraceEvent` 都是平台中立 JSON，受 `analyzer/schemas-json/` 约束。Windows 后端产出同样 envelope 即可 |
| `Sensor` trait 平台中立 | `crates/respond/src/sensors/mod.rs` | `run(tx: Sender<Detection>, shutdown)`；Linux 传感器是 `#[cfg(all(target_os="linux", feature=…))]` 模块。pipeline（decide→respond→report）、reporter、`AnalyzerGuardSink` 上报全平台中立 |
| trace 后端可插拔 | `crates/collect/trace/src/capture/mod.rs` | `CaptureBackend`(Mock/Pcap/Ebpf)，feature+cfg gated；IOC/ThreatFeed 匹配平台中立 |
| 非 Linux 已有桩 | `guard/src/supervisor.rs` / `safety.rs` / `respond.rs` 的 `#[cfg(not(target_os="linux"))]` 分支 | 当前是“拒绝运行”的空实现，正好替换为 Windows 真实路径 |

→ **Windows 传感器 = 新增 `#[cfg(all(target_os="windows", feature=…))]` 模块实现同一 `Sensor` trait，
`build_sensors` 注册即可**；trace 加一个 `CaptureBackend::Etw`。上层无需任何改动。

## 2. 信号 × 机制（用户态，无驱动）

| 契约目标 | Windows 用户态机制 | 映射要点 | 限制 |
| --- | --- | --- | --- |
| **FIM** → `GuardEvent::Fim` / `FileIntegrityEvent` | **`ReadDirectoryChangesW`**（每目录递归监听，等价 inotify） | `FILE_ACTION_ADDED→Created`、`MODIFIED→Modified`、`REMOVED→Deleted`、`RENAMED_*→Metadata/重命名`；填 `path` / `change_type` | `hash_before/after` 需读文件计算（可选，删除/高频时跳过） |
| **网络** → `TraceEvent`（+ `NetworkEvent` IOC） | **v1 已用：IP Helper 轮询（`netstat2`）**；备选 ETW `Kernel-Network` | 连接表 5-tuple TCP → `TraceEvent`(src/dst ip+port, proto)；IOC 匹配 dst_ip 照常 | IP Helper：无需管理员、可验证、**无字节计数**；ETW：有字节/包但需管理员+会话（留增强） |
| **进程/行为** → `ProcessTraceEvent` / `GuardEvent::Process` | **ETW `Microsoft-Windows-Kernel-Process`**（ProcessStart/Stop），降级用 Toolhelp32 轮询 | ProcessStart→`ProcessTraceEvent{event_type:exec, pid, ppid, exe, argv}`；行为规则→`ProcessEvent{behavior, rule_id}` | Kernel-Process 含 image/cmdline；轮询是降级 |
| **on-access 查毒** → `GuardEvent::Malware` | ✗ 用户态做不到（需 minifilter 拦 open） | — | 留路线③ |
| **IDS** → `GuardEvent::Ids` | 复用 trace 的 IOC/规则匹配（平台中立） | 仅“采集源”是新的 | — |

**ETW 选型**：① **`ferrisetw`**（纯 Rust ETW 消费封装，活跃维护）——上手快、样板少；② 直接 `windows`
crate 的 `Win32_System_Diagnostics_Etw`——零额外依赖但 ETW 样板多。**建议先 `ferrisetw` 起步**，必要时换原生。

## 3. 架构与结构（最小侵入，**Windows 代码并入现有模块、cfg 分段、不新建模块文件/crate**）

Windows 实现写进 host/trace/guard **现有对应模块**，与 Linux 实现**同文件**、按 `#[cfg(target_os="windows")]`
分段；**不新建 crate、不新建模块文件**（契约 / pipeline / 上报全复用）。

```
crates/respond/src/
  sensors/
    mod.rs            # mod fim 的 gate 放宽到 any(linux,windows)；build_sensors 的 fim push 按 OS 分支
    fim.rs            # 现有文件：Linux inotify (#[cfg(linux)]) + 新增 Windows ReadDirectoryChangesW (#[cfg(windows)]) 同文件分段
  supervisor.rs       # cfg(not linux) 桩 → 拆成 cfg(windows) 真实运行（Ctrl-C 关停）+ 保留 macOS bail 桩
  safety.rs/respond.rs# 不改（not-linux 分支 + Action::None 短路即 monitor-only）
crates/collect/trace/src/capture/
  mod.rs              # CaptureBackend 加 Etw 分支；ETW 网络后端按 cfg(windows) 并入现有 capture 结构（②b）
```

**依赖**（feature-gated，仅 windows target 拉，镜像 guard 现有的 `[target.'cfg(target_os="linux")'.dependencies] nix`）：

```toml
[target.'cfg(windows)'.dependencies]
windows = { version = "0.5x", features = ["Win32_Storage_FileSystem", "Win32_System_Threading",
           "Win32_System_Diagnostics_Etw", "Win32_Foundation", "Win32_System_IO"] }
ferrisetw = { version = "1", optional = true }   # 若走 ferrisetw
```

## 4. 契约映射（关键：上层零改动）

**FIM**（`win_fim` → `FileIntegrityEvent`，monitor-only）：
`path`=变更文件全路径；`change_type`=映射自 `FILE_ACTION_*`；`severity`=Info/Low（可按规则提升）；
`action_taken`=`Logged`、`outcome`=`Success`（monitor-only）；`host_id`=hostname 派生；`event_id`=uuid；
`hash_before/after`=可选 SHA-256。

**网络**（`etw_net` → `TraceEvent`）：`src_ip/dst_ip/src_port/dst_port/proto` 来自 ETW 字段；
`bytes_sent/recv`、`packets_sent/recv` 累加；`start_ts/end_ts` 取流首末；IOC 命中后另生成 `NetworkEvent`
（`indicator/indicator_type/category/source` 来自匹配的 feed）。

**进程**（`win_behavior` → `ProcessTraceEvent` / `ProcessEvent`）：`pid/ppid/exe/argv/comm` 来自 ETW
Kernel-Process；行为规则命中→`ProcessEvent{behavior, rule_id, evidence}`，`action_taken=Logged`。

> 所有事件 `host_id` 用同一套（hostname 派生，复用 host crate 已有逻辑）；`severity`/`ActionTaken`/`Outcome`
> 直接用契约枚举，monitor-only 下恒为 `Logged`/`Success`——analyzer 关联/检测与 admin 展示完全照常。

## 5. 权限与运行

- **ETW 内核提供者**（Kernel-Network/Process）：需管理员 + 适当权限（`SeSystemProfilePrivilege` / 私有
  ETW 会话）。**FIM（ReadDirectoryChangesW）仅需对目标目录读权限**——所以 ②a 权限最轻。
- **部署**：`agentd.exe guard`（Windows 版 agentd，经 WinRM/手动投放）。
- **配置**：复用 `guard.json`（`fim.paths` 等）；ETW provider / 会话名走配置新增字段。

## 6. monitor-only 边界（为什么 Windows guard 先不主动处置）

guard 的 responder（`respond.rs`）是 Linux 专属（fanotify `FAN_DENY`、iptables drop、`kill`）。Windows 主动
处置（WFP 阻断 / `TerminateProcess` / 文件隔离）是**另一块工作且更需谨慎**。路线② Windows guard 先**检测+上报**
（`ActionTaken::Logged`），主动处置留后续。契约的 `action_taken` 字段照常携带，analyzer/admin 不受影响。

## 7. 构建与 CI（本环境无法验证 → 必须先打通）

**现状（已核实）**：
- CI 无任何 Windows job（`.github/workflows/` 无 `windows-latest` / `pc-windows-msvc` / `xwin`）。
- `agent-collect-host` 有 Windows 平台实现（`crates/collect/host/src/platform/windows/`，`windows_sys`），可 `cargo build
  --target x86_64-pc-windows-msvc` 出 `agent-collect-host.exe`，但**仅手动构建，不在 CI**。
- **`guard` / `trace` / `agentd` 从未为 Windows 构建**（无 `cfg(windows)` 依赖）。

**结论**：路线② 必须先：
1. 让 `guard`/`trace`/`agentd` 能为 windows-msvc 编译（加 `cfg(windows)` 依赖与桩）。
2. **加 GitHub Actions `windows-latest` job**：`cargo clippy/build -p agent-respond -p agent-collect-trace
   --target x86_64-pc-windows-msvc --features …` + 平台中立逻辑单测 + 一个本机 smoke（FIM 建/改/删文件断言事件）。
3. （可选）Linux→windows-msvc 交叉（`cargo-xwin`）作编译门禁，但 ETW/SDK 链接需 xwin 提供 import libs；
   真机/Windows runner 才能跑行为。

## 8. 分期（②内部，薄垂直切片优先）

- ✅ **②a FIM（已落地）**：`ReadDirectoryChangesW`（via `notify`）→ `GuardEventBatch`，monitor-only。并入
  既有 `sensors/fim.rs`；新增 windows-latest CI + FIM smoke。
- ✅ **②b 网络（已落地，IP Helper v1）**：改用 **`netstat2`（IP Helper on Windows / `/proc` on Linux）轮询
  连接表** → 5-tuple TCP 连接 → `TraceEvent`（IOC 匹配 dst_ip 照常），并入 trace 既有 `capture/mod.rs`，gate 于
  `feature="winnet"`（**跨平台 → 纯逻辑 + 回环 smoke 可在 Linux 跑**）。选它而非 ETW 是因为**无需管理员、可验证、
  实现简单**；代价是连接快照（**无字节/包计数**）。**ETW `Kernel-Network`（事件驱动、有字节计数）留作 ②b' 增强。**
- **②c 进程/行为**：ETW `Kernel-Process` → `ProcessTraceEvent` / `ProcessEvent`。

每片：契约映射单测（平台中立部分，可在 Linux 跑）+ Windows runner 编译/smoke。

## 9. 风险 / 未决

- ETW 内核会话权限 + NT Kernel Logger 单例争用（与其他 ETW 工具冲突）→ 用私有会话 + 现代 `Kernel-*`
  manifest provider 缓解。
- `ReadDirectoryChangesW` 缓冲溢出（高频变更丢事件）→ 大缓冲 + 溢出标记。
- USN Journal 是卷级替代（更省、能补历史）但解析更复杂 → 先 `ReadDirectoryChangesW`，USN 作可选增强。
- 无法在本仓库 Linux 环境验证 → 依赖 Windows CI runner + 真机。

## 10. 决策点（需拍板后再进入实现）

1. **先做哪片**：建议 **②a FIM**（权限最轻、最自包含）。
2. **ETW 选型**：`ferrisetw` vs 原生 `windows` crate。
3. **Windows 构建链路**：GitHub `windows-latest` runner vs `cargo-xwin` 交叉——决定 CI 形态（这是 ②的硬前置）。
4. **guard monitor-only**：Windows 先只检测+上报（不主动处置）是否可接受。

---

# 附：②a FIM 详细实现设计（DESIGN-ONLY，已对真实代码逐行核对）

> 下面所有 Rust 均为**设计示意、未编译**。已选定：先做 ②a FIM、monitor-only、Windows CI 用 `windows-latest`。

## A0. 先讲一个硬约束：workspace `unsafe_code = "deny"`（`agent/Cargo.toml:52`）

全工作区禁 `unsafe`；Linux 传感器靠 `nix` 的**安全封装**保持干净。原始 `windows`/`windows-sys` 全是
`unsafe extern`（`CreateFileW`/`ReadDirectoryChangesW`/`CancelIoEx`…）。两条路：
- **A（推荐）：用安全封装 `notify` crate**——它本身就是 `ReadDirectoryChangesW` 后端，`unsafe` 藏在其 API 后，
  `agent-respond` 保持 unsafe-free，与现有「用 nix 安全封装」哲学一致。代价：缓冲/溢出控制少（但 `notify` 会以
  rescan-required 事件暴露溢出，正好转成合成检测）。关停也用 `ctrlc`（内部 `SetConsoleCtrlHandler`，避免 FFI 回调的 unsafe）。
- **B（仅当需要裸控制）：直连 `windows` crate** → 新模块需 scoped `#[allow(unsafe_code)]` + **评审签字**（局部破坏工作区不变量）。
  下文 §A2 给出裸机制（满足"具体 win32 名"），实际落地时它**藏在 notify 之内**。

## A1. 传感器必须产出的形状（template spec）

`impl Sensor`（`sensors/mod.rs:25-38`）：`name()->"fim"`，`run(self: Box<Self>, tx: Sender<Detection>,
shutdown: Arc<AtomicBool>) -> anyhow::Result<()>`。**只 push** `Detection::Fim { severity, path, change,
hash_before, hash_after }`（`event.rs:13-25`）——`event_id`/`timestamp`/`host_id`/`action_taken`/`outcome`
由 reporter 在装配 `FileIntegrityEvent` 时填（`report.rs`），传感器**不要碰**。

| `Detection::Fim` 字段 | 来源（镜像 `fim.rs:74-80`） |
| --- | --- |
| `severity: Severity` | `severity_for(path)`——Windows 版（见 §A3） |
| `path: String` | 变更文件全路径 `to_string_lossy().into_owned()` |
| `change: FimChange` | `FILE_ACTION_*` 映射（§A2） |
| `hash_after: Option<String>` | best-effort SHA-256；删除/不可读→`None` |
| `hash_before: Option<String>` | v1 恒 `None` |

循环 `while !shutdown.load(Relaxed)`；`tx.send` 失败→`Ok(())`；**存活时早返回 `Ok` 会被 supervisor 当致命降级**
（非零退出，`supervisor.rs:114-127`）。**monitor-only 自动成立**：FIM 的 `Detection` 没有 file_path/pid/dst_ip
（`event.rs:114-137`），`decide` 只对这些返回处置 → 返回 `Action::None` → `apply` 在 `respond.rs:57-59` 短路成
`(Logged, Success)`。**无需任何 Windows responder**。

## A2. 机制：`ReadDirectoryChangesW`（经 notify，或直连）

- 每目录一 handle：`CreateFileW(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, FILE_LIST_DIRECTORY,
  FILE_SHARE_READ|WRITE|DELETE)`；filter：`FILE_NOTIFY_CHANGE_FILE_NAME|DIR_NAME|LAST_WRITE|SIZE`。
- **`FILE_ACTION_*` → `FimChange`**（与 Linux `change_for` 语义一致）：`ADDED`/`RENAMED_NEW_NAME`→`Created`；
  `REMOVED`/`RENAMED_OLD_NAME`→`Deleted`；`MODIFIED`→`Modified`。
- **递归**：`bWatchSubtree=TRUE`。建议给 `FimConfig` 加 `recursive: bool`（`#[serde(default)]`=false，向后兼容、
  默认与 Linux 非递归 v1 对齐）。
- **多路径**：`Vec<PathBuf>` 每条一 handle，不存在则跳过+`eprintln!`（镜像 `fim.rs:44-54`）。
- **关停**（`AtomicBool` 唤不醒阻塞 wait）：v1 用 timed `WaitForMultipleObjects(~500ms)` 轮询 `shutdown`；
  收尾 `CancelIoEx` + drain `ERROR_OPERATION_ABORTED`。低延迟升级：`ctrlc`/`SetEvent` 唤醒。（notify 路径下由其线程模型处理。）
- **溢出**（0 bytes 或 `ERROR_NOTIFY_ENUM_DIR`）→ 发一条合成 rescan 检测（`change=Modified, path=base, severity=Medium`）
  并重挂，**绝不 `Err`**（否则 supervisor 误杀传感器）。notify 把溢出报成 rescan 事件，直接转成这条合成检测。

## A3. 正确性风险（实现必带）

1. **UTF-16 解码**：`file_name` 长度是**字节**、**无 NUL**、可能含孤立代理 → `OsString::from_wide`（取 `len/2` 个 u16）；
   **勿** `String::from_utf16`（会因孤立代理报错且易越界）。
2. **相对路径**：即便 subtree，`file_name` 仍是**相对 base**（含 `\`）→ 永远 `base.join(name)`，勿当绝对路径。
3. **Modified vs Metadata 不可区分**：`_SECURITY`/`_ATTRIBUTES` 改动也报 `FILE_ACTION_MODIFIED`。v1 **去掉这两个 filter、
   不发 `Metadata`**（诚实），需要再上 stat-diff。
4. **重命名**：`RENAMED_OLD_NAME`→`Deleted`、`RENAMED_NEW_NAME`→`Created`；**各自独立**处理（可能单边、或跨 read 分裂）。
5. **缓冲 DWORD 对齐**；遍历前校验 `next_entry_offset` 单调且在界内（裸路径才需关心；notify 已处理）。
6. **>63 路径**超 `WaitForMultipleObjects` 上限 → 分线程或 IOCP（notify 内部已处理）。
7. **Windows `severity_for`**：`C:\Windows\System32\config\{SAM,SYSTEM,SECURITY}`（注册表 hive）、`drivers\etc\hosts`、
   启动文件夹、`System32\Tasks`、`Run`/`RunOnce` 背靠、服务二进制 → `High`，余 `Medium`；**大小写不敏感**。

## A4. 集成改动清单（精确，已对 cfg 拓扑）

> **结构原则**：Windows 代码**并入 host/trace/guard 现有对应模块**，按 `#[cfg(target_os="windows")]` 分段，
> **不新建模块文件**。FIM 的 Windows 实现写进既有 `sensors/fim.rs`（与 Linux inotify 实现同文件、OS cfg 分段，
> 对外仍是 `fim::FimSensor`）；同理 ②b 的 ETW 网络后端并入 trace 既有 `capture/` 现有结构，host 的 Windows 部分
> 沿用既有 `platform/windows/`。

| 文件 | 改动 | cfg |
| --- | --- | --- |
| `guard/Cargo.toml` | 加 Windows 依赖块（推荐 `notify = "6"`；裸机制则 `windows = {features…}` + `ctrlc = "3"`）。`fim` 是空 marker feature、已在 default/all，**无需改 feature** | `[target.'cfg(target_os="windows")'.dependencies]`（与现有 `nix` 块同风格） |
| `sensors/mod.rs` | 把 `mod fim;` 的 gate 从 `all(target_os="linux", feature="fim")` **放宽为** `all(any(target_os="linux", target_os="windows"), feature="fim")`；`build_sensors` 的 `fim` push 同样改成 `any(linux, windows)` 分支 | 现有行改 cfg |
| `sensors/fim.rs`（**现有文件，不新建**） | 文件内加 `#[cfg(target_os="windows")]` 段：Windows `FimSensor::run`（ReadDirectoryChangesW via `notify`）+ Windows `severity_for`；Linux 的 `nix`/inotify 导入与实现收敛进 `#[cfg(target_os="linux")]`；`hash_file` 等共用逻辑保持平台中立。结构体 `FimSensor { paths, recursive }` 字段平台中立，`run` 体按 OS cfg 分 | 文件内按 OS cfg 分段 |
| `supervisor.rs`（现有文件） | **把 `cfg(not(target_os="linux"))` 桩（`:153-160`）拆成两个**：`#[cfg(target_os="windows")]` 真实 `run_impl`（`ctrlc` 关停替代 signalfd，其余 50-150 逐行照搬）+ `#[cfg(not(any(target_os="linux", target_os="windows")))]` 保留 bail 桩 | ⚠️ **不拆会让 macOS 丢 `run_impl` 编译失败** |
| `respond.rs` / `safety.rs` | **不改**——`not-linux` 分支 + `Action::None`/veto 短路已给 monitor-only `(Logged, Success)` | n/a |

**为什么这么省**：`nix` 只在 `cfg(target_os="linux")` 依赖里（不在 Windows 依赖树），且 `Detection`/`Action`/`Responder`
流已平台中立 → Windows 只缺**一个传感器实现（并入 fim.rs）+ 一个关停机制**，不需要 responder、不需要新模块。

## A5. 构建 & CI（硬前置；已核实）

现状：无 windows job；guard/trace/agentd 从未为 windows 构建。但源码**已大体可为 `x86_64-pc-windows-msvc` 编译**
（host 有 windows 实现；trace 全可移植；guard 核心可移植、`nix` 不在 windows 依赖树、supervisor non-linux 是**运行时 bail
非编译错**）。

**加 `agent-windows`（`windows-latest`）job**（YAML 草图）：
```yaml
  agent-windows:
    name: agent (Windows MSVC)
    runs-on: windows-latest
    defaults: { run: { working-directory: agent } }
    steps:
      - uses: actions/checkout@v6
      - uses: dtolnay/rust-toolchain@stable
        with: { targets: x86_64-pc-windows-msvc, components: clippy }
      - uses: Swatinem/rust-cache@v2
        with: { workspaces: agent }
      - run: cargo clippy --locked --all-targets --target x86_64-pc-windows-msvc
             -p agent-respond -p agent-collect-trace -p agentd
             --no-default-features --features agent-respond/fim,agent-respond/behavior -- -D warnings
      - run: cargo build  --locked --target x86_64-pc-windows-msvc
             -p agent-respond -p agent-collect-trace -p agentd
             --no-default-features --features agent-respond/fim,agent-respond/behavior
      - run: cargo test   --locked --all-targets --target x86_64-pc-windows-msvc
             -p agent-respond -p agent-collect-trace
             --no-default-features --features agent-respond/fim,agent-respond/behavior
```
- **不带** `ebpf`/`pcap`（aya/libpcap Linux 专属）；`fim`+`behavior` 都是空 marker，安全。
- **`agentd` umbrella 在 windows-latest 上 build 通过**是最关键断言（它把 guard+trace+host 链到一起；任何漏 gate 的
  `nix`/`/proc`/`os::unix` 会在这里断链）。先让 **build+clippy 阻塞**冻结「windows 可构建」不变量。
- **FIM smoke**（`tests/fim_smoke.rs`，`#![cfg(all(windows, feature="fim"))]`）：临时目录（**无需管理员**）建/改/删文件，
  断言产出针对该文件的 `Detection::Fim`；**待 Windows 传感器落地后**再让 test 步骤阻塞。
- **`cargo-xwin`** 从 Linux 编译预门禁（`continue-on-error`，快但不能跑 test、ETW/部分 SDK import lib 可能缺）→ 仅建议信号。

## A6. ②a 落地顺序（建议，每步可在 windows-latest 验证）

1. 先加 `agent-windows` CI（build+clippy 阻塞）→ 冻结「windows 可构建」（此时无 Windows 传感器，guard 在 Windows 跑会运行时 bail）。
2. 加 `notify` 依赖 + 在**现有 `sensors/fim.rs`** 内补 Windows `#[cfg(windows)]` 段（emit `Detection::Fim`）+ `sensors/mod.rs`/`supervisor.rs` 接线（不新建文件）。
3. 加 `fim_smoke` 测试，test 步骤转阻塞。
4. config 层补 Windows 默认 FIM 路径 + `recursive` 配置项。

> 本仓库 Linux 环境只能跑**平台中立单测** + `cargo-xwin` 编译预检；行为正确性（ReadDirectoryChangesW / 关停 / 溢出）
> 必须在 `windows-latest` 或真机验证。

## A7. 需拍板（②a 进入实现前）

1. **传感器后端**：`notify`（安全、推荐）vs 直连 `windows` crate（需 `unsafe` 签字）。
2. **`recursive` 配置项**：建议加（默认 false，向后兼容）。
3. **Windows 高危路径清单**（severity_for）确认。

---

# 附：编排接入（已落地）

把已交付的 ②a FIM / ②b WinNet 接入 `agentd run`，让 Windows 常驻 daemon 周期性真正跑这些后端并上报：
- **trace 阶段**：`run.rs` 加 `TraceBackend::WinNet`（agentd `winnet` feature 透传 `agent-collect-trace/winnet`）→
  windows run 配置 `"trace": { "backend": "winnet" }` 即用 IP Helper 连接表捕获 → `TraceBatch` 上报。
- **guard 阶段**：`agentd run` 的 guard 阶段经 ②a 的 `Supervisor` 在 Windows 跑 FIM（agentd 默认带
  `agent-respond/fim`）；windows 设 `"guard": { "enabled": true, "config_path": "C:\\ProgramData\\kcatta\\guard.json" }`。
- 验证：WinNet 后端选择 + 纯捕获逻辑在 Linux 单测（netstat2 跨平台）；windows-latest CI 编译 agentd
  （`agentd/winnet`）+ 跑 FIM/WinNet smoke。

# 附：②b' ETW 网络（字节计数）——**暂缓**（决策记录）

设计成立（`ferrisetw` + NT Kernel Logger `TcpIp`，`SendIPV4/RecvIPV4` 的 `size` → `bytes_sent/recv`/`packets`），
但**暂缓**，原因：
1. **实时字节计数行为本地/CI 都无法可靠验证**：②b 的回环 smoke 靠读**套接字表**才看得到 loopback；ETW 字节来自
   **数据路径**，而 loopback 经 ETW `TcpIp` 是否吐字节**受 TCP Loopback Fast Path 影响、无文档保证**——不能当 CI 门禁。
2. **NT Kernel Logger 是单例**（`ERROR_ALREADY_EXISTS`）→ runner 上额外一层 flaky（需私有 system-logger 会话）。
3. **价值次要**：抓 C2 的主信号 `dst_ip` IOC 匹配已由 ②b 交付；字节数仅为 exfil-volume 之类增强。

→ 真要做时，诚实范围为：`etwnet` feature + **合成记录的纯聚合 Linux 单测**（唯一真验证）+ windows CI compile/clippy +
实时捕获作 `#[ignore]` 测并文档标注**需真机**；ETW 未给到计数时老实保留 `bytes=0`。**真正「证实」需一台真实/自托管
Windows 主机**——windows-latest CI 只能编译、给不了这个证明。
