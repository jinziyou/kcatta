# Windows 支持现状与可选方案

> 面向「kcatta 能不能管 Windows 端点 / eBPF 在不在 Windows 上跑」这个问题的一份现状盘点 +
> 后续路线评估。结论先行，再给代码出处与方案对比，便于排期。

## TL;DR

| 能力 | Windows 现状 | 说明 |
| --- | --- | --- |
| **eBPF 路径**（trace 的 ebpf 后端 / guard 全部传感器） | ❌ **不支持，且非开关问题** | 绑定 Linux 内核（Aya + BPF syscall），见下「为什么」 |
| **主机静态采集 `agent-host`** | ✅ **已支持**（有原生 Windows 实现） | `agent-host.exe` 采包/用户 profile 等 → `AssetReport` |
| **WinRM host 扫描（admin 触发）** | ✅ **已接通**（路线①） | admin 注册→一键下发；走客户端证书托管凭证 |
| **WinRM 证书托管凭证**（注册 bootstrap + `/credentials` 纳管） | ⚠️ **已实现，目标侧 PS 未经真机验证** | 一次性口令引导客户端证书+映射、之后免口令；详见 §三 |
| **Windows 运行时检测**（流量 / FIM / 行为 / onaccess / IDS / 主动处置） | ❌ **暂无** | 需一条与 Linux 内核接口并行的新后端，见「可选方案」 |

一句话：**Windows 现在能从 admin 一键做静态资产扫描（WinRM + 证书托管凭证），但没有任何运行时检测；eBPF 是 Linux 专属。**

> ⚠️ **真机验证待办**：WinRM 证书托管的目标侧 PowerShell（启用证书认证 / 导入证书 /
> `WSMan:\localhost\ClientCertificate` 映射）按 Microsoft 文档编写、由 mock pywinrm 单测覆盖，但
> **未在真实 Windows 主机上端到端验证**。前置条件：目标已有 **HTTPS WinRM 监听器**（端口 5986）。
> 上生产前请在真机走通。

---

## 一、为什么 eBPF 是 Linux 专属

不是“还没适配”，而是技术栈本身就钉在 Linux 内核上：

- **eBPF crate 用 Aya**（`crates/ebpf/Cargo.toml`）：内核侧 `aya-ebpf` 编译出 GPL-2.0 的 BPF 程序
  （`trace-ebpf` / `guard-ebpf` 两个 bin），用户态由 `aya 0.13`（`agent-trace` / `agent-guard` 的
  `ebpf` feature）经 **Linux `bpf(2)` 系统调用**加载。Aya 整条链只在 Linux 上工作。
- **trace 的 eBPF 后端**：`CaptureBackend::Ebpf`（cgroup-skb 流量遥测，`crates/trace/src/capture/mod.rs`）
  仅在 `feature = "ebpf"` 下存在，而 `aya` 依赖本身在非 Linux 上构建不出来。
- **guard 全部常驻传感器**显式 `#[cfg(all(target_os = "linux", feature = "..."))]`
  （`crates/guard/src/sensors/mod.rs`）：
  - FIM → inotify
  - behavior → 轮询 `/proc`
  - onaccess → fanotify + agent-host 签名扫描
  - network → cgroup-connect eBPF
  其内核依赖 `nix`（fanotify / inotify / signal）更是写在
  `[target.'cfg(target_os = "linux")'.dependencies]`（`crates/guard/Cargo.toml`）下。
- 非 Linux 上只有 `#[cfg(not(target_os = "linux"))]` 的桩实现（`supervisor.rs` / `safety.rs` /
  `respond.rs` 都成对存在）——能编译过，但**不做任何内核级检测**。
- 部署二进制也只产 **linux-musl**（x86_64 / aarch64），workspace 里没有任何 Windows 目标三元组。

> 备注：微软有 [eBPF for Windows](https://github.com/microsoft/ebpf-for-windows) 运行时，但它
> **不能用 Aya**（Aya 走 Linux BPF syscall），program type / hook 点也远比 Linux 受限——详见方案 A。

---

## 二、Windows 现在到底能得到什么

### 2.1 静态资产采集：已支持（agent-host 有原生 Windows 实现）

- `crates/host/src/platform/windows/`（如 `boot.rs` 经 `windows_sys` 调 `GetTickCount64` 取启动时间）
- `crates/host/src/walk/handlers/ssh_home.rs::scan_windows_profiles`（扫 Windows 用户 profile / SSH home，跳过系统账号）
- `--windows-packages full|apps` 包采集 profile（`crates/host/src/cli.rs`、`collector.rs`）

即 `agent-host.exe` 可在 Windows 上跑出标准 `AssetReport`（包 / 服务 / 账号 / 凭据线索 …），
后续 CVE 判定与关联照常在 analyzer 侧完成。

### 2.2 WinRM host 扫描：已接通 admin 触发 + 证书托管凭证（路线①）

- **投放**：`analyzer/src/analyzer/deploy/winrm.py::run_winrm_agent_scan` 上传 `agent-host.exe`、对 `C:\`
  运行、base64 回拉 per-asset JSON。CLI（`analyzer-scan --transport winrm`）与 admin 触发都走它。
- **admin 触发**：`api/scans.py::_execute_job` 的 host 远程分支按 `transport` 路由——
  `transport=winrm` → `deploy_trigger.run_host_winrm`（用托管证书免口令），与 SSH/local 并列。
- **证书托管凭证（SSH 同款）**：`analyzer/src/analyzer/deploy/winrm_bootstrap.py`——
  - 注册时一次性口令 → `ensure_cert_auth` 在目标上启用证书认证 + 导入客户端证书 +
    `WSMan:\localhost\ClientCertificate` 映射；口令随即丢弃，**绝不持久化**。
  - 之后 `WinRmSession` 用 `transport=ssl` + `cert_pem/cert_key_pem` 免口令连。
  - `/credentials` 按 transport 分发：列出（含证书指纹）/测连/轮换/吊销与 SSH 同构
    （WinRM 轮换需口令——没有 SSH 那种“旧密钥免密”路径）。
- **差异点**：WinRM 仅支持 **host**（trace/guard 需 SSH 常驻 agent）；`--malware` 不支持（SSH/Linux only）。

**前置 & 约束**：
- 目标需已有 **HTTPS WinRM 监听器**（端口 5986）——证书认证仅 HTTPS；`ensure_cert_auth` 会校验并在缺失时清晰报错（不自动建监听器）。
- 需在 `ANALYZER_AGENT_TARGET_DIR/x86_64-pc-windows-msvc/release/agent-host.exe` 提供 Windows 版 agent。
- ⚠️ 目标侧 PowerShell **未经真机端到端验证**（仅 mock 单测）；上生产前请在真机走通。

### 2.3 运行时检测：完全没有

trace 的流量采集、guard 的 FIM / 行为 / onaccess / 网络 IOC / IDS 与端上主动处置，在 Windows 上都不可用
（见第一节，全部 Linux-gated）。

---

## 三、可选方案（要给 Windows 上运行时检测）

### 方案 A：eBPF for Windows（微软运行时）

- **思路**：复用「写 eBPF 程序」的范式，目标机装 eBPF-for-Windows 运行时（含驱动）。
- **硬约束**：
  - 用不了 Aya，得换加载器（`ebpfapi.dll` / libbpf-for-windows）；
  - 仅支持有限 program types（XDP-lite、socket、bind/connect 等），**没有** LSM / kprobe / tracepoint，
    FIM / 进程行为 / onaccess 几乎覆盖不到；
  - 目标机需预装运行时（驱动安装 + 签名）。
- **能覆盖**：trace「网络流量」的一小部分；guard 的其余传感器基本无法照搬。
- **评价**：可观测面窄 + 部署门槛高 + 无法复用现有 Aya 代码，**性价比低**，不建议优先。

### 方案 B：Windows 原生传感器（推荐）

与 Linux 内核接口完全并行的一套实现，按「是否需要内核驱动」分两层：

| guard/trace 等价能力 | Windows 原生机制 | 是否需驱动 |
| --- | --- | --- |
| 网络流量 / IOC | ETW（`Microsoft-Windows-Kernel-Network`）或 WFP | 否（ETW/WFP-events）/ 是（WFP 阻断回调） |
| 文件完整性 FIM | `ReadDirectoryChangesW` / USN Journal / minifilter | 否 / 是（minifilter） |
| 进程 / 行为 | ETW（`Kernel-Process` / Threat-Intelligence provider）、WMI 事件 | 否 |
| onaccess 查毒 | minifilter + 复用 agent-host 签名扫描器 | 是 |
| 主动处置（阻断 / 隔离 / kill） | 网络阻断走 WFP；隔离 / kill 走 Win32 API | 视粒度 |

- **用户态优先**（ETW / WFP-events / USN / `ReadDirectoryChangesW`）：无需驱动签名，可作为第一阶段。
- **内核态**（minifilter / kernel callbacks 如 `PsSetCreateProcessNotifyRoutine`）：覆盖更深，但需驱动 + 签名，工程量大。

---

## 四、建议路线（分阶段、低风险优先）

1. ✅ **「Windows 静态资产」闭环已补齐**（本 PR）：`winrm.py` 接入 admin 触发 + WinRM 证书托管凭证纳入
   `/credentials`（与 SSH 同构）。**剩余**：在真实 Windows 主机上端到端验证目标侧 PowerShell（见 §2.2 ⚠️）。
2. **用户态运行时检测（无驱动）**：trace network 用 ETW/WFP-events，FIM 用 USN/`ReadDirectoryChangesW`，
   行为用 ETW `Kernel-Process`。产出映射到现有 `TraceBatch` / `GuardEventBatch` 契约即可。
3. **更深可观测再上内核驱动**（onaccess / 内核级阻断 → minifilter / callbacks，需签名）。
4. **不优先 eBPF-for-Windows**：覆盖面窄、要装运行时、且无法复用 Aya（见方案 A）。

### 为什么分阶段可行：契约是语言/内核中立的

数据契约（`AssetReport` / `TraceBatch` / `GuardEventBatch`）是语言中立 JSON（`crates/contract` +
`analyzer/schemas-json/`），**analyzer / admin 不关心 agent 用什么内核机制采集**。因此 Windows 后端只要产出
同样的 envelope，上层（关联、检测、UI）零改动——这是分阶段推进 Windows 支持最大的有利条件。
