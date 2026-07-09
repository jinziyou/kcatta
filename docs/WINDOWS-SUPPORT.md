# kcatta 是否支持 Windows —— 决策文档

> 决策版评估。回答的问题是：**在 Windows 已自带 Defender 的前提下，kcatta 上 Windows 还有没有意义。**
> 结论先行——「要不要支持 Windows」是个伪二元问题，应**按三大能力分层决策**：让 Windows 主机
> 在态势图里「可见」非常有意义，但把端点检测/响应原样移植过去基本没意义。
>
> 仓库级架构见 [`../ARCHITECTURE.md`](../ARCHITECTURE.md)，演进路线见 [`ROADMAP.md`](./ROADMAP.md)。

## 1. 核心结论

kcatta 的 agent 是三个相互独立的能力（**host / trace / guard**），它们在「Defender 已存在」下的
性价比完全不同。一刀切地「全量移植到 Windows」没意义，但**让 Windows 主机在 kcatta 的态势图里可见
非常有意义**。

关键在于定位：kcatta 的价值不是「再做一个端点杀毒」，而是**跨异构主机的统一态势 + 关联分析 +
攻击路径预测**——而 Defender 恰恰不进你这张图。

> **一句话**：把 kcatta 在 Windows 上定位成「**态势 + 关联层**，消费并补全 Defender」，而不是
> 「再来一个端点 EDR」——这样有意义；反过来想做第二个 Defender，基本没意义。

## 2. 为什么 Defender 改变了算法

Defender（尤其 MDE + Defender 漏洞管理 MDVM）在 Windows 上很强，且与 kcatta 能力高度重叠：

- MDE ≈ kcatta 的 **guard + trace**（实时防护 / 行为 / 网络）；
- MDVM ≈ kcatta 的 **host**（软件清单 / CVE / 配置基线）。

所以正面硬刚端点检测，kcatta 大概率打不过、也没必要打。**但 Defender 有三个致命的「在场缺口」**，
正好是 kcatta 的机会：

1. **数据落在微软云，不落在 analyzer**。Defender 的发现进不了 kcatta 的资产模型 / 关联引擎 /
   `attack-paths` 图。攻击路径预测一旦对 Windows 主机睁眼瞎，整张图就是残缺的。
2. **MDVM（漏洞/态势那部分）是付费 add-on**（E5 / MDE P2）。很多组织只有免费的 Defender AV，
   根本没有清单 / CVE 能力。
3. **主权 / 离线 / 合规场景**。面向蓝队自建的环境往往不愿/不能用 MDE 云，要的是**自托管、可审计、
   数据不出境**的态势平台。在这种语境下，「Defender 存在」几乎不构成反对理由。

## 3. 按三大能力分层评估

| 能力 | 现状（技术依赖） | Windows + Defender 下是否值得 |
| --- | --- | --- |
| **host**（静态文件 / 资产 / CVE / SBOM / 配置采集） | 读文件系统 / 包管理器，**无内核依赖** | ✅ **最值得**。移植成本最低（改成读注册表 / WMI / MSI / 服务 / 证书），且与 Defender **互补**——填上混合机群的态势盲区，数据进 kcatta 自己的图。 |
| **trace**（eBPF 网络 / 文件 / 进程追踪） | eBPF，**Linux 内核专属** | ⚠️ **成本最高**。Windows 上需换成 ETW / Sysmon 重写一遍（eBPF-for-Windows 不成熟）。仅在「关联引擎确实需要 Windows 侧遥测」时再做。 |
| **guard**（实时防护 / 主动处置） | on-access 查毒 / cgroup 阻断，Linux 原语 | ❌ **最不值得**。这正是 Defender 的主场，要它需要 minifilter 驱动 / AMSI / WFP 全套，投入巨大且大概率不如 Defender。**应「消费 Defender」而非替代它。** |

## 4. 推荐路线（分层，而非「支持 / 不支持」）

1. **先做 Windows 静态态势采集（host 等价物）**——注册表 / WMI / 已安装软件 / 服务 / 账户 /
   RDP & 证书配置 / 补丁级别 → 喂 analyzer 的 CVE 与攻击路径。ROI 最高，纯用户态、无驱动，
   且与 Defender 不打架。README 中 deploy 层已提到 **WinRM**，投放通道本就给 Windows 留了口子。
2. **检测 / 响应不要自己造，改成「接 Defender」**——通过 Windows 事件日志 / Sysmon / MDE API
   把 Defender 的告警 ingest 进 analyzer。Windows 主机在关联图里既有「态势」又有「检测信号」，
   成本只是写个采集 / 解析，而非一套内核栈。
3. **trace / guard 的原生 Windows 实现先搁置**，等有明确需求（尤其是不能用 MDE 的离线 / 主权
   场景）再评估 ETW 路线。

## 5. 待核实（把成本落到数字）

- **host 采集器的 Linux 专属度**：统计 `agent-collect-host` 里 `#[cfg(target_os = "linux")]` 与
  Linux-only 系统调用 / 路径假设的比例，估 Windows 移植真实工作量。
- **deploy 层 WinRM 现状**：确认是已实现的投放通道，还是仅停留在文档/契约里。
- **契约影响面**：Windows 资产（注册表项、服务、MSI、Defender 告警）能否落进现有
  `AssetReport` / `GuardEventBatch` 契约，还是需要扩 schema（牵动 Pydantic→JSON Schema→Rust/TS
  漂移门禁）。
