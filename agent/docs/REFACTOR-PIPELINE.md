# agent 目标架构：流水线四层重构方案

> **状态**：**P0–P3 已完成**。权威架构说明见 [`ARCHITECTURE.md`](./ARCHITECTURE.md)。  
> **上手与构建**：[`../README.md`](../README.md)。  
> 本文保留动机、边界与迁移史；新贡献以 ARCHITECTURE 为准。

本文汇总对 `agent` 模块重构的评估结论：在保留契约、上报不变量与可独立部署能力的前提下，将端点逻辑按 **agentd · collect · detect · respond** 四层组织，并在 `collect` / `detect` 下按可复用边界再分子模块。

---

## 1. 背景与动机

### 1.1 现状（能力轴）

当前 workspace（`crates/`）按**观测能力**组织：

| 目录 | 包名 | 角色 |
| --- | --- | --- |
| `contract/` | `agent-contract` | 数据契约（DAG 根） |
| `host/` | `agent-collect-host` | 主机静态采集 + **内嵌** malware/posture/secrets/sbom |
| `trace/` | `agent-collect-trace` | 捕获 + **同调用内** IOC enrich |
| `guard/` | `agent-respond` | sensors → decide → respond（唯一可主动处置） |
| `agentd/` | `agentd` | 编排 + 唯一上报（ingest/spool） |
| `ebpf/` | `agent-ebpf` | 内核支撑 |

不变量（必须保留）：

1. **host / trace 路径不上报**；上报仅 `agentd`（`--upload` / `run`）。
2. **CVE / 跨源关联**在 Python **`analyzer/`**，不在 agent。
3. **端上主动处置**仅 respond 层（今日为 guard）；默认 monitor + safety 否决。
4. **契约单源**：analyzer Pydantic → JSON Schema → `agent-contract`。
5. **依赖单向无环**；lib 含 `cli`，bin 为薄壳。

### 1.2 痛点

- **`agent-collect-host` 体量过大**（约一半 agent Rust LOC），采集与本地分析混装。
- **采集与分析同调用**：如 `run_capture_with_detect` 一次完成 capture + `ThreatFeed::enrich`。
- **复用面过宽**：guard on-access 为 `scan_bytes` 却可选依赖整个 `agent-collect-host`。
- **文档语言与流水线不一致**：guard 已是 sensor → decide → respond，顶层却无「处置」一等名。

### 1.3 已否决与已采纳

| 提案 | 结论 |
| --- | --- |
| 仅三模块：agentd / scanner / analyzer | **否决为顶层切分**——放不下处置；且 `analyzer` 与 Python `analyzer/` 撞名 |
| 四模块：agentd / 采集 / 分析 / 处置 | **采纳为架构语言** |
| 英文目录：`agentd` / `collect` / `detect` / `respond` | **采纳**（`detect` 避免 analyzer 撞名） |
| 四扁仓、不再细分 | **否决**——`collect` 会变成更大上帝 crate |
| 根目录直接放四模块（去掉 `crates/`） | **可选**；本方案默认仍放 **`crates/`**，与现仓库一致 |
| 嵌套 Cargo workspace | **禁止**——根 `Cargo.toml` 扁平 `members` |

---

## 2. 目标原则

1. **两轴并存，职责不同**  
   - **流水线轴**（文档 / 依赖方向）：`collect → detect → respond`，`agentd` 调度与上报。  
   - **实现轴**（crate / 部署）：`collect` / `detect` 下再按来源或引擎分包；二进制可继续按能力裁剪。

2. **collect：按信息来源划分，输出为资产**  
   - **划分轴** = 信息来源（host 文件系统/注册表/包库、trace 网卡/连接表/eBPF…），不是 `Asset` 变体、也不是检测引擎。  
   - **产出** = 资产侧事实：`HostInfo`、`Asset`（Package/Service/Port/…），以及 trace 侧尚未 enrich 的观测事件。  
   - **禁止**在 collect 内产生引擎语义 finding（`Vulnerability`、IOC `ThreatMatch`）。finding 只来自 detect；合并进 `AssetReport` / 标注进 `TraceBatch` 由编排层完成。  
   - 一种来源可产出多种 `Asset`；**禁止**「一个 Asset 变体一个 collect crate」。

3. **子模块粒度**  
   - **独立 crate**：不同依赖矩阵、被 ≥2 消费者复用、或需独立裁剪进部署包。  
   - **crate 内 `mod`**：同依赖、无独立消费者（如 dpkg/apk/rpm；respond 内各动作后端）。

4. **窄依赖**  
   - `respond` 只依赖 detect 的窄 API（如 `scan_bytes`、`ThreatFeed`），不依赖完整 `collect-host` 树。

5. **命名**  
   - 端上检测层目录/包名用 **`detect`**（或 `agent-detect-*`），**禁止**再引入 agent 侧 crate 名 `analyzer`。

6. **decide 归属**  
   - **策略决策（decide）与执行（respond）同属 `respond` crate**（今日 guard 后半段）。  
   - `detect` 只产出 finding / `Detection` 级结果，不直接改系统状态。

---

## 3. 目标目录与 crate 布局

### 3.1 目录树（目标）

```
agent/
├── Cargo.toml                 # workspace：扁平 members（无嵌套 workspace）
├── README.md
├── docs/
│   ├── ARCHITECTURE.md        # 现状 + 指向本文
│   ├── REFACTOR-PIPELINE.md   # 本文（目标方案）
│   └── …
└── crates/
    ├── contract/              # 保持：agent-contract
    ├── ebpf/                  # 保持：agent-ebpf
    ├── agentd/                # 保持角色：编排 + ingest + spool
    ├── collect/
    │   ├── host/              # crate：静态主机事实（现 host 采集侧）
    │   └── trace/             # crate：网络/文件/进程捕获（现 trace 采集侧）
    ├── detect/
    │   ├── malware/           # crate：签名/哈希引擎（优先抽出；respond 复用）
    │   └── …                  # umbrella 或并列：posture / secrets / ioc / sbom
    └── respond/               # crate：sensors 编排 + decide + safety + actions + report
                               # （现 respond 主体；部署 bin `agent-respond`，见 §6）
```

> **sensors 归属**：起步将实时事件源留在 `respond`（与 decide/respond 同进程生命周期）。若某 sensor 变为纯无策略事件源且被多处复用，再抽到 `collect/sensors`。

### 3.2 Workspace members（示意）

```toml
members = [
    "crates/contract",
    "crates/collect/host",
    "crates/collect/trace",
    "crates/detect/malware",
    "crates/detect",              # umbrella：posture/secrets/ioc/sbom + re-export（可分期）
    "crates/respond",
    "crates/agentd",
    "crates/ebpf",
]
default-members = [
    "crates/contract",
    "crates/collect/host",
    "crates/collect/trace",
    "crates/detect/malware",
    "crates/detect",
    "crates/respond",
    "crates/agentd",
]
```

包名建议（可与目录对齐，前缀保持 `agent-` 以降低迁移噪音）：

| 目录 | 建议 package name | lib name |
| --- | --- | --- |
| `collect/host` | `agent-collect-host` | `agent_collect_host` |
| `collect/trace` | `agent-collect-trace` | `agent_collect_trace` |
| `detect/malware` | `agent-detect-malware` | `agent_detect_malware` |
| `detect`（umbrella） | `agent-detect` | `agent_detect` |
| `respond` | `agent-respond` | `agent_respond` |
| `agentd` | `agentd` | （bin only，可保持） |

部署主名见 §6。

### 3.3 子模块怎么拆

#### collect（按信息来源拆 crate；输出资产）

| 子模块 | 信息来源 | 产出（资产侧） | 粒度 |
| --- | --- | --- | --- |
| `collect/host` | 主机 FS / 注册表 / 包库 / 容器元数据 | `HostInfo` + `Asset`；可选 SBOM 导出（由包资产派生） | **crate** |
| `collect/trace` | 网卡 / 连接表 / eBPF 观测 | 未 enrich 的 `TraceEvent` 等观测事实（契约上尚未并入 `Asset` 枚举） | **crate** |
| `packages/{dpkg,apk,rpm,…}` | 各包管理器路径 | `Asset::Package` | **host 内 mod** |
| `collect/sensors`（可选后期） | 纯事件源 | 无策略原始事件 | 仅当与 respond 解耦且有第二消费者时再拆 |

> **验收（已满足）**：`Collector` / `capture_batch` 成功路径不返回 finding / IOC 标注；detect 由编排层 `run_detect_at` / `enrich_batch` 完成。

#### detect（按引擎拆，不按 Asset 枚举）

| 子模块 | 职责 | 粒度 |
| --- | --- | --- |
| `detect/malware` | `SignatureSet` / `scan_bytes` / 文件扫描 → finding | **优先独立 crate** |
| posture / secrets | 配置与密钥类 finding | 先 **detect umbrella 内 mod**，体量与复用稳定后再拆 crate |
| ioc | 现 `ThreatFeed::enrich`；输入原始 `TraceEvent`，输出带 `ThreatMatch` 的事件 | umbrella mod 或 `detect/ioc` crate |
| sbom | CycloneDX 组装 | umbrella mod |

**禁止**：按 `Asset::Package|Service|Port|…` 为每个变体建 detect crate——资产类型属于 **contract + collect 组装**，不是检测引擎边界。

#### respond（单 crate + 内部 mod）

| 内部 mod（示意） | 职责 |
| --- | --- |
| `sensors` | fim / behavior / onaccess / network / ids（起步） |
| `decide` | monitor / enforce 策略 → `Action` |
| `safety` | 否决关键路径 / PID1 / 回环等 |
| `actions` | quarantine / netblock / deny-open / kill |
| `report` | `GuardEventBatch` + `ReportSink` |
| `supervisor` | 线程与优雅停机 |

动作后端（nft vs eBPF netblock）保持 **同 crate 内 mod / feature**，除非未来需要独立发布某后端。

#### agentd（不拆）

保持：`run` 调度、`ingest`、`spool`、CLI 分发、feature 转发。不内嵌采集/检测实现细节。

---

## 4. 模块边界（可验收）

| 模块 | 允许 | 禁止 |
| --- | --- | --- |
| **collect** | 按来源读系统 → **资产**（`HostInfo`/`Asset`）或未判定观测事件；来源内 mod 细分 | 引擎语义 `Vulnerability` / IOC 标注；改系统状态；HTTP 上报；按 Asset 变体拆 crate |
| **detect** | 消费资产或原始事实 → finding / `Detection` / IOC 标注；供 CLI/lib 单测 | CVE/OSV（属 Python analyzer）；隔离/杀进程/阻断；自行上报；按 Asset 变体硬切引擎 crate |
| **respond** | 消费 Detection；decide + safety + ledger；执行 Action；产出 `GuardEvent` 结果字段 | 全量主机扫描实现；绕过 safety；默认 enforce；拥有上报 HTTP 客户端 |
| **agentd** | 调度 collector/detect 计划；注入 `ReportSink`；spool；POST ingest | 在能力 crate 内开上报通道；复制 detect/respond 业务逻辑 |

数据流：

```
collect ──事实──► detect ──finding / Detection──► respond（可选）
                      │
                      ▼
              envelope（AssetReport / TraceBatch / GuardEventBatch）
                      │
                      ▼
                   agentd ingest ──► Python analyzer
```

周期路径（host/trace）通常 **collect → detect → 写文件 / 交 agentd 上报**，不经 respond。  
实时路径：**respond.sensors → detect（窄 API）→ decide → actions → report →（agentd 注入的 sink）**。

---

## 5. 目标依赖 DAG

```
agent-contract
      ▲
      │
collect-host · collect-trace · detect-*（malware / …）
      ▲                              ▲
      │                              │
      └──────── agent-respond ───────┘
                    ▲
                    │
                 agentd

agent-ebpf ◄── collect-trace / respond   （feature ebpf，与今日相同）
```

规则：

- `detect-*` **不**依赖 `respond`。
- `collect-*` **不**依赖 `detect-*`（组装顺序由调用方 / agentd / respond 编排；避免 collect↔detect 环）。
- 若某 collector 适配器需要「采集后立刻跑 detect」，适配器放在 **agentd** 或 **detect umbrella 的 facade**，或 thin 的 `collect` bin `cli` 中编排，而不是让 `collect-host` lib 依赖 `detect-malware`。
- `respond` → `detect-malware` / `detect`（ioc）为 **optional feature**（对应当今日 `onaccess` / `network`）。

> 编排例外：今日 `MalwareCollector` 实现 `Collector` 并在 `run_scan_at` 计划中执行。迁移后等价物为 agentd / host-cli **先** `collect` **再**调用 detect，或 detect 提供 `MalwareCollector` 适配器 crate/模块依赖 collect 的上下文类型（`ScanContext`）——优先把 `ScanContext` 下沉到 `contract` 或小 `collect-core` 以免环依赖。具体实现在 P0 设计记录中选定一种并写进 ARCHITECTURE。

---

## 6. 二进制与兼容

| 角色 | 部署 / analyzer / package / bin 主名 |
| --- | --- |
| 主机采集（+可选 detect CLI） | **`agent-collect-host`** |
| 追踪采集 | **`agent-collect-trace`** |
| 实时防护 | **`agent-respond`** |
| 编排 | **`agentd`**（子命令 `collect-host` / `collect-trace` / `respond`；别名 `host` / `trace` / `guard`） |

- **包名 / lib / 部署主名**已切到流水线名；musl deploy 与 analyzer `resolve_agent_binary` 同步。  
- 旧独立 bin 名（`agent-host` 等）已移除；`agentd` 保留短子命令别名以兼容既有脚本与文档。

CLI 模式不变：**领域逻辑 + `pub mod cli` 在 lib；bin 薄壳；agentd 复用同一 `cli`**。

---

## 7. 与 Python analyzer 的职责切分

| 层级 | 负责 | 不负责 |
| --- | --- | --- |
| agent **detect** | 端上签名查毒、posture、secrets、IOC 标注、SBOM | CVE/OSV、跨主机关联、攻击路径 |
| Python **analyzer** | ingest、CVE、跨源关联、攻击路径、远程投放调度 | 端上 fanotify/隔离执行 |

文档与代码评审中统一用语：**「analyzer」仅指 Python 服务**；端上称 **detect**。

---

## 8. 迁移阶段

每阶段结束须：`cargo test --workspace`（及既有 feature 矩阵关键子集）通过；契约测试不漂移。

### P0 — 抽出 `detect/malware`（最高价值、最低风险） — **已完成（2026-07-09）**

1. ~~新建 `crates/detect/malware`，迁入现 `host/src/malware.rs` 及测试。~~  
2. ~~`agent-collect-host` / `agent-respond`（onaccess）改为依赖该 crate；`scan_bytes` 路径不变。~~  
   - `agent-collect-host`：`malware` 模块改为 re-export + `MalwareCollector` 适配器。  
   - `agent-respond` `onaccess`：直接依赖 `agent-detect-malware`（不再拉整棵 `agent-collect-host`）。  
3. ~~验证：host `--malware`、guard onaccess 单测/集成行为不变。~~

### P1 — 目录归位（流水线顶层可见） — **已完成（2026-07-09）**

1. ~~`crates/host` → `crates/collect/host`（package 名仍为 `agent-collect-host`）。~~  
2. ~~`crates/trace` → `crates/collect/trace`（package 名仍为 `agent-collect-trace`）。~~  
3. ~~`crates/guard` → `crates/respond`（package 名仍为 `agent-respond`）。~~  
4. ~~更新根 `Cargo.toml` members、README、文档路径。~~  
5. ~~不改变对外 bin 名~~（`agent-collect-host` / `agent-collect-trace` / `agent-respond` / `agentd` 保持）。

### P2 — 采集与检测调用切开 — **已完成（2026-07-09）**

1. ~~`collect/trace`：`capture_batch`（只采集）与 `ThreatFeed::enrich` 分 API；`run_capture_with_detect` = capture + enrich 便利包装。~~  
2. ~~posture / secrets 迁入 `crates/detect`（`agent-detect` umbrella）；malware 已在 P0。~~  
   - **sbom 暂留 `collect/host`**：与 `collect_packages` / `read_distro` / 包源强耦合，强迁会拉环依赖；记入后续可选拆分。  
3. ~~分析型 Collector 变为薄适配器~~（`PostureCollector` / `SecretsCollector` / `MalwareCollector` 调 detect 引擎）。  
4. ~~文档化双路径~~：`scan_runner`（合并 `AssetReport`）vs `scan`（`-o DIR` 分文件）；见 `scan_runner.rs` 模块注释。

### P3 — 文档与命名收口 — **已完成（2026-07-09）**

1. ~~重写 [`ARCHITECTURE.md`](./ARCHITECTURE.md) 以流水线轴为主、部署二进制为辅。~~  
2. ~~CONTRIBUTING / crates README / agent README 同步；「analyzer」仅指 Python。~~  
3. ~~package / bin / musl / analyzer 主名切换为 `agent-collect-host` / `agent-collect-trace` / `agent-respond`；旧独立 bin 已移除。~~  
4. ~~`agentd` 主子命令切为 `collect-host` / `collect-trace` / `respond`（别名 `host` / `trace` / `guard`）。~~

### 后续（P3 之后可选） — **已完成（2026-07-09；SBOM 刻意保留）**

| 项 | 状态 | 说明 |
| --- | --- | --- |
| IOC enrich → detect | **已完成** | `ThreatFeed` / `FeedIndicator` 在 `agent_detect::ioc`；trace `intel` re-export；`intel::sync` 仍在 collect/trace |
| collect 输出=资产（编排两步） | **host + trace 已落地** | host：`detect_phase` + `run_scan_with_detect`。trace：编排显式 `capture_batch` → `enrich_batch`；`run_capture_with_detect`；CLI `--no-intel` 可 collect-only |
| 删除过渡 detect `Collector` | **已完成** | 移除 `MalwareCollector` / `PostureCollector` / `SecretsCollector`；`CollectorOutput` 仅 `Host`/`Assets` |
| SBOM | **留 collect/host** | 由包**资产**派生的导出，不是 detect finding；与「collect 输出资产」一致 |
| package / 部署主名切换 | **已完成** | package/lib/bin → `agent-collect-host` / `agent-collect-trace` / `agent-respond`；Makefile musl + analyzer 同步 |
| 收尾 | **已完成** | 删兼容 bin；删 `run_capture_with_config`；`agentd` 主子命令切流水线名；host 去 malware re-export；CI/文档收口 |

### 明确不做（本方案范围外）

- 用 scanner/analyzer 三扁仓替换四层。  
- 删除 `contract` / `ebpf` 或合并进四层之一。  
- 嵌套 workspace。  
- 将 CVE 引擎下沉到 agent detect。  
- 默认打开 enforce / 削弱 safety。

---

## 9. 成功标准

| ID | 标准 |
| --- | --- |
| S1 | 依赖图无环；`respond` 不依赖完整 collect-host 源码树（仅窄 detect API + contract） |
| S2 | `cargo test --workspace` 与 musl deploy 构建保持绿 |
| S3 | 独立运行 collect/detect CLI 可只写本地文件；仅 agentd 上报 |
| S4 | 文档中「analyzer」仅指 Python；端上为 detect |
| S5 | `agent-collect-host` 迁出 detect 后 LOC 明显下降；malware 可被 respond feature 单独依赖 |

---

## 10. 现状 → 目标对照表

| 现状 | 目标 |
| --- | --- |
| `crates/agentd` | `crates/agentd`（角色不变） |
| `crates/collect/host` 采集部分 | `crates/collect/host` |
| `crates/collect/host` malware/posture/secrets | `crates/detect/…`（已迁） |
| `crates/collect/host` sbom | 留 host（资产导出） |
| `crates/collect/trace` capture | `crates/collect/trace` |
| `crates/collect/trace` intel enrich | `crates/detect`（ioc） |
| `crates/respond` | `crates/respond` |
| `crates/contract` / `ebpf` | 保持 |

---

## 11. 相关文档

| 文档 | 关系 |
| --- | --- |
| [`ARCHITECTURE.md`](./ARCHITECTURE.md) | **现状** crate DAG 与能力说明 |
| [`CONTRIBUTING.md`](./CONTRIBUTING.md) | 开发流程；架构速查将链到本文 |
| [`../README.md`](../README.md) | 使用与部署；含指向本文的「目标架构」入口 |
| [`../crates/README.md`](../crates/README.md) | crate 索引 |
| [`../../ARCHITECTURE.md`](../../ARCHITECTURE.md) | kcatta 仓级架构；agent 内设计以 agent 文档为准 |

---

## 12. 修订记录

| 日期 | 说明 |
| --- | --- |
| 2026-07-09 | 初版：综合四层流水线、crates 下细分、命名与分阶段迁移评估结论 |
| 2026-07-09 | P0 落地：新增 `crates/detect/malware`（`agent-detect-malware`）；guard onaccess 窄依赖 |
| 2026-07-09 | P1 落地：`host`/`trace` → `collect/`，`guard` → `respond/`；包名/bin 名不变 |
| 2026-07-09 | P2 落地：`capture_batch`；`agent-detect`（posture/secrets）；sbom 暂留 host |
| 2026-07-09 | P3 落地：ARCHITECTURE 流水线轴收口；bin 名保持兼容 |
| 2026-07-09 | 后续：IOC enrich 迁入 `agent-detect::ioc`；SBOM/bin 改名明确延期并记阻塞原因 |
| 2026-07-09 | 锁定：collect 按信息来源划分、输出为资产；detect 伪 Collector / 默认 enrich 列为待收敛 |
| 2026-07-09 | host 编排两步落地：`detect_phase` + `run_scan_with_detect`；CLI/agentd 接轨 |
| 2026-07-09 | trace 编排两步落地：`enrich_batch`；CLI/agentd/guard network 显式 collect→detect；`--no-intel` |
| 2026-07-09 | 删除过渡 detect Collector 适配器；`CollectorOutput` 收紧为资产-only |
| 2026-07-09 | 增加流水线 bin 别名（随后主名切换） |
| 2026-07-09 | package/bin/musl/analyzer 主名切换为 `agent-collect-*` / `agent-respond`；旧名降为兼容别名 |
| 2026-07-09 | 收尾：删兼容 bin / `run_capture_with_config`；`agentd` 主子命令切流水线名；host 去 malware re-export |
