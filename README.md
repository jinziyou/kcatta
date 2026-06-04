# cyber-posture

> 安全态势综合管理平台 —— 通过「主机 + 网络」双维度采集与智能关联分析，让安全团队实时掌握整体安全状态。

本仓库是一个 **monorepo**，由三个相互独立但协同工作的组件构成：

| 组件 | 语言 / 技术栈 | 角色 | 子目录 |
| --- | --- | --- | --- |
| **probe** | Rust | 「主机 + 网络」双维度采集探针：主机端资产与风险采集（软件包、SBOM、服务、账户、SSH 公钥指纹、ClamAV）+ 网络流量元数据与威胁情报旁路采集（会话、协议、外联、IOC 命中）；CVE 匹配在 form 侧 | [`probe/`](./probe) |
| **form** | Python | 数据标准化、关联分析、风险评分与态势感知后端 | [`form/`](./form) |
| **portal** | Node.js / Next.js / Shadcn-ui / Tailwind | 管理控制台、可视化大屏、告警处置、扫描策略管理 | [`portal/`](./portal) |

## 数据流（高层视图）

```
 ┌────────────────────────────┐
 │            probe           │
 │   probe-host   probe-flow  │   ← 主机批扫 + 网络抓包（独立二进制，共享契约/上报）
 └───────┬────────────┬───────┘
         │            │
         ▼            ▼
       ┌────────────────┐
       │      form      │  ← 关联分析 / 风险评分 / 入库
       └───────┬────────┘
               ▼
       ┌────────────────┐
       │     portal     │  ← 大屏 / 资产 / 告警 / 策略
       └────────────────┘
```

## 仓库结构

```
cyber-posture/
├── README.md              # 顶层架构说明（本文）
├── .gitignore
├── probe/                 # Rust workspace（主机 + 网络采集探针）
├── form/                  # Python project
└── portal/                # Next.js app
```

每个子目录是相对自治的开发单元，拥有自己的构建工具链与说明文档。根目录提供 **Makefile** 与 **GitHub Actions CI** 作为跨组件快捷入口，各组件仍按其语言原生工具链独立构建。

## 开发约定

- **语言版本**：Rust stable、Python ≥ 3.11、Node.js LTS。
- **代码风格**：交由各子目录的 lint / formatter 配置约束（`rustfmt` / `ruff` / `eslint + prettier`）。
- **提交规范**：建议使用 [Conventional Commits](https://www.conventionalcommits.org/)。
- **分支模型**：`main` 为发布分支；开发请走 feature 分支并通过 PR 合入。
- **跨组件接口**：probe 上报的数据契约（schema）以 form 端为准，维护于 `form/src/form/schemas/` 与 `form/schemas-json/`；Rust 侧镜像见 `probe/crates/probe-contract/`。

## probe 能力概览

probe 是 Rust workspace，职责边界为 **只采集、不分析**（CVE 判定与关联分析交给 form），按「主机（内视）+ 网络（外视）」两个领域拆分，编译为多个独立二进制，共享 `probe-contract`（数据契约）与 `probe-ingest`（上报客户端）。

**主机域（probe-host / 内视）**

| 能力 | 入口 |
| --- | --- |
| 本机 / 挂载目录静态扫描（包、SBOM、服务、账户、SSH 指纹） | `probe-asset`、`probe-host` |
| ClamAV 病毒查杀 | `probe-malware` |
| 合并 `AssetReport` + 上报 form | `probe-host --upload` |
| SSH 远端 agent 扫描 | `probe-remote` |

**网络域（probe-flow / 外视）**

| 能力 | 入口 |
| --- | --- |
| 流量元数据采集（mock 默认；pcap 需 `--features pcap`） | `probe-flow` |
| 威胁情报 IOC 匹配（IP / 域名 / JA3） | `probe-flow`（`probe_flow::intel`） |
| 情报库自动同步（abuse.ch Feodo 等） | `probe-intel-sync` |
| 上报 `FlowBatch` → form | `probe-flow --upload` |

详细用法与架构见 [`probe/README.md`](./probe/README.md)、[`probe/docs/ARCHITECTURE.md`](./probe/docs/ARCHITECTURE.md)。

## form 关联分析

form 接收 probe-flow 上报的、已带威胁情报命中（`FlowEvent.threat_intel`）的 `FlowBatch`，
按指标(IOC)聚合关联成 `Alert`（命中同一指标的多条流合并为一条告警），经 `/reports/alerts`
暴露给 portal。详见 [`form/README.md`](./form/README.md)。

## 构建与 CI

```bash
make test-all            # probe + form + portal（单元/集成，不含 e2e）
make lint-all
make schema-check        # form JSON Schema 导出一致性
make contracts-check     # portal TS 契约生成一致性
make test-portal-e2e     # Playwright（form + portal 栈）
docker compose up --build   # 本地 form + portal（SQLite + 可选鉴权）
```

Push 与 PR 会触发 GitHub Actions：`probe`、`form`、`portal`、`e2e` 四个 job 并行运行。环境变量模板见 [`.env.example`](./.env.example)。

## 快速开始

请进入对应子目录查看各自的 README：

- [`probe/README.md`](./probe/README.md)
- [`form/README.md`](./form/README.md)
- [`portal/README.md`](./portal/README.md)
