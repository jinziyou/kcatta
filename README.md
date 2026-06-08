# posture

> 安全态势综合管理平台 —— 通过「主机 + 网络」双维度采集与智能关联分析，让安全团队实时掌握整体安全状态。

本仓库是一个 **monorepo**，由三个相互独立但协同工作的组件构成：

| 组件 | 语言 / 技术栈 | 角色 | 子目录 |
| --- | --- | --- | --- |
| **agent** | Rust | 「主机 + 网络」双维度采集探针：主机端资产与风险采集（软件包、SBOM、服务、账户、SSH 公钥指纹、ClamAV）+ 网络流量元数据与威胁情报旁路采集（会话、协议、外联、IOC 命中）；CVE 匹配在 fusion 侧 | [`agent/`](./agent) |
| **fusion** | Python | 数据标准化、关联分析、风险评分、攻击路径预测（ingest 外部红队能力图）与态势感知后端 | [`fusion/`](./fusion) |
| **portal** | Node.js / Next.js / React / Tailwind CSS / Shadcn-ui 风格组件（@base-ui/react） | 管理控制台、可视化大屏、告警处置、扫描策略管理 | [`portal/`](./portal) |

## 数据流（高层视图）

```
 ┌────────────────────────────┐
 │            agent          │
 │   agent host   agent flow│   ← 主机批扫 + 网络抓包（单一 agent 二进制的子命令，共享契约/上报）
 └───────┬────────────┬───────┘
         │            │
         ▼            ▼
       ┌────────────────┐
       │      fusion      │  ← 关联分析 / 风险评分 / 入库
       └───────┬────────┘
               ▼
       ┌────────────────┐
       │     portal     │  ← 大屏 / 资产 / 告警 / 策略 / 攻击路径
       └────────────────┘
```

> fusion 另可 ingest 一份**外部红队能力图**（`POST /ingest/capability-graph`，opaque JSON——由独立红队工具产出、不属本仓库），结合观测态势前向推导**预测攻击路径**（`GET /attack-paths`），供 portal 的 `/attack-paths` 可视化。fusion 只消费该 JSON 契约，不感知产出方。

## 仓库结构

```
posture/
├── README.md              # 顶层架构说明（本文）
├── .gitignore
├── agent/                 # Rust workspace（主机 + 网络采集探针）
├── fusion/                  # Python project
└── portal/                # Next.js app
```

每个子目录是相对自治的开发单元，拥有自己的构建工具链与说明文档。根目录提供 **Makefile** 与 **GitHub Actions CI** 作为跨组件快捷入口，各组件仍按其语言原生工具链独立构建。

## 开发约定

- **语言版本**：Rust stable、Python ≥ 3.11、Node.js LTS。
- **代码风格**：交由各子目录的 lint / formatter 配置约束（`rustfmt` / `ruff` / `eslint + prettier`）。
- **提交规范**：建议使用 [Conventional Commits](https://www.conventionalcommits.org/)。
- **分支模型**：`main` 为发布分支；开发请走 feature 分支并通过 PR 合入。
- **跨组件接口**：agent 上报的数据契约（schema）以 fusion 端为准，维护于 `fusion/src/fusion/schemas/` 与 `fusion/schemas-json/`；Rust 侧镜像见 `agent/crates/contract/`（包名 `agent-contract`）。

## agent 能力概览

agent 是 Rust workspace，职责边界为 **只采集、不分析**（CVE 判定与关联分析交给 fusion），按职责拆成 **5 个扁平 crate**（`contract` / `ingest` / `host` / `flow` / `runtime`），编译为 **单一 `agent` 二进制**——`runtime` 通过子命令调度 `host` / `flow` 模块。跨机投放/调用/取回由 **fusion** 调度（见 fusion 的 `fusion-scan`）。

**主机域（`agent host` / 内视）**

| 能力 | 入口 |
| --- | --- |
| 本机 / 挂载目录静态扫描（包、SBOM、服务、账户、SSH 指纹） | `agent host -t … -o DIR`（分文件 JSON） |
| 合并 `AssetReport`（stdout / 文件 / 上报） | `agent host`（不带 `-o`；`--report-out` / `--upload`） |
| ClamAV 病毒查杀 | `agent host --malware`（需 `--features malware`） |
| SSH/WinRM 远端 agent 扫描 | fusion 的 `fusion-scan`（投放 `agent` 探针；已由 agent-remote 上移到 fusion） |

**网络域（`agent flow` / 外视）**

| 能力 | 入口 |
| --- | --- |
| 流量元数据采集（mock 默认；pcap 需 `--features pcap`） | `agent flow` |
| 威胁情报 IOC 匹配（IP / 域名 / JA3） | `agent flow`（`agent_flow::intel`） |
| 情报库自动同步（abuse.ch Feodo 等） | `agent intel-sync` |
| 上报 `FlowBatch` → fusion | `agent flow --upload` |

详细用法与架构见 [`agent/README.md`](./agent/README.md)、[`agent/docs/ARCHITECTURE.md`](./agent/docs/ARCHITECTURE.md)。

## fusion 关联分析

fusion 接收 agent-flow 上报的、已带威胁情报命中（`FlowEvent.threat_intel`）的 `FlowBatch`，
按指标(IOC)聚合关联成 `Alert`（命中同一指标的多条流合并为一条告警），经 `/reports/alerts`
暴露给 portal。详见 [`fusion/README.md`](./fusion/README.md)。

## 构建与 CI

```bash
make test-all            # agent + fusion + portal（单元/集成，不含 e2e）
make lint-all
make schema-check        # fusion JSON Schema 导出一致性
make contracts-check     # portal TS 契约生成一致性
make test-portal-e2e     # Playwright（fusion + portal 栈）
cp .env.example .env        # 然后设置强随机 FUSION_API_TOKEN（compose 无内置默认，必填）
docker compose up --build   # 本地 fusion + portal（SQLite + bearer 鉴权）
```

Push 与 PR 会触发 GitHub Actions：`agent`、`fusion`、`portal`、`e2e` 四个 job 并行运行。环境变量模板见 [`.env.example`](./.env.example)。

## 快速开始

请进入对应子目录查看各自的 README：

- [`agent/README.md`](./agent/README.md)
- [`fusion/README.md`](./fusion/README.md)
- [`portal/README.md`](./portal/README.md)
