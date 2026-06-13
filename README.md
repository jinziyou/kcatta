# kcatta

> 安全态势综合管理平台 —— 通过「主机 + 网络」双维度采集与智能关联分析，让安全团队实时掌握整体安全状态。

本仓库是一个 **monorepo**，由三个相互独立但协同工作的组件构成：

| 组件 | 语言 / 技术栈 | 角色 | 子目录 |
| --- | --- | --- | --- |
| **agent** | Rust | 三大能力、三独立二进制：**主机静态文件检测**（`agent-host`：包/SBOM/服务/账户/SSH 指纹 + 内置签名查毒）、**流量检测**（`agent-flow`：流量元数据 + 威胁情报 IOC）、**实时防护**（`agent-guard`：FIM/on-access/行为/网络 实时检测 + 端上主动处置）；CVE 匹配在 fusion 侧 | [`agent/`](./agent) |
| **fusion** | Python | 数据标准化、关联分析、风险评分、攻击路径预测（ingest 外部红队能力图）与态势感知后端 | [`fusion/`](./fusion) |
| **portal** | Node.js / Next.js / React / Tailwind CSS / Shadcn-ui 风格组件（@base-ui/react） | 管理控制台、可视化大屏、告警处置、扫描策略管理 | [`portal/`](./portal) |

## 数据流（高层视图）

```
 ┌────────────────────────────┐
 │            agent          │
 │ agent-host/flow/guard │   ← 主机静态文件检测 + 流量检测 + 实时防护（三独立二进制，共享契约/上报）
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

**检测全链路（主动触发，闭环）**：portal `/targets` 注册目标 + `/scans` 触发 → fusion `POST /scans` 建异步作业、复用 deploy 层投放 agent（host/flow 一次性拉回、guard 常驻 `agent guard --upload`）→ agent 采集并（经 fusion 入库路径）落 `AssetReport`/`FlowBatch`/`GuardEventBatch` + CVE/查毒检测与 IOC 关联 → portal `/scans/[jobId]` 轮询状态并查看本次结果（`/reports`、`/vulnerabilities`、`/flows`、`/guard`）。凭据为 fusion 主机上的托管 SSH 密钥（注册时一次性密码 bootstrap 后丢弃，不持久化）。

## 仓库结构

```
kcatta/
├── README.md              # 顶层架构说明（本文）
├── SECURITY.md            # 部署与安全须知
├── Makefile               # 跨组件任务快捷入口
├── docker-compose.yml     # 本地 fusion + portal 栈
├── .env.example           # 环境变量模板
├── .gitignore
├── .github/               # GitHub Actions CI（workflows/ci.yml）
├── agent/                 # Rust workspace（主机 + 网络采集探针）
├── fusion/                # Python project
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

agent 是 Rust workspace，分为**三大能力、三独立二进制**（一个能力 = 一个目录 = 一个 crate），
共享 `contract` 数据契约底座：

- **主机静态文件检测（`agent-host`）**：本机 / 挂载目录静态扫描（包、SBOM、服务、账户、SSH 指纹）+ 内置签名查毒，产出 `AssetReport`（CVE 判定交给 fusion）。
- **流量检测（`agent-flow`）**：流量元数据采集 + 威胁情报 IOC 匹配与情报库同步，产出 `FlowBatch`。
- **实时防护（`agent-guard`）**：长驻守护（FIM / on-access 查毒 / 进程行为 / 网络 IOC / IDS 实时检测），可选端上主动处置（默认全关），产出 `GuardEventBatch`。

**三种运行方式**：① 三独立二进制各自运行（只产出本地结果，不上报）；② 统一 `agent`
命令（umbrella，子命令 `host`/`flow`/`guard`，`--upload` 时上报 fusion）；③ 由 **fusion**
的 `fusion-scan` 经 SSH 远程调度。

flag 级用法与架构详见 [`agent/README.md`](./agent/README.md)、[`agent/docs/ARCHITECTURE.md`](./agent/docs/ARCHITECTURE.md)（以其为准）。

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
make build-agent-deploy  # 静态(musl,x86_64) agent 部署二进制（fusion 远程投放产物；需 musl-tools）
make build-agent-deploy-arm64  # 同上，aarch64（用 cross）；fusion 按目标 arch 自动选
make test-portal-e2e     # Playwright（fusion + portal 栈）
cp .env.example .env        # 然后设置强随机 FUSION_API_TOKEN（compose 无内置默认，必填）
docker compose up --build   # 本地 fusion + portal（SQLite + bearer 鉴权）
```

Push 与 PR 会触发 GitHub Actions，多个 job 并行运行：`agent`、`fusion`、`portal` 各组件构建测试，两个 agent musl 部署构建（x86_64 / aarch64），`security-audit` 依赖漏洞扫描（非阻断），以及 `e2e`（详见 [`.github/workflows/ci.yml`](./.github/workflows/ci.yml)）。环境变量模板见 [`.env.example`](./.env.example)。

## 快速开始

请进入对应子目录查看各自的 README：

- [`agent/README.md`](./agent/README.md)
- [`fusion/README.md`](./fusion/README.md)
- [`portal/README.md`](./portal/README.md)
