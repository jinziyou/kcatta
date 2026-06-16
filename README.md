# kcatta

> 安全态势综合管理平台 —— 通过「主机 + 网络」双维度采集与智能关联分析，让安全团队实时掌握整体安全状态。

本仓库是一个 **monorepo**，由三个相互独立但协同工作的组件构成：

| 组件 | 语言 / 技术栈 | 角色 | 子目录 |
| --- | --- | --- | --- |
| **agent** | Rust | 三大能力 + 编排：**主机静态文件检测**（`agent-host`：包/SBOM/服务/容器/账户/SSH 指纹 + 内置签名查毒）、**eBPF 追踪**（`agent-trace`：网络流量元数据 + 文件操作 + 程序调用 + 威胁情报 IOC）、**实时防护**（`agent-guard`：FIM/on-access/行为/网络 实时检测 + 端上主动处置，含 eBPF cgroup 阻断）；伞形 `agentd` 编排调度（`agentd run`）并统一上报；CVE 匹配在 analyzer 侧 | [`agent/`](./agent) |
| **analyzer** | Python | 数据标准化、关联分析、风险评分、攻击路径预测（ingest 外部红队能力图）与态势感知后端 | [`analyzer/`](./analyzer) |
| **admin** | Node.js / Next.js / React / Tailwind CSS / Shadcn-ui 风格组件（@base-ui/react） | 管理控制台、可视化大屏、告警处置、扫描策略管理 | [`admin/`](./admin) |

## 数据流（高层视图）

```
 ┌───────────────────────────┐
 │           agent           │
 │   agent-host/trace/guard   │  ← 主机静态文件检测 + 网络追踪 + 实时防护（三独立二进制，共享契约/上报）
 └─────────────┬─────────────┘
               ▼
 ┌───────────────────────────┐
 │         analyzer          │  ← 关联分析 / 风险评分 / 入库 / 攻击路径预测
 └─────────────┬─────────────┘
               ▼
 ┌───────────────────────────┐
 │           admin           │  ← 大屏 / 资产 / 告警 / 策略 / 攻击路径
 └───────────────────────────┘
```

> analyzer 另可 ingest 一份**外部红队能力图**（`POST /ingest/capability-graph`，opaque JSON——由独立红队工具产出、不属本仓库），结合观测态势前向推导**预测攻击路径**（`GET /attack-paths`），供 admin 的 `/attack-paths` 可视化。analyzer 只消费该 JSON 契约，不感知产出方。

**检测全链路（主动触发，闭环）**：admin `/targets` 注册目标 + `/scans` 触发 → analyzer `POST /scans` 建异步作业、复用 deploy 层投放 agent（host/trace 一次性拉回、guard 常驻 `agentd guard --upload`）→ agent 采集并（经 analyzer 入库路径）落 `AssetReport`/`TraceBatch`/`GuardEventBatch` + CVE/查毒检测与 IOC 关联 → admin `/scans/[jobId]` 轮询状态并查看本次结果（`/reports`、`/vulnerabilities`、`/traces`、`/guard`）。凭据为 analyzer 主机上的托管 SSH 密钥（注册时一次性密码 bootstrap 后丢弃，不持久化）。亦支持注册 `transport=local` 目标**扫描 analyzer 主机自身**（就地跑 agent-host，无需 SSH/凭据，仅 host 能力；容器内需挂载宿主根目录并设 `ANALYZER_LOCAL_SCAN_ROOT`）。

## 授权与合规使用

kcatta 是**防御 / 蓝队**安全态势平台，但其能力具有双用途性质——尤其 agent 的**远端投放采集**
（analyzer 经 SSH/WinRM 把 agent 投到目标主机并执行）、内置查毒与 eBPF 监控。请仅在**你拥有或已获得
明确书面授权**的资产/网络上部署与运行：

- **只扫你有权扫的资产**：远端投放、主机采集、网络追踪均须在授权范围内进行；未经授权访问他人系统可能违法。
- **凭据与密钥安全**：托管 SSH 密钥落在 analyzer 主机本地；首连一次性口令仅用于 bootstrap 后丢弃。跨信任域使用前评估中间人风险（见 [`SECURITY.md`](./SECURITY.md)）。
- **生产须开鉴权**：analyzer 未设 `ANALYZER_API_TOKEN` 时放行所有请求，**仅适合本机 dev**；生产部署务必设置强随机 token 并经 TLS/反代收敛暴露面。
- 使用者须自行确保符合所在司法辖区的法律法规与目标系统的使用条款；维护者不对滥用承担责任（见 [`LICENSE`](./LICENSE) 免责条款）。

## 仓库结构

```
kcatta/
├── README.md           # 顶层架构说明（本文）
├── LICENSE             # CE 源代码许可证（Apache-2.0）
├── NOTICE              # 组件许可说明（含 eBPF GPL 部分）
├── GOVERNANCE.md       # 项目治理与决策流程
├── CONTRIBUTING.md     # 贡献指南（环境 / 构建 / 测试 / DCO 签核）
├── CODE_OF_CONDUCT.md  # 行为准则（Contributor Covenant）
├── DCO.md              # 贡献者原创声明（Signed-off-by）
├── TRADEMARK.md        # 「kcatta」商标使用政策
├── SECURITY.md         # 安全策略（漏洞报告流程 + 部署须知）
├── Makefile            # 跨组件任务快捷入口
├── docker-compose.yml  # 本地 analyzer + admin 栈
├── .env.example        # 环境变量模板
├── .gitignore
├── .github/            # GitHub Actions CI、CODEOWNERS、PR 模板、分支保护说明
├── scripts/            # 维护脚本（含 setup-branch-protection.sh）
├── agent/              # Rust workspace（host/trace/guard 采集探针）
├── analyzer/           # Python 分析后端（检测/关联/预测/调度）
└── admin/              # Next.js 管理控制台
```

每个子目录是相对自治的开发单元，拥有自己的构建工具链与说明文档。根目录提供 **Makefile** 与 **GitHub Actions CI** 作为跨组件快捷入口，各组件仍按其语言原生工具链独立构建。

## 开发约定

- **语言版本**：Rust stable、Python ≥ 3.11、Node.js LTS。
- **代码风格**：交由各子目录的 lint / formatter 配置约束（`rustfmt` / `ruff` / `eslint + prettier`）。
- **提交规范**：建议使用 [Conventional Commits](https://www.conventionalcommits.org/)；向本仓库贡献时每个 commit 须带 DCO 签核（`git commit -s`），见 [`DCO.md`](./DCO.md)。
- **分支模型**：`main` 为开发集成分支（保持稳定、可随时 CI 绿）；开发走 feature 分支并通过 PR 合入，版本以 tag 发布。详见 [`GOVERNANCE.md`](./GOVERNANCE.md)。
- **治理与许可**：[`GOVERNANCE.md`](./GOVERNANCE.md) · [`TRADEMARK.md`](./TRADEMARK.md) · [`LICENSE`](./LICENSE)（Apache-2.0，Community Edition） · [`main` 分支保护](.github/BRANCH_PROTECTION.md)
- **跨组件接口**：agent 上报的数据契约（schema）以 analyzer 端为准，维护于 `analyzer/src/analyzer/schemas/` 与 `analyzer/schemas-json/`；Rust 侧镜像见 `agent/crates/contract/`（包名 `agent-contract`）。

## agent 能力概览

agent 是 Rust workspace，分为**三大能力、三独立二进制**（一个能力 = 一个目录 = 一个 crate），
共享 `contract` 数据契约底座：

- **主机静态文件检测（`agent-host`）**：本机 / 挂载目录静态扫描（包、SBOM、服务、容器、账户、SSH 指纹）+ 内置签名查毒，产出 `AssetReport`（CVE 判定交给 analyzer）。容器发现覆盖 Docker/Podman/containerd/k8s 静态元数据；`--scan-containers` 还可在容器 merged rootfs 内复用采集器、以 `parent_asset_id` 归属容器。
- **eBPF 追踪（`agent-trace`）**：网络流量元数据 +（`ebpf` feature 下）文件操作、程序调用采集 + 威胁情报 IOC 匹配与情报库同步，产出 `TraceBatch`（`events`/`file_events`/`process_events` 三流）。
- **实时防护（`agent-guard`）**：长驻守护（FIM / on-access 查毒 / 进程行为 / 网络 IOC / IDS 实时检测），可选端上主动处置（默认全关），产出 `GuardEventBatch`。

**三种运行方式**：① 三独立二进制各自运行（只产出本地结果，不上报）；② 统一 `agentd`
命令（umbrella，子命令 `host`/`trace`/`guard`，`--upload` 时上报 analyzer）；③ 由 **analyzer**
的 `analyzer-scan` 经 SSH 远程调度。

flag 级用法与架构详见 [`agent/README.md`](./agent/README.md)、[`agent/docs/ARCHITECTURE.md`](./agent/docs/ARCHITECTURE.md)（以其为准）。

## analyzer 关联分析

analyzer 接收 agent-trace 上报的、已带威胁情报命中（`TraceEvent.threat_intel`）的 `TraceBatch`，
按指标(IOC)聚合关联成 `Alert`（命中同一指标的多条流合并为一条告警），经 `/reports/alerts`
暴露给 admin。详见 [`analyzer/README.md`](./analyzer/README.md)。

## 构建与 CI

```bash
make test-all            # agent + analyzer + admin（单元/集成，不含 e2e）
make lint-all
make schema-check        # analyzer JSON Schema 导出一致性
make contracts-check     # admin TS 契约生成一致性
make build-agent-deploy  # 静态(musl,x86_64) agent 部署二进制（analyzer 远程投放产物；需 musl-tools）
make build-agent-deploy-arm64  # 同上，aarch64（用 cross）；analyzer 按目标 arch 自动选
make test-admin-e2e     # Playwright（analyzer + admin 栈）
cp .env.example .env        # 可选：显式设 ANALYZER_API_TOKEN（compose 未设时自动生成强随机值）
docker compose up --build   # 本地 analyzer + admin（SQLite + bearer 鉴权）
```

Push 与 PR 会触发 GitHub Actions，多个 job 并行运行：`agent`、`analyzer`、`admin` 各组件构建测试，两个 agent musl 部署构建（x86_64 / aarch64），`security-audit` 依赖漏洞扫描（非阻断），以及 `e2e`（详见 [`.github/workflows/ci.yml`](./.github/workflows/ci.yml)）。环境变量模板见 [`.env.example`](./.env.example)。

## 快速开始

请进入对应子目录查看各自的 README：

- [`agent/README.md`](./agent/README.md)
- [`analyzer/README.md`](./analyzer/README.md)
- [`admin/README.md`](./admin/README.md)
