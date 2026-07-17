# kcatta

> 安全态势综合管理平台 ——聚焦与外界有交互的应用/服务。

本仓库是一个 **monorepo**，由四个职责隔离、通过 Form 协同的组件构成：


| 组件           | 语言 / 技术栈                                                                  | 角色                                                                                                                                                                                                                                                                                   | 子目录                       |
| ------------ | ------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------- |
| **agent**    | Rust                                                                      | 三大能力 + 编排：**主机静态文件检测**（`agent-collect-host`：包/SBOM/服务/容器/账户/SSH 指纹 + 内置签名查毒）、**eBPF 追踪**（`agent-collect-trace`：网络流量元数据 + 文件操作 + 程序调用 + 威胁情报 IOC）、**实时防护**（`agent-respond`：FIM/on-access/行为/网络 实时检测 + 端上主动处置，含 eBPF cgroup 阻断）；伞形 `agentd` 编排调度（`agentd run`）并统一上报；CVE 匹配在 analyzer 侧 | `[agent/](./agent)`       |
| **analyzer** | Python                                                                    | 数据标准化、关联分析、风险评分、攻击路径预测（ingest 外部红队能力图）与态势感知后端                                                                                                                                                                                                                                        | `[analyzer/](./analyzer)` |
| **form**     | Python / FastAPI                                                          | 唯一跨组件编排与交互边界：`:10067` Admin/control/facade + `:10443` 专用 Agent mTLS ingest、目标/任务/凭据/身份、Agent 投放                                                                                                                                                                                      | `[form/](./form)`         |
| **admin**    | Node.js / Next.js / React / Tailwind CSS / Shadcn-ui 风格组件（@base-ui/react） | 管理控制台、可视化大屏、告警处置、扫描策略管理                                                                                                                                                                                                                                                              | `[admin/](./admin)`       |




## 数据流（高层视图）

```text
agent ── per-Agent mTLS ──► Form :10443 ──┐
                                          ├── private API ──► analyzer
admin ── control/query ───► Form :10067 ──┘
```

强制边界：`admin ↔ form ↔ analyzer`、`form ↔ agent`；禁止
`admin ↔ analyzer`、`analyzer ↔ agent`、`agent ↔ analyzer` 直连。

> 外部红队能力图同样提交给 Form 的 `POST /ingest/capability-graph`，由 Form 转发到 analyzer；analyzer 结合观测态势推导攻击路径，但不直接暴露给产出方或 Admin。

**检测全链路（主动触发，闭环）**：Admin 向 Form 注册目标并触发任务 → Form 持久化任务、经 SSH/WinRM/local 投放 Agent（host/trace 一次性拉回，guard 常驻 `agentd respond --upload <agent-form-url>`）→ Guard 以 per-Agent mTLS 回到 Form 专用 listener → Form 将结果送入 Analyzer 的内部 ingest → Analyzer 先写入持久化幂等 outbox，再由可恢复 Worker 完成 CVE、关联和预测 → Admin 仍只经 Form 查询状态与结果。托管密钥/证书及 `transport=local` 都属于 Form 主机；本地扫描根由 `FORM_LOCAL_SCAN_ROOT` 控制。

> 完整的仓库级架构见 `[ARCHITECTURE.md](./ARCHITECTURE.md)`；部署入口见 `[docs/DEPLOYMENT.md](./docs/DEPLOYMENT.md)`；agent 流水线架构（`agentd` / `collect` / `detect` / `respond`）见 `[agent/docs/ARCHITECTURE.md](./agent/docs/ARCHITECTURE.md)`；迁移史见 `[agent/docs/REFACTOR-PIPELINE.md](./agent/docs/REFACTOR-PIPELINE.md)`。



## 授权与合规使用

kcatta 是**防御 / 蓝队**安全态势平台，但其能力具有双用途性质——尤其 agent 的**远端投放采集**
（Form 经 SSH/WinRM 把 agent 投到目标主机并执行）、内置查毒与 eBPF 监控。请仅在**你拥有或已获得
明确书面授权**的资产/网络上部署与运行：

- **只扫你有权扫的资产**：远端投放、主机采集、网络追踪均须在授权范围内进行；未经授权访问他人系统可能违法。
- **凭据与密钥安全**：托管 SSH 密钥/WinRM 证书和 Agent CA signing key 只落在 control Form；专用 Agent listener 没有 signing key。当前 MVP 的 Agent leaf key 由 Form 内存生成、经已认证 SFTP 一次传送且 Form 不持久化；CSR/TPM 留待后续。SSH 默认持久 TOFU、WinRM 默认验证 TLS；生产环境应预置 host key/CA。部署规则见 `.env.example` 与 `docker-compose.yml`。
- **鉴权默认分域**：Admin 使用 `FORM_API_TOKEN`，监控只读抓取使用 `FORM_METRICS_TOKEN` / `ANALYZER_METRICS_TOKEN`，新 Agent 使用 scoped client certificate，Form→Analyzer 使用 `ANALYZER_INTERNAL_TOKEN`。Compose 默认 `mixed`，`FORM_INGEST_TOKEN` 只供旧 Agent 迁移；strict `mtls` 拒绝 bearer ingest。只有显式 `FORM_ALLOW_INSECURE_NO_AUTH=true` 才允许隔离的无令牌本地开发；生产还必须保持 Analyzer 私网隔离。
- 使用者须自行确保符合所在司法辖区的法律法规与目标系统的使用条款；维护者不对滥用承担责任（见 `[LICENSE](./LICENSE)` 免责条款）。



## 仓库结构

```
kcatta/
├── README.md              # 顶层简介（本文）：是什么 / 三组件 / 数据流 / 快速开始
├── ARCHITECTURE.md        # 仓库级架构综述（领域模型 / 组件边界 / 数据流 / 关键不变量）
├── LICENSE                # 源代码许可证（Apache-2.0）
├── DCO.md                 # 贡献者原创声明（Signed-off-by）
├── .env.example           # 环境变量模板
├── .gitleaks.toml         # secret 扫描配置
├── Makefile               # 跨组件任务快捷入口
├── docker-compose.yml     # 本地 Form control/Agent listener + analyzer + admin 栈
├── docs/                  # DEPLOYMENT / ROADMAP / Windows 支持说明
├── .github/               # GitHub Actions CI、CODEOWNERS、PR 模板、分支保护说明
├── scripts/               # 分支保护配置 / 验证脚本
├── agent/                 # Rust workspace（collect / detect / respond / agentd / contract / eBPF）
│   ├── README.md
│   ├── docs/              # agent 架构、贡献与 Windows 支持
│   └── crates/
├── analyzer/              # Python 分析后端（内部 ingest / 检测 / 关联 / 预测）
│   ├── README.md
│   ├── pyproject.toml
│   ├── schemas-json/      # 导出的 JSON Schema 契约
│   └── src/analyzer/
├── form/                  # Python 控制面（唯一交互边界 / 编排 / Agent 投放）
│   ├── README.md
│   ├── pyproject.toml
│   └── src/kcatta_form/
└── admin/                 # Next.js 管理控制台（只调用 Form）
    ├── README.md
    ├── package.json
    └── src/
```

每个子目录是相对自治的开发单元，拥有自己的构建工具链与说明文档。根目录提供 **Makefile** 与 **GitHub Actions CI** 作为跨组件快捷入口，各组件仍按其语言原生工具链独立构建。

构建 / 运行产物（如 `analyzer/.venv/`、`analyzer/.pytest_cache/`、`admin/node_modules/`、`admin/.next/`、`admin/test-results/`、`agent/target/`、`*.tsbuildinfo`）不列入上面的权威结构树，由根目录或子目录 `.gitignore` 管理。

## 开发约定

- **语言版本**：Rust stable、Python ≥ 3.11、Node.js LTS。
- **代码风格**：交由各子目录的 lint / formatter 配置约束（`rustfmt` / `ruff` / `eslint + prettier`）。
- **提交规范**：建议使用 [Conventional Commits](https://www.conventionalcommits.org/)；向本仓库贡献时每个 commit 须带 DCO 签核（`git commit -s`），见 `[DCO.md](./DCO.md)`。
- **分支模型**：`main` 为开发集成分支（保持稳定、可随时 CI 绿）；开发走 feature 分支并通过 PR 合入，分支保护规则见 `[.github/BRANCH_PROTECTION.md](.github/BRANCH_PROTECTION.md)`。
- **许可与合规**：`[LICENSE](./LICENSE)`（Apache-2.0）· `[DCO.md](./DCO.md)` · 本文「授权与合规使用」· `main` [分支保护](.github/BRANCH_PROTECTION.md)
- **跨组件接口**：Analyzer Pydantic 仍定义分析 wire，Form 在 `form/schemas-json/` 发布公共边界契约；Agent/Admin 只消费 Form 发布的边界，Rust 镜像见 `agent/crates/contract/`。



## agent 能力概览

agent 是 Rust workspace，分为**三大能力、三独立二进制**（一个能力 = 一个目录 = 一个 crate），
共享 `contract` 数据契约底座：

- **主机静态文件检测（**`agent-collect-host`**）**：本机 / 挂载目录 / 容器镜像静态扫描（包、SBOM、服务、端口、账户、SSH 指纹）+ 内置签名查毒，产出 `AssetReport`（CVE 判定交给 analyzer）。容器/镜像资产默认启用；可用 `--no-container-assets` / `--no-image-assets` 关闭，或用 `--container-asset-targets` 控制容器内资产类别。
- **eBPF 追踪（**`agent-collect-trace`**）**：网络流量元数据 +（`ebpf` feature 下）文件操作、程序调用采集 + 威胁情报 IOC 匹配与情报库同步，产出 `TraceBatch`（`events`/`file_events`/`process_events` 三流）。
- **实时防护（**`agent-respond`**）**：长驻守护（FIM / on-access 查毒 / 进程行为 / 网络 IOC / IDS 实时检测），可选端上主动处置（默认全关），产出 `GuardEventBatch`。

**三种运行方式**：① 三独立二进制各自运行（只产出本地结果，不上报）；② 统一 `agentd`
命令（umbrella，主子命令 `collect-host`/`collect-trace`/`respond`，兼容别名 `host`/`trace`/`guard`，`--upload` 时上报 Form）；③ 由 **Form**
的 `form-scan` / worker 经 SSH/WinRM/本机 transport 调度。

flag 级用法与架构详见 `[agent/README.md](./agent/README.md)`、`[agent/docs/ARCHITECTURE.md](./agent/docs/ARCHITECTURE.md)`（以其为准）。

## analyzer 关联分析

analyzer 经 Form 接收已带威胁情报命中的 `TraceBatch`，按 IOC 聚合关联成 `Alert`；结果仍由 Form 的
`/reports/alerts` facade 暴露给 Admin。详见 `[analyzer/README.md](./analyzer/README.md)`。
主机报告同时携带 Agent 检测器执行证据，Analyzer 在 `DetectionResult.coverage` 中合并为
检测器/生态覆盖矩阵；Admin 会分别展示已完成、部分覆盖、未启用、失败和旧版未知状态，
不会再把单纯的“0 条发现”解释为“所有检测均已执行且安全”。

## 构建与 CI

```bash
make test-all            # agent + analyzer + form + admin（单元/集成，不含 e2e）
make lint-all
make schema-check        # analyzer JSON Schema 导出一致性
make contracts-check     # admin TS 契约生成一致性
make build-agent-deploy  # 静态(musl,x86_64) Agent 部署二进制（Form 远程投放产物；需 musl-tools）
make build-agent-deploy-arm64  # 同上，aarch64（用 cross）；Form 按目标 arch 自动选
make test-admin-e2e     # Playwright（analyzer + form + admin 栈）
cp .env.example .env        # 可选：编辑 .env 固定 token；不复制时 compose 自动生成
make compose-config      # 校验 docker-compose.yml 语法与变量插值
docker compose up --build   # 本地 analyzer + Form 双入口 + admin（mTLS/隔离令牌 + SQLite）
# 可选：Prometheus 告警规则 + 轻量只读缓存面板（10065 / 10064）
make monitoring-check
docker compose --profile monitoring up -d --build
```

Push 与 PR 会触发 GitHub Actions，多个 job 并行运行：`agent`、`agent-windows`、`analyzer`、`form`、`admin` 各组件构建测试，两个 Agent musl 部署构建、组件边界、schema/contract 漂移、secret scan、dependency audit、DCO 以及完整栈 `e2e`。

## 快速开始

请进入对应子目录查看各自的 README：

- `[agent/README.md](./agent/README.md)`
- `[analyzer/README.md](./analyzer/README.md)`
- `[form/README.md](./form/README.md)`
- `[admin/README.md](./admin/README.md)`



## 文档地图


| 文档                                                                                                                                                                             | 范围                                         |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------ |
| `[README.md](./README.md)`（本文）                                                                                                                                                 | 顶层简介：是什么、四组件、数据流、快速开始、Makefile/CI          |
| `[ARCHITECTURE.md](./ARCHITECTURE.md)`                                                                                                                                         | 仓库级架构综述：领域模型、组件边界、数据流、关键不变量、部署形态           |
| `[docs/DEPLOYMENT.md](./docs/DEPLOYMENT.md)`                                                                                                                                   | 部署入口：compose、token、安全暴露面、agent 投放二进制、部署前验证 |
| `[docs/QUICKSTART-ATTACK-PATH.md](./docs/QUICKSTART-ATTACK-PATH.md)`                                                                                                           | 从 0 到第一次 attack-path 的最短闭环操作手册                     |
| `[agent/README.md](./agent/README.md)` · `[agent/docs/ARCHITECTURE.md](./agent/docs/ARCHITECTURE.md)` · `[agent/docs/REFACTOR-PIPELINE.md](./agent/docs/REFACTOR-PIPELINE.md)` | agent 用法 / 现状架构 / 目标流水线重构方案                |
| `[analyzer/README.md](./analyzer/README.md)` · `[analyzer/schemas-json/README.md](./analyzer/schemas-json/README.md)`                                                          | analyzer 内部 API / 检测 / 关联；分析模型契约           |
| `[form/README.md](./form/README.md)`                                                                                                                                           | 公共 API、跨组件编排、Agent 投放与公共 Schema            |
| `[admin/README.md](./admin/README.md)`                                                                                                                                         | 管理控制台：路由、契约生成、开发与构建                        |
