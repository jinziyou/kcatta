# cyber-posture

> 安全态势综合管理平台 —— 通过「主机 + 网络」双维度采集与智能关联分析，让安全团队实时掌握整体安全状态。

本仓库是一个 **monorepo**，由四个相互独立但协同工作的组件构成：

| 组件 | 语言 / 技术栈 | 角色 | 子目录 |
| --- | --- | --- | --- |
| **scanner** | Rust | 主机端资产与风险扫描引擎（软件包、应用、运行服务、SSH/API 密钥、恶意代码扫描） | [`scanner/`](./scanner) |
| **collector** | Rust | 网络流量元数据采集与威胁情报旁路监听（会话、协议、外联行为） | [`collector/`](./collector) |
| **form** | Python | 数据标准化、关联分析、风险评分与态势感知后端 | [`form/`](./form) |
| **portal** | Node.js / Next.js / Shadcn-ui / Tailwind | 管理控制台、可视化大屏、告警处置、扫描策略管理 | [`portal/`](./portal) |

## 数据流（高层视图）

```
 ┌───────────┐         ┌────────────┐
 │  scanner  │──┐   ┌──│ collector  │
 └───────────┘  │   │  └────────────┘
                ▼   ▼
            ┌──────────┐
            │   form   │  ← 关联分析 / 风险评分 / 入库
            └────┬─────┘
                 ▼
            ┌──────────┐
            │  portal  │  ← 大屏 / 资产 / 告警 / 策略
            └──────────┘
```

## 仓库结构

```
cyber-posture/
├── README.md              # 顶层架构说明（本文）
├── .gitignore
├── scanner/               # Rust workspace
├── collector/             # Rust workspace
├── form/                  # Python project
└── portal/                # Next.js app
```

每个子目录是相对自治的开发单元，拥有自己的构建工具链与说明文档。本 monorepo 暂不引入统一的任务编排器（如 Nx / Turborepo / Bazel），各组件按其语言原生工具链独立构建；后续若跨组件协作频繁再行抽象。

## 开发约定

- **语言版本**：Rust stable、Python ≥ 3.11、Node.js LTS。
- **代码风格**：交由各子目录的 lint / formatter 配置约束（`rustfmt` / `ruff` / `eslint + prettier`）。
- **提交规范**：建议使用 [Conventional Commits](https://www.conventionalcommits.org/)。
- **分支模型**：`main` 为发布分支；开发请走 feature 分支并通过 PR 合入。
- **跨组件接口**：scanner / collector 上报的数据契约（schema）以 form 端为准，建议放在 `form/schemas/` 下统一维护，后续可再共享给 Rust / TS 端。

## 快速开始

请进入对应子目录查看各自的 README：

- [`scanner/README.md`](./scanner/README.md)
- [`collector/README.md`](./collector/README.md)
- [`form/README.md`](./form/README.md)
- [`portal/README.md`](./portal/README.md)
