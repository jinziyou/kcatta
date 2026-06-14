# admin

**综合管理与可视化平台**，kcatta 的用户驾驶舱。Next.js 16 + React 19 + Tailwind CSS v4 + Shadcn/ui。

## 当前状态（v0）

已落地：

- Next.js 16 App Router + TypeScript（strict）+ Tailwind v4 + Shadcn/ui（vendored 到 `src/components/ui/`：button / card / badge / table / sidebar / sheet / tooltip / sonner 等），中文界面 + 侧边导航 + 深色模式（next-themes）
- 类型化的 analyzer API 客户端（`src/lib/api.ts`）；数据契约由 `analyzer/schemas-json/*.schema.json` 代码生成到 `src/lib/schemas/`，`src/lib/contracts.ts` 统一 re-export 给组件
- **概览**（`/`）：聚合扫描目标 / 任务 / 资产报告 / 漏洞的统计卡片，加重点告警、最近任务、最近资产报告；含连不上 analyzer 时的错误态
- **资产报告**（`/reports`）：`AssetReport` 列表（主机 / 系统 / 资产数 / 漏洞数 / 采集时间）；详情页（`/reports/[reportId]`）展示主机信息 + 按类型分组的资产（packages / services / ports / accounts / credentials / containers）+ 检出漏洞
- **漏洞 / 发现**（`/vulnerabilities`）：`DetectionResult` 列表，可按最小严重度与来源（OSV/CVE / ClamAV）过滤
- **告警**（`/alerts`）：`Alert` 列表，按严重度与风险分排序、展示处理状态；详情页（`/alerts/[alertId]`）含相关资产 / 漏洞 / 流
- **网络流**（`/traces`）：`TraceBatch` 列表，可按 IOC 命中过滤，展示威胁情报匹配徽标
- **攻击路径**（`/attack-paths`）：analyzer 基于能力图 + 观测态势推导的预测攻击路径列表；详情页（`/attack-paths/[pathId]`）用 React Flow 节点-链路图（`components/attack-graph.tsx`）可视化链路
- **目标**（`/targets`）：注册/查看扫描目标（`POST /targets`）；表单只填 目标+凭据模式+一次性密码（managed_key bootstrap，**不经客户端存储**）
- **扫描**（`/scans`）：**触发**一次扫描（选目标 + 能力 host/trace/guard + 选项）经 Server Action 调 `POST /scans`；列出作业；详情页（`/scans/[jobId]`）客户端轮询 `GET /scans/{id}` 显示 pending→running→succeeded/failed，并链到本次结果（AssetReport / TraceBatch / guard 事件）
- **Guard 事件**（`/guard`）：`GET /reports/guard-events` 实时防护事件，可按 `?host=` 过滤
- 生产构建（`pnpm build`）、TypeScript（`tsc --noEmit`）、ESLint（`pnpm lint`）全部干净

**只读 → 可触发**：除上述只读视图外，新增唯一的写路径——经 Next Server Action（`app/{targets,scans}/actions.ts`，`'use server'`）调 analyzer 的 `POST /targets`/`POST /scans`；`ANALYZER_API_TOKEN` 仍只在服务端，浏览器永不持有。

尚未落地：登录与用户级权限（`api.ts` 仅按 `ANALYZER_API_TOKEN` 转发服务端 bearer）；WinRM 触发；扫描计划/定时。

## 目录结构

```
admin/
├── package.json
├── pnpm-lock.yaml
├── next.config.ts / tsconfig.json / eslint.config.mjs / postcss.config.mjs
├── playwright.config.ts            # Playwright e2e 配置
├── components.json                 # Shadcn 配置
├── Dockerfile                      # 多阶段构建（standalone output；compose context ./admin）
├── pnpm-workspace.yaml             # pnpm ignoredBuiltDependencies（sharp / unrs-resolver）
├── .env.example                    # NEXT_PUBLIC_ANALYZER_BASE_URL / ANALYZER_API_TOKEN
├── scripts/
│   ├── generate-contracts.mjs      # schema → TS 类型生成
│   ├── e2e-analyzer.sh               # CI: 起 analyzer-api 供 Playwright
│   └── e2e-admin.sh               # CI: 起生产构建的 admin 供 Playwright
├── e2e/                            # Playwright 用例（smoke / auth / fixtures / global-setup）
└── src/
    ├── app/
    │   ├── layout.tsx              # 全局 Shell：侧边导航 + 顶栏 + 主题（next-themes）
    │   ├── page.tsx                # 概览仪表盘（统计卡片 / 重点告警 / 最近任务与报告）
    │   ├── globals.css
    │   ├── error.tsx               # 路由段错误边界（analyzer 不可达时的友好回退）
    │   ├── loading.tsx / not-found.tsx    # 全局加载态 / 404
    │   ├── targets/
    │   │   ├── page.tsx                   # 扫描目标列表 + 注册表单
    │   │   └── actions.ts                 # Server Action：POST /targets
    │   ├── scans/
    │   │   ├── page.tsx                   # 扫描任务配置与下发 + 作业列表
    │   │   ├── actions.ts                 # Server Action：POST /scans
    │   │   └── [jobId]/page.tsx           # 任务详情（客户端轮询状态 + 结果链接）
    │   ├── reports/
    │   │   ├── page.tsx                   # 资产报告列表
    │   │   └── [reportId]/page.tsx        # 资产报告详情
    │   ├── vulnerabilities/page.tsx       # 漏洞发现列表（按严重度 / 来源过滤）
    │   ├── traces/page.tsx                # 网络流量批次（按 IOC 命中过滤）
    │   ├── guard/page.tsx                 # 实时防护事件
    │   ├── alerts/
    │   │   ├── page.tsx                   # 关联告警列表
    │   │   └── [alertId]/page.tsx         # 告警详情
    │   └── attack-paths/
    │       ├── page.tsx                   # 预测攻击路径列表
    │       └── [pathId]/page.tsx          # 攻击路径详情（React Flow 图）
    ├── components/
    │   ├── app-sidebar.tsx / site-header.tsx          # 侧边导航 + 顶栏
    │   ├── theme-provider.tsx / theme-toggle.tsx      # 深色模式
    │   ├── register-target-form.tsx / scan-config-form.tsx    # 注册目标 / 配置扫描表单
    │   ├── scan-jobs-table.tsx / scan-job-monitor.tsx / targets-table.tsx
    │   ├── severity-badge.tsx / state-badge.tsx / alert-status-badge.tsx / filter-chip.tsx
    │   ├── page-header.tsx / stat.tsx / states.tsx / copy-button.tsx
    │   ├── attack-graph.tsx        # React Flow 攻击路径节点-链路图
    │   └── ui/                     # Shadcn vendored 组件（button / card / badge / table / sidebar …）
    ├── hooks/use-mobile.ts         # 视口断点 hook（sidebar 移动端折叠用）
    └── lib/
        ├── api.ts                  # analyzer HTTP 客户端
        ├── contracts.ts            # 契约导出（re-export 生成类型 + 派生别名）
        ├── format.ts               # 纯展示格式化（时间 / 字节 / 时长 / 端点 …）
        ├── meta.ts                 # 枚举 → 中文标签 / 徽标样式映射
        ├── nav.ts                  # 侧边导航模型
        ├── scan.ts                 # 扫描编排类型（与 analyzer schemas/scan.py 手工镜像）
        ├── schemas/                # 自动生成的 TS 类型（pnpm generate:contracts）
        │   └── Alert.ts · AssetReport.ts · AttackPath.ts · DetectionResult.ts · TraceBatch.ts · GuardEventBatch.ts
        └── utils.ts                # Shadcn 工具函数
```

## 环境变量

| 变量 | 默认 | 用途 |
| --- | --- | --- |
| `NEXT_PUBLIC_ANALYZER_BASE_URL` | `http://127.0.0.1:8000` | analyzer HTTP API 的基准 URL |
| `ANALYZER_API_TOKEN` | （未设置） | 服务端调用 analyzer API 时携带的 Bearer Token（与 analyzer 的 `ANALYZER_API_TOKEN` 对应）；analyzer 无鉴权时留空 |

复制 `.env.example` 为 `.env.local` 即可在本地覆盖。

## 安装 & 开发

```bash
cd admin
pnpm install                 # 首次拉依赖
pnpm dev                     # 本地开发服务器 http://localhost:3000
```

## 质量门

```bash
pnpm exec tsc --noEmit       # TypeScript 类型检查
pnpm lint                    # ESLint
pnpm build                   # 生产构建（含上述两项）
pnpm test:e2e                # Playwright e2e（Chromium）
```

e2e 覆盖主要用户流：资产报告列表与详情、网络流量列表与 IOC 过滤、关联告警列表、全局导航跳转，以及 analyzer API 鉴权（`e2e/auth.spec.ts`）。本地复用已起的 analyzer/admin 服务，CI 下自动拉起（见 `playwright.config.ts`）。

## 添加新 Shadcn 组件

```bash
pnpm dlx shadcn@latest add dialog table input form switch
```

新组件会落到 `src/components/ui/`，可直接 `import { ... } from "@/components/ui/..."`。

## 端到端联调

需要先启 analyzer（默认 `127.0.0.1:8000`，CORS 已默认放行 `http://localhost:3000`）：

```bash
# 终端 1：起 analyzer
cd ../analyzer
source .venv/bin/activate
analyzer-api

# 终端 2：灌点数据（agent-host 上报）
cd ../agent
cargo run --quiet -p agent-host -- -r / | \
  curl -X POST --data-binary @- \
    http://127.0.0.1:8000/ingest/asset-report

# 终端 3：起 admin
cd ../admin
pnpm dev
# 访问 http://localhost:3000
```

如 analyzer 跑在不同端口，启动 admin 时覆盖：

```bash
NEXT_PUBLIC_ANALYZER_BASE_URL=http://127.0.0.1:18000 pnpm dev
```

## 契约约定

- 数据契约的**源头**在 `analyzer/src/analyzer/schemas/`（Pydantic）。
- 跨语言**派生**在 `analyzer/schemas-json/*.schema.json`。
- admin 通过**代码生成**获取契约：`pnpm generate:contracts`（`scripts/generate-contracts.mjs`，基于 `json-schema-to-typescript`）把 `analyzer/schemas-json/*.schema.json` 转为 `src/lib/schemas/*.ts`（带「勿手改」banner）；`src/lib/contracts.ts` 统一 re-export 这些生成类型，并补两个派生别名（`Asset` / `AssetKind`）。`make contracts-check` 在 CI 校验生成结果不漂移。
