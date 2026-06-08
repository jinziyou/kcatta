# portal

**综合管理与可视化平台**，posture 的用户驾驶舱。Next.js 16 + React 19 + Tailwind CSS v4 + Shadcn/ui。

## 当前状态（v0）

已落地：

- Next.js 16 App Router + TypeScript（strict）+ Tailwind v4 + Shadcn/ui 初始化
- Shadcn 组件：`Button` / `Card` / `Badge`
- 类型化的 form API 客户端（`src/lib/api.ts`）；数据契约由 `form/schemas-json/*.schema.json` 代码生成到 `src/lib/schemas/`，`src/lib/contracts.ts` 统一 re-export 给组件
- **首页**（`/`）：从 `form` 的 `GET /reports/asset-reports` 拉取最近 50 条 `AssetReport`，以卡片形式展示主机、采集时间、各类型资产计数；含空态与连不上 form 时的错误态
- **资产报告详情**（`/reports/[reportId]`）：主机信息 + 按类型分组的资产（packages / services / ports / accounts / credentials）+ 检出漏洞
- **漏洞 / 发现**（`/vulnerabilities`）：`DetectionResult` 列表，可按 severity 与来源（OSV / ClamAV）过滤
- **告警**（`/alerts`）：`Alert` 列表，可按 severity 与 status 过滤、展示命中主机/流计数；详情页（`/alerts/[alertId]`）含相关资产 / 流 / 漏洞
- **网络流**（`/flows`）：`FlowBatch` 列表，可按 IOC 命中过滤，展示威胁情报匹配徽标
- **攻击路径**（`/attack-paths`）：form 基于能力图 + 观测态势推导的预测攻击路径列表；详情页（`/attack-paths/[pathId]`）用 React Flow 节点-链路图（`components/attack-graph.tsx`）可视化链路
- 生产构建（`pnpm build`）、TypeScript（`tsc --noEmit`）、ESLint（`pnpm lint`）全部干净

尚未落地：扫描策略管理、登录与权限（`api.ts` 仅按 `FORM_API_TOKEN` 转发服务端 bearer，尚无用户级登录）。

## 目录结构

```
portal/
├── package.json
├── pnpm-lock.yaml
├── next.config.ts / tsconfig.json / eslint.config.mjs / postcss.config.mjs
├── playwright.config.ts            # Playwright e2e 配置
├── components.json                 # Shadcn 配置
├── Dockerfile                      # 多阶段构建（standalone output；compose context ./portal）
├── pnpm-workspace.yaml             # pnpm ignoredBuiltDependencies（sharp / unrs-resolver）
├── .env.example                    # NEXT_PUBLIC_FORM_BASE_URL / FORM_API_TOKEN
├── public/
├── scripts/
│   ├── generate-contracts.mjs      # schema → TS 类型生成
│   ├── e2e-form.sh                 # CI: 起 form-api 供 Playwright
│   └── e2e-portal.sh               # CI: 起生产构建的 portal 供 Playwright
├── e2e/                            # Playwright 用例（smoke / auth / fixtures / global-setup）
└── src/
    ├── app/
    │   ├── layout.tsx              # 全局导航
    │   ├── page.tsx                # 资产报告列表（首页）
    │   ├── globals.css
    │   ├── reports/[reportId]/page.tsx    # 资产报告详情
    │   ├── vulnerabilities/page.tsx       # 漏洞 / 发现列表
    │   ├── alerts/
    │   │   ├── page.tsx                   # 告警列表
    │   │   └── [alertId]/page.tsx         # 告警详情
    │   ├── flows/page.tsx                 # 网络流列表
    │   ├── attack-paths/
    │   │   ├── page.tsx                   # 预测攻击路径列表
    │   │   └── [pathId]/page.tsx          # 攻击路径详情（React Flow 图）
    │   └── error.tsx                      # 路由段错误边界（form 不可达时的友好回退）
    ├── components/
    │   ├── attack-graph.tsx        # React Flow 攻击路径节点-链路图
    │   └── ui/                     # Shadcn: button.tsx / card.tsx / badge.tsx
    └── lib/
        ├── api.ts                  # form HTTP 客户端
        ├── contracts.ts            # 契约导出（re-export 生成类型 + 派生别名）
        ├── schemas/                # 自动生成的 TS 类型（pnpm generate:contracts）
        │   └── Alert.ts · AssetReport.ts · AttackPath.ts · DetectionResult.ts · FlowBatch.ts
        └── utils.ts                # Shadcn 工具函数
```

## 环境变量

| 变量 | 默认 | 用途 |
| --- | --- | --- |
| `NEXT_PUBLIC_FORM_BASE_URL` | `http://127.0.0.1:8000` | form HTTP API 的基准 URL |
| `FORM_API_TOKEN` | （未设置） | 服务端调用 form API 时携带的 Bearer Token（与 form 的 `FORM_API_TOKEN` 对应）；form 无鉴权时留空 |

复制 `.env.example` 为 `.env.local` 即可在本地覆盖。

## 安装 & 开发

```bash
cd portal
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

e2e 覆盖主要用户流：首页资产列表、报告详情、网络流列表与过滤、告警列表与详情、全局导航跳转。本地复用已起的 form/portal 服务，CI 下自动拉起（见 `playwright.config.ts`）。

## 添加新 Shadcn 组件

```bash
pnpm dlx shadcn@latest add dialog table input form switch
```

新组件会落到 `src/components/ui/`，可直接 `import { ... } from "@/components/ui/..."`。

## 端到端联调

需要先启 form（默认 `127.0.0.1:8000`，CORS 已默认放行 `http://localhost:3000`）：

```bash
# 终端 1：起 form
cd ../form
source .venv/bin/activate
form-api

# 终端 2：灌点数据（fusion host 上报）
cd ../fusion
cargo run --quiet -p fusion-runtime -- host -r / | \
  curl -X POST --data-binary @- \
    http://127.0.0.1:8000/ingest/asset-report

# 终端 3：起 portal
cd ../portal
pnpm dev
# 访问 http://localhost:3000
```

如 form 跑在不同端口，启动 portal 时覆盖：

```bash
NEXT_PUBLIC_FORM_BASE_URL=http://127.0.0.1:18000 pnpm dev
```

## 契约约定

- 数据契约的**源头**在 `form/src/form/schemas/`（Pydantic）。
- 跨语言**派生**在 `form/schemas-json/*.schema.json`。
- portal 通过**代码生成**获取契约：`pnpm generate:contracts`（`scripts/generate-contracts.mjs`，基于 `json-schema-to-typescript`）把 `form/schemas-json/*.schema.json` 转为 `src/lib/schemas/*.ts`（带「勿手改」banner）；`src/lib/contracts.ts` 统一 re-export 这些生成类型，并补两个派生别名（`Asset` / `AssetKind`）。`make contracts-check` 在 CI 校验生成结果不漂移。
