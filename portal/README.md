# portal

**综合管理与可视化平台**，cyber-posture 的用户驾驶舱。Next.js 16 + React 19 + Tailwind CSS v4 + Shadcn/ui。

## 当前状态（v0）

已落地：

- Next.js 16 App Router + TypeScript（strict）+ Tailwind v4 + Shadcn/ui 初始化
- Shadcn 组件：`Button` / `Card` / `Badge`
- 类型化的 form API 客户端（`src/lib/api.ts`），手写契约镜像（`src/lib/contracts.ts`），与 Python 端 Pydantic 模型对齐
- **首页**：从 `form` 的 `GET /reports/asset-reports` 拉取最近 50 条 `AssetReport`，以卡片形式展示主机、采集时间、各类型资产计数；包含空态与连不上 form 时的错误态
- 生产构建（`pnpm build`）、TypeScript（`tsc --noEmit`）、ESLint（`pnpm lint`）全部干净

尚未落地：告警视图、流量视图、扫描策略管理、资产明细页、登录与权限。

## 目录结构

```
portal/
├── package.json
├── pnpm-lock.yaml
├── next.config.ts / tsconfig.json / eslint.config.mjs / postcss.config.mjs
├── components.json                  # Shadcn 配置
├── .env.example                     # NEXT_PUBLIC_FORM_BASE_URL
├── public/
└── src/
    ├── app/
    │   ├── layout.tsx
    │   ├── page.tsx                 # 资产报告列表（首页）
    │   └── globals.css
    ├── components/ui/               # Shadcn 组件
    │   ├── button.tsx
    │   ├── card.tsx
    │   └── badge.tsx
    └── lib/
        ├── api.ts                   # form HTTP 客户端
        ├── contracts.ts             # 数据契约 TS 镜像
        └── utils.ts                 # Shadcn 工具函数
```

## 环境变量

| 变量 | 默认 | 用途 |
| --- | --- | --- |
| `NEXT_PUBLIC_FORM_BASE_URL` | `http://127.0.0.1:8000` | form HTTP API 的基准 URL |

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
```

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

# 终端 2：灌点数据（probe-host 上报）
cd ../probe
cargo run --quiet -p probe-host-cli | \
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
- portal 当前**手写镜像**到 `src/lib/contracts.ts`——v0 类型少、改动可控；若契约持续增长，应引入 `json-schema-to-typescript` 之类的代码生成。
