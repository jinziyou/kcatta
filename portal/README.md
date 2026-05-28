# portal

**综合管理与可视化平台**，cyber-posture 的用户驾驶舱。基于 Next.js + Shadcn/ui + Tailwind CSS 构建。

## 职责

- **态势大屏**：攻击来源地图、风险趋势、资产画像、关键告警 Top 视图等。
- **资产管理**：浏览 / 检索 / 标签化 scanner 上报的资产清单。
- **告警处置**：查看 form 产出的告警，进行确认 / 派单 / 抑制 / 关闭。
- **扫描策略管理**：下发与编辑扫描器 / 采集器的策略与任务。
- **权限与审计**：用户、角色、操作日志。

## 仓库形态

本目录是一个 Next.js 应用（App Router 推荐）。当前只放置最小 `package.json` 占位，**实际项目结构请通过下文的脚手架命令初始化**，以确保使用最新依赖版本。

## 初始化（推荐路径）

> 由 monorepo 维护者首次执行，并把生成结果与本目录现有的 `package.json` 合并。

```bash
cd portal
# 使用官方脚手架（会询问 TypeScript / ESLint / Tailwind / App Router 等）
npx create-next-app@latest . \
  --typescript \
  --eslint \
  --tailwind \
  --app \
  --src-dir \
  --import-alias "@/*"

# 接入 Shadcn/ui
npx shadcn@latest init
```

随后再添加常用组件（按需）：

```bash
npx shadcn@latest add button card dialog table input form
```

## 开发

```bash
npm install     # 或 pnpm install / bun install
npm run dev
npm run build
npm run lint
npm run typecheck
```

## 与 form 的对接

portal 通过 REST / WebSocket 调用 `form` 暴露的 API。建议把 API 客户端类型生成放在 `src/lib/api/` 下，未来与 `form/schemas/` 对齐（可考虑用 OpenAPI / typed schema 自动生成）。
