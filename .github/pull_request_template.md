## 摘要

<!-- 本 PR 做什么？关联 Issue：Fixes # -->

## 变更类型

- [ ] Bug 修复
- [ ] 新功能
- [ ] 破坏性变更（API / Schema / 默认行为）
- [ ] 文档
- [ ] CI / 构建
- [ ] 重构（无行为变化）

## 影响范围

- [ ] agent
- [ ] analyzer
- [ ] admin
- [ ] 跨组件契约（`schemas-json` / `agent-contract` / admin 生成类型）

## 测试

<!-- 如何验证？例如：make test-all、cargo test -p …、pnpm test:e2e -->

- [ ] 本地测试通过
- [ ] 已更新/无需更新文档

## DCO（必填）

- [ ] 我已阅读 [`DCO.md`](../DCO.md)
- [ ] **本 PR 的每个 commit 均包含** `Signed-off-by: Your Name <email@example.com>`（推荐 `git commit -s`）

## 清单（若适用）

- [ ] Schema 变更已运行 `make schema-check` / `analyzer-export-schemas`
- [ ] admin 契约已运行 `make contracts-check` / `pnpm generate:contracts`
- [ ] 安全 / 部署相关变更已对照 `README.md`「授权与合规使用」、`.env.example` 与 `docker-compose.yml`
