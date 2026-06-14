# GitHub Branch Protection（`main` 硬开关）

本文是 [`GOVERNANCE.md`](../GOVERNANCE.md) 的配套操作指南：把「Project Leadership 控制官方主线」落到 GitHub 设置上。

**目标：**

- 禁止直接 push `main`
- PR 必须 review（含 CODEOWNERS）
- CI + DCO 必须通过才能合并

---

## 0. 前置条件（重要）

当前仓库 `jinziyou/kcatta` 若为 **Private**：

| GitHub 计划 | Private 仓库 Branch Protection |
|-------------|--------------------------------|
| **Free** | ❌ 不可用（API/UI 均提示需 Pro 或改为 Public） |
| **Pro / Team / Enterprise** | ✅ 可用 |

**开源前常见路径：**

1. 将仓库改为 **Public**，再启用本页规则；或  
2. 升级 **GitHub Pro**，在仍 Private 时先启用规则，再公开。

---

## 1. 一键脚本（推荐）

仓库根目录：

```bash
# 预览将提交的规则（不调用 API）
./scripts/setup-branch-protection.sh --dry-run

# 应用规则（需 gh 已登录且有 admin 权限）
./scripts/setup-branch-protection.sh

# 验证
./scripts/verify-branch-protection.sh
```

脚本会配置：

| 规则 | 值 |
|------|-----|
| Require pull request | 是 |
| Required approving reviews | 1 |
| Require review from Code Owners | 是（见 [`.github/CODEOWNERS`](CODEOWNERS)） |
| Dismiss stale reviews | 是 |
| Require conversation resolution | 是 |
| Require status checks (strict) | 是 — 分支必须基于最新 `main` |
| Require branches up to date | 是（`strict: true`） |
| Include administrators | 是（管理员也走 PR） |
| Allow force push | 否 |
| Allow deletions | 否 |

**Required checks（与 workflow job 名一致）：**

| Check | 来源 |
|-------|------|
| `agent (Rust)` | [`.github/workflows/ci.yml`](workflows/ci.yml) |
| `agent (musl deploy build)` | CI |
| `agent (musl deploy build, arm64)` | CI |
| `analyzer (Python)` | CI |
| `admin (Next.js)` | CI |
| `e2e (admin + analyzer)` | CI |
| `Signed-off-by` | [`.github/workflows/dco.yml`](workflows/dco.yml) |

**未纳入：** `dependency audit` — CI 中 `continue-on-error: true`，故意不阻断合并。

> 若改名 workflow job，请同步修改 `scripts/setup-branch-protection.sh` 并重新运行。

---

## 2. 手动配置（GitHub Web UI）

**Settings → Branches → Branch protection rules → Add rule**

Branch name pattern: `main`

勾选：

- [x] **Require a pull request before merging**
  - [x] Require approvals: **1**
  - [x] **Require review from Code Owners**
  - [x] Dismiss stale pull request approvals when new commits are pushed
- [x] **Require status checks to pass before merging**
  - [x] **Require branches to be up to date before merging**
  - 搜索并添加上表 7 个 checks（须至少有一次 PR 跑过 CI 后才会出现在列表里）
- [x] **Require conversation resolution before merging**
- [x] **Do not allow bypassing the above settings**（Include administrators）
- [ ] Allow force pushes — **关闭**
- [ ] Allow deletions — **关闭**

保存后，用 `./scripts/verify-branch-protection.sh` 或 Settings 页确认。

---

## 3. 组织与权限（建议）

| 项 | 建议 |
|----|------|
| 仓库位置 | 放在 **`jinziyou` org** 下（已是） |
| 默认权限 | Settings → Collaborators：外部贡献者 **Read**；Maintainer 才 **Write** |
| Secret 管理 | 仅 Maintainers 可改 Actions secrets |
| Fork | Public 后允许 fork；合并权仍只在官方 repo |

---

## 4. 与治理文档的关系

| 文档 / 文件 | 作用 |
|-------------|------|
| [`GOVERNANCE.md`](../GOVERNANCE.md) | 谁有权 merge、RFC、Release |
| [`.github/CODEOWNERS`](CODEOWNERS) | 哪些路径必须 `@jinziyou` approve |
| [`DCO.md`](../DCO.md) + [`workflows/dco.yml`](workflows/dco.yml) | 贡献签核 |
| **本文** | GitHub 上强制执行上述规则 |

---

## 5. 故障排查

| 现象 | 处理 |
|------|------|
| API 403 “Upgrade to GitHub Pro or make public” | 见 §0 |
| Required check 列表为空 | 先开一条 PR 跑完 CI + DCO，再回到 Branch protection 添加 |
| CODEOWNERS review 不生效 | 确认文件在 `.github/CODEOWNERS`；PR 改动了 owned 路径 |
| 管理员直推仍成功 | 确认勾选 **Include administrators** / `enforce_admins: true` |
| 改 job 名后 merge 被卡 | 更新 `setup-branch-protection.sh` 中的 `context` 并重新 apply |

---

## 6. 相关链接

- [GitHub: About protected branches](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches)
- [GitHub REST: Update branch protection](https://docs.github.com/en/rest/branches/branch-protection#update-status-checks-protection)
