# GitHub Branch Protection（`main` 硬开关）

本文记录 `main` 分支保护的 GitHub 设置与脚本用法，把「PR + CI + DCO 后合并」落到仓库硬开关上。

**目标（个人维护阶段，默认 solo 模式）：**

- 禁止直接 push `main`（仍走 feature 分支 + PR，留审计轨迹）
- **不要求**他人或 CODEOWNERS approve（维护者自己的 PR，CI 绿即可合并）
- CI + DCO 必须通过才能合并

出现外部协作者后，可切换 **team 模式**（见 §1.1）。

---

## 1. 一键脚本（推荐）

仓库根目录：

```bash
# 预览将提交的规则（不调用 API）
./scripts/setup-branch-protection.sh --dry-run

# 个人项目（默认）：PR + CI + DCO，无人工 review
./scripts/setup-branch-protection.sh

# 多人维护：PR + CI + DCO + CODEOWNERS review
SOLO=0 ./scripts/setup-branch-protection.sh

# 验证
./scripts/verify-branch-protection.sh
```

### 1.1 Solo 模式（默认，`SOLO=1`）

| 规则 | 值 |
|------|-----|
| Require pull request | 是 |
| Required approving reviews | **0** |
| Require review from Code Owners | **否** |
| Require status checks (strict) | 是 |
| Include administrators | 是 |
| Allow force push / deletions | 否 |

适合：**只有你一人 merge**，但希望 `main` 始终经 PR + CI，避免手滑直推。

### 1.2 Team 模式（`SOLO=0`）

| 规则 | 值 |
|------|-----|
| Require pull request | 是 |
| Required approving reviews | 1 |
| Require review from Code Owners | 是（见 [`.github/CODEOWNERS`](CODEOWNERS)） |
| Dismiss stale reviews | 是 |
| Require conversation resolution | 是 |
| Require status checks (strict) | 是 |
| Include administrators | 是 |
| Allow force push / deletions | 否 |

---

## 0. 前置条件（重要）

当前仓库 `jinziyou/kcatta` 若为 **Private**：

| GitHub 计划 | Private 仓库 Branch Protection |
|-------------|--------------------------------|
| **Free** | ❌ 不可用（API/UI 均提示需 Pro 或改为 Public） |
| **Pro / Team / Enterprise** | ✅ 可用 |

**Required checks（与 workflow job 名一致；脚本会写入同一列表）：**

| Check | 来源 |
|-------|------|
| `agent (Rust)` | [`.github/workflows/ci.yml`](workflows/ci.yml) |
| `agent (Windows MSVC)` | CI |
| `agent (musl deploy build)` | CI |
| `agent (musl deploy build, arm64)` | CI |
| `analyzer (Python)` | CI |
| `form (Python control plane)` | CI |
| `admin (Next.js)` | CI |
| `dependency audit` | CI（HIGH/CRITICAL 阻断；cargo-audit 子步骤暂为提示信号） |
| `secret scan (gitleaks)` | CI（全历史 secret 扫描，硬阻断） |
| `e2e (admin + form + analyzer)` | CI |
| `Signed-off-by` | [`.github/workflows/dco.yml`](workflows/dco.yml) |

**起步不阻断（continue-on-error，暂不纳入 required）：**

| Check | 来源 | 说明 |
|-------|------|------|
| `agent (eBPF kernel build)` | CI | G1：真实编译内核 eBPF 程序，先暴露断裂，稳定后再设为必需 |
| `image scan (Trivy)` | CI | G3：扫描 analyzer/form/admin 镜像的 OS/库 CVE |
| `CodeQL SAST (python)` / `CodeQL SAST (javascript-typescript)` | CI | G3：SAST，结果进 Security 标签页 |

> 上述三组 job 当前 `continue-on-error: true`，**真实运行**但不阻断合并；待信号稳定后逐项去掉 `continue-on-error` 并加入 required checks。

> 若改名 workflow job，请同步修改 `scripts/setup-branch-protection.sh` 并重新运行。

---

## 2. 手动配置（GitHub Web UI）

**Settings → Branches → Branch protection rules → Add rule**

Branch name pattern: `main`

勾选（**solo 模式**）：

- [x] **Require a pull request before merging**
  - [ ] Require approvals — **0**（个人项目可不勾 approval）
- [x] **Require status checks to pass before merging**
  - [x] **Require branches to be up to date before merging**
  - 搜索并添加上表 10 个 checks
- [x] **Do not allow bypassing the above settings**（Include administrators）
- [ ] Allow force pushes — **关闭**
- [ ] Allow deletions — **关闭**

多人维护时改为：approvals **1** + **Require review from Code Owners** + conversation resolution。

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
| [`.github/BRANCH_PROTECTION.md`](BRANCH_PROTECTION.md) | PR / CI / DCO 的 GitHub 硬开关配置 |
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
