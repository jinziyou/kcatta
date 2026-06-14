# kcatta 项目治理

本文说明 [kcatta](https://github.com/jinziyou/kcatta) 开源社区版（Community Edition，下称 **CE**）的决策权、贡献流程与发布规则。  
**官方仓库**仅为 `https://github.com/jinziyou/kcatta`；其他 fork 或镜像均非官方，除非项目 Leadership 另行书面授权。

## 1. 治理模型

kcatta 采用 **BDFL（Benevolent Dictator for Life，仁慈独裁者）** 模型。

**当前阶段（个人维护）：** 由单一维护者（`@1yping` / `jinziyou` 组织）担任 Project Leadership 与 Maintainer。决策、合并与发版均由此维护者负责；[`CODEOWNERS`](.github/CODEOWNERS) 预留给未来协作者，**现阶段不强制 CODEOWNERS 审查**（见 [分支保护](.github/BRANCH_PROTECTION.md) 的 solo 模式）。

| 角色 | 职责 |
| --- | --- |
| **Project Leadership** | 最终决策权：路线图优先级、许可证与商标政策、maintainer 任命、版本发布、重大架构变更 |
| **Maintainers** | 日常审查 PR、分类 issue、维护 CI、协调跨组件（agent / analyzer / admin）接口 |
| **Contributors** | 通过 Pull Request 提交补丁；须遵守 [DCO](DCO.md) 与本文 |

**原则：** 日常技术讨论鼓励共识；无法达成共识时，由 Project Leadership 做最终决定。出现外部协作者后，可启用 CODEOWNERS 强制审查（`SOLO=0 ./scripts/setup-branch-protection.sh`）。

## 2. 适用范围

| 范围 | 说明 |
| --- | --- |
| **本仓库（CE）** | `agent/`、`analyzer/`、`admin/` 及根目录共享基础设施；许可证见根目录 `LICENSE`（当前为 Apache-2.0） |
| **Enterprise Edition（EE）** | 不在本公开仓库内分发；由 Project Leadership 单独授权。EE 功能边界以官方文档为准 |
| **商标** | 「kcatta」名称与标识的使用见 [`TRADEMARK.md`](TRADEMARK.md)；与代码许可证相互独立 |

## 3. 贡献流程

### 3.1 开始之前

1. 搜索现有 [Issues](https://github.com/jinziyou/kcatta/issues) 与 [Pull Requests](https://github.com/jinziyou/kcatta/pulls)，避免重复劳动。
2. 较大变更（新 API、跨组件契约、破坏性改动）建议先开 Issue 或 Discussion 简述方案，再动手编码。
3. 阅读组件级指南：
   - [`agent/docs/CONTRIBUTING.md`](agent/docs/CONTRIBUTING.md)
   - [`analyzer/README.md`](analyzer/README.md)
   - [`admin/README.md`](admin/README.md)

### 3.2 Pull Request 要求

- 从 `main` 拉出的 **feature 分支** 发起 PR，目标分支为 `main`。
- 提交信息建议遵循 [Conventional Commits](https://www.conventionalcommits.org/)。
- **每个 commit 须带 DCO 签核**（`Signed-off-by`），详见 [`DCO.md`](DCO.md)。
- CI 必须通过（`make test-all` / GitHub Actions 等价检查）。
- 修改跨组件数据契约（`analyzer/schemas-json/`、`agent/crates/contract/`、`admin` 生成类型）时，须同步更新 Schema 导出与契约一致性检查。
- 安全相关漏洞请 **不要** 在公开 Issue 讨论，见 [`SECURITY.md`](SECURITY.md)。

### 3.3 审查与合并

- 至少一名 Maintainer（或 Project Leadership）批准后方可合并。
- Maintainer 可要求补充测试、文档或拆分 PR。
- Project Leadership 保留拒绝合并、要求 revert 或冻结争议 PR 的权利。

## 4. 决策流程

### 4.1 日常决策（Maintainers）

- Bug 修复、测试、文档、内部重构（无 API 行为变化）
- 依赖小版本升级、CI 配置调整
- 在 Maintainer 共识下可直接合并

### 4.2 重大决策（需 Project Leadership 确认）

以下变更须先经 Issue/RFC 公开讨论，并由 Project Leadership 批准：

- 公共 HTTP API、ingest 契约、JSON Schema 的**破坏性**变更
- 默认安全行为变更（鉴权、agent 处置策略默认值等）
- CE 许可证变更
- CE / EE 功能边界调整
- 新 top-level 组件或删除现有组件
- Maintainer 增删

**RFC 建议格式：** 背景 → 目标 → 方案 → 替代方案 → 对 agent/analyzer/admin 的影响 → 迁移计划。

### 4.3 紧急决策

- **安全漏洞：** 按 [`SECURITY.md`](SECURITY.md) 私下报告；Project Leadership 协调补丁与披露时间线。
- **CI / 主分支不可用：** Project Leadership 或 Maintainer 可直接 hotfix，事后补 PR 说明。

## 5. 版本与发布

- **`main`** 为开发集成分支；保持稳定、可随时 CI 绿。
- **版本标签** 采用 [Semantic Versioning](https://semver.org/lang/zh-CN/)（`vMAJOR.MINOR.PATCH`）。
- **发布权** 仅 Project Leadership 持有；发布须：
  - 更新相应 CHANGELOG（若存在）或 Release Notes
  - 对 tag 进行签名（推荐 GPG / Sigstore）
  - 注明各组件（agent / analyzer / admin）的兼容性说明
- **安全补丁** 优先于功能发布；严重漏洞可跨 minor 版本 backport，由 Project Leadership 决定。

## 6. Fork 与下游分发

在 CE 许可证（Apache-2.0）允许范围内，任何人可以 fork 本仓库并自行维护。请注意：

- Fork **不得** 暗示与 Project Leadership 的官方关系；见 [`TRADEMARK.md`](TRADEMARK.md)。
- 官方不保证对外部 fork 提供支持或合并回 upstream 的承诺。
- 欢迎通过 PR 向上游贡献；合并后版权与许可安排见 [`DCO.md`](DCO.md)。

## 7. 行为准则

参与 issue、PR、Discussion 时：

- 就事论事，尊重他人。
- 禁止骚扰、歧视、人身攻击与泄露他人隐私。
- Project Leadership 可对持续违反者限制参与（comment ban、PR block 等）。

## 8. 治理文件修订

修订 `GOVERNANCE.md`、`TRADEMARK.md`、`DCO.md` 须通过公开 PR，并由 Project Leadership 最终批准。  
重大治理变更应在合并前至少留 **7 天** 供社区评论（紧急安全情形除外）。

## 9. 相关文档

| 文档 | 用途 |
| --- | --- |
| [`DCO.md`](DCO.md) | 贡献者原创声明与 `Signed-off-by` 规范 |
| [`TRADEMARK.md`](TRADEMARK.md) | 「kcatta」名称与标识的使用政策 |
| [`SECURITY.md`](SECURITY.md) | 安全漏洞报告流程 |
| [`LICENSE`](LICENSE) | CE 源代码许可证 |
| [`README.md`](README.md) | 项目架构与快速开始 |
| [`.github/BRANCH_PROTECTION.md`](.github/BRANCH_PROTECTION.md) | `main` 分支保护（GitHub 硬开关 + 脚本） |

## 10. 联系

- **一般问题 / 功能讨论：** [GitHub Issues](https://github.com/jinziyou/kcatta/issues)
- **安全漏洞：** 见 [`SECURITY.md`](SECURITY.md)（勿公开贴 PoC）
- **商标授权咨询：** 见 [`TRADEMARK.md`](TRADEMARK.md)
