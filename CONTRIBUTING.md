# 贡献指南（Contributing to kcatta）

感谢你对 kcatta 社区版（Community Edition）的关注！本文是**实操向**的贡献入口——环境、构建、测试、
提交与签核。**治理、决策权与正式贡献流程**以 [`GOVERNANCE.md`](GOVERNANCE.md) 为准；参与即表示你同意
遵守 [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md)。

> 官方仓库仅为 `https://github.com/jinziyou/kcatta`。当前为**个人维护的早期阶段**（BDFL 模型，见 GOVERNANCE）。

## 开始之前

1. 先搜索现有 [Issues](https://github.com/jinziyou/kcatta/issues) 与 [Pull Requests](https://github.com/jinziyou/kcatta/pulls)，避免重复劳动。
2. **较大变更**（新 API、跨组件契约、破坏性改动）请**先开 Issue / Discussion 简述方案**，达成方向再动手。
3. **安全漏洞不要走公开 Issue/PR**，按 [`SECURITY.md`](SECURITY.md) 的流程私下上报。

## 环境与工具链

kcatta 是 monorepo，三组件各用原生工具链（版本要求见各组件 README 与 `agent/Cargo.toml` 的 `rust-version`）：

| 组件 | 工具链 | 最低要求 |
| --- | --- | --- |
| **agent** (Rust) | `rustup` stable + `cargo` | rustc ≥ 1.96；musl 部署构建需 `musl-tools`，eBPF（可选）需 nightly + rust-src + `bpf-linker` |
| **analyzer** (Python) | `uv` | Python ≥ 3.11 |
| **admin** (Next.js) | `pnpm`（由 `packageManager` 字段锁定）+ Node | Node ≥ 22、pnpm 10.x |

```bash
# agent
cd agent     && cargo build --workspace --locked
# analyzer
cd analyzer  && uv venv && uv pip install -e ".[dev]"
# admin
cd admin     && pnpm install --frozen-lockfile
```

## 构建与测试

提交前请在改动涉及的组件跑通对应检查；根 `Makefile` 提供跨组件快捷入口：

```bash
make test-all        # agent cargo test + analyzer pytest + admin 构建/类型检查
make lint-all        # rustfmt+clippy / ruff / eslint
make schema-check     # analyzer Pydantic → schemas-json 是否同步
make contracts-check  # admin TS 契约是否与 schemas-json 同步
```

**跨组件数据契约**：若改动 `analyzer/src/analyzer/schemas/`，须重新导出 `analyzer/schemas-json/` 并同步
`agent/crates/contract/`（Rust 镜像）与 `admin/src/lib/schemas/`（TS 类型），CI 用 `schema-check`/`contracts-check`
做 git-diff 校验。详见 [`README.md`](README.md#开发约定) 的“开发约定 / 跨组件接口”。

## 提交与 PR

- **分支与 PR 流程**：以 [`GOVERNANCE.md` §3](GOVERNANCE.md) 为准（feature 分支 + PR + CI 通过 + 维护者审查）。
- **提交规范**：建议 [Conventional Commits](https://www.conventionalcommits.org/)（如 `feat(host): …` / `fix(analyzer): …`）。
- **DCO 签核（必须）**：每个 commit 须带 `Signed-off-by` —— 用 `git commit -s` 自动添加，邮箱须与提交者一致。
  含义见 [`DCO.md`](DCO.md)；CI 的 DCO 检查会拦截缺签核的提交。
- **CI 必须通过**：本地可先 `make test-all && make lint-all` 自检。
- PR 请填写 [`pull_request_template.md`](.github/pull_request_template.md) 的检查项。

```bash
git checkout -b feat/my-change
# … 修改 …
git commit -s -m "feat(host): 简要描述"     # -s 自动 DCO 签核
git push origin feat/my-change                # 再开 PR
```

## 许可与版权

kcatta CE 以 **Apache-2.0** 授权（eBPF 内核 bin 另含 GPL-2.0，见 [`NOTICE`](NOTICE)）。提交贡献即表示：
你以 Apache-2.0 授权你的贡献，并通过 DCO 签核声明你有权提交这些代码（见 [`LICENSE`](LICENSE) / [`DCO.md`](DCO.md)）。
「kcatta」名称/标识的使用另见 [`TRADEMARK.md`](TRADEMARK.md)。
