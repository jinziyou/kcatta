# 安全策略与部署须知（kcatta）

本文分两部分：**（一）安全漏洞报告流程**（如何私下上报漏洞）；**（二）部署与运行安全须知**
（集中说明散落在 `analyzer/README.md`、`admin/README.md`、`.env.example`、`docker-compose.yml`
中的安全/运维约定）。

---

## 一、报告安全漏洞（Reporting a Vulnerability）

我们重视所有安全问题。**请不要在公开 Issue / PR / Discussion 中披露漏洞或贴 PoC**，以免在修复前被利用。

**上报渠道（唯一）—— GitHub 私密漏洞上报（Private Vulnerability Reporting）：**

在本仓库 **`Security` 标签页 → “Report a vulnerability”** 提交。这会开启一个仅维护者与你可见的私密
advisory 线程，我们在其中协作分诊、修复与协调披露。

> 请使用此渠道，**不要**通过公开 Issue/PR/Discussion，也无需邮件。若你在该仓库看不到 “Report a
> vulnerability” 按钮，说明维护者尚未启用此功能；可改在本仓库提一个**不含任何漏洞细节/PoC** 的占位
> Issue 请求开启私密上报，切勿在其中粘贴利用细节。

**请在报告中尽量包含：** 受影响组件（agent / analyzer / admin）与版本/commit、复现步骤或 PoC、影响面与你认为的严重度、可能的修复建议。

**支持的版本：** 当前为个人维护的早期阶段，**仅对默认分支（`main`）的最新提交提供安全修复**；旧 commit / fork / 镜像不在支持范围（参见 [`GOVERNANCE.md`](GOVERNANCE.md)，官方仓库仅 `github.com/jinziyou/kcatta`）。

**响应预期（尽力而为，best-effort）：** 我们力争 **5 个工作日内确认**收到报告，并在评估后与你商定修复与**协调披露（coordinated disclosure）**的时间线；修复发布后会在 release notes / GitHub Security Advisory 致谢报告者（除非你要求匿名）。

> 范围说明：kcatta 是**防御/蓝队**安全态势平台。报告请聚焦 kcatta 自身代码的可被利用缺陷（如鉴权绕过、注入、SSRF、越权、远端投放链路的命令注入/路径穿越、敏感信息泄露等）。第三方依赖漏洞优先走上游 + Dependabot；纯运维配置不当（如未设 token 裸跑）属于下方“部署须知”，非代码漏洞。

---

## 二、部署与运行安全须知

kcatta 自身是安全态势平台，部署时请遵循以下要点。

## 鉴权（analyzer API）

- analyzer 用 `ANALYZER_API_TOKEN` 做可选 bearer 鉴权，比较走 `secrets.compare_digest`（恒定时间）。
- **未设置 token 时，analyzer 放行所有请求（无鉴权）** —— 仅适合本机 dev。
- 设置 token 后，`/ingest`、`/reports`、`/detect`、`/attack-paths`、`/targets`、`/scans` 全部需要
  `Authorization: Bearer <token>`；只有 `/health` 公开。
- **生产必须设置强随机 token**，例如：
  ```bash
  python -c "import secrets; print(secrets.token_urlsafe(32))"
  ```
- `docker compose` **没有内置默认 token**，但**零配置**：未设置 `ANALYZER_API_TOKEN` 时，一次性
  `token-init` 服务会生成一个**每次部署唯一的强随机 token**（`secrets.token_urlsafe(32)`）写入私有
  `kcatta-secrets` 卷，analyzer/admin 启动时自动从卷加载——既不内置弱口令、也无需手动填。
  要**固定/共享**一个已知 token（例如分发给远端部署的 agent），在环境或 `.env` 显式设置
  `ANALYZER_API_TOKEN` 即可覆盖；`docker compose down -v` 清卷后下次重新生成。
- 空字符串（`ANALYZER_API_TOKEN=`）等同未设置 —— agent 上报端也按未设置处理，不会发送空 Bearer 头。

## 网络暴露

- 生产建议把 analyzer 绑定到 `127.0.0.1` 并经反向代理（TLS + 鉴权）对外，而非直接 `0.0.0.0:10068`。
- **CORS**：默认仅放行 `http://localhost:10063`；生产用 `ANALYZER_CORS_ORIGINS` 收敛到真实前端域名。
  允许的请求头已收敛为 `Authorization` / `Content-Type`，且不允许携带 Cookie（鉴权只走 bearer 头）。
- **请求体上限**：ingest 默认限制单请求 ≤ 10MB（`ANALYZER_MAX_BODY_BYTES` 可调），防止超大上传打满内存/磁盘。
  生产仍建议在反向代理层再设一道 body-size 上限。

## 持久化

- v0 默认 JSONL（单写者）；**生产推荐 SQLite**（`ANALYZER_STORAGE=sqlite`，docker compose 即用此）。
- 切换后端前先 `analyzer-migrate-storage` 迁移历史数据。
- JSONL 仅适合单写者；多 worker 部署请用 SQLite。

## 远端投放采集（analyzer-scan）

- SSH/WinRM 主机密钥当前采用 `AutoAddPolicy`（等价 `StrictHostKeyChecking=no`），**仅适用于可信实验/内网环境**；
  跨信任域使用前请评估中间人风险（首连一次性口令可能被截获）。
- `--target` / `--windows-packages` 在投放前已做白名单校验，并在拼入远端命令时统一转义。
- `--winrm-skip-cert-check` 会关闭 TLS 校验并配合 NTLM，**仅限你完全掌控网络路径时使用**。
- 受管密钥落在 `~/.config/scdr/agent-remote/keys/`；用 `analyzer-scan --revoke-key` 撤销。
- **本机扫描（transport=local）**：不连 SSH、不需凭据，直接在 analyzer 主机上跑 agent-host（子进程的环境已剥离 `ANALYZER_API_TOKEN`）。容器化部署若要扫描真实宿主机，需把宿主根目录挂进容器——务必**只读**（`/:/host:ro`）并仅在确需时开启。注意边界：只读挂载本就意味着 analyzer 进程（及其 agent-host 子进程）可**读取整机文件系统**——这正是本机扫描的目的，但也把宿主上的密钥/配置/凭据等敏感文件纳入可读范围。容器加固（`no-new-privileges`、`cap_drop: ALL`，本仓库 compose 已默认启用）限制的是容器内**提权**，并**不**收窄上述读取范围；因此请把开启该挂载视同「授予 analyzer 对宿主文件系统的只读访问」来评估，仅在受信主机上启用。

## admin

- analyzer token 仅在 admin **服务端**转发（非 `NEXT_PUBLIC_`），不会进入客户端 bundle。
- `NEXT_PUBLIC_ANALYZER_BASE_URL` 是 **构建期** 注入（Next.js），Docker 下通过 `--build-arg` 传入。

## 供应链

- 三语言均提交 lockfile（`Cargo.lock` / `uv.lock` / `pnpm-lock.yaml`）。
- CI 含一个非阻断的依赖漏洞扫描 job（cargo-audit / pip-audit / pnpm audit），并启用 Dependabot。
