# 部署与安全须知（kcatta）

kcatta 自身是安全态势平台，部署时请遵循以下要点。本文集中说明散落在
`analyzer/README.md`、`admin/README.md`、`.env.example`、`docker-compose.yml`
中的安全/运维约定。

## 鉴权（analyzer API）

- analyzer 用 `ANALYZER_API_TOKEN` 做可选 bearer 鉴权，比较走 `secrets.compare_digest`（恒定时间）。
- **未设置 token 时，analyzer 放行所有请求（无鉴权）** —— 仅适合本机 dev。
- 设置 token 后，`/ingest`、`/reports`、`/detect`、`/attack-paths`、`/targets`、`/scans` 全部需要
  `Authorization: Bearer <token>`；只有 `/health` 公开。
- **生产必须设置强随机 token**，例如：
  ```bash
  python -c "import secrets; print(secrets.token_urlsafe(32))"
  ```
- `docker compose` **没有内置默认 token**：未在 `.env` 设置 `ANALYZER_API_TOKEN` 会拒绝启动
  （避免“出厂即弱口令”）。`cp .env.example .env` 后填入强随机值。
- 空字符串（`ANALYZER_API_TOKEN=`）等同未设置 —— agent 上报端也按未设置处理，不会发送空 Bearer 头。

## 网络暴露

- 生产建议把 analyzer 绑定到 `127.0.0.1` 并经反向代理（TLS + 鉴权）对外，而非直接 `0.0.0.0:8000`。
- **CORS**：默认仅放行 `http://localhost:3000`；生产用 `ANALYZER_CORS_ORIGINS` 收敛到真实前端域名。
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

## admin

- analyzer token 仅在 admin **服务端**转发（非 `NEXT_PUBLIC_`），不会进入客户端 bundle。
- `NEXT_PUBLIC_ANALYZER_BASE_URL` 是 **构建期** 注入（Next.js），Docker 下通过 `--build-arg` 传入。

## 供应链

- 三语言均提交 lockfile（`Cargo.lock` / `uv.lock` / `pnpm-lock.yaml`）。
- CI 含一个非阻断的依赖漏洞扫描 job（cargo-audit / pip-audit / pnpm audit），并启用 Dependabot。
