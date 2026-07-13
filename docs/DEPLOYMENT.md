# kcatta 部署与运维入口

本文只记录部署相关事实：本地 compose 栈、环境变量、安全默认值、agent 投放二进制与验证命令。组件内部用法仍以各组件 README 为准。

## 1. 本地 compose 栈

```bash
cd kcatta
make compose-config       # 校验 docker-compose.yml 语法与插值
make compose-up           # 等价于 docker compose up --build
# 浏览器访问 http://localhost:10063
make compose-down
```

compose 启动五个服务（`form` 与 `form-agent` 是 Form 组件的两个隔离进程）：

| 服务 | 暴露面 | 作用 |
| --- | --- | --- |
| `token-init` | 不暴露端口 | 生成 Admin→Form、legacy Agent→Form、Form→Analyzer 三个隔离令牌 |
| `analyzer` | 仅私有 `form-analyzer` 网络 `10068` | 分析、关联、预测与结果存储；只接受 Form 内部令牌 |
| `form` | 宿主回环 `127.0.0.1:10067` | Form 控制/查询面；目标、任务、凭据、身份签发、Agent 投放与 Analyzer facade；mixed 期兼容旧 bearer ingest |
| `form-agent` | 宿主回环 `127.0.0.1:10443` | 专用 Agent mTLS listener；只提供三条 telemetry ingest 路由与探针 |
| `admin` | 宿主回环 `127.0.0.1:10063` | Next.js 控制台；服务端只调用 `http://form:10067` |

默认无需 `.env` 即可在回环地址启动：`token-init` 会生成并复用三个令牌，Form 还会初始化
per-Agent CA、listener server certificate 和身份库。Compose 默认
`FORM_AGENT_AUTH_MODE=mixed`；新部署 Agent 使用客户端证书，`FORM_INGEST_TOKEN` 只供尚未
迁移的旧 Agent。Admin 只持有 `FORM_API_TOKEN`，Form→Analyzer 单独使用
`ANALYZER_INTERNAL_TOKEN`。

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
FORM_API_TOKEN=<控制令牌> \
FORM_INGEST_TOKEN=<端点令牌> \
ANALYZER_INTERNAL_TOKEN=<内部令牌> \
docker compose up --build
```

不要把 `docker compose down -v` 当成“只轮换/删除密钥”的命令：`-v` 会删除本项目的
**全部** named volumes，包括 Analyzer/Form 数据、作业与 handoff spool、托管凭据、Agent
身份库、CA/TLS material 和 token secrets。普通停机使用 `docker compose down`；任何卷删除
都应先做并验证备份，再逐个明确处理。

## 2. 生产暴露面

- Analyzer 不发布到宿主机，并位于 Admin 无法加入的私有网络；不要绕过 Form 暴露它。
- Form 是唯一组件交互边界，但按信任域拆成两个入口：`:10067` 是 Admin/control/facade，
  `:10443` 是 Agent 专用 mTLS listener。后者只注册 `/ingest/asset-report`、
  `/ingest/trace-batch`、`/ingest/guard-event`（另有 `/health`、`/ready`），没有 target、
  scan、credential、报告查询或 capability-graph API。
- 远程 Agent 应使用可达的 HTTPS `FORM_AGENT_PUBLIC_URL`，并显式设置
  `FORM_AGENT_BIND_ADDRESS=0.0.0.0`，或在前面使用 L4 TCP/TLS pass-through。客户端证书由
  `form-agent` 自己在 TLS 握手中验证；不要在普通反向代理终止 mTLS 后传
  `X-Client-Cert` 一类 header，Form 不信任这些 header。`:10067` 应继续留在回环、VPN 或
  受保护的控制网络。
- `mixed` 模式迁移旧 Agent 时，旧 Guard 可暂时使用 `FORM_PUBLIC_URL` +
  `FORM_INGEST_TOKEN` 访问 `:10067`；此时才需要暴露相应 legacy 路径。strict `mtls` 模式
  拒绝 bearer ingest，也不要求 `FORM_INGEST_TOKEN`。
- Admin 无内置用户登录且其服务端持有 Form 控制 token。默认只绑定回环；必须先放到
  TLS / SSO / VPN 后，才能设置 `ADMIN_BIND_ADDRESS=0.0.0.0`。
- Form 裸机 legacy/mixed 本地开发若不设 control/ingest 令牌，必须显式设置
  `FORM_ALLOW_INSECURE_NO_AUTH=true`；strict mTLS 仍要求 control token，但不要求 ingest
  token。Analyzer 无内部令牌时同样必须显式设置
  `ANALYZER_ALLOW_INSECURE_NO_AUTH=true`。Compose 始终自动生成非空、相互隔离的
  token secrets；strict mTLS 下 legacy Agent token 即使仍在卷中也不会被 Form 接受。
- Form 在读取请求体前实施全局/每-peer 并发上限、ingest token-bucket、请求体大小和
  读取时限；代理层若改写 peer 地址，应只信任明确配置的代理，不应无条件信任
  `X-Forwarded-For`。
- SSH/WinRM 目标属于低信任边界。Form 对远端扫描产物同时执行流式单文件上限
  (`FORM_MAX_SCAN_ARTIFACT_BYTES`) 和单次扫描总量上限 (`FORM_MAX_SCAN_TOTAL_BYTES`)，
  并在 JSON 解析前重新校验本地文件。两者默认均为 32 MiB；Form 验证聚合结果后，
  再按每个 Analyzer 请求 9 MiB 及契约条数上限无损拆分。

## 3. Per-Agent mTLS 上线与轮换

### 首次配置

为目标可达的 Agent 域名配置 public URL，再启动栈：

```bash
FORM_AGENT_AUTH_MODE=mixed \
FORM_AGENT_PUBLIC_URL=https://agents.example.com:10443 \
FORM_AGENT_TLS_SERVER_NAME=agents.example.com \
FORM_AGENT_BIND_ADDRESS=0.0.0.0 \
docker compose up -d --build
```

`FORM_AGENT_TLS_SERVER_NAME` 应与 public URL 的主机名一致；额外 DNS/IP SAN 用逗号分隔的
`FORM_AGENT_TLS_SANS`。应在第一次签发 listener certificate 前确定这些名称。control Form
拥有 `form-credentials` 中的 CA signing key，并把 public CA certificate 与独立 server
leaf/key 写入 `form-agent-tls`。`form-agent` 对 TLS material 只读挂载，且完全不挂载
`form-credentials`，因此没有 signing key；它只读取共享 `form-agent-identities` 来逐请求检查
证书状态、scope 和吊销。listener server leaf 默认 30 天；control Form 在启动时以及运行中
每 `FORM_AGENT_TLS_RENEW_CHECK_SECONDS`（默认 6 小时，最长 24 小时）检查一次，剩余有效期
不超过 7 天时原子发布新的 cert/key generation。`form-agent` 每
`FORM_AGENT_TLS_RELOAD_POLL_SECONDS`（默认 5 秒）验证共享只读卷中的新快照；完整且有效时
优雅排空请求并重建 Uvicorn SSLContext，不完整 publication 则继续使用旧 generation 并重试。
因此续签不依赖 control Form 或整个 Compose 栈重启，listener 也不需要 CA signing key/写卷
权限。Compose 为 listener 配置 `restart: unless-stopped`，处理进程级意外退出；仍应监控
`/agent-tls/current/server-cert.pem` 的到期时间和轮换失败日志。

每个 Agent 身份稳定绑定 `target_id`、canonical host ID 和 telemetry scopes。Form 从真实
TLS peer certificate 解析 principal，不接受 payload 或代理 header 自报身份；因此持有 Agent A
证书也不能把数据归属伪装成 target B。证书默认 30 天、API 上限 90 天，需纳入到期监控。

### 从 fleet bearer 迁移

1. 保持 `FORM_AGENT_AUTH_MODE=mixed`。旧 Agent 继续用 `FORM_PUBLIC_URL` +
   `FORM_INGEST_TOKEN`，新/重新投放的 Guard 使用 `FORM_AGENT_PUBLIC_URL` + per-Agent mTLS。
2. 逐目标从 Admin/Form 重新触发 Guard 投放并确认其 identity/generation 为 active。托管投放
   会先 stage generation，再经已认证且已校验 host key 的 SFTP 安装 cert/key/CA，远端启动
   成功后才 activate。
3. 确认所有驻留 Agent 已在 `:10443` 上报后，设置 `FORM_AGENT_AUTH_MODE=mtls`，从部署环境
   移除 `FORM_INGEST_TOKEN` 并重启 `form`。专用 `form-agent` listener 始终是 strict mTLS，
   不受迁移模式放宽。

当前 MVP 的客户端 leaf 私钥由 Form 在内存中生成，只存在于首次签发的一次性 bundle；Form
身份库与 CA 服务不持久化它。托管 Guard 通过上述 SFTP 边界传送一次。直接调用
`POST /targets/{target_id}/agent-identity/provision` 或
`POST /agent-identities/{agent_id}/rotate` 的运维客户端必须把响应当作一次性 secret；若在安装
前丢失，abort staged generation 后重新签发。CSR 自助注册与 TPM/HSM 不可导出端点密钥尚未
实现，属于下一增量。

轮换顺序固定为 stage → 安装 → activate。activate 后旧 active certificate 默认再接受 10 分钟，
避免在连接切换时丢 telemetry；失败时 abort staged generation 不会碰旧证书。紧急处置使用
generation 或整个 identity 的 revoke，立即生效且不等待 overlap。`agentd` 会在上传周期检测
cert/key/CA 文件变化并切换 client，无需重启；401/403 时保留 spool 并停止该轮 drain，凭据修复
后再 oldest-first 重放。

上述热加载只消费**已经安装**的新客户端材料，不会自行向 Form 申请或安装证书。当前只有
listener 的服务端 leaf 具备定时自动续签；客户端 leaf 到期前仍需通过托管 Guard 重新投放，或由
运维显式执行 provision/rotate、安装并 activate。必须分别监控两类证书，不能用服务端自动轮换
推断端点证书也已轮换。

## 4. agent 投放二进制

SSH/Linux 远程扫描由 Form 投放静态 musl 二进制。每个架构需要三件产物：

| 文件 | 用途 |
| --- | --- |
| `agent-collect-host` | host 一次性静态采集 |
| `agent-collect-trace` | trace 一次性捕获 |
| `agentd` | guard 常驻守护；只有 `agentd` 负责上报 |

本地构建：

```bash
make build-agent-deploy         # x86_64-unknown-linux-musl；需 musl-tools
make build-agent-deploy-arm64   # aarch64-unknown-linux-musl；需 cross
make build-agent-deploy-windows # x86_64-pc-windows-gnu；需 gcc-mingw-w64-x86-64
```

Form 按目标 `uname -m` 自动从 `FORM_AGENT_TARGET_DIR/<triple>/release/<bin>` 选择二进制。默认 `FORM_AGENT_TARGET_DIR=../agent/target`；容器镜像内默认是 `/opt/kcatta/agent-bins`。

当前 Form 容器内置 x86_64 musl 的 `agent-collect-host`、带真实连接表后端的 `agent-collect-trace`、`agentd`，以及 WinRM 使用的 x86_64 Windows GNU `agent-collect-host.exe`。host/trace 可直接触发；远程 guard 还必须显式配置目标可达的 `FORM_AGENT_PUBLIC_URL`（legacy 迁移才使用 `FORM_PUBLIC_URL`），否则 Form 会拒绝任务。扫描 aarch64 目标时，需要另外构建 arm64 产物并挂载到 `FORM_AGENT_TARGET_DIR`。

## 5. 本机扫描（transport=local）

`transport=local` 不走 SSH，直接在 Form 主机执行本机架构的 `agent-collect-host`，仅支持 host 能力。

容器内默认扫描 Form 容器自身。要扫描宿主机，将宿主根目录只读挂载，并设置扫描根：

```yaml
services:
  form:
    volumes:
      - /:/host:ro
    environment:
      FORM_LOCAL_SCAN_ROOT: /host
```

## 6. 从旧版 Analyzer 控制面升级

旧版的 target/job 位于 `analyzer-data`；新版 Form 使用独立 `form-data`。升级前
不要执行 `docker compose down -v`，否则旧数据以及当前栈的所有数据、凭据、身份、TLS
和 token 卷都会被删除。先备份卷并停止 Admin、Form（含 Agent listener）与 Analyzer，
然后运行一次离线迁移。

裸机/目录部署：

```bash
make migrate-control-state \
  OLD_ANALYZER_DATA_DIR=/srv/kcatta/analyzer-data \
  FORM_DATA_DIR=/srv/kcatta/form-data \
  OLD_ANALYZER_STORAGE=auto \
  FORM_STORAGE=sqlite
```

Compose 部署先用 `docker volume ls` 确认旧卷名；默认项目名下通常为
`kcatta_analyzer-data`：

```bash
docker compose stop admin form-agent form analyzer
docker compose build form
OLD_ANALYZER_VOLUME=kcatta_analyzer-data
docker compose run --rm --no-deps \
  --volume "${OLD_ANALYZER_VOLUME}:/old-analyzer:ro" \
  --entrypoint .venv/bin/form-migrate-control-state \
  form \
  --analyzer-data-dir /old-analyzer \
  --form-data-dir /data \
  --source-storage auto \
  --form-storage sqlite
docker compose up -d
```

该命令只读取 `scan_targets` / `scan_jobs`（或同名 JSONL 文件），不会迁移 Analyzer
的报告、Trace、Guard 事件、漏洞、告警或预测数据。它按 ID 保留源端最后记录，且不
覆盖 Form 已有 ID，因此可幂等重跑；旧 pending/running 作业会变成 failed，需重新
触发。

升级后还必须完成运行时切换：

1. 停止旧常驻 Guard，并通过 Form 重新部署。旧 Guard 保存的是 Analyzer URL/token，
   不会因数据库迁移自动更新。
2. 旧 `ANALYZER_API_TOKEN` / `ANALYZER_INGEST_TOKEN` 不再有效。Admin 使用
   `FORM_API_TOKEN`；新 Agent/Guard 使用专用 `:10443` per-Agent mTLS，旧 Agent 仅在
   mixed 迁移窗口使用 `FORM_INGEST_TOKEN`。
3. 迁移命令不复制或重命名秘密；新版 managed-key 文件名还加入端点摘要以避免
   sanitize 碰撞。因此迁移后的 SSH/WinRM managed-key 目标需重新注册并重新引导
   凭据；identity 模式则必须保证 `identity_path` 在 Form 主机可访问。

## 7. 持久作业、容量与备份

Form 的 `form-data` 卷现在包含三类必须一起纳入备份/容量监控的状态：

- target registry：`form.db`（`FORM_STORAGE=sqlite`）或 JSONL；
- durable job queue：固定为 `form-jobs.db`，不受 `FORM_STORAGE` 选择影响；
- collect→Analyzer handoff：`scan-artifacts/`。

凭据和 Agent CA signing key 位于独立 `form-credentials` 卷；Agent identity SQLite 位于
`form-agent-identities`，listener server leaf/key 与 public CA certificate 位于
`form-agent-tls`。做一致性备份时先停止 `form` 与 `form-agent`，随后一起备份
`form-data`、`form-credentials`、`form-agent-identities` 和 `form-agent-tls`；还应按 Analyzer
恢复要求备份 `analyzer-data`。只复制主 `.db` 而漏掉活动 WAL，或只复制 job DB 而漏掉
spool，都不能形成可恢复快照。默认 job DB/spool 预算各为 256 MiB，可用
`FORM_SCAN_JOB_*` 与 `FORM_SCAN_SPOOL_*` 调整；接近上限时新任务返回可重试的 507，
不会为腾空间删除 active head。

worker 使用 lease + epoch fencing，重启后继续 pending/retrying，并回收过期 running。
job store 在同一 target 上只允许一个 active job；直接 Guard 操作会取得 durable
target-operation lease，并与该 target 的 job claim 互斥。远端 Guard 目录另有带 owner fencing
和过期时间的 `.deployment-lock`；每条受保护的远端 shell 命令会在整个执行期间持有稳定 gate
inode 的内核 `flock`，并在锁内检查/续期 owner lease，防止旧 owner 与过期接管发生 TOCTOU。
Guard Linux 目标必须提供 util-linux `flock`，缺失时投放会 fail closed。

Guard 投放本身是可回滚事务：先保留旧 binary/config/env/identity pointer，再安装新 generation；
只有新进程存活且包含 deployment ID、identity generation、binary/config hash、PID、unit 与路径的
manifest 已原子发布后，Form 才 activate staged 客户端证书。若 SSH 响应丢失且无法证明回滚，
任务保留为 outcome uncertain，后续 owner 必须以远端 manifest 对账，不能盲目 abort 或再投放。
取消/补偿使用 expected-manifest compare-and-swap：远端 manifest 与完整预期不一致时拒绝 stop，避免
旧任务误杀更新的 Guard。

远端执行语义仍是 at-least-once。最终一次执行若以 `running` 租约过期，会得到一个固定为
`max_attempts + 1` 的 reconciliation-only claim；反复崩溃不会继续增加 attempt。Host/Trace 此时
只能转发已有 durable artifact，缺少 artifact 时拒绝再次采集。Guard 只接受与该 job 的幂等证书
generation 和 live manifest 完整匹配的部署。正常情况要求 manifest PID 与存活 PID 完全一致；仅
mTLS + systemd 重启可在证明 binary/config hash、当前 identity generation 和 `/proc/<pid>/exe`
均属于原部署后，以旧 manifest bytes 为条件 CAS 刷新 PID。Legacy bearer manifest 没有唯一的
identity-generation nonce，因此始终要求精确 PID；崩溃窗口无法唯一归属时会 fail closed，可能需要
运维核查并清理，系统不会猜测后重新投放。

因此自定义投放脚本仍必须保持幂等或可补偿，并不得绕过 manifest/锁语义。

当前协调只支持**同一主机的本地持久卷**。不要把 SQLite WAL 与 spool `flock` 放到
NFS/跨主机共享卷后运行多个 Form 副本；跨主机高可用需要外部事务数据库或队列。

## 8. 部署前验证

```bash
make compose-config
make component-boundaries
make schema-check
make contracts-check
```

针对具体改动再跑组件级验证：

```bash
make test-analyzer
make test-form
make test-admin
make test-agent
```

CI 分别覆盖 Rust Agent、Windows 构建、musl 投放构建、Python Analyzer/Form、Next Admin、组件边界、schema/contract 漂移、DCO、secret scan、dependency audit 与完整栈 e2e smoke。
