# kcatta Form

Form 是 kcatta 的唯一编排与组件交互边界：

```text
admin ──► Form ──► analyzer
             │
             ├──► agent（SSH / WinRM / local 投放）
             ◄─── agent（专用 mTLS telemetry ingest）
```

admin、analyzer、agent 不再互相直连。Form 拥有目标、凭据、扫描作业和
Guard 生命周期；analyzer 只负责存储、检测、关联与预测；agent 只负责端上
`Collect → Detect → Respond`。

## API

- 控制面：`/targets`、`/scans`、`/credentials`、`/targets/{id}/guard*`
- admin 查询 facade：`/reports/*`、`/attack-paths/*`
- Agent 身份管理：`/agent-identities*`、`/targets/{id}/agent-identity*`
- Agent ingress：专用 `form-agent:10443` 只提供
  `/ingest/asset-report`、`/ingest/trace-batch`、`/ingest/guard-event`
- 外部知识入口：`/ingest/capability-graph`
- 探针：`/health`（Form 存活）、`/ready`（含 analyzer 连通性与 durable worker 健康）

`form-api` 的控制/查询面监听 `:10067`。独立的 `form-agent-api` 监听 `:10443`，在 TLS
握手阶段强制校验客户端证书，而且没有 target、scan、credential、报告查询或 capability
graph 路由。公共路径保持原 analyzer API 的形状，以便 Admin 与已部署 Agent 平滑迁移。
Form 会用私有服务令牌调用 Analyzer；不会转发 Admin 或 Agent 的 Authorization。

## 环境变量

| 变量 | 默认 | 用途 |
| --- | --- | --- |
| `FORM_API_TOKEN` | 未设置 | admin 控制/查询令牌 |
| `FORM_INGEST_TOKEN` | 未设置 | mixed/legacy 迁移期的 fleet-wide ingest 令牌；strict mTLS 不需要 |
| `FORM_AGENT_AUTH_MODE` | 裸机 `legacy`；Compose `mixed` | `legacy`、`mixed` 或 `mtls`；`mixed` 同时接受旧 bearer 与新证书，`mtls` 拒绝 bearer ingest |
| `FORM_AGENT_IDENTITY_ENABLED` | mixed/mtls 时 `true` | 启用 per-target Agent 身份、证书签发与吊销管理 |
| `FORM_ALLOW_INSECURE_NO_AUTH` | `false` | 仅隔离本地开发允许 control/ingest 无令牌启动 |
| `FORM_ANALYZER_BASE_URL` | `http://127.0.0.1:10068` | analyzer 私有地址 |
| `ANALYZER_INTERNAL_TOKEN` | 认证开启时必填 | Form 调 analyzer 的独立服务令牌 |
| `FORM_AGENT_PUBLIC_URL` | 未设置 | 新常驻 Agent 使用的、目标可达的 `https://...:10443` mTLS 地址 |
| `FORM_PUBLIC_URL` | 未设置 | mixed/legacy 迁移期下发给旧 bearer Guard 的 `:10067` 地址 |
| `FORM_AGENT_IDENTITY_DATA_DIR` | `FORM_DATA_DIR` | per-Agent 身份/证书元数据 SQLite 目录；Compose 使用独立卷 |
| `FORM_AGENT_PKI_DIR` | 身份启用时必填 | 在线 CA 私钥目录；只能挂到 control Form，不能挂到 Agent listener |
| `FORM_AGENT_TLS_DIR` | 身份启用时必填 | Agent CA 公钥证书与 listener server leaf/key 目录 |
| `FORM_AGENT_TLS_SERVER_NAME` | 从 public URL 推导 | `:10443` 服务端证书主名称 |
| `FORM_AGENT_TLS_SANS` | 未设置 | listener 服务端证书的逗号分隔附加 DNS/IP SAN |
| `FORM_AGENT_TLS_CERT/KEY/CLIENT_CA` | `/agent-tls/current/*`、`/agent-tls/ca-cert.pem` | `form-agent-api` 的 server cert、server key 与 client CA 路径；cert/key 由原子 `current` generation 发布 |
| `FORM_AGENT_TLS_RENEW_CHECK_SECONDS` | `21600` | control Form 检查/续签 listener leaf 的周期；最大被限制为 24 小时 |
| `FORM_AGENT_TLS_RELOAD_POLL_SECONDS` | `5` | listener 检查原子 TLS generation 是否变化的周期 |
| `FORM_AGENT_TLS_GRACEFUL_SHUTDOWN_SECONDS` | `30` | listener 为加载新 SSLContext 而优雅 recycle 时的请求排空上限 |
| `FORM_ALLOW_INSECURE_HTTP` | `false` | 仅隔离实验网允许旧 bearer Guard 使用 HTTP；mTLS Agent 仍要求 HTTPS |
| `FORM_DATA_DIR` | `data` | target、`form-jobs.db` 与 `scan-artifacts/` 状态目录 |
| `FORM_STORAGE` | `jsonl` | target registry 的 `jsonl` 或 `sqlite`；作业队列始终使用独立 SQLite |
| `FORM_AGENT_TARGET_DIR` | `../agent/target` | 多架构 agent 部署产物根目录 |
| `FORM_WINDOWS_AGENT_BINARY` | 自动解析 GNU/MSVC 产物 | 可选的 WinRM `agent-collect-host.exe` 覆盖路径 |
| `FORM_TRACE_PCAP_ENABLED` | `false` | 已替换为带 `pcap` feature 的自定义 trace 二进制时显式开启 |
| `FORM_LOCAL_SCAN_ROOT` | `/` | `transport=local` 扫描根；此时扫描的是 Form 主机 |
| `FORM_MAX_BODY_BYTES` | `10485760` | Form 边界请求体上限（含无 Content-Length 的流式请求） |
| `FORM_MAX_IN_FLIGHT` | `16` | body 缓冲前的全局并发请求上限 |
| `FORM_MAX_IN_FLIGHT_PER_PEER` | `8` | 按直接网络 peer 的总并发上限（容纳 Admin 并行查询） |
| `FORM_MAX_INGEST_IN_FLIGHT_PER_PEER` | `4` | 低信任 ingest 在同一 peer 下的更严格并发上限 |
| `FORM_INGEST_RATE_PER_SECOND` | `5` | 每个 peer 的 ingest token-bucket 补充速率 |
| `FORM_INGEST_BURST` | `20` | 每个 peer 的 ingest 突发容量 |
| `FORM_BODY_READ_TIMEOUT_SECONDS` | `30` | 完整接收请求体的总时限 |
| `FORM_MAX_SCAN_ARTIFACT_BYTES` | `33554432` | 从不可信远端拉取的单个扫描产物上限；解析后按 9 MiB 拆分转发 |
| `FORM_MAX_SCAN_TOTAL_BYTES` | `33554432` | 单次远端扫描全部产物的合计上限 |
| `FORM_MAX_CONCURRENT_SCANS` | `4` | 同时运行的扫描作业上限 |
| `FORM_SCAN_JOB_TIMEOUT_SECONDS` | `1800` | 单作业总超时 |
| `FORM_REMOTE_COMMAND_TIMEOUT_SECONDS` | `1800` | SSH/WinRM 单命令硬超时；worker 在真实 transport 返回前不释放槽位 |
| `FORM_SCAN_LEASE_SECONDS` | `60` | durable claim 租约时长 |
| `FORM_SCAN_HEARTBEAT_SECONDS` | `min(15, lease/3)` | 续租与跨副本取消观察周期，必须短于 lease |
| `FORM_SCAN_POLL_SECONDS` | `1` | 空队列轮询周期 |
| `FORM_SCAN_MAX_ATTEMPTS` | `3` | 自动重试次数上限（最多 20） |
| `FORM_SCAN_RETRY_BASE_SECONDS` | `5` | 指数退避基准秒数 |
| `FORM_SCAN_RETRY_MAX_SECONDS` | `300` | 指数退避上限秒数 |
| `FORM_SCAN_SHUTDOWN_GRACE_SECONDS` | `15` | 关闭时等待真实执行停止的宽限期 |
| `FORM_SCAN_JOB_DB_MAX_BYTES` | `268435456` | 独立 scan-job SQLite 主库预算 |
| `FORM_SCAN_JOB_WAL_MAX_BYTES` | `16777216` | scan-job WAL 保留预算 |
| `FORM_SCAN_JOB_MAX_RECORD_BYTES` | `65536` | 单个公开 job head 上限 |
| `FORM_SCAN_JOB_MAX_ROWS` | `100000` | job head 上限；只淘汰终态 head |
| `FORM_SCAN_JOB_HISTORY_MAX_ROWS` | `100000` | 状态转换历史总行数上限 |
| `FORM_SCAN_SPOOL_MAX_ARTIFACT_BYTES` | `37748736` | collect→Analyzer 单个 durable handoff 制品上限 |
| `FORM_SCAN_SPOOL_MAX_TOTAL_BYTES` | `268435456` | handoff spool 总预算 |
| `FORM_SSH_HOST_KEY_POLICY` | `accept-new` | SSH 主机密钥策略：`accept-new` 或 `strict` |
| `FORM_SSH_KNOWN_HOSTS` | `$XDG_CONFIG_HOME/scdr/agent-remote/known_hosts` | Form 持久化的 SSH 主机密钥文件 |
| `FORM_WINRM_SKIP_CERT_CHECK` | `false` | 显式跳过 WinRM HTTPS 服务端证书校验（仅实验网） |

Form 官方 Linux 投放包将 trace 编译为 `winnet` connection-table 后端；默认
trace 任务读取真实连接而不是生成 mock。Admin 的 libpcap 开关仅适用于运维方
另行提供的 `pcap` feature 构建，并要求设置 `FORM_TRACE_PCAP_ENABLED=true`；
否则 Form 会在创建作业前返回 422。Form 镜像同时包含 WinRM Python 依赖和
`x86_64-pc-windows-gnu/release/agent-collect-host.exe`，Windows host 扫描无需另挂
二进制；也可通过 `FORM_WINDOWS_AGENT_BINARY` 使用运维方的 MSVC/签名版本。

SSH 默认采用持久化的 TOFU（`accept-new`）：首次连接记录目标 host key，后续
key 变化会拒绝连接。生产可改为 `strict`，并在首次注册/扫描前通过可信带外渠道
核验指纹后预置 `FORM_SSH_KNOWN_HOSTS`（非 22 端口使用 `[host]:port` 格式）。
`FORM_WINRM_SKIP_CERT_CHECK` 默认关闭；设置为 `true` 会允许中间人冒充 WinRM
服务端，只能用于隔离且可信的自签名证书实验环境。

生产环境应把 `FORM_AGENT_PUBLIC_URL` 配置为目标主机可达的 HTTPS `:10443` 地址。
Compose 服务名或 `127.0.0.1` 不能下发给远端 Agent。Compose 默认把 Form、form-agent
和 Admin 都绑定到 `127.0.0.1`；远程 Guard 场景应显式设置
`FORM_AGENT_BIND_ADDRESS=0.0.0.0`，或在前面使用 L4 TCP/TLS pass-through，让该 listener
直接完成 mTLS 握手并取得真实客户端证书。
不要用普通 TLS 反向代理终止 mTLS 后再伪造证书 header：Form 只信任直接 TLS transport
提供的 peer certificate。`:10067` 控制面通常仍留在回环/VPN；Admin 无内置用户登录，
不能在没有 SSO/auth proxy 时设置 `ADMIN_BIND_ADDRESS=0.0.0.0`。

## Per-Agent mTLS 身份

每个稳定 Agent 身份由 Form 绑定到 `target_id`、canonical `host_id` 和允许上报的
telemetry scopes。`:10443` 在每次请求上以 TLS peer certificate 的 serial/fingerprint
查询共享身份库，执行证书状态、有效期、吊销和 route scope 检查，再由 Form 写入可信
provenance；payload 自报的其它 Agent/target/host 身份不能覆盖该绑定。吊销身份或某一
generation 会立即影响后续请求。

Compose 默认使用 `FORM_AGENT_AUTH_MODE=mixed`：新部署 Guard 通过
`FORM_AGENT_PUBLIC_URL` 和 per-Agent 证书访问 `:10443`；已部署的 fleet-token Agent 可在
迁移窗口继续携带 `FORM_INGEST_TOKEN` 访问 `:10067`。确认旧 Agent 全部轮换后，切到
`FORM_AGENT_AUTH_MODE=mtls` 并移除 `FORM_INGEST_TOKEN`。`form-agent` listener 本身无论
control Form 使用何种迁移模式都只接受 mTLS。

当前 MVP 由 Form 在内存中生成客户端 leaf 私钥，并只在新 generation 的一次性 bundle
中返回。托管 Guard 投放会通过已经认证且完成 host-key 校验的 SFTP 将 bundle 原子安装到
目标；Form 的身份库和 CA 服务只保存证书元数据，**不持久化 leaf 私钥**。手工调用
provision/rotate API 的客户端必须同样把响应视作一次性 secret：丢失后应 abort staged
generation 并重新签发。CSR 自助注册、TPM/硬件不可导出密钥不是本 MVP 的能力，留作后续
增强。

轮换先创建 staged generation，成功安装后才 activate；失败时 abort 不影响旧 active
证书。activate 后旧证书默认有 10 分钟 overlap，便于驻留 Agent 无重启切换；显式 revoke
不等待 overlap。CA signing key 位于 `FORM_AGENT_PKI_DIR`，只由 `form-api` 持有；
`form-agent-api` 只挂载身份元数据、listener server key/cert 和公共 CA certificate，绝不
获得 signing key。

listener server leaf 默认 30 天；control Form 启动后仍每 6 小时检查一次，若其剩余有效期
不超过 7 天，会签发新 generation 并以一个原子 `current` symlink 切换 cert/key，避免读取到
错配文件。`form-agent-api` 只读监测该 generation；变化后先让当前 Uvicorn 排空请求，再用已
验证的新 cert/key/CA 重建 SSLContext。无效或不完整的 publication 不会替换仍可用的旧
SSLContext，且整个闭环不要求 listener 获得 CA signing key 或 TLS 卷写权限。客户端 leaf 的
热加载与此独立：Agent 只会加载已经安装的材料，Form 尚不会定时签发并远程安装客户端 leaf。
其到期前仍需托管 Guard 重投放，或显式执行 rotate、安装、activate。

## 开发

```bash
cd form
uv sync --extra dev
FORM_ALLOW_INSECURE_NO_AUTH=true uv run form-api --host 127.0.0.1 --port 10067
# 身份管理启用并已生成 listener material 后，另开一个终端：
uv run form-agent-api --host 127.0.0.1 --port 10443
uv run pytest
uv run ruff check src tests scripts
uv run form-export-schemas
uv run form-export-openapi
```

`form/schemas-json/` 是对 admin 和 agent 暴露的公共契约。当前迁移阶段，wire
模型复用 `kcatta-analyzer` 的 Pydantic 定义；target/job/credential 控制模型由
Form 自己拥有。

## 从旧 Analyzer 控制面升级

旧版把 target/job 状态写在 Analyzer 数据目录。升级时先停止 Form，再显式复制
这两类控制状态；命令不会读取或复制报告、告警、漏洞等 Analyzer 遥测/分析表：

```bash
uv run form-migrate-control-state \
  --analyzer-data-dir /path/to/old-analyzer-data \
  --form-data-dir /path/to/form-data \
  --source-storage auto \
  --form-storage sqlite
```

`auto` 在旧目录同时保留 JSONL 和 SQLite 时优先选择含控制记录的
`analyzer.db`。每个 `target_id` / `job_id` 只复制源端最后追加的记录；目标 Form
中已经存在的 ID 不覆盖，因此中断后可安全重跑。旧 pending/running 作业没有可恢复
runner，会在迁移时写为 failed，并提示从 Form 重新触发。源与目标必须是不同目录，
迁移期间 Form 必须停止写入。

状态迁移不等于运行时迁移：

- 旧常驻 Guard 仍携带旧 Analyzer URL/token，必须停止并由 Form 重新部署；
- 旧 `ANALYZER_API_TOKEN` / `ANALYZER_INGEST_TOKEN` 不再有效，Admin、Agent 应分别
  改用 `FORM_API_TOKEN` / Form 的 Agent ingress；新 Agent 应使用 `:10443` per-Agent
  mTLS，`FORM_INGEST_TOKEN` 只用于 mixed 模式下尚未轮换的旧 Agent；
- CLI 不复制或重命名 SSH key / WinRM 证书；新版托管凭据文件名还加入了端点摘要以
  避免 sanitize 碰撞。因此迁移后的 managed-key 目标应重新注册并引导凭据；
  identity 模式也必须确保原路径在 Form 主机可访问。

仓库根目录也提供同一入口：

```bash
make migrate-control-state \
  OLD_ANALYZER_DATA_DIR=analyzer/data \
  FORM_DATA_DIR=form/data \
  OLD_ANALYZER_STORAGE=auto \
  FORM_STORAGE=sqlite
```

## 持久作业与恢复语义

`POST /scans` 只把任务原子写入 `form-jobs.db`，执行不再依附 HTTP 请求或 FastAPI
`BackgroundTask`。应用 lifespan 内的 worker 使用 SQLite `BEGIN IMMEDIATE` 领取任务，
并以不可公开的 lease token + epoch fencing 续租/提交；同一本机数据卷上的多个 Form
进程不会同时提交同一 generation。`pending` / `retrying` 会在重启后继续消费，过期
`running` 会被新 generation 重新领取；operator 可调用 cancel/retry 端点。

远端 collect 成功后，Form 先把原始 `AssetReport` / `TraceBatch` 原子写入
`scan-artifacts/`，再调用 Analyzer。Analyzer 暂时失败时复用同一个 report/batch ID，
不会重新投放采集；成功 fenced 提交或取消后删除制品，启动时还会清理 crash temp 与
无对应活动 job 的 orphan。

执行保证是 **at-least-once（至少一次）**，不是 exactly-once：进程可能在远端副作用
完成但提交状态前崩溃。lease fencing 防止旧 worker 覆盖新状态，稳定制品 ID 缩小重复
窗口。最终一次 `running` 租约过期后使用固定的 `max_attempts + 1` 对账 attempt，反复重领也
不再增长：Host/Trace 只转发已有制品，缺少制品时不再远程采集；Guard 只接管与 job 的幂等
证书 generation 和远端 manifest 一致的已提交部署。

job store 在同一 target 上只允许一个 active job；直接 Guard 操作取得 durable target-operation
lease，并与 job claim 互斥。Guard 远端目录再以 owner-fenced TTL lease 保护，且每条受保护的
远端 shell 命令在整个执行期间持有同一稳定 inode 的内核 `flock`，关闭过期接管与旧命令之间的
TOCTOU 窗口；Linux 目标因此必须提供 util-linux `flock`。投放会保留旧
binary/config/env/identity pointer，证明新进程存活并原子发布包含 deployment/identity
generation、hash、PID、unit 与路径的 manifest 后才 activate；取消只在远端 manifest 与
expected manifest 完全相等时 teardown。正常恢复要求 exact PID；仅 mTLS systemd 重启可在证明
binary/config hash、当前 identity generation 与 `/proc/<pid>/exe` 后 CAS 刷新 manifest PID。
Legacy bearer 没有唯一 generation nonce，不能安全放宽 PID 或自动猜测归属，歧义崩溃窗口会
fail closed 并可能要求运维清理。

所有远端动作仍应保持幂等/可补偿。当前 SQLite WAL + 文件锁只支持同一主机的本地持久卷，
不应把 `form-data` 放到 NFS 后跨主机横向扩容；跨主机需要外部事务数据库或消息队列。
