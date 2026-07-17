# analyzer

kcatta 的内部数据分析与态势感知服务。Analyzer 只负责：

- 接收 Form 转发的 `AssetReport`、`TraceBatch`、`GuardEventBatch` 与 `CapabilityGraph`；
- 基于本地 OSV 与 Debian Security Tracker 数据做漏洞检测；
- 对网络、Guard 与跨来源证据做关联；
- 生成并持久化 `DetectionResult`、`Alert` 与 `AttackPath`；
- 向 Form 提供内部查询 API。

Analyzer 不再管理目标、凭据、扫描任务，也不通过 SSH/WinRM 投放 Agent。跨组件调用必须经过 Form：

```text
Admin  <->  Form  <->  Analyzer
Agent  <->  Form
```

## 边界

Analyzer 保留以下域：

```text
src/analyzer/
├── api/
│   ├── app.py          # 内部 FastAPI 工厂
│   ├── auth.py         # Form -> Analyzer 内部服务令牌
│   ├── ingest.py       # 遥测接入 + 检测/关联处理器
│   ├── ingest_queue.py # 持久化幂等账本、任务租约与后台重试
│   ├── detect.py       # 无状态按需检测
│   ├── reports.py      # 资产、漏洞、Trace、Guard 查询
│   ├── alerts.py       # 告警读模型、处置状态与导出
│   ├── predict.py      # 攻击路径预测
│   └── idempotency.py  # 幂等窗口默认值与兼容工具
├── detect/              # OSV 与 Kali 精确源包检测引擎
├── correlate/           # IOC、Guard、跨来源关联
├── predict/             # 攻击路径推导
├── schemas/             # 遥测与分析契约源
└── storage/             # JSONL / SQLite 分析数据存储
```

以下能力归 Form 所有，不应重新引入 Analyzer：

- `/targets`、`/scans`、`/credentials`；
- Guard 守护进程的部署、状态查询与停止；
- SSH、WinRM、本机 Agent 执行；
- 托管密钥/证书及 Agent 部署二进制；
- 扫描任务状态机、并发控制与恢复语义。

## 内部 API

除公开存活探针 `/health` 与使用 metrics-only 令牌的 `/metrics` 外，所有路由都使用
Form-to-Analyzer 内部服务令牌。

| 路径 | 方法 | 用途 |
| --- | --- | --- |
| `/health` | GET | 存活检查 |
| `/ready` | GET | 就绪检查；OSV 或 Debian Tracker 为空/过期时 `status=degraded` 且 HTTP **200**（可服务降级） |
| `/metrics` | GET | Prometheus 文本指标；仅接受 metrics-only token |
| `/ingest/asset-report` | POST | 持久化接收资产报告并排队检测 |
| `/ingest/trace-batch` | POST | 持久化接收 Trace 并排队关联 |
| `/ingest/guard-event` | POST | 持久化接收 Guard 事件并排队关联 |
| `/ingest/status?kind=...&id=...` | GET | 查询一个逻辑上报（含全部分片）的派生状态 |
| `/ingest/capability-graph` | POST | 存储能力图 |
| `/detect/asset-report` | POST | 无状态检测一个资产报告 |
| `/reports/asset-reports[/{report_id}]` | GET | 资产报告查询 |
| `/reports/report-details/{report_id}` | GET | 有界的报告元数据、资产/发现分页与覆盖汇总（Admin 详情页） |
| `/reports/trace-batches` | GET | Trace 批次查询 |
| `/reports/vulnerabilities[/{report_id}]` | GET | 漏洞结果查询 |
| `/reports/guard-events` | GET | Guard 事件查询 |
| `/reports/alerts` | GET | 聚合告警查询 |
| `/reports/alerts/{alert_id}` | GET | 单个告警查询 |
| `/reports/alerts/export.csv` | GET | 告警 CSV 导出 |
| `/reports/alerts/{alert_key}/triage` | POST | 告警处置状态更新 |
| `/attack-paths[/{path_id}]` | GET | 攻击路径查询 |

Form 可以向 Admin 暴露兼容路径，但 Admin 和 Agent 不应直接访问 Analyzer。

报告列表默认返回 `X-Kcatta-Next-Cursor`；后续请求传 `cursor` 可按 SQLite 行 ID 或
JSONL 稳定字节位置继续读取，不会因新记录插入而重复/跳过。旧 `page` / `offset` 参数仍保留兼容。
报告详情与 lineage 查询在 SQLite 后端使用持久化的逻辑根表达式索引定位分片；JSONL 后端
使用一次反向扫描，避免按页重复从文件尾部重扫。旧数据库启动时会幂等创建索引，无需重写记录。
`DetectionResult.coverage` 逐项记录 OSV 生态、Debian Tracker 及 malware/posture/secret 的
complete/partial/disabled/failed/unknown 状态、扫描/跳过/发现数量；0 条发现只有在对应项
明确 complete 时才表示该检测器完成了零发现检查。

## 鉴权

生产环境设置：

```bash
export ANALYZER_INTERNAL_TOKEN='form-to-analyzer-secret'
export ANALYZER_METRICS_TOKEN='prometheus-read-only-secret'
```

Form 调用时发送：

```text
Authorization: Bearer form-to-analyzer-secret
```

`ANALYZER_API_TOKEN` 与 `ANALYZER_INGEST_TOKEN` 属于旧的直连拓扑，不再被 Analyzer 接受。
Analyzer 默认要求内部令牌，Compose 还会生成相互独立的 metrics-only 令牌；只有隔离的本地
开发可显式设置 `ANALYZER_ALLOW_INSECURE_NO_AUTH=true`。生产部署还应通过网络策略确保只有
Form 与受控 Prometheus 可访问 Analyzer。

## 数据契约

Pydantic 是 Analyzer 遥测与分析契约的源：

- 上行：`AssetReport`、`TraceBatch`、`GuardEventBatch`、`CapabilityGraph`；
- 派生：`DetectionResult`、`Alert`、`AttackPath`。

JSON Schema 位于 `schemas-json/`。扫描目标、任务和访问凭据是 Form 控制面模型，不属于 Analyzer schema。

## 配置

| 环境变量 | 默认值 | 含义 |
| --- | --- | --- |
| `ANALYZER_INTERNAL_TOKEN` | 未设置 | Form-to-Analyzer bearer token |
| `ANALYZER_METRICS_TOKEN` | 回退到 internal token（Compose 独立生成） | Prometheus `/metrics` 只读 bearer token |
| `ANALYZER_ALLOW_INSECURE_NO_AUTH` | `false` | 仅隔离本地开发允许无内部令牌启动 |
| `ANALYZER_DATA_DIR` | `data` | 分析数据目录 |
| `ANALYZER_STORAGE` | `jsonl` | `jsonl` 或 `sqlite` |
| `ANALYZER_OSV_DIR` | `data/osv` | OSV 本地库 |
| `ANALYZER_OSV_ECOSYSTEM` | 自动推断 | 固定 OSV 生态 |
| `ANALYZER_DEBIAN_TRACKER_DIR` | `data/debian-tracker` | Debian Security Tracker 精确源包版本索引 |
| `ANALYZER_DEBIAN_TRACKER_AUTO_SYNC` | `false`（Compose: `true`） | 启动时或索引过期时后台刷新，之后按周期刷新 |
| `ANALYZER_DEBIAN_TRACKER_MAX_AGE_HOURS` | `48` | Tracker 索引允许的最大年龄；超过后检测覆盖降为 `partial` |
| `ANALYZER_DEBIAN_TRACKER_REFRESH_SECONDS` | `86400` | Tracker 后台刷新周期 |
| `ANALYZER_MAX_BODY_BYTES` | 10 MiB | 内部接入请求上限 |
| `ANALYZER_DERIVED_ASYNC` | `false`（Compose: `true`） | 先写 durable outbox 并返回 `derived_status=pending`，再后台派生 |
| `ANALYZER_INGEST_LEDGER_PATH` | `<data>/ingest-ledger.db` | 跨重启/多 Worker 的幂等与派生任务 SQLite 账本 |
| `ANALYZER_INGEST_LEDGER_MAX_BYTES` | 512 MiB | durable outbox 的数据库容量预算 |
| `ANALYZER_INGEST_DEDUP_WINDOW` | 50000 | 持久保留的已完成幂等结果数量；待处理任务不在淘汰范围内 |
| `ANALYZER_DERIVED_LEASE_SECONDS` | 30 | 派生任务租约；运行时按三分之一周期续租 |
| `ANALYZER_DERIVED_RETRY_BASE_SECONDS` | 5 | 后台派生失败的指数退避起点 |
| `ANALYZER_DERIVED_RETRY_MAX_SECONDS` | 300 | 后台派生重试最大间隔 |
| `ANALYZER_SQLITE_MAX_BYTES` | 1 GiB | SQLite DB + WAL + SHM 总容量预算；`max_page_count` 为最终硬边界 |
| `ANALYZER_SQLITE_WAL_MAX_BYTES` | 64 MiB | 从总预算预留的 WAL 容量与 checkpoint 阈值 |
| `ANALYZER_SQLITE_MAX_TABLE_BYTES` | 96 MiB | 每表 payload 逻辑保留上限，事务内淘汰最旧记录 |
| `ANALYZER_SQLITE_MAX_ROWS_PER_TABLE` | 100000 | 每表最大保留行数 |
| `ANALYZER_STORAGE_MAX_RECORD_BYTES` | 12 MiB | 单条持久化记录硬上限 |
| `ANALYZER_STORAGE_READ_MAX_BYTES` | 32 MiB | 单次 tail/history 读取总字节上限 |
| `ANALYZER_REPORT_PROJECTION_CACHE_ENTRIES` | 64 | 报告详情投影 LRU 最大条目数；设为 `0` 禁用 |
| `ANALYZER_REPORT_PROJECTION_CACHE_BYTES` | 64 MiB | 报告详情投影估算内存上限；设为 `0` 禁用 |
| `ANALYZER_JSONL_MAX_BYTES` | 256 MiB | 每个 JSONL 文件硬上限；到顶后按完整行滚至低水位 |
| `ANALYZER_JSONL_MAX_LINES` | 0 | JSONL 可选行数上限；0 表示仅使用字节上限 |
| `ANALYZER_JSONL_FSYNC` | `true` | 每条 JSONL 在确认前执行文件同步 |

异步接入只有在完整 envelope 已提交到独立 SQLite outbox 后才返回 202；`pending` 表示原始
载荷已持久化、派生尚未完成。Worker 使用原子 claim、可续租 lease 与指数退避，进程重启后
继续未完成任务；相同 ID 的已完成请求直接重放原派生状态。接入还在模型和派生阶段限制
字符串、列表、告警关联数量与每次派生总字节，避免合法小请求在关联时放大为无界内存/磁盘
写入。SQLite 旧库若已超过新页预算会拒绝启动并给出显式的离线清理/VACUUM 提示，而不会
伪装成配额已经生效。

## 开发

```bash
cd analyzer
uv sync --locked --extra dev

.venv/bin/ruff check src tests scripts
.venv/bin/ruff format --check src tests scripts
.venv/bin/pytest

ANALYZER_ALLOW_INSECURE_NO_AUTH=true \
  .venv/bin/analyzer-api --host 127.0.0.1 --port 10068
.venv/bin/analyzer-osv-sync
.venv/bin/analyzer-debian-tracker-sync
.venv/bin/analyzer-export-schemas
.venv/bin/analyzer-export-openapi
```

无外网环境可先在联网机器下载 OSV 的 `all.zip`，按顶层生态精确命名为
`<ecosystem>.zip`（例如 `PyPI.zip`、`Rocky Linux.zip`），再离线导入并校验：

```bash
.venv/bin/analyzer-osv-sync \
  --archive-dir /mnt/osv-archives --index-only --db /data/osv
.venv/bin/analyzer-osv-sync --verify-only --db /data/osv
```

只需要部分生态时可同时传入 `--ecosystem PyPI npm`；未导入生态的软件包会在检测覆盖率中
明确标为 `partial`，不会被误报为“完成且零发现”。归档导入与在线同步使用相同的记录校验、
原子目录替换和逐生态计数 manifest。`--index-only` 是运行环境推荐模式：完整 advisory 以
按包查询的压缩 SQLite 索引保存，不展开数 GiB JSON，也不会在 Analyzer 启动时整体载入内存。

Kali 的 dpkg 包不会直接继承 Debian 的漏洞结论。Agent 会同时上报二进制包与其 dpkg
`Source` 名称/版本；Analyzer 仅在该源包版本与 Debian Tracker 仓库版本完全一致时采用
对应 CVE 状态。带 `+kali` 的 fork、Kali 独有包及无法核验的版本都会保留为 `partial`，不会
被误判为已检查且安全。离线环境可导入预下载的官方 JSON：

```bash
.venv/bin/analyzer-debian-tracker-sync \
  --json-file /mnt/debian-security-tracker.json --db /data/debian-tracker
.venv/bin/analyzer-debian-tracker-sync \
  --verify-only --db /data/debian-tracker
```

索引记录 UTC 同步时间；`--verify-only` 默认拒绝超过最大年龄的索引，也可用
`--max-age-hours` 调整阈值。仅在诊断或受控离线场景需要确认旧索引结构仍可查询时，才使用
`--allow-stale`。Compose 默认每 24 小时后台原子刷新一次；下载、校验或替换失败会保留当前
索引并累计失败指标，不会用空库覆盖旧数据。过期索引仍可用于查询已知记录，但 `/ready` 和
检测覆盖都会明确标为 `stale` / `partial`，避免把旧数据的零命中解释成安全。

存储迁移：

```bash
.venv/bin/analyzer-migrate-storage --data-dir data
```

OpenAPI 是 Form-facing 的内部服务契约，提交在 `openapi.json`；路由或模型变化后重新导出并提交。
# Microsoft Defender cloud ingest

Form 可将只读 Microsoft Graph 告警/事件规范化后提交到
`POST /ingest/mde-security-batch`。Analyzer 保留原始规范化批次供
`GET /reports/mde-security-batches` 查询，并将每个 MDE alert/incident 幂等转换为公共
`Alert`，因此现有告警 API 与 Admin 页面无需第二套生命周期。Analyzer 本身不持有 Microsoft
凭据，也不调用任何 Defender 响应 API。

Form 还可提交 `POST /ingest/mdvm-vulnerability-batch`。Analyzer 会保留
`/reports/mdvm-vulnerability-batches` 原始规范化快照，并为每台设备生成现有
`AssetReport` 与完整覆盖的 `DetectionResult`；修复后零发现快照同样保留，避免将“没有当前
漏洞”误解为“没有执行检测”。
