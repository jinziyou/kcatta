# analyzer

kcatta 的内部数据分析与态势感知服务。Analyzer 只负责：

- 接收 Form 转发的 `AssetReport`、`TraceBatch`、`GuardEventBatch` 与 `CapabilityGraph`；
- 基于本地 OSV 数据做漏洞检测；
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
│   ├── ingest.py       # 遥测接入 + 自动检测/关联
│   ├── detect.py       # 无状态按需检测
│   ├── reports.py      # 资产、漏洞、Trace、Guard 查询
│   ├── alerts.py       # 告警读模型、处置状态与导出
│   ├── predict.py      # 攻击路径预测
│   └── idempotency.py  # 接入幂等窗口
├── detect/              # OSV 检测引擎
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

除 `/health` 外，所有路由都使用同一个 Form-to-Analyzer 内部服务令牌。

| 路径 | 方法 | 用途 |
| --- | --- | --- |
| `/health` | GET | 存活检查 |
| `/ingest/asset-report` | POST | 存储资产报告并自动检测 |
| `/ingest/trace-batch` | POST | 存储 Trace 并自动关联 |
| `/ingest/guard-event` | POST | 存储 Guard 事件并自动关联 |
| `/ingest/capability-graph` | POST | 存储能力图 |
| `/detect/asset-report` | POST | 无状态检测一个资产报告 |
| `/reports/asset-reports[/{report_id}]` | GET | 资产报告查询 |
| `/reports/trace-batches` | GET | Trace 批次查询 |
| `/reports/vulnerabilities[/{report_id}]` | GET | 漏洞结果查询 |
| `/reports/guard-events` | GET | Guard 事件查询 |
| `/reports/alerts` | GET | 聚合告警查询 |
| `/reports/alerts/{alert_id}` | GET | 单个告警查询 |
| `/reports/alerts/export.csv` | GET | 告警 CSV 导出 |
| `/reports/alerts/{alert_key}/triage` | POST | 告警处置状态更新 |
| `/attack-paths[/{path_id}]` | GET | 攻击路径查询 |

Form 可以向 Admin 暴露兼容路径，但 Admin 和 Agent 不应直接访问 Analyzer。

## 鉴权

生产环境设置：

```bash
export ANALYZER_INTERNAL_TOKEN='form-to-analyzer-secret'
```

Form 调用时发送：

```text
Authorization: Bearer form-to-analyzer-secret
```

`ANALYZER_API_TOKEN` 与 `ANALYZER_INGEST_TOKEN` 属于旧的直连拓扑，不再被 Analyzer 接受。Analyzer 默认要求内部令牌；只有隔离的本地开发可显式设置 `ANALYZER_ALLOW_INSECURE_NO_AUTH=true`。生产部署还应通过网络策略确保只有 Form 可访问 Analyzer。

## 数据契约

Pydantic 是 Analyzer 遥测与分析契约的源：

- 上行：`AssetReport`、`TraceBatch`、`GuardEventBatch`、`CapabilityGraph`；
- 派生：`DetectionResult`、`Alert`、`AttackPath`。

JSON Schema 位于 `schemas-json/`。扫描目标、任务和访问凭据是 Form 控制面模型，不属于 Analyzer schema。

## 配置

| 环境变量 | 默认值 | 含义 |
| --- | --- | --- |
| `ANALYZER_INTERNAL_TOKEN` | 未设置 | Form-to-Analyzer bearer token |
| `ANALYZER_ALLOW_INSECURE_NO_AUTH` | `false` | 仅隔离本地开发允许无内部令牌启动 |
| `ANALYZER_DATA_DIR` | `data` | 分析数据目录 |
| `ANALYZER_STORAGE` | `jsonl` | `jsonl` 或 `sqlite` |
| `ANALYZER_OSV_DIR` | `data/osv` | OSV 本地库 |
| `ANALYZER_OSV_ECOSYSTEM` | 自动推断 | 固定 OSV 生态 |
| `ANALYZER_MAX_BODY_BYTES` | 10 MiB | 内部接入请求上限 |
| `ANALYZER_INGEST_DEDUP_WINDOW` | 50000 | 接入幂等 ID 窗口 |
| `ANALYZER_SQLITE_MAX_BYTES` | 1 GiB | SQLite DB + WAL + SHM 总容量预算；`max_page_count` 为最终硬边界 |
| `ANALYZER_SQLITE_WAL_MAX_BYTES` | 64 MiB | 从总预算预留的 WAL 容量与 checkpoint 阈值 |
| `ANALYZER_SQLITE_MAX_TABLE_BYTES` | 96 MiB | 每表 payload 逻辑保留上限，事务内淘汰最旧记录 |
| `ANALYZER_SQLITE_MAX_ROWS_PER_TABLE` | 100000 | 每表最大保留行数 |
| `ANALYZER_STORAGE_MAX_RECORD_BYTES` | 12 MiB | 单条持久化记录硬上限 |
| `ANALYZER_STORAGE_READ_MAX_BYTES` | 32 MiB | 单次 tail/history 读取总字节上限 |
| `ANALYZER_JSONL_MAX_BYTES` | 256 MiB | 每个 JSONL 文件硬上限；到顶后按完整行滚至低水位 |
| `ANALYZER_JSONL_MAX_LINES` | 0 | JSONL 可选行数上限；0 表示仅使用字节上限 |
| `ANALYZER_JSONL_FSYNC` | `true` | 每条 JSONL 在确认前执行文件同步 |

接入还在模型和派生阶段限制字符串、列表、告警关联数量与每次派生总字节，避免合法小请求在关联时放大为无界内存/磁盘写入。SQLite 旧库若已超过新页预算会拒绝启动并给出显式的离线清理/VACUUM 提示，而不会伪装成配额已经生效。

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
.venv/bin/analyzer-export-schemas
.venv/bin/analyzer-export-openapi
```

存储迁移：

```bash
.venv/bin/analyzer-migrate-storage --data-dir data
```

OpenAPI 是 Form-facing 的内部服务契约，提交在 `openapi.json`；路由或模型变化后重新导出并提交。
