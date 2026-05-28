# form

**数据分析与态势感知平台**，cyber-posture 的分析核心。基于 Python 构建，负责把 `scanner` 与 `collector` 上传的异构数据标准化、做关联分析、打分入库，并对 `portal` 暴露查询接口。

## 当前状态（v0）

已落地：

- 跨组件**数据契约**：Pydantic 源 + 自动导出的 JSON Schema
- `AssetReport`（scanner → form）/ `FlowBatch`（collector → form）/ `Alert`（form → portal）三大 envelope
- 测试覆盖 round-trip 序列化、严格性校验、tagged-union 鉴别
- **接入层 API**：FastAPI 起 `/ingest/asset-report`、`/ingest/flow-batch`、`/health`，自动用 Pydantic 校验入参，落盘为 JSONL
- **端到端打通**：`scanner-cli` 与 `collector-cli` 的 JSON 输出可以直接 `curl -X POST` 到 form 完成入库

尚未落地（按 ROI 顺序）：标准化（JSONL → 结构化存储）、关联分析、风险评分、对 portal 的查询 API。

## 目录结构

```
form/
├── pyproject.toml
├── README.md
├── src/
│   └── form/
│       ├── __init__.py
│       ├── cli.py                # form-export-schemas / form-api 入口
│       ├── schemas/              # 数据契约源（source of truth）
│       │   ├── common.py         # Severity / Confidence / StrictModel / Timestamp
│       │   ├── asset.py          # Package / Service / Port / Account / Credential
│       │   ├── vulnerability.py
│       │   ├── flow.py           # FlowEvent
│       │   ├── alert.py
│       │   └── envelope.py       # AssetReport / FlowBatch / HostInfo
│       ├── api/                  # FastAPI 接入层
│       │   ├── app.py            # create_app() 工厂
│       │   └── ingest.py         # /ingest/* 路由
│       └── storage/
│           └── jsonl.py          # JsonlStore（v0 持久化）
├── scripts/
│   └── export_schemas.py
├── schemas-json/                 # 由 Pydantic 模型导出的 JSON Schema
│   ├── AssetReport.schema.json
│   ├── FlowBatch.schema.json
│   └── Alert.schema.json
├── data/                         # JsonlStore 默认落盘位置（被 .gitignore）
└── tests/
    ├── test_schemas.py
    └── test_api.py
```

## 数据契约约定

- **严格模式**：所有契约模型继承自 `StrictModel`，`extra="forbid"`——上游若发了未定义字段会**显式失败**，不静默吞掉。
- **discriminated union**：`Asset` 是 5 种资产类型的 tagged union，靠 `kind` 字段区分；新增资产类型必须随契约版本升级。
- **时间**：所有时间字段为带 UTC tzinfo 的 `datetime`，JSON 形式为 RFC 3339 字符串。
- **跨语言**：`schemas-json/` 是面向 Rust（scanner/collector）和 TypeScript（portal）的权威接口；只读，由 Python 端模型生成。

## 环境

推荐用 [`uv`](https://github.com/astral-sh/uv)：

```bash
cd form
uv venv --python 3.13
source .venv/bin/activate
uv pip install -e ".[dev]"
```

或纯 `pip`：

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## 常用命令

```bash
pytest                              # 运行测试
ruff check src tests scripts        # lint
ruff format src tests scripts       # 格式化

form-export-schemas                 # 把 Pydantic 模型导出为 JSON Schema
form-export-schemas --out /tmp/out  # 指定输出目录

form-api                            # 启 HTTP API（默认 127.0.0.1:8000）
form-api --host 0.0.0.0 --port 9000
form-api --reload                   # 开发模式：代码改动自动重载
```

## API 速查

| 路径 | 方法 | 状态码 | 用途 |
| --- | --- | --- | --- |
| `/health` | GET | 200 | 存活检查 |
| `/ingest/asset-report` | POST | 202 | 接收 scanner 的 `AssetReport`，落盘 JSONL |
| `/ingest/flow-batch` | POST | 202 | 接收 collector 的 `FlowBatch`，落盘 JSONL |

校验失败统一返回 **422** + Pydantic 错误详情。

### 端到端冒烟（scanner / collector → form）

```bash
# 启 API
form-api --port 8000 &

# scanner -> form
cd ../scanner && cargo run --quiet -p scanner-cli | \
  curl -s -X POST -H "Content-Type: application/json" \
    --data-binary @- http://127.0.0.1:8000/ingest/asset-report

# collector -> form
cd ../collector && cargo run --quiet -p collector-cli | \
  curl -s -X POST -H "Content-Type: application/json" \
    --data-binary @- http://127.0.0.1:8000/ingest/flow-batch

# 落盘位置（FORM_DATA_DIR 可覆盖，默认 ./data/）
ls form/data/
#   asset-reports.jsonl
#   flow-batches.jsonl
```

## 计划中的下一步

按 ROI：

- `form.normalize`：把 JSONL 中的 `AssetReport` 拆解为结构化资产 / 漏洞条目（候选 SQLite / DuckDB / Postgres）。
- `form.correlate`：关联分析与规则引擎（如：高危漏洞主机的对外流量产生告警）。
- `form.score`：风险评分。
- 查询 API：给 portal 提供资产、告警、统计接口。
