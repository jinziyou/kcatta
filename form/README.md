# form

**数据分析与态势感知平台**，cyber-posture 的分析核心。基于 Python 构建，负责把 `scanner` 与 `collector` 上传的异构数据标准化、做关联分析、打分入库，并对 `portal` 暴露查询接口。

## 当前状态（v0）

已落地：

- 跨组件**数据契约**：Pydantic 源 + 自动导出的 JSON Schema
- `AssetReport`（scanner → form）/ `FlowBatch`（collector → form）/ `Alert`（form → portal）三大 envelope
- 测试覆盖 round-trip 序列化、严格性校验、tagged-union 鉴别

尚未落地（按 ROI 顺序）：接入层 API、标准化、关联分析、风险评分、持久化。

## 目录结构

```
form/
├── pyproject.toml
├── README.md
├── src/
│   └── form/
│       ├── __init__.py
│       ├── cli.py                # form-export-schemas 入口
│       └── schemas/              # 数据契约源（source of truth）
│           ├── __init__.py
│           ├── common.py         # Severity / Confidence / StrictModel / Timestamp
│           ├── asset.py          # Package / Service / Port / Account / Credential
│           ├── vulnerability.py
│           ├── flow.py           # FlowEvent
│           ├── alert.py
│           └── envelope.py       # AssetReport / FlowBatch / HostInfo
├── scripts/
│   └── export_schemas.py         # 未安装包时也能跑的便捷脚本
├── schemas-json/                 # 由 Pydantic 模型导出的 JSON Schema
│   ├── README.md
│   ├── AssetReport.schema.json
│   ├── FlowBatch.schema.json
│   └── Alert.schema.json
└── tests/
    └── test_schemas.py
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
```

## 计划中的初始模块

> 仅作为规划占位，尚未实现。

- `form.ingest`：上报数据接入（FastAPI 候选）。
- `form.normalize`：异构事件标准化（如把 scanner.AssetReport 拆解入存储模型）。
- `form.correlate`：关联分析与规则引擎。
- `form.score`：风险评分。
- `form.api`：对 portal 的查询/订阅 API。
