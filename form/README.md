# form

**数据分析与态势感知平台**，cyber-posture 的分析核心。基于 Python 构建，负责把 `scanner` 与 `collector` 上传的异构数据标准化、做关联分析、打分入库，并对 `portal` 暴露查询接口。

## 职责

- **接入层**：接收 scanner / collector 的上报数据（HTTP / gRPC / 消息队列，待定）。
- **标准化**：异构事件 → 统一资产 / 漏洞 / 流量 / 告警模型。
- **关联分析**：例如「高危漏洞」与「对外流量」关联、「失陷主机」与「恶意 C2 通信」匹配。
- **风险评分**：基于关联结果产出量化风险分。
- **持久化**：标准化数据与分析结论统一入库。
- **对外 API**：为 portal 提供查询 / 检索 / 实时事件订阅能力。

## 仓库形态

本目录是一个 Python 项目（monorepo 内的一个组件），采用现代 PEP 621 `pyproject.toml`。

```
form/
├── pyproject.toml
├── README.md
└── src/
    └── form/          # 源码包（待创建）
```

## 环境

推荐使用 [`uv`](https://github.com/astral-sh/uv) 管理虚拟环境与依赖（也可用 `pip` / `poetry`）。

```bash
cd form
uv venv
source .venv/bin/activate
uv pip install -e ".[dev]"
```

或使用纯 `pip`：

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## 质量工具

- **Ruff**：lint + import 排序（已在 `pyproject.toml` 中配置）。
- 后续按需引入 `pytest` / `mypy` / `pre-commit`。

```bash
ruff check src
ruff format src
```

## 计划中的初始模块

> 仅作为规划占位，尚未实现。

- `form.ingest`：上报数据接入。
- `form.normalize`：异构事件标准化。
- `form.correlate`：关联分析与规则引擎。
- `form.score`：风险评分。
- `form.api`：对外 API（FastAPI 候选）。
- `form.schemas`：跨组件共享的数据契约（JSON Schema / Pydantic）。
