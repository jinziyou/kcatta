# form

**数据分析与态势感知平台**，cyber-posture 的分析核心。基于 Python 构建，负责把 `probe`（主机 + 网络探针）上传的异构数据标准化、做关联分析、打分入库，并对 `portal` 暴露查询接口。

## 当前状态（v0）

已落地：

- 跨组件**数据契约**：Pydantic 源 + 自动导出的 JSON Schema
- `AssetReport`（probe-host → form）/ `FlowBatch`（probe-flow → form）/ `Alert`（form → portal）三大 envelope
- 测试覆盖 round-trip 序列化、严格性校验、tagged-union 鉴别
- **接入层 API**：FastAPI 起 `/ingest/asset-report`、`/ingest/flow-batch`、`/health`，自动用 Pydantic 校验入参，落盘为 JSONL
- **端到端打通**：`probe-host-cli` 与 `probe-flow-cli` 的 JSON 输出可以直接 `curl -X POST` 到 form 完成入库

- **漏洞检测引擎**（`form.detect`）：自实现，不依赖 trivy/grype。基于本地 OSV
  通告库,把 ingest 进来的 `AssetReport` 软件包清单与漏洞数据做匹配,产出
  `Vulnerability`。含 dpkg 语义的版本比较、OSV 受影响区间判定、本地库索引。

- **关联分析（`form.correlate`，v0 规则）**：collector 在流上做完威胁情报 IOC 匹配
  （`FlowEvent.threat_intel`）后上报；ingest `/ingest/flow-batch` 时**按指标(IOC)聚合**
  关联——命中同一指标的多条流合并成一个 `Alert`，`related_flow_ids` / `related_asset_ids`
  汇总所有命中流与主机，严重级取该指标命中的最坏级别、`score` 由严重级映射；落盘并经
  `/reports/alerts` 暴露给 portal。

尚未落地（按 ROI 顺序）：标准化（JSONL → 结构化存储）、跨源关联（高危漏洞主机 × 对外可疑流量）、风险评分、对 portal 的更多查询 API。

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
│       │   ├── flow.py           # FlowEvent（含 threat_intel）
│       │   ├── threat.py         # ThreatMatch / IndicatorType（IOC 命中）
│       │   ├── alert.py
│       │   └── envelope.py       # AssetReport / FlowBatch / HostInfo
│       ├── api/                  # FastAPI 接入层
│       │   ├── app.py            # create_app() 工厂
│       │   ├── ingest.py         # /ingest/* 路由（asset 自动检测 / flow 自动关联）
│       │   └── reports.py        # /reports/* 读侧路由
│       ├── correlate/            # 关联分析：流威胁情报命中 → Alert
│       │   └── flow.py
│       ├── detect/               # 自实现漏洞检测引擎（基于 OSV，无 trivy）
│       │   ├── debversion.py     # dpkg 语义版本比较
│       │   ├── versioning.py     # 按生态选版本比较器（dpkg/PEP440/SemVer）
│       │   ├── cvss.py           # CVSS v3.1 基础分计算 + 严重级映射
│       │   ├── osv.py            # OSV 记录解析 + 受影响区间匹配
│       │   ├── store.py          # 本地 OSV 库加载/索引
│       │   ├── engine.py         # AssetReport → Vulnerability[]
│       │   └── sync.py           # 离线下载 OSV 导出
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
- **跨语言**：`schemas-json/` 是面向 Rust（probe）和 TypeScript（portal）的权威接口；只读，由 Python 端模型生成。

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

form-osv-sync --ecosystem Debian PyPI npm   # 一次拉多生态 → data/osv/{Debian,PyPI,npm}/
form-detect                         # 用本地库匹配 data/asset-reports.jsonl
form-detect --ecosystem Debian:12 --db data/osv --pretty
```

## 漏洞检测（form.detect，自实现，不依赖 trivy）

把 ingest 进来的 `AssetReport` 软件包清单与**本地 OSV 通告库**做匹配,产出
`Vulnerability`。匹配引擎全部自实现:OSV 记录解析、按生态选用的版本比较、受影响
区间（`introduced`/`fixed`/`last_affected`）判定。

**多生态**:按 OSV 生态自动选版本比较器——Debian/Ubuntu 用 dpkg 语义、PyPI 用
PEP 440、Rocky/Alma/SUSE 等 rpm 系用 rpm EVR(`rpmvercmp` + epoch/release)、Alpine
用 apk 版本序(`-rN` 修订、`_alpha/_p` 后缀)、npm/Go/crates.io 等用 SemVer 2.0;
未知生态回退 SemVer。区间类型同时支持 `ECOSYSTEM`（用生态原生比较）与 `SEMVER`
（npm/Go 常用,强制 SemVer 比较）。

**包级生态**:每个 `Package` 可带 `ecosystem` 字段（如 probe-host 给 deb 包打的
`Debian:12`、语言包的 `PyPI`/`npm`）。检测对每个包用其自身生态匹配,未设置时回退
到由 `host.os` 推断的默认生态——于是同一份报告可混合 OS 包与语言包,各按自己的
库与比较器命中。

```bash
# 1. 同步漏洞库（顶层生态，可一次多个；记录内含 Debian:12 等发行版限定）
form-osv-sync --ecosystem Debian PyPI npm --db data/osv

# 2. 对已 ingest 的报告跑检测（生态可显式指定或从 host.os 自动推断）
form-detect --reports data/asset-reports.jsonl --db data/osv --pretty
```

| 模块 | 职责 |
| --- | --- |
| `debversion.py` | `dpkg --compare-versions` 语义（epoch、`~` 预发布、前导零） |
| `versioning.py` | 按生态选比较器：dpkg / PEP 440 / rpm EVR / apk / SemVer 2.0（未知回退 SemVer） |
| `cvss.py` | CVSS v3.x 基础分计算 + 分数→严重级映射 |
| `osv.py` | OSV 记录模型 + 版本是否落在受影响区间（`ECOSYSTEM`/`SEMVER`） |
| `store.py` | 本地 OSV JSON 库加载,按 `(生态, 包名)` 索引 |
| `engine.py` | `AssetReport` → `Vulnerability[]`，CVE 别名优先、去重 |
| `sync.py` | 用 stdlib 下载 OSV 导出 zip 并解包（检测本身不联网） |

> 取向:probe-host 出 SBOM/清单,检测集中在 form——中心一份库、可对历史清单回溯匹配。
> 数据源覆盖决定匹配质量:OSV 覆盖 Debian/Ubuntu/Alpine 等,**不含 Kali**
> （Kali 基于 Debian testing,只能近似映射）。严重级优先按 OSV 的 CVSS v3 向量
> 算出基础分并据此定级（同时填入 `cvss_score`）;无向量时退回文本字段,再缺失按
> `medium`。CVSS v4 向量暂不计算分值（走文本/兜底）。

## API 速查

| 路径 | 方法 | 状态码 | 用途 |
| --- | --- | --- | --- |
| `/health` | GET | 200 | 存活检查 |
| `/ingest/asset-report` | POST | 202 | 接收 probe-host 的 `AssetReport`，落盘 JSONL；自动检测 OSV CVE（若库已加载）并合并报告内 ClamAV 命中，把合并后的 `DetectionResult` 落盘 |
| `/ingest/flow-batch` | POST | 202 | 接收 probe-flow 的 `FlowBatch`，落盘 JSONL；按指标(IOC)聚合关联成 `Alert` 落盘 |
| `/reports/asset-reports?limit=N` | GET | 200 | 读最近 N 条 `AssetReport`（默认 50，范围 1–500），newest first |
| `/reports/flow-batches?limit=N` | GET | 200 | 读最近 N 条 `FlowBatch` |
| `/reports/vulnerabilities?limit=N` | GET | 200 | 读最近 N 条 `DetectionResult`（OSV + ClamAV 合并结果） |
| `/reports/alerts?limit=N` | GET | 200 | 读最近 N 条 `Alert`（关联分析产物） |
| `/detect/asset-report` | POST | 200 | 对传入 `AssetReport` 按需跑 OSV 检测并合并 ClamAV 命中，返回 `DetectionResult`（无状态，不落盘） |

检测在应用启动时加载一次本地 OSV 库（`FORM_OSV_DIR`，默认 `data/osv`）。生态默认
从 `host.os` 推断；`/detect` 无法推断（如 Kali）时返回 **422**（除非报告内已有 ClamAV
命中），ingest 自动检测则在无 OSV 命中且无 ClamAV 时静默跳过。可用 `FORM_OSV_ECOSYSTEM`
（如 `Debian:12`）固定生态。ingest 的自动检测是
**尽力而为**：未加载 OSV 库 / 生态推断不出 / 检测异常都不会影响报告入库（仍 202）。

校验失败统一返回 **422** + Pydantic 错误详情。

**CORS**：默认放行 `http://localhost:3000`（portal 开发地址）。生产部署通过 `FORM_CORS_ORIGINS=https://a.example.com,https://b.example.com` 配置。

### 端到端冒烟（probe → form）

```bash
# 启 API
form-api --port 8000 &

# probe-host -> form
cd ../probe && cargo run --quiet -p probe-host-cli | \
  curl -s -X POST -H "Content-Type: application/json" \
    --data-binary @- http://127.0.0.1:8000/ingest/asset-report

# probe-flow -> form（抓包 + 威胁情报 IOC 匹配 + 上报，一步到位）
cd ../probe && cargo run --quiet -p probe-flow-cli -- --upload http://127.0.0.1:8000

# 或手动管道（等价）
cargo run --quiet -p probe-flow-cli | \
  curl -s -X POST -H "Content-Type: application/json" \
    --data-binary @- http://127.0.0.1:8000/ingest/flow-batch

# 命中威胁情报的流会被自动关联成告警
curl -s http://127.0.0.1:8000/reports/alerts | python3 -m json.tool

# 落盘位置（FORM_DATA_DIR 可覆盖，默认 ./data/）
ls form/data/
#   asset-reports.jsonl
#   flow-batches.jsonl
#   vulnerabilities.jsonl
#   alerts.jsonl
```

## 计划中的下一步

按 ROI：

- `form.normalize`：把 JSONL 中的 `AssetReport` 拆解为结构化资产 / 漏洞条目（候选 SQLite / DuckDB / Postgres）。
- `form.correlate`：关联分析与规则引擎（如：高危漏洞主机的对外流量产生告警）。
- `form.score`：风险评分。
- 查询 API：给 portal 提供资产、告警、统计接口。
