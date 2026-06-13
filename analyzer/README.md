# analyzer

**数据分析与态势感知平台**，kcatta 的分析核心。基于 Python 构建，负责把 `agent`（主机 + 网络探针）上传的异构数据标准化、做关联分析、打分入库，并对 `admin` 暴露查询接口。

## 当前状态（v0）

已落地：

- 跨组件**数据契约**：Pydantic 源 + 自动导出的 JSON Schema
- 数据契约共 7 类：**上行采集 envelope** `AssetReport`（`agent-host` → analyzer）、`FlowBatch`（`agent-flow` → analyzer）、`GuardEventBatch`（`agent-guard` → analyzer）；**analyzer 派生、对 admin 暴露** `DetectionResult`、`Alert`、`AttackPath`；**外部红队** `CapabilityGraph`（opaque，→ analyzer）
- 测试覆盖 round-trip 序列化、严格性校验、tagged-union 鉴别
- **接入层 API**：FastAPI 起 `/ingest/*`（asset-report / flow-batch / guard-event / capability-graph）等路由（完整清单见下文「API 速查」），自动用 Pydantic 校验入参，落盘持久化
- **端到端打通**：`agent-host` 与 `agent-flow capture` 的 JSON 输出可以直接 `curl -X POST` 到 analyzer 完成入库
- **远端投放采集**（`analyzer-scan`）：把 `agent` 探针经 SSH/WinRM 投放到待测机器、就地扫描、回传并组装 `AssetReport` 上报（详见下文「远端投放采集」）

- **漏洞检测引擎**（`analyzer.detect`）：自实现，不依赖 trivy/grype。基于本地 OSV
  通告库,把 ingest 进来的 `AssetReport` 软件包清单与漏洞数据做匹配,产出
  `Vulnerability`。含 dpkg 语义的版本比较、OSV 受影响区间判定、本地库索引。

- **关联分析（`analyzer.correlate`，v0 规则）**：分两层。(1) **IOC 流聚合**：collector
  在流上做完威胁情报 IOC 匹配（`FlowEvent.threat_intel`）后上报；ingest `/ingest/flow-batch`
  时**按指标(IOC)聚合**——命中同一指标的多条流合并成一个 `Alert`，`related_flow_ids` /
  `related_asset_ids` 汇总所有命中流与主机，严重级取该指标命中的最坏级别、`score` 由严重级
  映射。(2) **跨源关联**：若 IOC 告警涉及高/严重级漏洞主机（来自最近 500 条
  `DetectionResult`），额外生成复合告警（`alert_id` 形如 `alert-cross-*`），注入
  `related_vuln_ids` 与 `related_asset_ids`。两层告警均落盘并经 `/reports/alerts` 暴露给 admin。

- **攻击路径预测（`analyzer.predict`）**：ingest 一份**外部红队能力图**（`POST /ingest/capability-graph`，
  opaque JSON，最新一份生效），据观测到的资产/漏洞/网络可达性构建态势图，将能力的 precondition
  前向链式匹配到已观测事实，推导出可落地的 `AttackPath`，经 `GET /attack-paths[/{id}]` 暴露给
  admin。analyzer 只消费这份 JSON 契约，从不 import 或硬编码产出工具（保持红蓝解耦）。

尚未落地（按 ROI 顺序）：标准化（JSONL → 结构化存储）、风险评分、对 admin 的更多查询 API。（跨源关联已落地——见上文「关联分析」。）

## 目录结构

```
analyzer/
├── pyproject.toml
├── README.md
├── src/
│   └── analyzer/
│       ├── __init__.py
│       ├── cli.py                # 控制台入口：analyzer-export-schemas / analyzer-api / analyzer-osv-sync / analyzer-detect / analyzer-migrate-storage / analyzer-scan
│       ├── deploy/               # 远端投放采集（analyzer-scan）：把 agent 探针投到待测机器
│       │   ├── ssh.py            # paramiko SSH（单连接多 channel 复用）
│       │   ├── bootstrap.py      # 口令→密钥引导 + 撤销（revoke）
│       │   ├── agent.py          # 探测/选工作目录/sha256 校验/执行 agent-host/回传/清理
│       │   ├── _util.py          # SSH/WinRM 共用纯函数（扫描目标表 / __exit= 解析 / sha256）
│       │   ├── report.py         # 由分文件 JSON 组装 AssetReport + 上报
│       │   ├── trigger.py        # admin 触发的扫描编排（api/scans.py → deploy 层桥接）
│       │   └── winrm.py          # 可选 WinRM（pywinrm；Windows 目标）
│       ├── schemas/              # 数据契约源（source of truth）
│       │   ├── common.py         # Severity / Confidence / StrictModel / Timestamp
│       │   ├── asset.py          # Package / Service / Port / Account / Credential
│       │   ├── vulnerability.py
│       │   ├── flow.py           # FlowEvent（含 threat_intel）
│       │   ├── threat.py         # ThreatMatch / IndicatorType（IOC 命中）
│       │   ├── alert.py
│       │   ├── envelope.py       # AssetReport / FlowBatch / HostInfo / DetectionResult
│       │   ├── guard_event.py    # GuardEventBatch / GuardEvent（agent-guard 实时防护事件）
│       │   ├── scan.py           # ScanTarget / ScanJob 等扫描编排模型（analyzer 内部，不导出 schemas-json）
│       │   └── attack.py         # CapabilityGraph（红队能力图，opaque）/ AttackPath（预测路径）
│       ├── api/                  # FastAPI 接入层
│       │   ├── app.py            # create_app() 工厂
│       │   ├── auth.py           # 可选 bearer token 认证（设了 ANALYZER_API_TOKEN 才生效）
│       │   ├── ingest.py         # /ingest/* 路由（asset 自动检测 / flow 自动关联）
│       │   ├── detect.py         # /detect/* 路由（按需检测，无状态）
│       │   ├── reports.py        # /reports/* 读侧路由
│       │   ├── scans.py          # /targets + /scans 扫描触发路由（admin 触发扫描）
│       │   └── predict.py        # /ingest/capability-graph + /attack-paths 攻击路径预测路由
│       ├── correlate/            # 关联分析：流威胁情报命中 → Alert；跨源关联
│       │   ├── flow.py           # IOC 聚合关联：Alert per indicator
│       │   └── cross.py          # 跨源关联：高危漏洞主机 + IOC 命中 → 复合 Alert
│       ├── detect/               # 自实现漏洞检测引擎（基于 OSV，无 trivy）
│       │   ├── debversion.py     # dpkg 语义版本比较
│       │   ├── versioning.py     # 按生态选版本比较器（dpkg/PEP440/SemVer）
│       │   ├── cvss.py           # CVSS v3.1 基础分计算 + 严重级映射
│       │   ├── osv.py            # OSV 记录解析 + 受影响区间匹配
│       │   ├── store.py          # 本地 OSV 库加载/索引
│       │   ├── engine.py         # AssetReport → Vulnerability[]
│       │   ├── combine.py        # 合并 OSV 检测 + scanner 发现（内置查毒）
│       │   └── sync.py           # 离线下载 OSV 导出
│       ├── predict/               # 攻击路径预测引擎（前向链式推导）
│       │   ├── graph.py           # 由观测遥测构建态势图（节点=主机，事实=暴露/弱点）
│       │   └── engine.py          # 能力 precondition × 态势事实 → AttackPath[]
│       └── storage/
│           ├── jsonl.py          # JsonlStore（v0 默认）
│           ├── sqlite.py         # SqliteStore（生产推荐）
│           └── migrate.py        # JSONL → SQLite 迁移工具
├── scripts/
│   └── export_schemas.py
├── schemas-json/                 # 由 Pydantic 模型导出的 JSON Schema
│   ├── AssetReport.schema.json
│   ├── DetectionResult.schema.json
│   ├── FlowBatch.schema.json
│   ├── GuardEventBatch.schema.json
│   ├── Alert.schema.json
│   ├── CapabilityGraph.schema.json
│   └── AttackPath.schema.json
├── data/                         # JsonlStore 默认落盘位置（被 .gitignore）
└── tests/
    ├── test_schemas.py           # 数据契约 round-trip 序列化
    ├── test_api.py               # 端到端 API 测试
    ├── test_correlate.py         # 流 IOC 聚合 + 跨源关联
    ├── test_predict.py           # 攻击路径预测引擎（能力图 × 态势事实）
    ├── test_detect_api.py        # /detect/asset-report 端点
    ├── test_detect.py            # 漏洞检测引擎
    ├── test_deploy.py            # 远端投放采集 deploy 层（analyzer-scan）
    ├── test_storage.py           # JSONL + SQLite 持久化
    ├── test_migrate.py           # JSONL → SQLite 迁移
    ├── test_cvss.py              # CVSS 基础分 + 严重级映射
    ├── test_debversion.py        # dpkg 版本比较
    └── test_versioning.py        # 多生态版本比较
```

## 数据契约约定

- **严格模式**：所有契约模型继承自 `StrictModel`，`extra="forbid"`——上游若发了未定义字段会**显式失败**，不静默吞掉。
- **discriminated union**：`Asset` 是 5 种资产类型的 tagged union，靠 `kind` 字段区分；新增资产类型必须随契约版本升级。
- **时间**：所有时间字段为带 UTC tzinfo 的 `datetime`，JSON 形式为 RFC 3339 字符串。
- **跨语言**：`schemas-json/` 是面向 Rust（agent）和 TypeScript（admin）的权威接口；只读，由 Python 端模型生成。

## 环境

推荐用 [`uv`](https://github.com/astral-sh/uv)：

```bash
cd analyzer
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

analyzer-export-schemas                 # 把 Pydantic 模型导出为 JSON Schema
analyzer-export-schemas --out /tmp/out  # 指定输出目录

analyzer-api                            # 启 HTTP API（默认 127.0.0.1:8000）
analyzer-api --host 0.0.0.0 --port 9000
analyzer-api --reload                   # 开发模式：代码改动自动重载

analyzer-osv-sync --ecosystem Debian PyPI npm   # 一次拉多生态 → data/osv/{Debian,PyPI,npm}/
analyzer-detect                         # 用本地库匹配最近 50 条 AssetReport（JSONL + SQLite 均可）
analyzer-detect --ecosystem Debian:12 --db data/osv --pretty
analyzer-detect --data-dir data --storage sqlite --ecosystem Debian:12  # 用 SQLite 后端

analyzer-migrate-storage                # 迁移 JSONL 文件到 SQLite analyzer.db（可选，生产推荐）
analyzer-migrate-storage --data-dir data
```

## 漏洞检测（analyzer.detect，自实现，不依赖 trivy）

把 ingest 进来的 `AssetReport` 软件包清单与**本地 OSV 通告库**做匹配,产出
`Vulnerability`。匹配引擎全部自实现:OSV 记录解析、按生态选用的版本比较、受影响
区间（`introduced`/`fixed`/`last_affected`）判定。

**多生态**:按 OSV 生态自动选版本比较器——Debian/Ubuntu 用 dpkg 语义、PyPI 用
PEP 440、Rocky/Alma/SUSE 等 rpm 系用 rpm EVR(`rpmvercmp` + epoch/release)、Alpine
用 apk 版本序(`-rN` 修订、`_alpha/_p` 后缀)、npm/Go/crates.io 等用 SemVer 2.0;
未知生态回退 SemVer。区间类型同时支持 `ECOSYSTEM`（用生态原生比较）与 `SEMVER`
（npm/Go 常用,强制 SemVer 比较）。

**包级生态**:每个 `Package` 可带 `ecosystem` 字段（如 agent-host 给 deb 包打的
`Debian:12`、语言包的 `PyPI`/`npm`）。检测对每个包用其自身生态匹配,未设置时回退
到由 `host.os` 推断的默认生态——于是同一份报告可混合 OS 包与语言包,各按自己的
库与比较器命中。

```bash
# 1. 同步漏洞库（顶层生态，可一次多个；记录内含 Debian:12 等发行版限定）
analyzer-osv-sync --ecosystem Debian PyPI npm --db data/osv

# 2. 对已 ingest 的报告跑检测（生态可显式指定或从 host.os 自动推断）
analyzer-detect --reports data/asset-reports.jsonl --db data/osv --pretty
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

> 取向:agent-host 出 SBOM/清单,检测集中在 analyzer——中心一份库、可对历史清单回溯匹配。
> 数据源覆盖决定匹配质量:OSV 覆盖 Debian/Ubuntu/Alpine 等,**不含 Kali**
> （Kali 基于 Debian testing,只能近似映射）。严重级优先按 OSV 的 CVSS v3 向量
> 算出基础分并据此定级（同时填入 `cvss_score`）;无向量时退回文本字段,再缺失按
> `medium`。CVSS v4 向量暂不计算分值（走文本/兜底）。

## API 速查

| 路径 | 方法 | 状态码 | 用途 |
| --- | --- | --- | --- |
| `/health` | GET | 200 | 存活检查 |
| `/ingest/asset-report` | POST | 202 | 接收 `agent-host` 的 `AssetReport`，落盘；自动检测 OSV CVE（若库已加载）并合并报告内内置查毒命中，把合并后的 `DetectionResult` 落盘 |
| `/ingest/flow-batch` | POST | 202 | 接收 `agent-flow` 的 `FlowBatch`，落盘；按指标(IOC)聚合成 `Alert`，并生成跨源关联告警（若涉及高危漏洞主机） |
| `/ingest/guard-event` | POST | 202 | 接收 `agent-guard` 的 `GuardEventBatch`（实时防护检测 + 处置动作），落盘（v1 仅存储；跨源关联留待后续） |
| `/ingest/capability-graph` | POST | 202 | 接收外部红队**能力图**（opaque JSON），最新一份生效，用于攻击路径预测 |
| `/reports/asset-reports?limit=N` | GET | 200 | 读最近 N 条 `AssetReport`（默认 50，范围 1–500），newest first |
| `/reports/asset-reports/{report_id}` | GET | 200 / 404 | 读单条 `AssetReport` |
| `/reports/flow-batches?limit=N` | GET | 200 | 读最近 N 条 `FlowBatch`（默认 50，范围 1–500） |
| `/reports/vulnerabilities?limit=N` | GET | 200 | 读最近 N 条 `DetectionResult`（OSV + 内置查毒 合并结果）（默认 50，范围 1–500） |
| `/reports/vulnerabilities/{report_id}` | GET | 200 / 404 | 读单个 `AssetReport` 的 `DetectionResult`（供 admin 查看某次扫描结果） |
| `/reports/alerts?limit=N` | GET | 200 | 读最近 N 条 `Alert`（关联分析产物）（默认 50，范围 1–500） |
| `/reports/alerts/{alert_id}` | GET | 200 / 404 | 读单条 `Alert` |
| `/reports/guard-events?host_id=&limit=N` | GET | 200 | 读最近 N 条 `GuardEventBatch`，可按 `host_id` 过滤（供 admin guard 视图） |
| `/attack-paths?limit=N` | GET | 200 | 基于当前态势 + 最新能力图按需推导攻击路径（无能力图→空数组；默认 500，范围 1–500） |
| `/attack-paths/{path_id}` | GET | 200 / 404 | 读单条预测 `AttackPath` |
| `/detect/asset-report` | POST | 200 / 422 | 对传入 `AssetReport` 按需跑 OSV 检测并合并 内置查毒 命中，返回 `DetectionResult`（无状态，不落盘）；无法推断生态时返回 422（除非报告内已有 内置查毒 命中） |
| `/targets` | POST | 201 | 注册扫描目标；managed_key 模式可带一次性 `password` 在 analyzer 主机 bootstrap 托管密钥（**不持久化密码**） |
| `/targets`、`/targets/{id}` | GET | 200 / 404 | 列出 / 读取已注册目标 |
| `/scans` | POST | 202 | **触发**一次扫描（`{target_id, capability, options}`）→ 建 `ScanJob`、后台异步投放 agent、入库、回填结果 → 返回 job |
| `/scans`、`/scans/{job_id}` | GET | 200 / 404 | 列出 / 轮询扫描作业状态（pending→running→succeeded/failed + result） |

检测在应用启动时加载一次本地 OSV 库（`ANALYZER_OSV_DIR`，默认 `data/osv`）。生态默认
从 `host.os` 推断；`/detect` 无法推断（如 Kali）时返回 **422**（除非报告内已有 内置查毒
命中），ingest 自动检测则在无 OSV 命中且无 内置查毒 时静默跳过。可用 `ANALYZER_OSV_ECOSYSTEM`
（如 `Debian:12`）固定生态。ingest 的自动检测是
**尽力而为**：未加载 OSV 库 / 生态推断不出 / 检测异常都不会影响报告入库（仍 202）。

校验失败统一返回 **422** + Pydantic 错误详情。

**CORS**：默认放行 `http://localhost:3000`（admin 开发地址）。生产部署通过 `ANALYZER_CORS_ORIGINS=https://a.example.com,https://b.example.com` 配置。

**存储后端**：v0 默认 JSONL（`ANALYZER_STORAGE=jsonl`，落盘 `data/*.jsonl`）；生产推荐 SQLite（`ANALYZER_STORAGE=sqlite`，库文件 `data/analyzer.db`，docker compose 即用此）。切后端前先用 `analyzer-migrate-storage` 迁移历史数据；两种后端共用同一套 `/reports/*` 查询接口，自动适配。

### admin 触发扫描（全链路：触发 → 投放 → 上报 → 入库 → 查看）

admin 调 `POST /targets`/`POST /scans` 即可从浏览器发起一次扫描，analyzer 复用 deploy 层异步投放 agent、入库并回填作业结果，admin 轮询 `GET /scans/{job_id}` 看状态、按结果 id 看 `AssetReport`/`FlowBatch`/guard 事件。

- **凭据**：目标注册表只存元数据 + 凭据**模式**；长期凭据是 analyzer 主机上的**托管 SSH 密钥**（注册时一次性 `password` bootstrap 后即丢弃，绝不持久化）或服务端 `identity` 路径。触发不需要任何密钥。
- **作业**：`POST /scans` 建 `ScanJob`(pending) + FastAPI BackgroundTask（`asyncio.to_thread` 跑阻塞 SSH，不阻塞事件循环）→ host/flow 一次性投放+拉回+入库（与 agent 直传同一 `store_asset_report`/`store_flow_batch` 路径），guard 投放 `agent` 二进制并 `agent guard --upload` 常驻。作业 append-only 版本化（每次状态变更追加同 `job_id` 一行；读取取最新、列表去重）。
- **配置**：`ANALYZER_PUBLIC_URL`（guard 守护回推 analyzer 的地址，默认 `http://127.0.0.1:8000`）；`ANALYZER_AGENT_TARGET_DIR`（analyzer 主机上 agent 的 cargo target 根，默认 `../agent/target`）。
- **多架构自动选择**：deploy 探测目标 `uname -m`（x86_64/amd64 → x86_64，aarch64/arm64 → aarch64），从 `ANALYZER_AGENT_TARGET_DIR/<triple>/release/<bin>` 取对应架构的静态二进制；`--agent-binary` 可显式覆盖。两架构的二进制由 agent 项目产出：仓库根 `make build-agent-deploy`（x86_64，需 `musl-tools`）/ `make build-agent-deploy-arm64`（aarch64，用 `cross`）；CI 两个 job 分别构建并上传制品。
- **范围**：触发聚焦 SSH/Linux（host/flow/guard 全支持）；WinRM 凭据落地留作后续。

### 端到端冒烟（agent → analyzer）

```bash
# 启 API
analyzer-api --port 8000 &

# agent-host -> analyzer
cd ../agent && cargo run --quiet -p agent-host -- -r / | \
  curl -s -X POST -H "Content-Type: application/json" \
    --data-binary @- http://127.0.0.1:8000/ingest/asset-report

# flow -> analyzer（抓包 + 威胁情报 IOC 匹配 + 上报，一步到位；上报经统一 agent，agent-flow 本身不上报）
cd ../agent && cargo run --quiet -p agent -- flow capture --upload http://127.0.0.1:8000

# 或手动管道（等价）
cargo run --quiet -p agent-flow -- capture | \
  curl -s -X POST -H "Content-Type: application/json" \
    --data-binary @- http://127.0.0.1:8000/ingest/flow-batch

# 命中威胁情报的流会被自动关联成告警
curl -s http://127.0.0.1:8000/reports/alerts | python3 -m json.tool

# 落盘位置（ANALYZER_DATA_DIR 可覆盖，默认 ./data/）
ls analyzer/data/
#   asset-reports.jsonl
#   flow-batches.jsonl
#   vulnerabilities.jsonl
#   alerts.jsonl
```

## 远端投放采集（analyzer-scan）

跨机编排是 analyzer 的职责：把 `agent-host` 探针**投放到待测机器**、就地扫描、把分文件
JSON 回传、组装成 `AssetReport` 并（可选）上报。这部分以前是 Rust `agent-remote`，现已用 Python
（paramiko / 可选 pywinrm）移植进 `analyzer.deploy`，对外即 `analyzer-scan` 命令。agent 本身只负责被调度
的本机检测，不再含跨机投放。

```bash
# 0. 先构建静态部署二进制（host/flow/agent，x86_64 + 可选 arm64）
make build-agent-deploy            # 从 kcatta/ 根；arm64 用 make build-agent-deploy-arm64
# SSH 投放时按目标 uname -m 自动选 x86_64/aarch64 二进制；无需 --agent-binary（除非显式覆盖）。

# 1. 首次：给一次口令安装受管密钥，扫描并上报 analyzer
SCDR_SSH_PASSWORD='...' analyzer-scan --ssh-host root@10.0.0.9 -t all -o ./reports/10.0.0.9 \
  --upload http://127.0.0.1:8000

# 2. 后续：密钥免密；--malware 在目标机跑内置签名查毒（无需 clamd）
analyzer-scan --ssh-host root@10.0.0.9 -t all -o ./reports/10.0.0.9 --malware \
  --upload http://127.0.0.1:8000

# 撤销受管密钥（恢复目标机 authorized_keys，删除本地密钥对）
analyzer-scan --ssh-host root@10.0.0.9 --revoke-key

# Windows 目标（WinRM；需 pip install 'kcatta-analyzer[winrm]' 与 agent-host.exe）
AGENT_WINRM_PASSWORD='...' analyzer-scan --transport winrm --ssh-host Administrator@10.0.0.50 \
  -t all -o ./reports/win50 \
  --agent-binary ../agent/target/x86_64-pc-windows-msvc/release/agent-host.exe

# 3. 调度其它能力（SSH/Linux）：--capability host(默认) | flow | guard
#    flow：远程一次性抓包，拉回 FlowBatch，--upload 则 POST /ingest/flow-batch
analyzer-scan --ssh-host root@10.0.0.9 --capability flow -o ./reports/10.0.0.9 \
  --upload http://127.0.0.1:8000
#    guard：部署 `agent` 二进制并以 `agent guard --upload` 常驻守护，持续推送 GuardEventBatch（--upload 必填）
analyzer-scan --ssh-host root@10.0.0.9 --capability guard \
  --upload http://127.0.0.1:8000
```

- 投放管线（host，默认）：探测 arch → 选可写非 `noexec` 工作目录 → 上传 `agent-host` 并 sha256 校验 →
  `agent-host -r <root> -t <target> -o <out>`（`--malware` 时另写 `malware.json`）→ 回传分文件 JSON →
  `rm -rf` 工作目录（即使出错也清理）。`-t host|all` 会本地组装 `asset_report.json`，`--upload` 再 POST。
  （注：上报由 analyzer-scan 自身完成；投放的 `agent-host` 只产出文件、不上报。）
- `--capability flow`：上传 `agent-flow` → 远程 `capture`（`--pcap`/`--iface`/`--duration`/`--bpf` 可选）→ 拉回 `flow.json` → `--upload` 则由 analyzer-scan POST `/ingest/flow-batch`。一次性，清理工作目录。
- `--capability guard`：上传 **`agent`** 二进制到持久目录 → `setsid` 后台启动 `agent guard --upload <analyzer>` 常驻守护（**不**清理，持续推送；只有 `agent` 会上报，故 guard 投 `agent` 而非 `agent-guard`）；`--guard-config` 可上传本地 `guard.json`。**`--upload` 必填**。
- flow/guard 仅 SSH/Linux；`--malware` 仅 SSH/Linux（WinRM 暂不支持）。
- 受管密钥仍在 `~/.config/scdr/agent-remote/keys/<user>@<host>-<port>.ed25519`（与旧版兼容）。

## 计划中的下一步

按 ROI：

- `analyzer.normalize`：把 JSONL/SQLite 中的 `AssetReport` 拆解为结构化资产 / 漏洞条目（候选 DuckDB / Postgres）。
- `analyzer.score`：风险评分（依赖 normalize）。
- 查询 API 扩展：给 admin 提供按资产/告警严重级的统计、时间窗口聚合等接口（目前仅 tail 查询）。

> `analyzer.correlate`（IOC 聚合 + 跨源关联）与 SQLite 持久化已在 v0 落地，不在此清单内。
