# fusion

**数据分析与态势感知平台**，posture 的分析核心。基于 Python 构建，负责把 `agent`（主机 + 网络探针）上传的异构数据标准化、做关联分析、打分入库，并对 `portal` 暴露查询接口。

## 当前状态（v0）

已落地：

- 跨组件**数据契约**：Pydantic 源 + 自动导出的 JSON Schema
- 数据契约共 7 类：**上行采集 envelope** `AssetReport`（`posture-host` → fusion）、`FlowBatch`（`posture-flow` → fusion）、`GuardEventBatch`（`posture-guard` → fusion）；**fusion 派生、对 portal 暴露** `DetectionResult`、`Alert`、`AttackPath`；**外部红队** `CapabilityGraph`（opaque，→ fusion）
- 测试覆盖 round-trip 序列化、严格性校验、tagged-union 鉴别
- **接入层 API**：FastAPI 起 `/ingest/asset-report`、`/ingest/flow-batch`、`/health`，自动用 Pydantic 校验入参，落盘为 JSONL
- **端到端打通**：`posture-host` 与 `posture-flow capture` 的 JSON 输出可以直接 `curl -X POST` 到 fusion 完成入库
- **远端投放采集**（`fusion-scan`）：把 `agent` 探针经 SSH/WinRM 投放到待测机器、就地扫描、回传并组装 `AssetReport` 上报（详见下文「远端投放采集」）

- **漏洞检测引擎**（`fusion.detect`）：自实现，不依赖 trivy/grype。基于本地 OSV
  通告库,把 ingest 进来的 `AssetReport` 软件包清单与漏洞数据做匹配,产出
  `Vulnerability`。含 dpkg 语义的版本比较、OSV 受影响区间判定、本地库索引。

- **关联分析（`fusion.correlate`，v0 规则）**：分两层。(1) **IOC 流聚合**：collector
  在流上做完威胁情报 IOC 匹配（`FlowEvent.threat_intel`）后上报；ingest `/ingest/flow-batch`
  时**按指标(IOC)聚合**——命中同一指标的多条流合并成一个 `Alert`，`related_flow_ids` /
  `related_asset_ids` 汇总所有命中流与主机，严重级取该指标命中的最坏级别、`score` 由严重级
  映射。(2) **跨源关联**：若 IOC 告警涉及高/严重级漏洞主机（来自最近 500 条
  `DetectionResult`），额外生成复合告警（`alert_id` 形如 `alert-cross-*`），注入
  `related_vuln_ids` 与 `related_asset_ids`。两层告警均落盘并经 `/reports/alerts` 暴露给 portal。

- **攻击路径预测（`fusion.predict`）**：ingest 一份**外部红队能力图**（`POST /ingest/capability-graph`，
  opaque JSON，最新一份生效），据观测到的资产/漏洞/网络可达性构建态势图，将能力的 precondition
  前向链式匹配到已观测事实，推导出可落地的 `AttackPath`，经 `GET /attack-paths[/{id}]` 暴露给
  portal。fusion 只消费这份 JSON 契约，从不 import 或硬编码产出工具（保持红蓝解耦）。

尚未落地（按 ROI 顺序）：标准化（JSONL → 结构化存储）、风险评分、对 portal 的更多查询 API。（跨源关联已落地——见上文「关联分析」。）

## 目录结构

```
fusion/
├── pyproject.toml
├── README.md
├── src/
│   └── fusion/
│       ├── __init__.py
│       ├── cli.py                # 控制台入口：fusion-export-schemas / fusion-api / fusion-osv-sync / fusion-detect / fusion-migrate-storage / fusion-scan
│       ├── deploy/               # 远端投放采集（fusion-scan）：把 agent 探针投到待测机器
│       │   ├── ssh.py            # paramiko SSH（单连接多 channel 复用）
│       │   ├── bootstrap.py      # 口令→密钥引导 + 撤销（revoke）
│       │   ├── agent.py          # 探测/选工作目录/sha256 校验/执行 posture-host/回传/清理
│       │   ├── _util.py          # SSH/WinRM 共用纯函数（扫描目标表 / __exit= 解析 / sha256）
│       │   ├── report.py         # 由分文件 JSON 组装 AssetReport + 上报
│       │   └── winrm.py          # 可选 WinRM（pywinrm；Windows 目标）
│       ├── schemas/              # 数据契约源（source of truth）
│       │   ├── common.py         # Severity / Confidence / StrictModel / Timestamp
│       │   ├── asset.py          # Package / Service / Port / Account / Credential
│       │   ├── vulnerability.py
│       │   ├── flow.py           # FlowEvent（含 threat_intel）
│       │   ├── threat.py         # ThreatMatch / IndicatorType（IOC 命中）
│       │   ├── alert.py
│       │   ├── envelope.py       # AssetReport / FlowBatch / HostInfo / DetectionResult
│       │   └── attack.py         # CapabilityGraph（红队能力图，opaque）/ AttackPath（预测路径）
│       ├── api/                  # FastAPI 接入层
│       │   ├── app.py            # create_app() 工厂
│       │   ├── auth.py           # 可选 bearer token 认证（设了 FUSION_API_TOKEN 才生效）
│       │   ├── ingest.py         # /ingest/* 路由（asset 自动检测 / flow 自动关联）
│       │   ├── detect.py         # /detect/* 路由（按需检测，无状态）
│       │   ├── reports.py        # /reports/* 读侧路由
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
    ├── test_deploy.py            # 远端投放采集 deploy 层（fusion-scan）
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
- **跨语言**：`schemas-json/` 是面向 Rust（agent）和 TypeScript（portal）的权威接口；只读，由 Python 端模型生成。

## 环境

推荐用 [`uv`](https://github.com/astral-sh/uv)：

```bash
cd fusion
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

fusion-export-schemas                 # 把 Pydantic 模型导出为 JSON Schema
fusion-export-schemas --out /tmp/out  # 指定输出目录

fusion-api                            # 启 HTTP API（默认 127.0.0.1:8000）
fusion-api --host 0.0.0.0 --port 9000
fusion-api --reload                   # 开发模式：代码改动自动重载

fusion-osv-sync --ecosystem Debian PyPI npm   # 一次拉多生态 → data/osv/{Debian,PyPI,npm}/
fusion-detect                         # 用本地库匹配最近 50 条 AssetReport（JSONL + SQLite 均可）
fusion-detect --ecosystem Debian:12 --db data/osv --pretty
fusion-detect --data-dir data --storage sqlite --ecosystem Debian:12  # 用 SQLite 后端

fusion-migrate-storage                # 迁移 JSONL 文件到 SQLite fusion.db（可选，生产推荐）
fusion-migrate-storage --data-dir data
```

## 漏洞检测（fusion.detect，自实现，不依赖 trivy）

把 ingest 进来的 `AssetReport` 软件包清单与**本地 OSV 通告库**做匹配,产出
`Vulnerability`。匹配引擎全部自实现:OSV 记录解析、按生态选用的版本比较、受影响
区间（`introduced`/`fixed`/`last_affected`）判定。

**多生态**:按 OSV 生态自动选版本比较器——Debian/Ubuntu 用 dpkg 语义、PyPI 用
PEP 440、Rocky/Alma/SUSE 等 rpm 系用 rpm EVR(`rpmvercmp` + epoch/release)、Alpine
用 apk 版本序(`-rN` 修订、`_alpha/_p` 后缀)、npm/Go/crates.io 等用 SemVer 2.0;
未知生态回退 SemVer。区间类型同时支持 `ECOSYSTEM`（用生态原生比较）与 `SEMVER`
（npm/Go 常用,强制 SemVer 比较）。

**包级生态**:每个 `Package` 可带 `ecosystem` 字段（如 posture-host 给 deb 包打的
`Debian:12`、语言包的 `PyPI`/`npm`）。检测对每个包用其自身生态匹配,未设置时回退
到由 `host.os` 推断的默认生态——于是同一份报告可混合 OS 包与语言包,各按自己的
库与比较器命中。

```bash
# 1. 同步漏洞库（顶层生态，可一次多个；记录内含 Debian:12 等发行版限定）
fusion-osv-sync --ecosystem Debian PyPI npm --db data/osv

# 2. 对已 ingest 的报告跑检测（生态可显式指定或从 host.os 自动推断）
fusion-detect --reports data/asset-reports.jsonl --db data/osv --pretty
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

> 取向:posture-host 出 SBOM/清单,检测集中在 fusion——中心一份库、可对历史清单回溯匹配。
> 数据源覆盖决定匹配质量:OSV 覆盖 Debian/Ubuntu/Alpine 等,**不含 Kali**
> （Kali 基于 Debian testing,只能近似映射）。严重级优先按 OSV 的 CVSS v3 向量
> 算出基础分并据此定级（同时填入 `cvss_score`）;无向量时退回文本字段,再缺失按
> `medium`。CVSS v4 向量暂不计算分值（走文本/兜底）。

## API 速查

| 路径 | 方法 | 状态码 | 用途 |
| --- | --- | --- | --- |
| `/health` | GET | 200 | 存活检查 |
| `/ingest/asset-report` | POST | 202 | 接收 `posture-host` 的 `AssetReport`，落盘；自动检测 OSV CVE（若库已加载）并合并报告内内置查毒命中，把合并后的 `DetectionResult` 落盘 |
| `/ingest/flow-batch` | POST | 202 | 接收 `posture-flow` 的 `FlowBatch`，落盘；按指标(IOC)聚合成 `Alert`，并生成跨源关联告警（若涉及高危漏洞主机） |
| `/ingest/guard-event` | POST | 202 | 接收 `posture-guard` 的 `GuardEventBatch`（实时防护检测 + 处置动作），落盘（v1 仅存储；跨源关联留待后续） |
| `/ingest/capability-graph` | POST | 202 | 接收外部红队**能力图**（opaque JSON），最新一份生效，用于攻击路径预测 |
| `/reports/asset-reports?limit=N` | GET | 200 | 读最近 N 条 `AssetReport`（默认 50，范围 1–500），newest first |
| `/reports/asset-reports/{report_id}` | GET | 200 / 404 | 读单条 `AssetReport` |
| `/reports/flow-batches?limit=N` | GET | 200 | 读最近 N 条 `FlowBatch`（默认 50，范围 1–500） |
| `/reports/vulnerabilities?limit=N` | GET | 200 | 读最近 N 条 `DetectionResult`（OSV + 内置查毒 合并结果）（默认 50，范围 1–500） |
| `/reports/alerts?limit=N` | GET | 200 | 读最近 N 条 `Alert`（关联分析产物）（默认 50，范围 1–500） |
| `/reports/alerts/{alert_id}` | GET | 200 / 404 | 读单条 `Alert` |
| `/attack-paths?limit=N` | GET | 200 | 基于当前态势 + 最新能力图按需推导攻击路径（无能力图→空数组；默认 200，范围 1–500） |
| `/attack-paths/{path_id}` | GET | 200 / 404 | 读单条预测 `AttackPath` |
| `/detect/asset-report` | POST | 200 / 422 | 对传入 `AssetReport` 按需跑 OSV 检测并合并 内置查毒 命中，返回 `DetectionResult`（无状态，不落盘）；无法推断生态时返回 422（除非报告内已有 内置查毒 命中） |

检测在应用启动时加载一次本地 OSV 库（`FUSION_OSV_DIR`，默认 `data/osv`）。生态默认
从 `host.os` 推断；`/detect` 无法推断（如 Kali）时返回 **422**（除非报告内已有 内置查毒
命中），ingest 自动检测则在无 OSV 命中且无 内置查毒 时静默跳过。可用 `FUSION_OSV_ECOSYSTEM`
（如 `Debian:12`）固定生态。ingest 的自动检测是
**尽力而为**：未加载 OSV 库 / 生态推断不出 / 检测异常都不会影响报告入库（仍 202）。

校验失败统一返回 **422** + Pydantic 错误详情。

**CORS**：默认放行 `http://localhost:3000`（portal 开发地址）。生产部署通过 `FUSION_CORS_ORIGINS=https://a.example.com,https://b.example.com` 配置。

**存储后端**：v0 默认 JSONL（`FUSION_STORAGE=jsonl`，落盘 `data/*.jsonl`）；生产推荐 SQLite（`FUSION_STORAGE=sqlite`，库文件 `data/fusion.db`，docker compose 即用此）。切后端前先用 `fusion-migrate-storage` 迁移历史数据；两种后端共用同一套 `/reports/*` 查询接口，自动适配。

### 端到端冒烟（agent → fusion）

```bash
# 启 API
fusion-api --port 8000 &

# posture-host -> fusion
cd ../agent && cargo run --quiet -p posture-host -- -r / | \
  curl -s -X POST -H "Content-Type: application/json" \
    --data-binary @- http://127.0.0.1:8000/ingest/asset-report

# posture-flow -> fusion（抓包 + 威胁情报 IOC 匹配 + 上报，一步到位）
cd ../agent && cargo run --quiet -p posture-flow -- capture --upload http://127.0.0.1:8000

# 或手动管道（等价）
cargo run --quiet -p posture-flow -- capture | \
  curl -s -X POST -H "Content-Type: application/json" \
    --data-binary @- http://127.0.0.1:8000/ingest/flow-batch

# 命中威胁情报的流会被自动关联成告警
curl -s http://127.0.0.1:8000/reports/alerts | python3 -m json.tool

# 落盘位置（FUSION_DATA_DIR 可覆盖，默认 ./data/）
ls fusion/data/
#   asset-reports.jsonl
#   flow-batches.jsonl
#   vulnerabilities.jsonl
#   alerts.jsonl
```

## 远端投放采集（fusion-scan）

跨机编排是 fusion 的职责：把 `posture-host` 探针**投放到待测机器**、就地扫描、把分文件
JSON 回传、组装成 `AssetReport` 并（可选）上报。这部分以前是 Rust `agent-remote`，现已用 Python
（paramiko / 可选 pywinrm）移植进 `fusion.deploy`，对外即 `fusion-scan` 命令。agent 本身只负责被调度
的本机检测，不再含跨机投放。

```bash
# 0. 先构建一个静态 posture-host 二进制（不牵 flow/guard）
cd ../agent
rustup target add x86_64-unknown-linux-musl
cargo build -p posture-host --target x86_64-unknown-linux-musl --release
cd ../fusion

# 1. 首次：给一次口令安装受管密钥，扫描并上报 fusion
SCDR_SSH_PASSWORD='...' fusion-scan --ssh-host root@10.0.0.9 -t all -o ./reports/10.0.0.9 \
  --agent-binary ../agent/target/x86_64-unknown-linux-musl/release/posture-host \
  --upload http://127.0.0.1:8000

# 2. 后续：密钥免密；--malware 在目标机跑内置签名查毒（无需 clamd）
fusion-scan --ssh-host root@10.0.0.9 -t all -o ./reports/10.0.0.9 --malware \
  --agent-binary ../agent/target/x86_64-unknown-linux-musl/release/posture-host \
  --upload http://127.0.0.1:8000

# 撤销受管密钥（恢复目标机 authorized_keys，删除本地密钥对）
fusion-scan --ssh-host root@10.0.0.9 --revoke-key

# Windows 目标（WinRM；需 pip install 'posture-fusion[winrm]' 与 posture-host.exe）
AGENT_WINRM_PASSWORD='...' fusion-scan --transport winrm --ssh-host Administrator@10.0.0.50 \
  -t all -o ./reports/win50 \
  --agent-binary ../agent/target/x86_64-pc-windows-msvc/release/posture-host.exe

# 3. 调度其它能力（SSH/Linux）：--capability host(默认) | flow | guard
#    flow：远程一次性抓包，拉回 FlowBatch，--upload 则 POST /ingest/flow-batch
fusion-scan --ssh-host root@10.0.0.9 --capability flow -o ./reports/10.0.0.9 \
  --agent-binary ../agent/target/x86_64-unknown-linux-musl/release/posture-flow \
  --upload http://127.0.0.1:8000
#    guard：部署 posture-guard 并以常驻守护启动，持续向 fusion 推送 GuardEventBatch（--upload 必填）
fusion-scan --ssh-host root@10.0.0.9 --capability guard \
  --agent-binary ../agent/target/x86_64-unknown-linux-musl/release/posture-guard \
  --upload http://127.0.0.1:8000
```

- 投放管线（host，默认）：探测 arch → 选可写非 `noexec` 工作目录 → 上传 `posture-host` 并 sha256 校验 →
  `posture-host -r <root> -t <target> -o <out>`（`--malware` 时另写 `malware.json`）→ 回传分文件 JSON →
  `rm -rf` 工作目录（即使出错也清理）。`-t host|all` 会本地组装 `asset_report.json`，`--upload` 再 POST。
- `--capability flow`：上传 `posture-flow` → 远程 `capture`（`--pcap`/`--iface`/`--duration`/`--bpf` 可选）→ 拉回 `flow.json` → `--upload` 则 POST `/ingest/flow-batch`。一次性，清理工作目录。
- `--capability guard`：上传 `posture-guard` 到持久目录 → `setsid` 后台启动 `--upload <fusion>` 常驻守护（**不**清理，持续推送）；`--guard-config` 可上传本地 `guard.json`。**`--upload` 必填**。
- flow/guard 仅 SSH/Linux；`--malware` 仅 SSH/Linux（WinRM 暂不支持）。
- 受管密钥仍在 `~/.config/scdr/agent-remote/keys/<user>@<host>-<port>.ed25519`（与旧版兼容）。

## 计划中的下一步

按 ROI：

- `fusion.normalize`：把 JSONL/SQLite 中的 `AssetReport` 拆解为结构化资产 / 漏洞条目（候选 DuckDB / Postgres）。
- `fusion.score`：风险评分（依赖 normalize）。
- 查询 API 扩展：给 portal 提供按资产/告警严重级的统计、时间窗口聚合等接口（目前仅 tail 查询）。

> `fusion.correlate`（IOC 聚合 + 跨源关联）与 SQLite 持久化已在 v0 落地，不在此清单内。
