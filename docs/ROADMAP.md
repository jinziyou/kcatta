# kcatta 演进路线图

> 决策版特性规划。基于对三组件（agent / analyzer / admin）真实代码的系统性走查，
> 对每条候选做影响力 / 可行性 / 架构契合度的对抗式评分后综合而成。
> 所有推荐项均守住三条架构不变量——**采集分离**（collector 只落本地文件，仅 `agentd` 上报）、
> **Pydantic 契约单一真源**（导出 JSON Schema → Rust contract + TS 类型，CI 拦漂移）、
> **自实现 OSV 检测**（检测路径不外挂 trivy/grype/clamav）。
>
> 仓库级架构见 [`ARCHITECTURE.md`](../ARCHITECTURE.md)。

## 1. 现状评估

kcatta 的**采集与契约骨架已经扎实**：host 静态盘点（dpkg/apk/rpm + PyPI/npm + 容器/镜像 rootfs
组装 + 路径穿越防护）、自实现的 OSV 版本比较器（deb/rpm/apk/PEP440/semver + CVSS v3 精确打分）、
Pydantic→JSON Schema→Rust/TS 的 CI 漂移门禁，以及 guard 的 detect→decide→respond 管线与
anti-self-DoS 安全否决层，都是真正 load-bearing 的资产。

但平台目前更接近**单节点实验工具**而非生产蓝队平台，四个结构性缺口最致命：

1. **"已采集但不出告警"的断链** —— guard 事件 ingest 只存不关联（`api/ingest.py`）、开放端口
   `Port` 契约已定义却无任何采集器产出（`agent/.../scan.rs`）、镜像内包采集了却不归因到镜像
   （`detect/engine.py`）。数据进来了，但变不成信号。
2. **告警 / 作业全无生命周期** —— Alert 有 `status` 字段却无 mutation 路由（`api/reports.py` 只读）、
   correlate 按 batch 重新生成、`alert_id` 含 `batch_id`（`correlate/trace.py`），持久 C2 信标每批刷
   一条新告警，且无去重 / 抑制 / 确认。
3. **可靠性与可观测性空洞** —— agentd 历史上无持久 spool（analyzer 宕机 >1.4s 即永久丢数据）、
   ingest 无幂等导致重试产生重复行、全平台零 metrics。（前两项见 §2 已落地。）
4. **检测内容稀薄** —— 恶意软件引擎仅内置 EICAR、威胁情报仅 Feodo（纯 IP）、IDS 仅 4 个硬编码端口。
   引擎建好了却"饿着"。

---

## 2. 已落地（本批次）

| 项 | 内容 | 改动 |
| --- | --- | --- |
| **Q1 OSV 检测正确性** ✅ | 跳过 `withdrawn` 顾问（消灭永不老化的误报）；`_cvss_vector` / `_cvss_v4_vector` 在多向量记录中取**最严重**而非第一条；`severity()` 改为**跨信号取 max**（CVSS v3 分数 / v4 向量 / 文本词三者中的最严重），不再因优先级级联而静默降级。 | `detect/osv.py`、`detect/store.py` + 3 个新测试 |
| **CI1 起步切片 · 幂等 ingest** ✅ | 按 `report_id` / `batch_id`（按 envelope 类型命名空间）去重，重试已处理过的上传只回原 `202` 不重复入库。有界 FIFO seen-set，零契约改动。 | `api/idempotency.py`（新）、`api/ingest.py`、`api/app.py` + 5 个新测试 |
| **CI1 起步切片 · 持久 spool** ✅ | agentd 新增有界 FIFO、file-per-item 磁盘 spool：analyzer 不可达时不再丢 telemetry，而是落盘排队，下次上传先 oldest-first 回放；permanent 失败进 `deadletter/`；超预算按环（oldest-first）淘汰。退避加 ±25% jitter（无新依赖，时钟取熵）。 | `agentd/src/spool.rs`（新）、`agentd/src/ingest.rs`、`main.rs`、`run.rs` + 6 个新测试 |
| **CI4 guard token 注入** ✅ | 修复确认的高危 bug：`start_guard_daemon` 从不注入 `ANALYZER_API_TOKEN`，authed analyzer 下每个 GuardEventBatch 被 401 静默丢弃。改为写 0600 `agentd.env`（systemd `EnvironmentFile=` / setsid `source`），token 经 SFTP 文件传入、绝不进 argv；scans 透传 `state.api_token`；非安全字符 token 拒绝注入并告警。 | `deploy/agent.py`、`deploy/trigger.py`、`api/scans.py` + 7 个新测试 |
| **CI2 告警生命周期 + 内容派生身份** ✅ | `alert_key`=sha1（indicator/host，**不含 batch_id**）让持久信标折叠为一条可处置告警；新增内部 `AlertState` append-only 全量快照覆盖层 + `alert_states` 存储 kind；读层 `merge_alerts` dedup-newest + 聚合 `occurrence_count`/`last_seen` + overlay；新 `api/alerts.py`（迁入增强读端点 + `POST /{alert_key}/triage`，CORS GET/POST→用 POST）；admin TriageBar（状态/处置人/备注/抑制，Server Action）+ 列表去重计数。**无 Rust 改动**（Alert 是 derived）。 | `schemas/alert.py`、`correlate/{identity,lifecycle,trace,cross}.py`、`storage/*`、`api/{alerts,reports,app}.py`、admin（api/actions/form/2 页 + 契约重生）+ 13 后端测试 |
| **CI3 guard 事件跨源关联** ✅ | guard `NetworkEvent`/`MalwareEvent`/高危 `IdsEvent` → Alert，**原生 `host_id` 直连**（无需 IP 索引）；guard 网络 IOC 命中复用 trace 的 `alert_key`（`alert_key_for("ioc",type,indicator)`），**同一 C2 被网络 tap 与端上 guard 双见时折叠为一条**；并与 host CVE posture join 出 compound alert。ingest guard 端点从「只存」改为「存 + 关联」。**无契约改动**。 | `correlate/guard.py`（新）、`correlate/__init__.py`、`api/ingest.py` + 9 个新测试 |
| **CI5 开放端口采集器** ✅ | 填补「`Port` 契约/admin 渲染/graph 消费全在、只缺生产者」的空洞：新 `sources/ports.rs` 读 `/proc/net/{tcp,tcp6,udp,udp6}`（IPv4/IPv6 hex 解析、TCP LISTEN / UDP bound）+ inode→PID best-effort 映射，产出 `Asset::Port`，并入 `default_collectors`。**relative-to-scan_root 自动 gate**：镜像/chroot 扫描的 `proc/` 为空 → 不产出，绝不错误归因。诚实承认非 root 下 pid/process_name 多为 None。**无契约/无 analyzer/无 admin 改动**（下游已就绪）。 | `agent-host`：`sources/ports.rs`+`collectors/ports.rs`（新）、`*/mod.rs`、`lib.rs` + 5 个新测试 |
| **Q4 openSUSE Leap ecosystem** ✅ | 对抗式核查后**只补真正可映射的缺口**：`sbom.rs::osv_ecosystem` 加 `opensuse-leap → openSUSE:Leap {VERSION_ID}`（全 x.y）。**故意不映射 RHEL/SLES**（OSV 按 CPE+repo / product-module 名键控，os-release 无法复现，exact-string lookup 会全空）与 CentOS/Fedora/Tumbleweed（OSV 不收录）。Rocky/Alma 已工作。**无契约改动**；**砍掉**分析器 `ecosystem_for_os` host-fallback（对嵌套镜像包会用宿主 os 串误判）。 | `agent-host/sbom.rs` + 扩展映射测试 |
| **Q6 OpenAPI 漂移门禁** ✅ | `analyzer-export-openapi` 子命令导出 `create_app().openapi()`（sort_keys，确定性）→ 提交 `analyzer/openapi.json`；CI 加 git-diff 步骤 + `make openapi-check`。首次把 **scan/credential/attack-path** 这些不在 `schemas-json/` 的 API 模型纳入机械漂移保护(此前 admin `scan.ts` 手抄、零 CI 守护)。pytest 侧加确定性/同步/覆盖三测。 | `cli.py`、`scripts/export_openapi.py`(新)、`pyproject`、`Makefile`、`ci.yml`、`openapi.json`(新) + 3 测试 |
| **Q7 guard 受保护进程策略化** ✅ | `safety.rs` 把硬编码的 ~11 名受保护进程改为「内置默认集 + `ResponsePolicy.protected_processes` 配置可加」（只增不减，配置错也无法 un-protect sshd）。内置默认补上 **数据库**（postgres/mysqld/mariadbd/mongod/redis-server）与 **Web/代理**（nginx/httpd/apache2/haproxy/envoy）+ 容器运行时，**默认即消除** `exe_deleted_running` 升级误报 SIGKILL 关键服务的自我 DoS。抽出纯函数 `is_protected_process_name` 便于单测。 | `guard/src/{safety,config}.rs` + 1 测试 |
| **Q5 镜像 CVE 归因** ✅ | `Vulnerability` 加 `parent_asset_id`，`detect._to_vulnerability` 从 matched Package 透传（镜像/容器包已带 `parent_asset_id` 且用镜像自身 os-release 打 ecosystem——前置校验通过）。admin 漏洞页按 image/container **分组**（`DetectionResult` 无 assets 数组，故必须 key 在 vuln 自带字段上）。走全契约链：Pydantic→schemas-json→admin TS 重生→**Rust 镜像手改**（漂移门禁不覆盖此字段，靠纪律）。 | `schemas/vulnerability.py`、`detect/engine.py`、`contract/lib.rs`、`host/malware.rs`、admin（2 页 + 契约重生）+ 2 个 detect 测试 |

> **诚实边界**：幂等 seen-set 为单进程内、有界、best-effort——多 worker 下各自持集，跨 worker
> 或超窗淘汰仍可能重复入库；它与 agentd 持久 spool 的"重发"互补，二者合起来让重复**变罕见而非
> 不可能**。spool 的回放也可能因"POST 成功但删文件前崩溃 / 两线程并发 drain"而双发，正是由幂等层
> 收敛——两机制是有意互补的。

---

## 3. 推荐优先级路线图

### 🟢 速赢（高影响 / 低投入 / 强契合，1~3 周级）

| # | 做什么 + 为何现在 | 改动组件 | 投入 |
| --- | --- | --- | --- |
| Q2 | **GHSA 顾问源接入**：GHSA 本就是 OSV 原生格式，store 直接加载 OSV-shape JSON，几乎零引擎改动即拓宽覆盖面。 | `detect/sync.py` + `detect/sources/` | S |
| Q3′ | **admin 真 partial-failure**：overview 把已算出的 `settled().ok` 渲染成 per-card 降级徽章——当前单个 fetch 失败显示"暂无"=安全隐患。（退避 jitter 已随 CI1 落地。） | `admin/.../page.tsx` | S |
| Q4 ✅ | **openSUSE Leap ecosystem 映射**（已落地，见 §2）。对抗式核查证伪了「扩 rhel/suse」——它们 OSV 不按 os-release 键控，只 openSUSE Leap 可安全映射。 | `agent-host/sbom.rs` | S |
| Q5 ✅ | **镜像 CVE 归因**（已落地，见 §2）。`Vulnerability.parent_asset_id` 透传 + admin per-image 分组（实为契约变更而非纯读侧，走全链路）。 | `schemas`、`detect`、`contract`、admin | S~M |
| Q6 ✅ | **OpenAPI 导出 + 漂移门禁**（已落地，见 §2）。`analyzer-export-openapi` 导出 `app.openapi()` → 提交 `openapi.json`，CI git-diff 门禁。首次把 scan/credential/attack-path API 面纳入机械漂移保护。 | `cli.py`、`ci.yml`、`Makefile`、`openapi.json` | S |
| Q7 ✅ | **guard 受保护进程策略化**（已落地，见 §2）。`safety.rs` 硬编码 11 名扩成「内置默认 + 配置可加」；默认集补上 nginx/postgres/redis/mysqld/... 直接消除升级时 SIGKILL 数据/Web 层的自我 DoS。 | `guard/src/safety.rs`、`guard/src/config.rs` | S |

### 🔵 核心投资（转型性，数周级，按依赖排序）

- **CI1 收尾**（剩余项）：当前 spool 默认目录优先 `ANALYZER_SPOOL_DIR` → `/var/lib/kcatta/agentd/spool`
  → temp。收尾包括：deploy 层显式注入持久 spool 目录、`agentd run` 关机时主动尝试 drain、spool 深度
  metric。投入：S~M。
- **CI2 — 告警生命周期 + 内容派生身份** ✅ **已落地**（见 §2）：`alert_key` 剔除 `batch_id`、append-only
  AlertState overlay、dedup-newest 读层、`POST /{alert_key}/triage` + admin TriageBar 均已交付。
- **CI3 — guard 事件跨源关联** ✅ **已落地**（见 §2）：guard network/malware/高危 IDS → Alert，原生
  `host_id` 直连，guard 网络 IOC 复用 trace `alert_key` 折叠，并与 host CVE posture join 出 compound alert。
- **CI4 — per-host token 注入** ✅ **已落地**（见 §2）：guard 守护进程经 0600 `agentd.env` 拿到
  bearer token，authed analyzer 下不再静默丢 guard 事件。*仍坚决拒绝捆绑 mTLS/PKI——纯 HTTP 栈、
  无 client-cert、无 principal，是 XL greenfield，单独评审。*
- **CI5 — 开放端口采集器** ✅ **已落地**（见 §2）：`sources/ports.rs` 读 `/proc/net/*` 产出 `Asset::Port`，
  relative-to-scan_root 自动 gate 镜像/静态扫描；下游（contract/admin/graph）零改动即点亮攻击面视图。
- **CI6 — eBPF per-flow 聚合 map**：用 `LRU_HASH` 按 5-tuple 在内核聚合 bytes/packets/`bpf_ktime`，
  替换 per-packet ring（10k+ pps 即溢出静默丢包），顺带修时间戳正确性。TraceBatch 线上字节不变、零漂移。投入：L。

### 🟡 探索 / 谨慎（有潜力但风险高 / 置信低，需先验证或硬降范围）

- **YARA-subset 规则引擎**：引擎合理且 `scan_bytes` 是 host+guard 共享 chokepoint，但价值受**规则内容**
  门控；须先配 ReDoS/字节预算限制 + 规则更新路径，否则先降为 monitor-only / offset-anchored literal。
- **风险感知评分**：先单独做"杀掉重复 `_SEVERITY_SCORE` 双表 + blast-radius 因子"这半个 S 级赢；
  exposure/confidence 的三语言契约 ripple 待有多源数据再谈。
- **攻击路径质量（scoped creds + 关联性可达）**：纯在 fixpoint 内、无契约改动，promising-近 strong 的 M；
  **拒绝其"防御门控"腿**（引用不存在的 `defense.*` 字段，对蓝队是危险的假阴性）。
- **多源情报接入**：只先做 abuse.ch/MISP 几个 Feodo 级 JSON adapter（立即点亮 domain/JA3 索引）；
  STIX/TAXII 是 stateful 分页协议，单独 L 项并配 feed 完整性加固（TLS pinning/校验/过期）。
- **Prometheus metrics + readiness**：架构契合极干净，但价值在多节点前是潜在的；做时修 `/ready` 空 OSV
  语料返 503 的首启脚枪（空语料是降级可服务，非 unready）。

---

## 4. 不建议 / 暂缓

| 提案 | 暂缓理由 |
| --- | --- |
| 横向扩展作业队列 + worker pool（XL） | 与处处刻意单节点对撞（storage 无 CAS、SSH/WinRM 无可杀句柄、OSV-in-RAM 单节点）。**只留**廉价一半：周期性 stale-lease 清扫 + CANCELLED 状态 + cancel 端点（独立 S/M）。 |
| JSONL 索引点查 + 游标分页（XL） | 最便宜的修复是生产默认切 SQLite（repo 已推荐）。游标 over append-id 与"每次状态转换 re-append"语义冲突。 |
| 增量 / delta 主机采集（XL） | 依赖不存在的幂等地基（CI1 部分满足）且 eviction-during-window 会静默损坏清单。413 的廉价正解是 per-envelope 分块。 |
| 时序 / beaconing 关联（XL） | 时间戳是 drain 时 `Utc::now()` 伪造的、capture 是 per-cycle 窗口——旗舰功能多数部署产垃圾。仅抽出 CROSS_SOURCE_WINDOW 从行数改时钟窗口（独立 S）。 |
| 篡改可证审计日志 | 核心价值依赖不存在的 principal 模型——今天全 shared-token，每行=`shared-token did it`=合规剧场。须在身份层之后。 |
| misconfig/secret 建模为新 Asset | 它是 **finding 不是 inventory**——建成 Asset 会绕过 correlation/dedup/告警。应扩展 Vulnerability（`source='posture'`），先做确定性低误报的 sshd_config + shadow + SUID 三项。 |
| per-host 身份 + scoped API keys / SIEM STIX 导出 | 正确终局但作为孤立项 mis-scoped（热路径 auth 退化为 stateful 查找；持久 Alert 已丢弃 STIX 所需字段）。应作为一个身份单元统一设计。仅保留 `/export/alerts.csv` 这类真 greenfield 廉价项。 |

---

## 5. 下一步建议

CI1/CI4/CI2/CI3 + CI5 + Q4/Q5/Q6/Q7 均已落地——主链路闭环，攻击面已点亮，检测覆盖/镜像归因补上，API 面纳入
漂移门禁，guard 自我 DoS 默认消除。剩余建议：

- **检测覆盖（剩余速赢）**：仅余 **Q3′ admin 真 partial-failure**（S）。（**Q2 GHSA 接入**需先核实当前 sync 的
  ecosystem 集合：OSV 的 per-ecosystem 导出已内含 GHSA，
  若默认未同步 PyPI/npm 才有缺口，否则降级为配置项。）
- **性能地基**（转型性核心投资）：**CI6 eBPF per-flow 聚合**——用 `LRU_HASH` 按 5-tuple 内核聚合，修高
  pps 静默丢包 + 时间戳正确性（L）。

并行可清掉速赢 Q2 / Q4 / Q5（检测覆盖与正确性），它们彼此独立、合计 S~M，且消灭的多是"保证存在的误报 /
漏判"，给路线图持续可见的质量信号。
