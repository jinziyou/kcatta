# agentd（`agentd` 统一 CLI + 编排器）

kcatta agent 的**统一入口**二进制：把三大能力聚合到单一 `agentd` 命令，子命令在进程内分发到
各能力库的 `cli` 模块。三个独立二进制（`agent-collect-host` / `agent-collect-trace` / `agent-respond`）仍是
精简、可单独部署的产物；本二进制是包含三者的「全功能」入口（体积更大，因为链接了全部能力），
并额外提供 `agentd run` 编排守护进程。

`agentd` 与各能力 CLI 是 composition/control plane：选择 Source、串接 detect、组装 envelope、
输出或上报；它们不是 `filesystem` / `network` / `ebpf` 并列的信息来源。现有子命令、参数与
`AssetReport` / `TraceBatch` / `GuardEventBatch` wire 保持不变。

**上报（ingest）内置于本 crate**（`src/ingest.rs`）：独立二进制只产出本地结果文件，**从不上报**；
**只有 `agentd <cap> --upload <URL>` 或 `agentd run` 才把结果上报 Form**。上报端点为
`/ingest/asset-report`、`/ingest/trace-batch`、`/ingest/guard-event`（均返回 `202 Accepted`）。
新部署应访问 Form 专用 `:10443` listener 并使用 per-Agent mTLS，不需要 bearer；
`FORM_AGENT_TOKEN` / `FORM_INGEST_TOKEN` 的优先级只用于 bearer 兼容集成和 mixed/legacy 迁移。
超时由 `FORM_UPLOAD_TIMEOUT` 控制。Agent 不直接连接 analyzer，也不能通过 Agent listener
访问 Form 的 control/query API。

可通过下面三个变量启用 Agent 独立 mTLS 身份；它们必须全部配置或全部不配置，部分配置会令本轮
上报 fail-closed：

| 变量 | 内容 |
| --- | --- |
| `FORM_AGENT_CERT` | Agent 客户端证书 PEM 路径；可包含 leaf 后的中间证书链 |
| `FORM_AGENT_KEY` | 与客户端证书匹配的私钥 PEM 路径；建议使用 PKCS#8 |
| `FORM_AGENT_CA` | 验证 Form 服务端证书的私有 CA PEM bundle 路径 |
| `FORM_AGENT_TOKEN` | 可选 bearer 兼容值；若非空则优先于旧 `FORM_INGEST_TOKEN`，专用 mTLS listener 不需要 |

mTLS 身份模式只允许绝对 `https://` Form URL，并且只信任 `FORM_AGENT_CA` 中显式配置的根证书，
不回退系统/内置公开根。ingest POST 在所有模式下均不跟随重定向，避免请求体、bearer 或客户端身份
被重放到另一个目标。驻留进程在每个上传周期重新读取证书、私钥和 CA；内容 generation 未变化时
继续复用 reqwest 连接池，变化且新组合成功构建后原子切换 client，因此证书轮换无需重启 Guard。
若轮换期间读到不完整或不匹配的组合，本轮上报失败但不会用它覆盖已缓存的有效 client。
Form 托管投放会把一次性 bundle 通过已认证 SFTP 安装到这些路径；当前 MVP 的 leaf 私钥由
Form 在内存生成且 Form 不持久化。CSR/TPM-backed 端点本地密钥留作后续能力。

上传失败会进入私有、持久化 FIFO spool。Linux 优先使用显式 `FORM_SPOOL_DIR`、
`/var/lib/kcatta/agentd/spool`，最后才使用带有效 UID 的私有临时目录；目录/文件分别强制
`0700`/`0600`，拒绝符号链接、错误 owner 或宽权限预创建路径。队列和 dead-letter 都有界：

Windows/non-Unix 当前 fail-closed 禁用磁盘 spool：系统服务临时目录可能共享，而标准库无法验证
owner-only DACL 与所有 junction/reparse-point 祖先。Guard 仍由后台 uploader 通过有界内存队列和
`FORM_UPLOAD_RETRIES` 执行 live POST；队列满时非阻塞地拒绝该 Form 投递并输出带累计计数的显著错误
（其他本地 audit sink 成功时不会承诺为 Form 重缓冲）。正常停机最多对一个 pending live batch 做一次
受 `FORM_UPLOAD_TIMEOUT` 约束的最终尝试，并报告剩余丢弃数。待实现专用 Windows DACL backend 后再
启用持久化；官方 WinRM host collector 不依赖 `agentd` spool。

升级时会检查旧 `ANALYZER_SPOOL_DIR` 与旧共享 temp 目录：仅当完整目录树均为当前 effective UID
所有、无 symlink、文件 `nlink=1` 且 group/world 不可写时，才一次性收紧为 `0700`/`0600` 并
继续 replay；否则只输出一次显著拒绝告警，绝不放宽接纳。旧 `ANALYZER_SPOOL_MAX_BYTES` 仅作为
deprecated fallback 读取，建议迁移到对应 `FORM_*` 变量。

| 变量 | 默认值 | 含义 |
| --- | ---: | --- |
| `FORM_SPOOL_MAX_BYTES` | `67108864` | 活跃待上传队列字节上限，超限淘汰最旧项 |
| `FORM_SPOOL_DEADLETTER_MAX_BYTES` | `67108864` | dead-letter 总字节上限（含 reason sidecar） |
| `FORM_SPOOL_DEADLETTER_MAX_ITEMS` | `1024` | dead-letter 条数上限 |
| `FORM_SPOOL_DEADLETTER_RETENTION_SECS` | `2592000` | dead-letter 最长保留时间（30 天） |

Form 返回 408（请求体读取超时）、429 或 5xx 时均按瞬态错误重试/入 spool。401/403 视为
`auth-blocked`：停止本轮 FIFO drain、保留原 spool item，新 payload 在有安全 spool 时也入队，等待
token 或证书轮换后重放，绝不进入 dead-letter。400/413/422 等不可由凭据轮换修复的契约错误仍是
永久失败，spool replay 时进入 dead-letter。

## 子命令

`agentd` 共四个子命令：`collect-host` / `collect-trace` / `respond` / `run`（兼容别名 `host` / `trace` / `guard`）。

```bash
# 不带 --upload：等价于三个独立二进制（只产出本地结果）
agentd collect-host  -r / --malware --pretty        # = agent-collect-host -r / --malware --pretty
agentd collect-trace capture --pretty               # = agent-collect-trace capture --pretty（网络抓包）
agentd collect-trace capture --ebpf --ebpf-duration 30   # + eBPF：进程 exec/exit + 文件 openat
agentd collect-trace intel-sync --source feodo --out data/feeds/feodo.json
agentd respond --stdout                       # = agent-respond --stdout

# 带 --upload：本地产出 + 上报 Form（collect-host/collect-trace 产出后 POST；respond 注入 Form sink 实时推送）
agentd collect-host  -r / --malware --upload https://agents.example:10443   # → /ingest/asset-report
agentd collect-trace capture --upload https://agents.example:10443          # → /ingest/trace-batch
agentd respond --upload https://agents.example:10443 --stdout               # → /ingest/guard-event（常驻推送）

cargo run -p agentd --features full -- respond --stdout   # 开启 onaccess/network/ids/pcap
```

feature：`pcap`（→ collect-trace / respond 网络抓包后端）、`winnet`（→ collect-trace 连接表）、
`onaccess`、`network`、`ids`、`full`，转发到对应能力
crate。eBPF 后端是各能力 crate 自身的 `ebpf` feature（构建期 nightly + bpf-linker、运行期需特权），
opt-in 且不进 musl 部署构建。文件/进程 `--ebpf` 加载失败会返回错误；network `--net-ebpf`
仅在编入 pcap 时回退真实 pcap，否则报错；respond netblock 加载/执行失败回退 nft。Respond 的
`network` feature 自带真实 winnet/连接表后端，无 pcap 时也不会使用 mock。

## `agentd run`：编排守护进程

`agentd run --config <PATH>`（默认 `/etc/kcatta/agentd.json`）加载一份 JSON `RunConfig` 并常驻运行：

- 每隔 `interval_secs`（默认 300s）调度一次 SOC 周期：host 显式执行
  `default_sources/run_scan_at_with_opts`（collect）→ `agent_detect::host::detect`（detect）→ 合并
  `AssetReport`；trace 同样显式执行 source capture（collect）→ 可选 `trace.intel` feed enrich
  （detect）→ `TraceBatch`，再各自 POST analyzer；未配置 feed 时保持原始 collect 事实；
- `guard.enabled` 时，respond 在后台线程常驻运行，实时把 `GuardEventBatch` 推送 Form
  （复用 `agentd respond --upload` 那条注入 sink 的通道）；Collect/Detect 周期与 Respond 通过
  `Supervisor::run_with_shutdown` 共用同一个 shutdown token；
- Respond 提前退出会置停整个 SOC 循环，不再留下只有周期采集仍运行的半失效进程；
- 优雅停机：捕获 SIGINT / SIGTERM / Ctrl-C 后置位共享 token，停止并 join sensors，最终 drain/report；
  Guard batch 已先写 durable FIFO outbox，join uploader 后只做一次有界发送尝试，其余留待下次启动；
- 单次周期失败只记录日志、下一 tick 重试 —— 一次坏上报不会拖垮守护进程。

`RunConfig` 示例（`upload_url` 必须是绝对 HTTP(S) URL；启用 Agent TLS 身份后必须是 HTTPS；
`interval_secs` 必须大于 0）：

```json
{
  "upload_url": "https://agents.example:10443",
  "interval_secs": 300,
  "host":  { "enabled": true,  "root": "/", "malware": false },
  "trace": { "enabled": true, "backend": "mock", "intel": null },
  "guard": { "enabled": false, "config_path": "/etc/kcatta/guard.json" }
}
```

`trace.backend` 可为 `mock` / `pcap` / `ebpf` / `winnet`；后三者需对应 build feature，缺 feature
会令本轮失败而不是改成 mock。eBPF network 运行时加载失败仅在编入 pcap 时回退真实 pcap，
否则失败。`trace.intel` 是可选本地 IOC JSON；缺省不 enrich。这里配置的是 `NetworkSource`，
不是文件/进程 `EbpfSource`。

> agent 的**三种运行方式**：① 三独立二进制各自运行（最精简、纯本地运行，不上报）；
> ② 本统一 `agentd` 命令（一个入口跑三能力，`--upload` 才上报，或 `agentd run` 按间隔编排调度并统一上报）；
> ③ 由 Form 的 `form-scan --capability {host|trace|guard}` / worker 远程调度（host/trace 投精简 bin + 拉回后经 Form 入库；guard 投本 `agentd` 二进制并 `agentd respond --upload <form-url>` 常驻推送）。

核心 collect API 不产生 finding；但独立 CLI 与 collect crate 中保留的兼容 façade 仍可组合 detect，
所以 Cargo 依赖图不承诺 `collect-*` 对 `agent-detect` 完全零依赖。阶段边界以 Source 输出与显式调用
顺序为准，而不是以二进制/package 边界推断。
