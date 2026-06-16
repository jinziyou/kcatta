# agentd（`agentd` 统一 CLI + 编排器）

kcatta agent 的**统一入口**二进制：把三大能力聚合到单一 `agentd` 命令，子命令在进程内分发到
各能力库的 `cli` 模块。三个独立二进制（`agent-host` / `agent-trace` / `agent-guard`）仍是
精简、可单独部署的产物；本二进制是包含三者的「全功能」入口（体积更大，因为链接了全部能力），
并额外提供 `agentd run` 编排守护进程。

**上报（ingest）内置于本 crate**（`src/ingest.rs`）：独立二进制只产出本地结果文件，**从不上报**；
**只有 `agentd <cap> --upload <URL>` 或 `agentd run` 才把结果上报 analyzer**。上报端点为
`/ingest/asset-report`、`/ingest/trace-batch`、`/ingest/guard-event`（均返回 `202 Accepted`），
鉴权用 `ANALYZER_API_TOKEN` bearer，超时由 `ANALYZER_UPLOAD_TIMEOUT` 控制。

## 子命令

`agentd` 共四个子命令：`host` / `trace` / `guard` 在进程内分发到对应能力，`run` 是编排守护进程。

```bash
# 不带 --upload：等价于三个独立二进制（只产出本地结果）
agentd host  -r / --malware --pretty        # = agent-host -r / --malware --pretty
agentd trace capture --pretty               # = agent-trace capture --pretty（网络抓包）
agentd trace capture --ebpf --ebpf-duration 30   # + eBPF：进程 exec/exit + 文件 openat
agentd trace intel-sync --source feodo --out data/feeds/feodo.json
agentd guard --stdout                       # = agent-guard --stdout

# 带 --upload：本地产出 + 上报 analyzer（host/trace 产出后 POST；guard 注入 analyzer sink 实时推送）
agentd host  -r / --malware --upload http://127.0.0.1:10068   # → /ingest/asset-report
agentd trace capture --upload http://127.0.0.1:10068          # → /ingest/trace-batch
agentd guard --upload http://127.0.0.1:10068 --stdout         # → /ingest/guard-event（常驻推送）

cargo run -p agentd --features full -- guard --stdout   # 开启 onaccess/network/ids/pcap
```

feature：`pcap`（→ trace/guard 网络抓包后端）、`onaccess`、`network`、`ids`、`full`，转发到对应能力
crate。eBPF 后端是各能力 crate 自身的 `ebpf` feature（构建期 nightly + bpf-linker、运行期需特权），
opt-in 且不进 musl 部署构建；缺失工具链/权限时优雅回退（trace→pcap/mock，guard→nft）。

## `agentd run`：编排守护进程

`agentd run --config <PATH>`（默认 `/etc/kcatta/agentd.json`）加载一份 JSON `RunConfig` 并常驻运行：

- 每隔 `interval_secs`（默认 300s）调度一次「采集周期」：`host.enabled` 时跑主机静态扫描 →
  `AssetReport`，`trace.enabled` 时跑一次 trace 抓包 → `TraceBatch`，各自 POST 到 analyzer；
- `guard.enabled` 时，guard 在后台线程常驻运行，实时把 `GuardEventBatch` 推送 analyzer
  （复用 `agentd guard --upload` 那条注入 sink 的通道）；
- 优雅停机：捕获 SIGINT / Ctrl-C，置位关停标志后退出；
- 单次周期失败只记录日志、下一 tick 重试 —— 一次坏上报不会拖垮守护进程。

`RunConfig` 示例（`upload_url` 必填，其余有默认值）：

```json
{
  "upload_url": "http://127.0.0.1:10068",
  "interval_secs": 300,
  "host":  { "enabled": true,  "root": "/", "malware": false },
  "trace": { "enabled": true },
  "guard": { "enabled": false, "config_path": "/etc/kcatta/guard.json" }
}
```

> agent 的**三种运行方式**：① 三独立二进制各自运行（最精简、纯本地采集，不上报）；
> ② 本统一 `agentd` 命令（一个入口跑三能力，`--upload` 才上报，或 `agentd run` 按间隔编排调度并统一上报）；
> ③ 由 analyzer 的 `analyzer-scan --capability {host|trace|guard}` 远程调度（host/trace 投精简 bin + 拉回入库；guard 投本 `agentd` 二进制并 `agentd guard --upload` 常驻推送）。
