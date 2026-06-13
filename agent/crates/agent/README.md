# agent（`agent` 统一 CLI）

kcatta agent 的**统一入口**二进制：把三大能力聚合到单一 `agent` 命令，子命令在进程内分发到
各能力库的 `cli` 模块。三个独立二进制（`agent-host` / `agent-flow` / `agent-guard`）仍是
精简、可单独部署的产物；本二进制是包含三者的「全功能」入口（体积更大，因为链接了全部能力）。

**上报（ingest）内置于本 crate**（`src/ingest.rs`）：独立二进制只产出本地结果文件，**从不上报**；
**只有 `agent <cap> --upload <URL>` 才把结果上报 fusion**。

```bash
# 不带 --upload：等价于三个独立二进制（只产出本地结果）
agent host  -r / --malware --pretty        # = agent-host -r / --malware --pretty
agent flow  capture --pretty               # = agent-flow capture --pretty
agent flow  intel-sync --source feodo --out data/feeds/feodo.json
agent guard --stdout                       # = agent-guard --stdout

# 带 --upload：本地产出 + 上报 fusion（host/flow 产出后 POST；guard 注入 fusion sink 实时推送）
agent host  -r / --malware --upload http://127.0.0.1:8000   # → /ingest/asset-report
agent flow  capture --upload http://127.0.0.1:8000          # → /ingest/flow-batch
agent guard --upload http://127.0.0.1:8000 --stdout         # → /ingest/guard-event（常驻推送）

cargo run -p agent --features full -- guard --stdout   # 开启 onaccess/network/ids/pcap
```

feature：`pcap`（→ flow/guard 抓包）、`onaccess`、`network`、`ids`、`full`，转发到对应能力 crate。

> agent 的**三种运行方式**：① 三独立二进制各自运行（最精简、纯本地采集，不上报）；
> ② 本统一 `agent` 命令（一个入口跑三能力，`--upload` 才上报）；
> ③ 由 fusion 的 `fusion-scan --capability {host|flow|guard}` 远程调度（host/flow 投精简 bin + 拉回入库；guard 投本 `agent` 二进制并 `agent guard --upload` 常驻推送）。
