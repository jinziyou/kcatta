# posture-agent（`agent` 统一 CLI）

posture agent 的**统一入口**二进制：把三大能力聚合到单一 `agent` 命令，子命令在进程内分发到
各能力库的 `cli` 模块。三个独立二进制（`posture-host` / `posture-flow` / `posture-guard`）仍是
精简、可单独部署的产物；本二进制是包含三者的「全功能」入口（体积更大，因为链接了全部能力）。

```bash
# 等价于三个独立二进制：
agent host  -r / --malware --pretty        # = posture-host -r / --malware --pretty
agent flow  capture --pretty               # = posture-flow capture --pretty
agent flow  intel-sync --source feodo --out data/feeds/feodo.json
agent guard --stdout                       # = posture-guard --stdout

cargo run -p posture-agent -- host -r / --pretty
cargo run -p posture-agent --features full -- guard --stdout   # 开启 onaccess/network/ids/pcap
```

feature：`pcap`（→ flow/guard 抓包）、`onaccess`、`network`、`ids`、`full`，转发到对应能力 crate。

> agent 的**三种运行方式**：① 三独立二进制各自运行（`posture-host`/`posture-flow`/`posture-guard`，最精简）；
> ② 本统一 `agent` 命令（一个入口跑三能力）；③ 由 fusion 的 `fusion-scan` 远程调度（投放精简独立二进制到目标机）。
