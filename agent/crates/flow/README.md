# posture-flow

posture 的**流量检测**能力：一个 crate = lib（捕获 + IOC 匹配 + feed 解析，被 guard 的 network
传感器复用）+ `posture-flow` 二进制。产出 [`FlowBatch`](../contract/src/lib.rs)。

**只采集、不分析、不上报**——`capture` 把 `FlowBatch` 写 stdout/`--out`；IOC 命中以 `ThreatMatch`
注入流事件，CVE 判定 / 跨源关联在 **fusion** 侧；上报由统一 `agent flow --upload` 负责。
lib **不含 reqwest**：`intel-sync` 的 feed HTTP 下载在 bin 的 `cli` 里（本地 `http_get_text`），
feed 字节解析在 lib 的 `intel::sync`。

## 子命令

- `capture` — 捕获一轮（`mock` 默认 / `pcap` feature 实时）→ IOC 匹配 → `FlowBatch`。
- `intel-sync` — 下载 IOC feed 写本地 JSON，供 `capture --intel` 只读匹配（离线友好）。
  feed 的 JSON 格式示例见 [`examples/threat-feed.json`](../../examples/threat-feed.json)。

## 命令

```bash
cargo run -p posture-flow -- capture --pretty                              # 只写文件，不上报
cargo run -p posture-flow -- capture --intel data/feeds/feodo.json --out flow.json
cargo run -p posture-flow -- capture --intel examples/threat-feed.json --pretty   # feed 格式示例
sudo cargo run -p posture-flow --features pcap -- capture --pcap --iface eth0 --duration 30 --bpf "tcp port 443" --pretty
cargo run -p posture-flow -- intel-sync --source feodo --out data/feeds/feodo.json
cargo run -p posture-agent -- flow --upload http://127.0.0.1:8000 capture   # 上报经统一 agent

cargo test -p posture-flow                        # mock 单元 + 契约测试
cargo test -p posture-flow --features pcap --lib  # 含 pcap parse 单元测试
```

威胁情报 IOC 匹配（IP / 域名父域 / JA3）在 flow 域内完成，命中注入 `FlowEvent.threat_intel`。
契约校验：[`tests/contract.rs`](tests/contract.rs)（`FlowBatch`）。
