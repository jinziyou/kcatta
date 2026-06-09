# posture-flow

posture 的**流量检测**能力：一个 crate = lib（捕获 + IOC 匹配 + feed 解析，被 guard 的 network
传感器复用）+ `posture-flow` 二进制。产出 [`FlowBatch`](../contract/src/lib.rs)。

**只采集、不分析**——IOC 命中以 `ThreatMatch` 注入流事件，CVE 判定 / 跨源关联在 **fusion** 侧。
lib **不含 reqwest**：feed 的 HTTP 下载在 bin 里用 `agent-cli-common::http`，feed 字节解析在
lib 的 `intel::sync`。

## 子命令

- `capture` — 捕获一轮（`mock` 默认 / `pcap` feature 实时）→ IOC 匹配 → `FlowBatch`。
- `intel-sync` — 下载 IOC feed 写本地 JSON，供 `capture --intel` 只读匹配（离线友好）。

## 命令

```bash
cargo run -p posture-flow -- capture --pretty
cargo run -p posture-flow -- capture --intel data/feeds/feodo.json --upload http://127.0.0.1:8000
sudo cargo run -p posture-flow --features pcap -- capture --pcap --iface eth0 --duration 30 --bpf "tcp port 443" --pretty
cargo run -p posture-flow -- intel-sync --source feodo --out data/feeds/feodo.json

cargo test -p posture-flow                        # mock 单元 + 契约测试
cargo test -p posture-flow --features pcap --lib  # 含 pcap parse 单元测试
```

威胁情报 IOC 匹配（IP / 域名父域 / JA3）在 flow 域内完成，命中注入 `FlowEvent.threat_intel`。
契约校验：[`tests/contract.rs`](tests/contract.rs)（`FlowBatch`）。
