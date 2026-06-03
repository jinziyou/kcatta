# probe-flow-cli

[`probe-flow`](../probe-flow/README.md) 的命令行驱动（bin: **`probe-flow`**）：跑一轮捕获 → 威胁情报匹配 → 输出 / 上报 [`FlowBatch`](../probe-contract/src/lib.rs)。

## 二进制

```bash
# mock 后端（默认，无需 root / libpcap）
cargo run -p probe-flow-cli -- --pretty
cargo run -p probe-flow-cli -- --intel data/feeds/feodo.json --upload http://127.0.0.1:8000

# pcap 实时抓包（需 --features pcap + libpcap + 通常 root）
cargo build -p probe-flow-cli --features pcap
sudo cargo run -p probe-flow-cli --features pcap -- \
    --pcap --iface eth0 --duration 30 --bpf "tcp port 443" --pretty
```

## 参数

| 参数 | 说明 |
| --- | --- |
| `--pretty` | 美化 JSON（默认紧凑） |
| `-o, --out <PATH>` | 写文件而非 stdout |
| `--intel <PATH>` | IOC 情报库 JSON；省略则用内置 demo feed |
| `--upload <URL>` | 捕获后 POST `<URL>/ingest/flow-batch` |
| `--mock` | 合成流（默认） |
| `--pcap` | libpcap 实时抓包（需 `--features pcap`） |
| `--iface` / `--duration` / `--bpf` | pcap 网卡 / 时长(秒) / BPF 过滤（默认 `any` / `5` / `tcp or udp or icmp`） |
| `--list-devices` | 列出 libpcap 设备并退出（`--features pcap`） |

`--mock` 与 pcap 参数互斥；未启用 `pcap` feature 时传 `--pcap` 会报错提示重建。

## 依赖

`probe-flow`（捕获 + 匹配）+ `probe-ingest`（上报）。情报库同步见 [`probe-intel-sync`](../probe-intel-sync/README.md)，用法速查见 [`../../README.md`](../../README.md)。
