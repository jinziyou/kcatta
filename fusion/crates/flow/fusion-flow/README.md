# fusion-flow

posture **网络域**（外视）：旁路捕获流量元数据，做威胁情报 IOC 初步匹配，产出 [`FlowBatch`](../../fusion-contract/src/lib.rs)。**只采集、不分析**——命中以 `ThreatMatch` 注入流事件，form 据此做告警关联。

一个 crate 同时提供库 + 两个二进制：

| 单元 | 类型 | 职责 |
| --- | --- | --- |
| `fusion-flow` | 库 | 捕获后端（mock / pcap）+ `ThreatFeed` IOC 匹配 |
| `fusion-flow` | bin（默认 `default-run`） | 采集 CLI：捕获 → 匹配 → 输出 / 上报 `FlowBatch` |
| `fusion-intel-sync` | bin | 离线拉取远程 IOC feed → 本地 JSON |

## 库 API

```rust
use fusion_flow::{run_capture_with_config, CaptureConfig, ThreatFeed};

// mock 后端 + 内置 demo 情报库
let batch = fusion_flow::run_capture()?;

// 指定情报库 + 捕获后端
let feed = ThreatFeed::from_json_path("data/feeds/feodo.json")?;
let batch = run_capture_with_config(&feed, &CaptureConfig::mock())?;
```

一次 `run_capture_*` = 捕获 → IOC 匹配 → `FlowBatch`，输出对照 `form/schemas-json/FlowBatch.schema.json` 校验。

## 模块

| 路径 | 内容 |
| --- | --- |
| `capture/` | 捕获后端：`mock`（合成流，默认）、`pcap`（libpcap 实时，feature `pcap`），统一返回 `Vec<FlowEvent>` |
| `intel/` | `ThreatFeed`：IP / 域名 / JA3 指标匹配，`enrich` 注入 `threat_intel` |
| `intel/sync/` | feed 适配器（`feodo.rs`）→ 本地 IOC JSON，供 `fusion-intel-sync` bin 调用 |
| `contract.rs` | 从 `fusion-contract` 重导出 `FlowBatch` / `FlowEvent` / `ThreatMatch` 等 |
| `bin/fusion-flow.rs` | 采集 CLI（见下） |
| `bin/fusion-intel-sync.rs` | 情报同步（见下） |

## 捕获后端

| 后端 | feature | 依赖 | 说明 |
| --- | --- | --- | --- |
| `mock` | 默认 | 无 | 合成 HTTPS / DNS / SSH / ICMP 四类典型流，CI / 离线可跑 |
| `pcap` | `pcap` | libpcap + 通常 root | 实时抓包 + 五元组聚合 + DNS / TLS SNI / JA3 解析 |

```bash
cargo test -p fusion-flow                        # mock 单元 + 契约测试
cargo test -p fusion-flow --features pcap --lib  # 含 pcap parse 单元测试
```

> 情报同步的 HTTP 下载在 `fusion-intel-sync` bin 内，库模块（`intel::sync` 适配器）只解析字节、不发请求；`pcap` 是 optional feature，默认 mock 采集路径不牵 libpcap。

## 威胁情报匹配

`ThreatFeed::enrich` 对每条流匹配本地 IOC 库；域名匹配大小写不敏感且父域命中子域（`a.b.evil` 命中 `evil`）。情报库由 `fusion-intel-sync` 离线同步，匹配时不联网。

## 采集 CLI（bin: `fusion-flow`）

跑一轮捕获 → 威胁情报匹配 → 输出 / 上报 `FlowBatch`。

```bash
# mock 后端（默认，无需 root / libpcap）
cargo run -p fusion-flow -- --pretty
cargo run -p fusion-flow -- --intel data/feeds/feodo.json --upload http://127.0.0.1:8000

# pcap 实时抓包（需 --features pcap + libpcap + 通常 root）
cargo build -p fusion-flow --features pcap
sudo cargo run -p fusion-flow --features pcap -- \
    --pcap --iface eth0 --duration 30 --bpf "tcp port 443" --pretty
```

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

## 情报同步（bin: `fusion-intel-sync`）

把远程威胁情报 IOC feed 下载为本地 JSON，供采集 CLI `--intel` 离线匹配。与 form 的 `form-osv-sync` 一样**离线友好**：同步是独立、可定时（cron / systemd timer）的步骤；采集时只读本地库，匹配不联网。

```bash
# 同步 abuse.ch Feodo Tracker → data/feeds/feodo.json
cargo run -p fusion-flow --bin fusion-intel-sync -- --source feodo --out data/feeds/feodo.json

# 用同步好的库做匹配
cargo run -p fusion-flow -- --intel data/feeds/feodo.json --upload http://127.0.0.1:8000
```

| 参数 | 说明 |
| --- | --- |
| `--source <NAME>` | feed 适配器，可重复；多源时输出合并。当前支持：`feodo` |
| `-o, --out <PATH>` | 输出 JSON（默认 `data/feeds/<source>.json`，多源为 `data/feeds/merged.json`） |
| `--feodo-url <URL>` | 覆盖 `feodo` 默认下载地址 |
| `--timeout <SEC>` | HTTP 超时秒数（默认 120） |

| source | 来源 | 映射 |
| --- | --- | --- |
| `feodo` | abuse.ch Feodo Tracker | 每条 IP → `type=ip` / `category=c2` / `severity=high` / `source=abuse.ch-feodo` |

新增情报源：在 [`src/intel/sync/`](./src/intel/sync/) 实现适配器（参考 `feodo.rs`），再接入 `--source` 分发。详见 [`../../../docs/CONTRIBUTING.md`](../../../docs/CONTRIBUTING.md)「新增情报源（网络域）」。

## 上下游

架构详见 [`../../../docs/ARCHITECTURE.md`](../../../docs/ARCHITECTURE.md)，整体用法见 [`../../../README.md`](../../../README.md)。
