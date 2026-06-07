# fusion-flow

posture **网络域**采集库（外视）：旁路捕获流量元数据，做威胁情报 IOC 初步匹配，产出 [`FlowBatch`](../fusion-contract/src/lib.rs)。**只采集、不分析**——命中以 `ThreatMatch` 注入流事件，form 据此做告警关联。

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
| `intel/sync/` | feed 适配器（`feodo.rs`）→ 本地 IOC JSON，供 `fusion-intel-sync` 调用 |
| `contract.rs` | 从 `fusion-contract` 重导出 `FlowBatch` / `FlowEvent` / `ThreatMatch` 等 |

## 捕获后端

| 后端 | feature | 依赖 | 说明 |
| --- | --- | --- | --- |
| `mock` | 默认 | 无 | 合成 HTTPS / DNS / SSH / ICMP 四类典型流，CI / 离线可跑 |
| `pcap` | `pcap` | libpcap + 通常 root | 实时抓包 + 五元组聚合 + DNS / TLS SNI / JA3 解析 |

```bash
cargo test -p fusion-flow                        # mock 单元 + 契约测试
cargo test -p fusion-flow --features pcap --lib  # 含 pcap parse 单元测试
```

## 威胁情报匹配

`ThreatFeed::enrich` 对每条流匹配本地 IOC 库；域名匹配大小写不敏感且父域命中子域（`a.b.evil` 命中 `evil`）。情报库由 `fusion-intel-sync` 离线同步，匹配时不联网。

## 下游

CLI 封装见 [`fusion-flow-cli`](../fusion-flow-cli/README.md)，情报同步见 [`fusion-intel-sync`](../fusion-intel-sync/README.md)。架构详见 [`../../docs/ARCHITECTURE.md`](../../docs/ARCHITECTURE.md)。
