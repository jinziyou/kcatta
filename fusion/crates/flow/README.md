# fusion-flow

posture **网络流域**（外视）的**纯库**：旁路捕获流量元数据，做威胁情报 IOC 初步匹配，产出 [`FlowBatch`](../contract/src/lib.rs)。**只采集、不分析**——命中以 `ThreatMatch` 注入流事件，CVE 判定 / 跨源关联在 **form** 侧完成。

本 crate 不含任何二进制：CLI（`fusion flow` / `fusion intel-sync`）、IOC feed 的 HTTP 下载、以及向 form 上报，全部在编排二进制 `fusion`（[`crates/runtime`](../runtime)）里。flow 库本身只做捕获、匹配、feed 字节解析，因此不依赖 clap / reqwest / ingest，保持网络域库远离 HTTP / 主机依赖面。仅依赖 [`fusion-contract`](../contract)。

## 库 API

```rust
use fusion_flow::{run_capture_with_config, CaptureConfig, ThreatFeed};

// mock 后端 + 内置 demo 情报库（一行跑通端到端）
let batch = fusion_flow::run_capture()?;

// 指定情报库 + 捕获后端
let feed = ThreatFeed::from_json_path("data/feeds/feodo.json")?;
let batch = run_capture_with_config(&feed, &CaptureConfig::mock())?;
```

一次 `run_capture_*` = 捕获 → IOC 匹配 → [`FlowBatch`](../contract/src/lib.rs)，输出对照 `form/schemas-json/FlowBatch.schema.json` 校验（由 [`tests/contract.rs`](./tests/contract.rs) 在 mock 后端上强制）。

要点：

| 单元 | 说明 |
| --- | --- |
| `run_capture()` | mock 后端 + `ThreatFeed::builtin()`，零外部输入产出一批合成流 |
| `run_capture_with_feed(&feed)` | mock 后端 + 指定情报库 |
| `run_capture_with_config(&feed, &cfg)` | 指定情报库 + 捕获后端（mock / pcap） |
| `CaptureConfig::mock()` / `CaptureConfig::pcap(iface, secs, bpf)` | 选捕获后端；`pcap(..)` 需 `pcap` feature |
| `ThreatFeed::builtin()` / `from_json_path` / `from_json_str` | 加载情报库（内置 demo / 磁盘 JSON / 内存字符串） |
| `ThreatFeed::match_flow(&flow)` / `enrich(&mut flows)` | 单流匹配 / 批量原地注入 `threat_intel` |
| `intel::sync::feodo::parse_json(text)` | feed 字节解析器：Feodo JSON → `ThreatFeed`（**只解析，不发请求**） |
| `intel::sync::{merge_feeds, write_feed}` | 多源合并（按 `(type,value)` 去重、取最高 severity）/ 落盘 |

## 模块

| 路径 | 内容 |
| --- | --- |
| `capture/` | 捕获后端：`mock`（合成流，默认）、`pcap`（libpcap 实时，feature `pcap`，含 `parse` 五元组聚合 / DNS / TLS SNI / JA3 解析），统一返回 `Vec<FlowEvent>` |
| `intel/` | `ThreatFeed`：IP / 域名 / JA3 指标匹配（哈希索引），`enrich` 原地注入 `threat_intel` |
| `intel/sync/` | feed 字节解析器（`feodo.rs`）+ `merge_feeds` / `write_feed`；供 `fusion intel-sync` 下载后调用，库内不联网 |
| `contract.rs` | 从 [`fusion-contract`](../contract) 重导出 `FlowBatch` / `FlowEvent` / `ThreatMatch` 等，保留历史 `fusion_flow::contract::*` 路径 |

## 捕获后端

| 后端 | feature | 依赖 | 说明 |
| --- | --- | --- | --- |
| `mock` | 默认 | 无 | 合成 HTTPS / DNS / SSH / ICMP 四类典型流，CI / 离线可跑 |
| `pcap` | `pcap` | libpcap + 通常 root | 实时抓包 + 五元组聚合 + DNS / TLS SNI / JA3 解析 |

```bash
cargo test -p fusion-flow                        # mock 单元 + 契约测试
cargo test -p fusion-flow --features pcap --lib  # 含 pcap parse 单元测试
```

> `pcap` 是 optional feature（`default = []`）：默认 mock 采集路径不牵 libpcap，`CaptureBackend::Pcap` 与 `CaptureConfig::pcap(..)` 仅在 `--features pcap` 下编译。

## 威胁情报匹配

`ThreatFeed::enrich` 对每条流匹配本地 IOC 库：IP（源 / 目的）、JA3（大小写不敏感）、域名（DNS 查询 / TLS SNI，大小写不敏感且父域命中子域，`login.a.evil` 命中 `evil`）。匹配走哈希索引，复杂度随流字段而非指标总数增长。情报库由 `fusion intel-sync` 离线同步，匹配时不联网。

## CLI（在 `fusion` 二进制里）

捕获 / 同步的命令行入口已上移到编排二进制 `fusion`（[`crates/runtime`](../runtime)）。flow 库只被它在进程内调度。

### `fusion flow`：捕获 → IOC 匹配 → `FlowBatch`

```bash
# mock 后端（默认，无需 root / libpcap）
cargo run -p fusion-runtime -- flow --pretty
cargo run -p fusion-runtime -- flow --intel data/feeds/feodo.json --upload http://127.0.0.1:8000

# pcap 实时抓包（需 --features pcap + libpcap + 通常 root）
cargo build -p fusion-runtime --features pcap
sudo cargo run -p fusion-runtime --features pcap -- \
    flow --pcap --iface eth0 --duration 30 --bpf "tcp port 443" --pretty
```

| 参数 | 说明 |
| --- | --- |
| `--pretty` | 美化 JSON（默认紧凑） |
| `-o, --out <FILE>` | 写文件而非 stdout |
| `--intel <PATH>` | IOC 情报库 JSON；省略则用内置 demo feed |
| `--upload <URL>` | 捕获后 POST `<URL>/ingest/flow-batch` |
| `--mock` | 合成流（默认） |
| `--pcap` | libpcap 实时抓包（需 `--features pcap`） |
| `--iface` / `--duration` / `--bpf` | pcap 网卡 / 时长(秒) / BPF 过滤 |
| `--list-devices` | 列出 libpcap 设备并退出（`--features pcap`） |

`--mock` 与 pcap 参数互斥；未启用 `pcap` feature 时传 `--pcap` 会报错提示重建。

### `fusion intel-sync`：下载 IOC feed → 本地 JSON

把远程威胁情报 feed 下载并经库内解析器（`intel::sync`）落为本地 JSON，供 `fusion flow --intel` 离线匹配。同步是独立、可定时（cron / systemd timer）的步骤；采集时只读本地库，匹配不联网。

```bash
# 同步 abuse.ch Feodo Tracker → data/feeds/feodo.json
cargo run -p fusion-runtime -- intel-sync --source feodo --out data/feeds/feodo.json

# 用同步好的库做匹配
cargo run -p fusion-runtime -- flow --intel data/feeds/feodo.json --upload http://127.0.0.1:8000
```

| 参数 | 说明 |
| --- | --- |
| `--source <NAME>` | feed 适配器，可重复（必填）；多源时输出合并 |
| `-o, --out <PATH>` | 输出 JSON |
| `--feodo-url <URL>` | 覆盖 `feodo` 默认下载地址 |
| `--timeout <SEC>` | HTTP 超时秒数 |

| source | 来源 | 映射 |
| --- | --- | --- |
| `feodo` | abuse.ch Feodo Tracker | 每条 IP → `type=ip` / `category=c2` / `severity=high` / `source=abuse.ch-feodo` |

新增情报源：在 [`src/intel/sync/`](./src/intel/sync/) 实现字节解析器（参考 `feodo.rs`），再在 `fusion intel-sync` 的 `--source` 分发里接入。详见 [`../../docs/CONTRIBUTING.md`](../../docs/CONTRIBUTING.md)「新增情报源（网络域）」。

## 上下游

依赖单向：[`fusion-contract`](../contract) ← `fusion-flow` ← [`fusion-runtime`](../runtime)。架构详见 [`../../docs/ARCHITECTURE.md`](../../docs/ARCHITECTURE.md)，整体用法见 [`../../README.md`](../../README.md)。
