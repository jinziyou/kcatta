# collector

**网络流量采集器 / 威胁情报采集**，cyber-posture 平台的外视引擎。基于 Rust 构建。

## 当前状态（v0）

已落地：

- **数据契约 Rust 镜像**：`collector_core::contract` 对齐 `form/src/form/schemas/` 中的 Pydantic 模型（`FlowEvent` / `FlowBatch` / `FlowProto` / `ThreatMatch` / `Severity` / `IndicatorType`）
- **端到端管道**：`collector-cli` → `run_capture_with_feed()`（抓包 → 威胁情报 IOC 匹配）→ 序列化为 JSON → 写 stdout / 文件 / 直接上报 form
- **威胁情报 IOC 匹配（初步处理）**：`collector_core::intel` 把每条流对照本地 IOC 情报库（恶意 IP / 域名 / JA3 指纹）匹配，命中结果以 `threat_intel` 注入对应 `FlowEvent`
- **情报库自动同步**：`collector-intel-sync` 从 abuse.ch Feodo Tracker 拉取 C2 IP 列表，写入本地 JSON（对齐 `ThreatFeed` 格式）；采集时 `--intel` 读本地库，匹配本身不联网
- **上报客户端**：`collector-ingest` 把 `FlowBatch` HTTP POST 到 form 的 `/ingest/flow-batch`（期望 `202`）
- **跨语言契约验证**（最重要的安全网）：集成测试 `tests/contract.rs` 用 `jsonschema` crate 将 Rust 输出对照 `form/schemas-json/FlowBatch.schema.json` 校验
- **mock 捕获后端**：合成 HTTPS / DNS / SSH / ICMP 四类典型流，覆盖 TCP/UDP/ICMP 协议与 Optional 字段组合
- **pcap 抓包后端**（feature `pcap`）：libpcap 实时抓包 + 五元组聚合 + DNS/TLS SNI/JA3 解析（需系统安装 `libpcap-dev`，通常需 root 或 `CAP_NET_RAW`）

尚未落地：

- 协议解析增强（HTTP 深度字段、双向流量合并）
- 大规模情报库索引（v0 为线性扫描；feed 增大后换哈希索引 / bloom 预筛）
- 更多情报源适配器（OTX、SSLBL/JA3、STIX/TAXII）
- eBPF 后端（aya）

## 仓库形态

Cargo workspace：

```
collector/
├── Cargo.toml                            # workspace root
└── crates/
    ├── collector-core/                   # 库：契约 + 捕获 + 情报匹配 + 调度
    │   ├── src/
    │   │   ├── lib.rs                    # run_capture() / run_capture_with_feed()
    │   │   ├── contract.rs               # FlowEvent / FlowBatch / ThreatMatch / ...
    │   │   ├── capture/
    │   │   │   ├── mod.rs                # CaptureConfig / 后端调度
    │   │   │   ├── mock.rs               # mock 生成 4 个典型流
    │   │   │   ├── parse.rs              # 以太网/IP/TCP/UDP 解析 + DNS/SNI/JA3
    │   │   │   └── pcap.rs               # libpcap 抓包 + 五元组聚合（feature pcap）
    │   │   └── intel/
    │   │       ├── mod.rs                # ThreatFeed：IOC 加载 + 匹配
    │   │       └── sync/                 # 远程 feed 下载适配器
    │   │           ├── mod.rs
    │   │           └── feodo.rs          # abuse.ch Feodo Tracker
    │   └── tests/contract.rs             # JSON Schema 跨语言对照
    ├── collector-intel-sync/             # 可执行：拉取 IOC feed → 本地 JSON
    │   └── src/main.rs
    ├── collector-ingest/                 # 库：上报客户端（POST FlowBatch → form）
    │   └── src/lib.rs
    └── collector-cli/                    # 可执行入口（--intel / --upload）
        └── src/main.rs

examples/threat-feed.json                 # IOC 情报库示例（--intel 用）
```

## 构建 & 测试

```bash
cd collector

cargo build --workspace
cargo test  --workspace                                # 含跨语言契约验证（mock 后端）
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all

# 启用 pcap 抓包（需 libpcap-dev，Debian/Ubuntu: apt install libpcap-dev）
cargo build -p collector-cli --features pcap
cargo test -p collector-core --features pcap --lib     # 含 parse 单元测试

# 同步威胁情报库（需联网；落盘默认 data/feeds/，已被顶层 .gitignore 忽略）
cargo run -p collector-intel-sync -- --source feodo
cargo run -p collector-intel-sync -- --source feodo --out data/feeds/feodo.json
```

## 跑一次捕获

**Mock（默认，无需 root / libpcap）**

```bash
cargo run -p collector-cli -- --pretty                  # 彩印 JSON 到 stdout（内置 demo 情报库）
cargo run -p collector-cli -- --out /tmp/batch.json     # 写入文件
cargo run -p collector-cli -- --intel examples/threat-feed.json --pretty   # 用外部 IOC 情报库
cargo run -p collector-cli -- --upload http://127.0.0.1:8000               # 抓包 + 匹配 + 上报 form
```

**Pcap 实时抓包（需 `--features pcap` + libpcap + 通常 root）**

```bash
# 编译
cargo build -p collector-cli --features pcap

# 列出可用网卡
cargo run -p collector-cli --features pcap -- --list-devices

# 在 loopback 上抓 10 秒，再上报 form
sudo cargo run -p collector-cli --features pcap -- --pcap --iface lo --duration 10 \
  --upload http://127.0.0.1:8000

# 指定 BPF 过滤（只抓 443）
sudo cargo run -p collector-cli --features pcap -- --pcap --iface eth0 --duration 30 \
  --bpf "tcp port 443" --pretty
```

| 参数 | 作用 |
| --- | --- |
| `--mock` | 使用 mock 合成流（默认） |
| `--pcap` | 使用 libpcap 实时抓包（需编译 feature `pcap`） |
| `--iface <NAME>` | pcap：网卡名（`any` / `lo` / `eth0` …，默认 `any`） |
| `--duration <SEC>` | pcap：抓包时长秒数（默认 5） |
| `--bpf <EXPR>` | pcap：BPF 过滤器（默认 `tcp or udp or icmp`） |
| `--list-devices` | pcap：列出 libpcap 可见网卡并退出 |
| `--intel <PATH>` | 指定 JSON 格式的 IOC 情报库；省略时用内置 demo 库 |
| `--upload <URL>` | 抓包后把 `FlowBatch` POST 到 `<URL>/ingest/flow-batch` |
| `--out <PATH>` | 把 JSON 写入文件而非 stdout |
| `--pretty` | 彩印（缩进）JSON |

输出形如：

```json
{
  "batch_id": "batch-<uuid>",
  "collected_at": "2026-05-28T...Z",
  "collector_id": "collector-<uuid>",
  "collector_version": "0.1.0",
  "flows": [
    { "flow_id": "...", "proto": "tcp",  "src_ip": "10.0.0.42", "dst_ip": "93.184.216.34", "dst_port": 443, "tls_sni": "example.com", "ja3": "...",
      "threat_intel": [ { "indicator": "93.184.216.34", "indicator_type": "ip", "category": "c2", "severity": "high", "source": "builtin-demo" } ] },
    { "flow_id": "...", "proto": "udp",  "dst_port": 53,        "dns_query": "example.com", "threat_intel": [], ... },
    { "flow_id": "...", "proto": "tcp",  "src_port": 40000,     "dst_port": 22, "app_proto": "SSH", "threat_intel": [], ... },
    { "flow_id": "...", "proto": "icmp", "src_port": null,      "dst_port": null, "threat_intel": [], ... }
  ]
}
```

## pcap 抓包原理（feature `pcap`）

1. **打开网卡**：`Capture::from_device()`，promisc 模式，snaplen 65535。
2. **BPF 过滤**：默认 `tcp or udp or icmp`，可用 `--bpf` 自定义（如 `tcp port 443`）。
3. **读包循环**：在 `--duration` 指定的时间窗内循环 `next_packet()`。
4. **解析**：`capture/parse.rs` 从以太网帧提取 IPv4/IPv6 五元组、IP 总长度，并从 payload 解析 DNS 查询名、TLS ClientHello 的 SNI 与 JA3。
5. **聚合**：按 `(proto, src_ip, dst_ip, src_port, dst_port)` 合并为一条 `FlowEvent`，累计 `bytes_sent` / `packets_sent`。
6. **后续**：与 mock 相同——IOC 匹配 → 序列化 / 上报 form。

## 威胁情报 IOC 匹配（初步处理）

`collector_core::intel::ThreatFeed` 把抓到的每条流对照一份本地 IOC 情报库匹配，命中
结果作为 `ThreatMatch` 列表写入对应 `FlowEvent.threat_intel`——这就是 collector 侧的
**初步处理**：在上报前先把「线上观测」与「已知恶意」关联起来，form 拿到后直接据此
做告警关联，无需重复查表。

支持三类指标（`type`）：

| type | 匹配对象 | 规则 |
| --- | --- | --- |
| `ip` | `src_ip` / `dst_ip` | 精确相等 |
| `domain` | `dns_query` / `tls_sni` | 大小写不敏感；指标为父域时命中子域（`a.b.evil` 命中 `evil`） |
| `ja3` | `ja3` | 大小写不敏感的十六进制相等 |

情报库 JSON 格式（见 `examples/threat-feed.json`）：

```json
{
  "source": "example-feed",
  "indicators": [
    { "type": "ip",     "value": "93.184.216.34", "category": "c2",       "severity": "high"   },
    { "type": "domain", "value": "example.com",    "category": "phishing", "severity": "medium" },
    { "type": "ja3",    "value": "e7d705a3...",    "category": "malware",  "severity": "high", "source": "abuse.ch-ja3" }
  ]
}
```

- `category` 自由文本（`c2` / `malware` / `phishing` / `tor-exit` / `scanner` ...）。
- `severity` 取 `info|low|medium|high|critical`，与 form `Severity` 对齐。
- `source` 可在单条指标上覆盖，缺省继承顶层 `source`。
- `value` 加载时统一去空格 + 转小写。

## 情报库自动同步（collector-intel-sync）

与 form 的 `form-osv-sync` 同样采用 **离线友好** 模型：同步是独立的、可定时执行的步骤；`collector-cli` 匹配时只读本地 JSON，不依赖外网。

```bash
# 拉取 abuse.ch Feodo Tracker C2 IP 列表
cargo run -p collector-intel-sync -- --source feodo

# 指定输出路径
cargo run -p collector-intel-sync -- --source feodo --out data/feeds/feodo.json

# 采集时使用同步后的库（不联网）
cargo run -p collector-cli -- --intel data/feeds/feodo.json --upload http://127.0.0.1:8000
```

| 参数 | 说明 |
| --- | --- |
| `--source feodo` | 适配器名称（可重复；多源时合并写入 `--out` 或默认 `data/feeds/merged.json`） |
| `--out <PATH>` | 输出 JSON；单源默认 `data/feeds/<source>.json` |
| `--feodo-url <URL>` | 覆盖 Feodo 下载地址（默认官方 `ipblocklist.json`） |
| `--timeout <SEC>` | HTTP 超时（默认 120） |

Feodo 每条 IP 映射为：`type=ip`、`category=c2`、`severity=high`、`source=abuse.ch-feodo`，`description` 含 malware/status/last_online。

生产环境建议 cron 定期执行 sync，采集节点始终 `--intel` 指向上一份成功落盘的 feed。

## 数据契约约定

- **源头**：所有类型的语义和字段以 `form/src/form/schemas/` 的 Pydantic 模型为准。
- **派生**：跨语言消费的标准是 `form/schemas-json/FlowBatch.schema.json`。
- **Rust 镜像**：`collector_core::contract` 手写——v0 类型少，自动生成器（typify）的复杂度不划算。
- **保护机制**：CI / 本地都跑 `cargo test`，集成测试会用 `jsonschema` 校验真实 `run_capture()` 输出。
- **新增字段流程**：
  1. 在 Python 端 Pydantic 模型加字段
  2. `form-export-schemas` 重新生成 JSON Schema
  3. 在 `collector_core::contract` 加对应 Rust 字段
  4. `cargo test` 验证

## 计划中的下一步

按 ROI：

1. **双向流量合并**：把 request/response 合并到同一条 `FlowEvent` 的 `bytes_recv`
2. **HTTP 深度解析**：从 payload 提取 Host / URI 等
3. **更多情报源**：OTX、abuse.ch SSLBL（JA3）、STIX/TAXII 适配器
4. **eBPF 后端**：使用 aya 在更低开销下抓取并聚合
