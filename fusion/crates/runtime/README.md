# fusion-runtime

fusion 的**编排二进制**：唯一入口 `fusion`，通过子命令把各能力域的进程内模块调度起来——主机资产扫描、网络流捕获、IOC 情报同步。本 crate 自身不实现检测逻辑，只负责参数解析、调度与（可选的）上报；具体采集分别落在 [`fusion-host`](../host)、[`fusion-flow`](../flow)，上报落在 [`fusion-ingest`](../ingest)，数据契约见 [`fusion-contract`](../contract)。

> 边界：fusion **只采集**本机/目标机上的检测工具集；CVE 判定与跨源关联在 **form** 侧。**跨机投放/调用/取回**（上传到待测机器、调用 `fusion`、取回结果）由 form 侧的 `form-scan`（Python）负责，不再属于 fusion——`fusion-runtime` 只调度本机/目标机上的进程内模块。

## 二进制 `fusion`

来自本 crate（bin 名 `fusion`），三个子命令：

| 子命令 | 职责 | 域模块 |
| --- | --- | --- |
| `fusion host` | 主机资产扫描（静态资产发现 + 可选 ClamAV 查杀） | [`fusion-host`](../host) |
| `fusion flow` | 网络流捕获 → IOC 匹配 → `FlowBatch` | [`fusion-flow`](../flow) |
| `fusion intel-sync` | 下载 IOC feed → 本地 JSON（供 `fusion flow --intel` 读取） | [`fusion-flow`](../flow) |

### `fusion host`

两种输出模式：

- **分文件（静态）**：`-o DIR` → `host.json` / `packages.json` / `sbom.cyclonedx.json` / `services.json` / `accounts.json` / `credentials.json`（经 `run_static_scan`）；`--malware` 时另写 `malware.json`。
- **合并**：不带 `-o` → 装配 collector 计划成单个 [`AssetReport`](../contract/src/lib.rs)，输出到 stdout（`--pretty`）/ 文件（`--report-out FILE`）/ form（`--upload URL`）；`--malware` 时 ClamAV 命中并入 `vulnerabilities`。

| 旗标 | 说明 |
| --- | --- |
| `-r, --root <PATH>` | 挂载文件系统根（默认 Linux `/`、Windows `%SystemDrive%\`） |
| `-t, --target <T>` | 扫描对象：`host`\|`packages`\|`sbom`\|`services`\|`accounts`\|`credentials`\|`identity`\|`all` |
| `-o, --output <DIR>` | 分文件 JSON 输出目录（选择分文件模式） |
| `--project-root <PATH>` | 语言包额外工程目录（venv / node_modules），可重复 |
| `--windows-packages <full\|apps>` | Windows 软件包范围（`full` 含 CBS 更新，`apps` 跳过 CBS） |
| `--pretty` | 美化打印合并 `AssetReport` 到 stdout（合并模式） |
| `--report-out <FILE>` | 合并 `AssetReport` 写入文件（合并模式） |
| `--upload <URL>` | 合并 `AssetReport` 上报 form（`<URL>/ingest/asset-report`） |
| `--malware` | 追加 ClamAV INSTREAM 查杀（需 `clamd`；`malware` feature） |
| `--malware-jobs <N>` | 并行 ClamAV worker 数（`malware` feature） |
| `--clamd-socket <PATH>` | clamd Unix socket 路径，覆盖自动探测（`malware` feature） |

### `fusion flow`

capture → IOC 匹配 → `FlowBatch`。

| 旗标 | 说明 |
| --- | --- |
| `--pretty` | 美化 JSON 输出（默认紧凑） |
| `-o, --out <FILE>` | JSON 写入文件而非 stdout |
| `--intel <PATH>` | 威胁情报 IOC feed（JSON）；省略时用内置演示 feed |
| `--upload <URL>` | 捕获后上报 form（`<URL>/ingest/flow-batch`） |
| `--mock` | 合成 mock 流量（默认） |
| `--pcap` | libpcap 实时抓包（构建时需 `pcap` feature） |
| `--iface <NAME>` | 抓包网卡（`any`、`eth0`、`lo` …；pcap 模式） |
| `--duration <SEC>` | 抓包时长秒数（pcap 模式） |
| `--bpf <EXPR>` | BPF 过滤表达式（pcap 模式） |
| `--list-devices` | 列出 libpcap 设备后退出（`pcap` feature） |

### `fusion intel-sync`

下载 IOC feed → 本地 JSON。沿用 `form-osv-sync` 的离线刷新模型：sync 是显式、可调度的一步，`fusion flow --intel` 只读盘上的 feed。

| 旗标 | 说明 |
| --- | --- |
| `--source <NAME>` | feed 适配器，可重复，**必填**；多个时输出合并 |
| `-o, --out <PATH>` | 输出 JSON 路径（默认 `data/feeds/<source>.json`，多源时 `merged.json`） |
| `--feodo-url <URL>` | 覆盖 `feodo` 适配器下载 URL |
| `--timeout <SEC>` | HTTP 超时秒数 |

## Feature 门控

各能力域均 feature 门控，使精简构建不链入无关域及其依赖面：

| feature | 作用 |
| --- | --- |
| `default` = `[host, flow]` | 默认启用主机域 + 网络流域 |
| `host` | 启用 `fusion host`，引入 `fusion-host` |
| `flow` | 启用 `fusion flow` / `fusion intel-sync`，引入 `fusion-flow` + `reqwest` |
| `malware` | 在 host 之上追加 ClamAV（`fusion-host/malware`） |
| `pcap` | 在 flow 之上启用 libpcap 实时抓包（`fusion-flow/pcap`） |
| `full` = `[host, flow, malware]` | 全功能 |

**精简主机 agent**：仅做主机扫描时只取 host（+可选 malware），不牵 flow/pcap/HTTP，产物为单一 `fusion` 二进制：

```bash
cargo build -p fusion-runtime --no-default-features --features host,malware \
  --target x86_64-unknown-linux-musl --release
```

## 代表性命令

```bash
# 合并 AssetReport（stdout）
cargo run -p fusion-runtime -- host -r / --pretty
# 分文件 JSON
cargo run -p fusion-runtime -- host -r / -t all -o ./scan-out
# 含 ClamAV 查杀
cargo run -p fusion-runtime --features full -- host -r / --malware --pretty
# 扫描并上报 form
cargo run -p fusion-runtime -- host -r / -t all --upload http://127.0.0.1:8000

# FlowBatch（mock 默认）
cargo run -p fusion-runtime -- flow --pretty
# 带情报 + 上报
cargo run -p fusion-runtime -- flow --intel data/feeds/feodo.json --upload http://127.0.0.1:8000
# 启用实时抓包构建 + 运行
cargo build -p fusion-runtime --features pcap
sudo cargo run -p fusion-runtime --features pcap -- \
  flow --pcap --iface eth0 --duration 30 --bpf "tcp port 443" --pretty

# 同步 IOC 情报库（abuse.ch Feodo）
cargo run -p fusion-runtime -- intel-sync --source feodo --out data/feeds/feodo.json
```

## 依赖

DAG 汇点 [`fusion-contract`](../contract)（数据契约，零内部依赖）↑；本 crate 位于依赖图顶端，无任何 crate 反向依赖它。

| 依赖 | 类型 | 用途 |
| --- | --- | --- |
| [`fusion-contract`](../contract) | 必选 | `AssetReport` / `FlowBatch` 数据契约 |
| [`fusion-ingest`](../ingest) | 必选 | 上报 form（`--upload`） |
| [`fusion-host`](../host) | 可选（`host`） | 主机资产采集与扫描调度（`Collector` / `ScanContext` / `run_scan_at*` / `run_static_scan`） |
| [`fusion-flow`](../flow) | 可选（`flow`） | 流量捕获 + IOC 匹配 + IOC feed 同步适配器 |
| `reqwest` | 可选（随 `flow`） | 阻塞 HTTP 客户端（rustls） |

依赖 DAG（单向无环）：`contract ← ingest`；`contract ← host`；`contract ← flow`；`{contract, ingest, host, flow} ← runtime`。
