# fusion workspace crates

Rust workspace 成员索引。架构说明见 [`../docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md)，使用指南见 [`../README.md`](../README.md)。

5 个**扁平** crate，全部位于 `crates/` 下，每个目录就是一个 crate（不再有 `host/runtime/` 这种目录套子 crate 的嵌套结构）。唯一二进制 `fusion` 由 `fusion-runtime` 产出，通过子命令调度各域模块。

## Crate 列表

| 域 | 目录 | 包名 | 说明 | 文档 |
| --- | --- | --- | --- | --- |
| 底座 | `contract/` | `fusion-contract` | 数据契约（form `schemas-json` 的 Rust 镜像）：`AssetReport` + `FlowBatch` + 共享 `Severity`。零内部依赖（DAG 汇点）。 | [README](./contract/README.md) |
| ingest | `ingest/` | `fusion-ingest` | 阻塞式 HTTP 上报客户端 → form：`upload_report`（`AssetReport`→`/ingest/asset-report`）、`upload_batch`（`FlowBatch`→`/ingest/flow-batch`），带 `FORM_API_TOKEN` Bearer，202 视为成功。 | [README](./ingest/README.md) |
| host | `host/` | `fusion-host` | 全部主机检测（纯库）：静态资产发现（packages/services/accounts/credentials/SBOM/platform/walk/sources）+ 主机域调度抽象（`Collector` trait、`ScanContext`、`CollectorOutput`、`WindowsPackageProfile`、`run_scan`/`run_scan_at*`）+ ClamAV INSTREAM 查杀（`malware` feature 下的 `MalwareCollector`）。 | [README](./host/README.md) |
| flow | `flow/` | `fusion-flow` | 网络流域纯库：`capture`（默认 mock / `pcap` feature 实时）+ 威胁情报 IOC 匹配（`ThreatFeed`）+ IOC feed 字节解析器（`intel::sync::feodo`）。不含 CLI/HTTP/ingest。 | [README](./flow/README.md) |
| runtime | `runtime/` | `fusion-runtime` | `fusion` 编排二进制：通过子命令调度各域模块。 | [README](./runtime/README.md) |

## 分层与依赖（单向、无环）

```
底座:   fusion-contract        (数据契约: AssetReport + FlowBatch + Severity, 零内部依赖, DAG 汇点)

         fusion-contract ◄── fusion-ingest    (POST AssetReport / FlowBatch → form)
         fusion-contract ◄── fusion-host      (全部主机检测; Collector / ScanContext / ClamAV)
         fusion-contract ◄── fusion-flow      (capture + IOC 匹配 + intel feed 解析)

编排:   {contract, ingest, host, flow} ◄── fusion-runtime   (bin: fusion，子命令调度各域)
```

> 单向无环：`contract ← ingest`、`contract ← host`、`contract ← flow`，再由 `runtime` 汇聚四者。`host` / `flow` 在 `fusion-runtime` 中按 feature 可选——精简的主机 agent 构建（`--features host,malware`）不会牵入网络抓包 / libpcap 依赖。

## Feature 速查

- `fusion-host`：`default=[]`；`malware=[]`（启用 ClamAV `MalwareCollector`）。
- `fusion-flow`：`default=[]`；`pcap`（实时抓包，否则 mock）。
- `fusion-runtime`：`default=[host,flow]`；`host`；`flow`；`malware`→`host/malware`；`pcap`→`flow/pcap`；`full=[host,flow,malware]`。

## 常用命令

唯一二进制 `fusion`（`fusion-runtime`），三个子命令：`host` / `flow` / `intel-sync`。

```bash
# 全 workspace 测试
cargo test --workspace

# —— host 子命令（主机资产扫描 → AssetReport）——
# 合并 AssetReport 到 stdout
cargo run -p fusion-runtime -- host -r / --pretty
# 分文件 JSON（host.json / packages.json / sbom.cyclonedx.json / services.json / accounts.json / credentials.json）
cargo run -p fusion-runtime -- host -r / -t all -o ./scan-out
# 含 ClamAV 查杀（合并模式 → 并入 vulnerabilities）
cargo run -p fusion-runtime --features full -- host -r / --malware --pretty
# 扫描并上报到 form
cargo run -p fusion-runtime -- host -r / -t all --upload http://127.0.0.1:8000

# —— flow 子命令（capture → IOC 匹配 → FlowBatch）——
# mock 默认
cargo run -p fusion-runtime -- flow --pretty
# 加载 IOC 情报并上报到 form
cargo run -p fusion-runtime -- flow --intel data/feeds/feodo.json --upload http://127.0.0.1:8000
# 实时抓包（需 pcap feature，通常需 root）
cargo build -p fusion-runtime --features pcap
sudo cargo run -p fusion-runtime --features pcap -- flow --pcap --iface eth0 --duration 30 --bpf "tcp port 443" --pretty

# —— intel-sync 子命令（下载 IOC feed → 本地 JSON）——
cargo run -p fusion-runtime -- intel-sync --source feodo --out data/feeds/feodo.json

# —— 精简主机 agent（不牵 flow/pcap），产物为单一 fusion 二进制 ——
cargo build -p fusion-runtime --no-default-features --features host,malware \
  --target x86_64-unknown-linux-musl --release
```

## 边界

fusion **只采集**（被调度的本机检测工具集）；CVE 判定 / 跨源关联在 **form** 侧。**跨机投放/调用/取回**（上传到待测机器、调用 `fusion`、取回结果）现在是 **form 的职责**（form 侧的 `form-scan`，Python 实现），不再属于 fusion；`fusion-runtime` 只调度本机/目标机上的进程内模块。

## 契约校验测试

- [`host/tests/contract.rs`](./host/tests/contract.rs) —— `AssetReport`。
- [`flow/tests/contract.rs`](./flow/tests/contract.rs) —— `FlowBatch`。
