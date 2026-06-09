# agent

posture 的端点组件，基于 Rust workspace 构建。分为**三大能力**，**一个能力 = 一个目录 =
一个 crate**（lib + bin 同处一个 crate），各能力可单独部署、单独运行：

| 能力 | 二进制 / crate | 视角 / 产出 | 运行模式 |
| --- | --- | --- | --- |
| **主机静态文件检测** | `posture-host`（`crates/host`） | 内视：主机信息 / 已装包 / SBOM / 服务 / 账户 / 凭证 / 内置查毒命中 → `AssetReport` | 周期性 |
| **流量检测** | `posture-flow`（`crates/flow`） | 外视：流量元数据 + 威胁情报 IOC 命中 → `FlowBatch` | 周期 + 持续 |
| **实时防护** | `posture-guard`（`crates/guard`） | 端内：文件 / 进程 / 网络实时事件 + **端上主动处置** → `GuardEventBatch` | 持续（长驻） |

职责边界：`posture-host` / `posture-flow` **只采集**（CVE 判定与跨源关联集中在 **fusion**）；
**`posture-guard` 是 agent 中唯一会端上主动处置的能力**——检测、（可配置地）处置、并实时上报。

## 架构概览

三大能力各一个 crate（lib+bin 同处），加三个共享底座，全部位于 `crates/`（无嵌套子 crate）：

```
agent/crates/
├── contract/     # agent-contract：数据契约（AssetReport + FlowBatch + GuardEventBatch）。零内部依赖
├── ingest/       # agent-ingest：阻塞 HTTP 上报 → fusion（三个 upload_*）
├── cli-common/   # agent-cli-common：共享 CLI 底座（JSON 输出 + 阻塞 HTTP）。零内部依赖
├── host/         # posture-host：主机检测 + 内置签名查毒（lib）+ posture-host 二进制
├── flow/         # posture-flow：捕获 + IOC 匹配 + feed 解析（lib）+ posture-flow 二进制
└── guard/        # posture-guard：实时防护引擎（lib）+ posture-guard 守护进程
```

**依赖方向**（单向无环；capability crate 互为 lib 依赖）：

```
contract ← ingest / scan / flow
contract ← guard ← scan(onaccess, 复用内置查毒) + flow(network, 复用 capture)
cli-common（无内部依赖）
```

guard 经 feature 可选依赖 scan/flow：默认 guard（fim+behavior）不牵入，FIM-only 构建不含
查毒 / libpcap。**恶意软件检测自实现**（签名/哈希引擎，仅 std+sha2，无 ClamAV / 外部守护进程），
在 `posture-host` 的 `malware` 模块，guard on-access 复用同一引擎。

## 构建 & 测试

```bash
cd agent
cargo build --workspace
cargo test  --workspace                              # 含三契约校验 + 内置查毒测试
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all

cargo test -p posture-guard --features all           # guard 全传感器（无需 root）
cargo build -p posture-flow --features pcap          # 实时抓包（需 libpcap-dev）
```

## 主机静态文件检测（posture-host）

产出 `AssetReport`；`--malware` 追加内置签名查毒。

```bash
cargo run -p posture-host -- -r / --pretty                                # 合并 AssetReport
cargo run -p posture-host -- -r / -t all -o ./scan-out                    # 分文件 JSON
cargo run -p posture-host -- -r / --malware --pretty                      # 含内置查毒
cargo run -p posture-host -- -r / --malware --malware-signatures sigs.json --pretty
cargo run -p posture-host -- -r / -t all --upload http://127.0.0.1:8000   # 上报 fusion
```

旗标：`-r/--root`、`-t/--target {host|packages|sbom|services|accounts|credentials|identity|all}`、
`--project-root`、`--windows-packages {full|apps}`、`--malware`、`--malware-jobs`、
`--malware-signatures PATH`、`--pretty`、`--report-out`、`--upload`。

- 内置查毒：每个文件读入（限大小）→ SHA-256 + 字节子串匹配签名集；内置 EICAR 测试签名，
  额外签名经 `--malware-signatures`（JSON：`sha256` / `bytes` 规则）加载。命中 → `Vulnerability`
  （`source = "posture-malware"`，severity critical）。**简单可用，后续可扩展（YARA 风格规则、更大的库）**。
- Linux 包覆盖 dpkg / apk / rpm / PyPI / npm；Windows 主机/服务/账户/已装程序来自注册表。SBOM 输出 CycloneDX 1.6。**CVE 检测集中在 fusion**。

```bash
# 精简静态二进制（musl，不牵 flow/guard）
cargo build -p posture-host --target x86_64-unknown-linux-musl --release
```

> 跨机投放 / 调用 / 取回由 fusion 的 `fusion-scan`（Python）负责（投放 `posture-host`，调用其单命令）。

## 流量检测（posture-flow）

两个子命令：`capture`（捕获 → IOC 匹配 → `FlowBatch`）与 `intel-sync`（拉 IOC feed）。

```bash
cargo run -p posture-flow -- capture --pretty
cargo run -p posture-flow -- capture --intel data/feeds/feodo.json --upload http://127.0.0.1:8000
sudo cargo run -p posture-flow --features pcap -- capture --pcap --iface eth0 --duration 30 --pretty
cargo run -p posture-flow -- intel-sync --source feodo --out data/feeds/feodo.json
```

## 实时防护（posture-guard）

长驻守护：实时检测 → 决策 → 处置 → 上报。**默认安全**（monitor、零破坏性动作），
启用 enforce + 单动作开关后才处置，受多重安全否决保护。

```bash
cargo run -p posture-guard -- --stdout                                    # monitor 默认，无需 root
cargo run -p posture-guard -- --config /etc/posture/guard.json --upload http://127.0.0.1:8000
cargo build -p posture-guard --no-default-features --features fim         # 精简：仅 FIM
cargo build -p posture-guard --features all                               # 全机制（+pcap 需 libpcap）
```

机制（Linux）：`fim`（inotify，默认）、`behavior`（/proc，默认）、`onaccess`（fanotify + 复用
`posture-host` 内置查毒，需 `CAP_SYS_ADMIN`）、`network`/`ids`（复用 `posture-flow` 捕获 + `ThreatFeed`）。
处置：可逆隔离（永不删除、不碰系统前缀 / 运行中-mmap 文件）、网络阻断（nft）、阻断打开（FAN_DENY）；
`kill` 仅搭骨架默认关闭。所有 syscall 走安全的 `nix` 封装，满足 `unsafe_code = "deny"`。

## 数据契约

| 层级 | 路径 |
| --- | --- |
| Pydantic（权威） | `fusion/src/fusion/schemas/`（含 `guard_event.py`） |
| JSON Schema | `fusion/schemas-json/`（含 `GuardEventBatch.schema.json`） |
| Rust 镜像 | `agent-contract`（三种 envelope，共享 `Severity`/`IndicatorType`） |
| 校验测试 | `scan/tests/contract.rs`、`flow/tests/contract.rs`、`contract/tests/guard_contract.rs` |

## 开发文档

| 文档 | 说明 |
| --- | --- |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | 三能力 / 三 crate 模型、各域架构、guard 流水线、扩展指南 |
| [`docs/CONTRIBUTING.md`](docs/CONTRIBUTING.md) | 开发环境、测试、新增采集器 / 传感器流程 |
| [`crates/README.md`](crates/README.md) | Workspace crate 索引 |
