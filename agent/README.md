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

## 三种运行方式（与上报模型）

**上报模型**：三个能力**独立运行只产出本地结果文件，从不上报**；**只有统一 `agent <cap> --upload <URL>` 才上报 fusion**（ingest 能力内置于 `agent`）。

1. **三独立二进制**（最精简、纯本地采集）：`posture-host` / `posture-flow` / `posture-guard` 各自单独构建、部署、运行，结果落文件/stdout/本地 NDJSON。
2. **统一 `agent` 命令**（umbrella）：单一二进制 `agent`，子命令 `host` / `flow` / `guard` 在进程内分发到三能力（见 [`crates/agent`](crates/agent)），共用各能力 lib 的 `cli` 模块；额外提供 `--upload` 上报 fusion。
3. **由 fusion 调度**：`fusion-scan --capability {host|flow|guard}` 经 SSH 远程投放——host/flow 投精简 bin、一次性拉回结果由 fusion 入库；guard 投 `agent` 二进制并以 `agent guard --upload` 常驻推送。

```bash
posture-host -r / --malware --pretty                       # 方式1：独立二进制（只产出文件，不上报）
agent host -r / --malware --upload http://fusion:8000      # 方式2：统一命令 + 上报 fusion
fusion-scan --ssh-host root@H --capability host -o out --upload http://fusion:8000   # 方式3：fusion 调度
fusion-scan --ssh-host root@H --capability guard --upload http://fusion:8000          #       （guard 常驻，投 agent）
```

## 部署构建（静态 musl —— 方式3 fusion 投放的产物）

fusion 远程投放（`fusion-scan` / portal 触发）需要**静态链接**的二进制，才能在任意 Linux 目标机上直接运行
（不受目标 glibc 版本影响）。这层由 agent 项目拥有，从仓库根用一条命令产出：

```bash
make build-agent-deploy        # 从 posture/ 根；输出到 agent/target/x86_64-unknown-linux-musl/release/
# 产物（fusion 的 FUSION_AGENT_BIN_DIR 即指向此目录）：
#   posture-host  —— host 能力（精简）
#   posture-flow  —— flow 能力（精简，mock；不含 pcap）
#   agent         —— umbrella（--features onaccess,network,ids；guard 用它常驻）
```

- **需要 musl C 工具链**（posture-host 的内置 SQLite、TLS 的 ring 走 C/asm）：Debian/Ubuntu `sudo apt-get install -y musl-tools`；纯 Rust 子集（如 `posture-guard --features fim`）无需。CI 的 `agent (musl deploy build)` job 装好 musl-tools 后构建并上传 `posture-agent-musl-x86_64` 制品。
- **pcap 不进部署 bin**：libpcap 是动态 C 库，静态 musl 难成；实时抓包属目标侧能力，部署构建用 mock。
- 多架构：目标若非 x86_64，加 `aarch64-unknown-linux-musl` 构建（fusion 的 arch 探测目前仅放行 x86_64）。

## 架构概览

5 个 crate：1 个数据契约底座 + 三大能力（lib+bin 同处）+ 1 个统一入口 `agent`（内置 ingest），全部位于 `crates/`（无嵌套子 crate）：

```
agent/crates/
├── contract/     # agent-contract：数据契约（AssetReport + FlowBatch + GuardEventBatch）。零内部依赖
├── host/         # posture-host：主机检测 + 内置签名查毒（lib + cli）+ posture-host 二进制（只写文件）
├── flow/         # posture-flow：捕获 + IOC 匹配 + feed 解析（lib + cli）+ posture-flow 二进制（只写文件）
├── guard/        # posture-guard：实时防护引擎（lib + cli）+ posture-guard 守护进程（本地 NDJSON/stdout）
└── agent/        # posture-agent：统一 `agent` 命令（umbrella）+ 内置 ingest（--upload 才上报 fusion）
```

> `cli-common` / `agent-ingest` 已移除：JSON 输出 / HTTP 下载内联进各能力 `cli`；上报（ingest）内置进 `agent`。

**依赖方向**（单向无环；capability crate 互为 lib 依赖，umbrella 聚合三者 + 持有 ingest）：

```
contract ← host / flow（只采集、只写文件）
contract ← guard ← host(onaccess, 复用内置查毒) + flow(network, 复用 capture)
agent(umbrella) → host + flow + guard + contract，内置 ingest 模块（reqwest）：--upload 时 POST → fusion
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
