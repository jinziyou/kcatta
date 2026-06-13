# agent

kcatta 的端点组件，基于 Rust workspace 构建。分为**三大能力**，**一个能力 = 一个目录 =
一个 crate**（lib + bin 同处一个 crate），各能力可单独部署、单独运行：

| 能力 | 二进制 / crate | 视角 / 产出 | 运行模式 |
| --- | --- | --- | --- |
| **主机静态文件检测** | `agent-host`（`crates/host`） | 内视：主机信息 / 已装包 / SBOM / 服务 / 账户 / 凭证 / 内置查毒命中 → `AssetReport` | 周期性 |
| **流量检测** | `agent-flow`（`crates/flow`） | 外视：流量元数据 + 威胁情报 IOC 命中 → `FlowBatch` | 周期 + 持续 |
| **实时防护** | `agent-guard`（`crates/guard`） | 端内：文件 / 进程 / 网络实时事件 + **端上主动处置** → `GuardEventBatch` | 持续（长驻） |

职责边界：`agent-host` / `agent-flow` **只采集**（CVE 判定与跨源关联集中在 **fusion**）；
**`agent-guard` 是 agent 中唯一会端上主动处置的能力**——检测、（可配置地）处置、并实时上报。

## 三种运行方式（与上报模型）

**上报模型**：三个能力**独立运行只产出本地结果文件，从不上报**；**只有统一 `agent <cap> --upload <URL>` 才上报 fusion**（ingest 能力内置于 `agent`）。
上报客户端环境变量：`FUSION_API_TOKEN`（Bearer 令牌，可选）、`FUSION_UPLOAD_TIMEOUT`（HTTP 上传超时秒数，默认 60）。

1. **三独立二进制**（最精简、纯本地采集）：`agent-host` / `agent-flow` / `agent-guard` 各自单独构建、部署、运行，结果落文件/stdout/本地 NDJSON。
2. **统一 `agent` 命令**（umbrella）：单一二进制 `agent`，子命令 `host` / `flow` / `guard` 在进程内分发到三能力（见 [`crates/agent`](crates/agent)），共用各能力 lib 的 `cli` 模块；额外提供 `--upload` 上报 fusion。
3. **由 fusion 调度**：`fusion-scan --capability {host|flow|guard}` 经 SSH 远程投放——host/flow 投精简 bin、一次性拉回结果由 fusion 入库；guard 投 `agent` 二进制并以 `agent guard --upload` 常驻推送。

```bash
agent-host -r / --malware --pretty                       # 方式1：独立二进制（只产出文件，不上报）
agent host -r / --malware --upload http://fusion:8000      # 方式2：统一命令 + 上报 fusion
fusion-scan --ssh-host root@H --capability host -o out --upload http://fusion:8000   # 方式3：fusion 调度
fusion-scan --ssh-host root@H --capability guard --upload http://fusion:8000          #       （guard 常驻，投 agent）
```

## 部署构建（静态 musl —— 方式3 fusion 投放的产物）

fusion 远程投放（`fusion-scan` / portal 触发）需要**静态链接**的二进制，才能在任意 Linux 目标机上直接运行
（不受目标 glibc 版本影响）。这层由 agent 项目拥有，从仓库根用一条命令产出：

```bash
make build-agent-deploy         # x86_64：输出到 agent/target/x86_64-unknown-linux-musl/release/
make build-agent-deploy-arm64   # aarch64：输出到 agent/target/aarch64-unknown-linux-musl/release/（需 cross）
# 每个架构产出三件（fusion 按目标 uname -m 自动选对应架构）：
#   agent-host  —— host 能力（精简）
#   agent-flow  —— flow 能力（精简，mock；不含 pcap）
#   agent         —— umbrella（--features onaccess,network,ids；guard 用它常驻）
```

- **x86_64**：需 musl C 工具链（agent-host 的内置 SQLite、TLS 的 ring 走 C/asm）：Debian/Ubuntu `sudo apt-get install -y musl-tools`；纯 Rust 子集（如 `agent-guard --features fim`）无需。
- **aarch64**：用 `cross`（`cargo install cross`，docker 化工具链,自带 C 交叉编译，省去手配 musl 交叉 gcc）。
- **多架构自动选择**：fusion 部署时探测目标 `uname -m`（x86_64/amd64 → x86_64，aarch64/arm64 → aarch64），从 `FUSION_AGENT_TARGET_DIR`（默认 `../agent/target`）下取 `<triple>/release/<bin>`。`--agent-binary` 可显式覆盖。
- **pcap 不进部署 bin**：libpcap 是动态 C 库，静态 musl 难成；实时抓包属目标侧能力，部署构建用 mock。
- **CI**：`agent (musl deploy build)` 与 `agent (musl deploy build, arm64)` 两个 job 分别构建并上传 `agent-musl-x86_64` / `agent-musl-aarch64` 制品。

## 架构概览

5 个 crate：1 个数据契约底座 + 三大能力（lib+bin 同处）+ 1 个统一入口 `agent`（内置 ingest），全部位于 `crates/`（无嵌套子 crate）：

```
agent/crates/
├── contract/     # agent-contract：数据契约（AssetReport + FlowBatch + GuardEventBatch）。零内部依赖
├── host/         # agent-host：主机检测 + 内置签名查毒（lib + cli）+ agent-host 二进制（只写文件）
├── flow/         # agent-flow：捕获 + IOC 匹配 + feed 解析（lib + cli）+ agent-flow 二进制（只写文件）
├── guard/        # agent-guard：实时防护引擎（lib + cli）+ agent-guard 守护进程（本地 NDJSON/stdout）
└── agent/        # agent：统一 `agent` 命令（umbrella）+ 内置 ingest（--upload 才上报 fusion）
```

**依赖方向**（单向无环）：依赖 DAG 见 [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)。

guard 经 feature 可选依赖 host/flow：默认 guard（fim+behavior）不牵入，FIM-only 构建不含
查毒 / libpcap。**恶意软件检测自实现**（签名/哈希引擎，仅 std+sha2，无 ClamAV / 外部守护进程），
在 `agent-host` 的 `malware` 模块，guard on-access 复用同一引擎。

## 构建 & 测试

```bash
cd agent
cargo build --workspace
cargo test  --workspace                              # 含三契约校验 + 内置查毒测试
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all

cargo test -p agent-guard --features all           # guard 全传感器（无需 root）
cargo build -p agent-flow --features pcap          # 实时抓包（需 libpcap-dev）
```

## 主机静态文件检测（agent-host）

产出 `AssetReport`；`--malware` 追加内置签名查毒。

```bash
cargo run -p agent-host -- -r / --pretty                                # 合并 AssetReport
cargo run -p agent-host -- -r / -t all -o ./scan-out                    # 分文件 JSON
cargo run -p agent-host -- -r / --malware --pretty                      # 含内置查毒
cargo run -p agent-host -- -r / --malware --malware-signatures sigs.json --pretty
cargo run -p agent -- host -r / -t all --upload http://127.0.0.1:8000   # 上报 fusion（统一 agent）
```

旗标：`-r/--root`、`-t/--target {host|packages|sbom|services|accounts|credentials|identity|all}`、
`--project-root`、`--windows-packages {full|apps}`、`--malware`、`--malware-jobs`、
`--malware-signatures PATH`、`--pretty`、`--report-out`。

- 内置查毒：每个文件读入（限大小）→ SHA-256 + 字节子串匹配签名集；内置 EICAR 测试签名，
  额外签名经 `--malware-signatures`（JSON：`sha256` / `bytes` 规则）加载。命中 → `Vulnerability`
  （`source = "kcatta-malware"`，severity critical）。**简单可用，后续可扩展（YARA 风格规则、更大的库）**。
- Linux 包覆盖 dpkg / apk / rpm / PyPI / npm；Windows 主机/服务/账户/已装程序来自注册表。SBOM 输出 CycloneDX 1.6。**CVE 检测集中在 fusion**。

```bash
# 精简静态二进制（musl，不牵 flow/guard）
cargo build -p agent-host --target x86_64-unknown-linux-musl --release
```

> 跨机投放 / 调用 / 取回由 fusion 的 `fusion-scan`（Python）负责（投放 `agent-host`，调用其单命令）。

## 流量检测（agent-flow）

两个子命令：`capture`（捕获 → IOC 匹配 → `FlowBatch`）与 `intel-sync`（拉 IOC feed）。

```bash
cargo run -p agent-flow -- capture --pretty
cargo run -p agent -- flow --upload http://127.0.0.1:8000 capture --intel data/feeds/feodo.json
sudo cargo run -p agent-flow --features pcap -- capture --pcap --iface eth0 --duration 30 --pretty
cargo run -p agent-flow -- intel-sync --source feodo --out data/feeds/feodo.json
```

## 实时防护（agent-guard）

长驻守护：实时检测 → 决策 → 处置 → 上报。**默认安全**（monitor、零破坏性动作），
启用 enforce + 单动作开关后才处置，受多重安全否决保护。

```bash
cargo run -p agent-guard -- --stdout                                    # monitor 默认，无需 root
cargo run -p agent -- guard --config /etc/kcatta/guard.json --upload http://127.0.0.1:8000
cargo build -p agent-guard --no-default-features --features fim         # 精简：仅 FIM
cargo build -p agent-guard --features all                               # 全机制（+pcap 需 libpcap）
```

机制（Linux）：`fim`（inotify，默认）、`behavior`（/proc，默认）、`onaccess`（fanotify + 复用
`agent-host` 内置查毒，需 `CAP_SYS_ADMIN`）、`network`/`ids`（复用 `agent-flow` 捕获 + `ThreatFeed`）。
处置：可逆隔离（永不删除、不碰系统前缀 / 运行中-mmap 文件）、网络阻断（nft）、阻断打开（FAN_DENY）；
`kill` 仅搭骨架默认关闭。所有 syscall 走安全的 `nix` 封装，满足 `unsafe_code = "deny"`。

## 数据契约

| 层级 | 路径 |
| --- | --- |
| Pydantic（权威） | `fusion/src/fusion/schemas/`（含 `guard_event.py`） |
| JSON Schema | `fusion/schemas-json/`（含 `GuardEventBatch.schema.json`） |
| Rust 镜像 | `agent-contract`（三种 envelope，共享 `Severity`/`IndicatorType`） |
| 校验测试 | `host/tests/contract.rs`、`flow/tests/contract.rs`、`contract/tests/guard_contract.rs` |

## 开发文档

| 文档 | 说明 |
| --- | --- |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | 三能力 / 三 crate 模型、各域架构、guard 流水线、扩展指南 |
| [`docs/CONTRIBUTING.md`](docs/CONTRIBUTING.md) | 开发环境、测试、新增采集器 / 传感器流程 |
| [`crates/README.md`](crates/README.md) | Workspace crate 索引 |
