# fusion 开发指南

面向在 `posture/fusion` workspace 内贡献代码的说明。

## 环境

- Rust stable（`rustup default stable`）
- 可选：`x86_64-unknown-linux-musl` target（构建精简主机 agent 静态二进制）

```bash
cd fusion
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo doc --no-deps --workspace --document-private-items
```

## 架构速查

详见 [`ARCHITECTURE.md`](./ARCHITECTURE.md)。

workspace 为 5 个**扁平** crate，位于 `crates/` 下（每个目录即一个 crate，无嵌套子 crate）：

| 目录 / 包名 | 职责 |
| --- | --- |
| `contract` / `fusion-contract` | 数据契约：`AssetReport` + `FlowBatch` + 共享 `Severity`（form `schemas-json` 的 Rust 镜像）。零内部依赖，是依赖 DAG 的汇点。 |
| `ingest` / `fusion-ingest` | 阻塞式 HTTP 上报客户端 → form：`upload_report`、`upload_batch`，带 `FORM_API_TOKEN` Bearer，HTTP 202 视为成功。仅依赖 `contract`。 |
| `host` / `fusion-host` | **全部主机检测**（纯库）：静态资产发现 + 主机域调度抽象（`Collector` / `ScanContext` / `run_scan_at`）+ `malware` feature 下的 ClamAV INSTREAM 查杀。仅依赖 `contract`。 |
| `flow` / `fusion-flow` | 网络流域**纯库**：capture（默认 mock，`pcap` feature 实时）+ 威胁情报 IOC 匹配（`ThreatFeed`）+ feed 字节解析器。仅依赖 `contract`。 |
| `runtime` / `fusion-runtime` | **`fusion` 编排二进制**：经子命令调度各域模块。依赖 `contract`、`ingest`、`host`（可选）、`flow`（可选）。 |

依赖 DAG（单向无环）：

```
contract ← ingest
contract ← host
contract ← flow
{ contract, ingest, host, flow } ← runtime
```

唯一二进制 `fusion`（来自 `fusion-runtime`），三个子命令：`host`（主机资产扫描）、`flow`（抓包 → IOC 匹配 → `FlowBatch`）、`intel-sync`（下载 IOC feed → 本地 JSON）。

**原则**：fusion 只采集（一组被调度的本机检测工具）；CVE 判定、漏洞识别与跨源关联在 form 侧完成。**跨机投放 / 调用 / 取回**由 form 侧的 `form-scan`（Python）负责，不属于 fusion；`fusion-runtime` 只调度本机 / 目标机上的进程内模块。

## 新增采集器（主机域）

采集器全部落在 `fusion-host`：

1. 在 `fusion-host` 实现 [`Collector`](../crates/host/src/collector.rs)。
2. 若产出新 asset 类型，**先**扩展 `form` Pydantic schema → 生成 JSON Schema → 更新 [`fusion-contract`](../crates/contract/src/lib.rs)。
3. 将 collector 编排进默认扫描计划（`crates/host/src/scan.rs` / `scan_runner.rs`）。
4. 在 [`crates/host/tests/contract.rs`](../crates/host/tests/contract.rs) 补充 `AssetReport` 契约校验。
5. 更新 `README.md` 与相关 crate 文档。

Host collector 必须排在计划首位，后续 collector 依赖 `ctx.host_id`。

### fusion-host 内部分层

`fusion-host` 对外按**资产语义**暴露 `Collector`（Host / Packages / …），内部按**采集策略**分层：

| 层 | 目录 | 职责 | 扩展示例 |
| --- | --- | --- | --- |
| 语义 facade | `collectors/` | 实现 `Collector` trait；Linux/Windows 分派；合并输出 | 新增 `MalwareCollector` 时在此挂接 |
| 固定路径 | `sources/` | 读取已知路径（`etc/passwd`、`var/lib/dpkg/status`、全局 `site-packages`） | 新 OS 包管理器 → `sources/packages/` |
| 有界遍历 | `walk/` | 统一 WalkDir、skip 规则、pattern registry | 新语言生态 → `walk/handlers/` 注册 match + extract |
| OS 后端 | `platform/` | `detect()`、Windows hive / live 注册表 | Windows 新数据源 → `platform/windows/` |

新增语言包（如 `go.mod` / `Cargo.lock`）推荐路径：

1. 在 `walk/handlers/` 实现 `matches` + `extract`
2. 在 `walk/registry.rs` 注册 `ProjectHandler`（或在 `sources/packages/` 读固定全局路径）
3. 在 `sources/packages/mod.rs` 或 `collectors/packages/mod.rs` 编排进 `PackagesCollector`

新增整类资产（如容器镜像清单）：

1. 在 `sources/` 或 `platform/windows/` 实现采集函数
2. 在 `collectors/` 添加 facade + `Collector` impl
3. 加入默认扫描计划（注意 host 必须先运行）

恶意软件查杀位于 `malware` feature 后（`crates/host/src/malware/`），通过 `MalwareCollector` 挂接；扩展时同样实现 `Collector`，并在 feature gate 下挂接。

## 新增情报源（网络域）

网络域（`fusion-flow`）的扩展点是威胁情报 IOC 源，详见
[`ARCHITECTURE.md`](./ARCHITECTURE.md)「扩展新情报源」：

1. 在 [`crates/flow/src/intel/sync/`](../crates/flow/src/intel/sync) 实现 feed 适配器（参考 `feodo.rs`）
2. 在 `fusion-runtime` 的 [`intel-sync` 子命令](../crates/runtime/src/cmd/intel_sync.rs) `--source` 分发中接入
3. 产出对齐 `ThreatFeed` 的本地 JSON（`type` / `value` / `category` / `severity`）

## 数据契约

| 步骤 | 位置 |
| --- | --- |
| 编辑模型 | `form/src/form/schemas/` |
| 生成 JSON Schema | `form/schemas-json/` |
| Rust 镜像 | [`contract/src/lib.rs`](../crates/contract/src/lib.rs)（`AssetReport`）、`contract/src/flow.rs`（`FlowBatch`） |
| 校验（主机域） | `cargo test -p fusion-host` |
| 校验（网络域） | `cargo test -p fusion-flow` |

分文件 JSON（`packages.json` 等）与 `AssetReport` 使用同一套类型。

## 代码风格

- 遵循 workspace `rustfmt` / `clippy`（`unsafe_code = deny`）。
- **文档 lint**：workspace 默认 `missing_docs = "warn"`；`fusion-contract` 为 `deny`（公共契约必须完整文档化）。
- 模块级 `//!` 文档说明职责与数据来源路径。
- 公共 API 用 `///` 简要说明；非显而易见的业务逻辑才加注释。
- 保持 diff 聚焦：不顺带重构无关代码。

## 测试

| 类型 | 位置 | 运行 |
| --- | --- | --- |
| 单元测试 | 各 crate `#[cfg(test)]` | `cargo test -p <crate>` |
| 主机契约测试 | [`crates/host/tests/contract.rs`](../crates/host/tests/contract.rs) | `cargo test -p fusion-host`，需 `form/schemas-json/` 存在 |
| 网络契约测试 | [`crates/flow/tests/contract.rs`](../crates/flow/tests/contract.rs) | `cargo test -p fusion-flow` |
| 恶意软件查杀 | `crates/host/tests/malware_instream.rs` | `cargo test -p fusion-host --features malware`，需本地 clamd |

Fixture 扫描根目录写法见 [`crates/host/tests/fixture.rs`](../crates/host/tests/fixture.rs)。

端到端验证用 `fusion` 子命令，例如：

```bash
cargo run -p fusion-runtime -- host -r / --pretty                            # 合并 AssetReport
cargo run -p fusion-runtime -- host -r / -t all -o ./scan-out                # 分文件 JSON
cargo run -p fusion-runtime --features full -- host -r / --malware --pretty  # 含 ClamAV
cargo run -p fusion-runtime -- flow --pretty                                 # FlowBatch（mock 默认）
cargo run -p fusion-runtime -- intel-sync --source feodo --out data/feeds/feodo.json
```

## 二进制与 feature

唯一二进制 `fusion`（bin 名 `fusion`），来自 `fusion-runtime`。各 crate 的 feature：

| crate | features |
| --- | --- |
| `fusion-host` | `default = []`；`malware`（ClamAV INSTREAM 查杀） |
| `fusion-flow` | `default = []`；`pcap`（实时抓包） |
| `fusion-runtime` | `default = [host, flow]`；`host`；`flow`；`malware → host/malware`；`pcap → flow/pcap`；`full = [host, flow, malware]` |

构建精简主机 agent（不牵 flow/pcap，产物为单一 `fusion` 二进制）：

```bash
cargo build -p fusion-runtime --no-default-features --features host,malware \
  --target x86_64-unknown-linux-musl --release
```

启用实时抓包：

```bash
cargo build -p fusion-runtime --features pcap
```

## 文档维护

修改公共 API 或 CLI 参数时，同步更新：

1. 对应 crate 的 `README.md`
2. `fusion/README.md`（用户面向）
3. 必要时 `docs/ARCHITECTURE.md`

Crate `Cargo.toml` 中 `readme = "README.md"` 指向各 crate 目录下的 README。
