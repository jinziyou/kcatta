# probe 开发指南

面向在 `cyber-posture/probe` workspace 内贡献代码的说明。

## 环境

- Rust stable（`rustup default stable`）
- 可选：`x86_64-unknown-linux-musl` target（远端投放静态二进制）

```bash
cd probe
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo doc --no-deps --workspace --document-private-items
```

## 架构速查

详见 [`ARCHITECTURE.md`](./ARCHITECTURE.md)。

```
主机域  domain crate (probe-asset, probe-malware)
          → probe-runtime (Collector, run_scan_at) → probe-contract (AssetReport)
网络域  probe-flow (capture + intel) → probe-contract (FlowBatch)
共享    probe-ingest 上报 AssetReport / FlowBatch → form
```

**原则**：probe 只采集；CVE / 漏洞识别与跨源关联在 form 侧完成。

## 新增采集器

1. 在 `probe-asset`（或新 domain crate）实现 [`Collector`](../crates/probe-runtime/src/collector.rs)。
2. 若产出新 asset 类型，**先**扩展 `form` Pydantic schema → 生成 JSON Schema → 更新 `probe-contract`。
3. 将 collector 加入 `default_collectors()` 或 `probe-host-cli::build_plan`。
4. 在 `probe-runtime/tests/contract.rs` 补充契约校验。
5. 更新 `README.md` 与相关 crate README。

Host collector 必须排在计划首位，后续 collector 依赖 `ctx.host_id`。

### probe-asset 内部分层

`probe-asset` 对外仍按**资产语义**暴露 `Collector`（Host / Packages / …），内部按**采集策略**分层：

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
3. 加入 `default_collectors()`（注意 host 必须先运行）

## 新增情报源（网络域）

网络域（`probe-flow`）的扩展点是威胁情报 IOC 源，详见
[`ARCHITECTURE.md`](./ARCHITECTURE.md)「扩展新情报源」：

1. 在 `probe-flow/src/intel/sync/` 实现 feed 适配器（参考 `feodo.rs`）
2. 在 `probe-intel-sync` 的 `--source` 分发中接入
3. 产出对齐 `ThreatFeed` 的本地 JSON（`type` / `value` / `category` / `severity`）

## 数据契约

| 步骤 | 位置 |
| --- | --- |
| 编辑模型 | `form/src/form/schemas/` |
| 生成 JSON Schema | `form/schemas-json/` |
| Rust 镜像 | `probe-contract/src/lib.rs` |
| 校验 | `cargo test -p probe-runtime` |

分文件 JSON（`packages.json` 等）与 `AssetReport` 使用同一套类型。

## 代码风格

- 遵循 workspace `rustfmt` / `clippy`（`unsafe_code = deny`）。
- **文档 lint**：workspace 默认 `missing_docs = "warn"`；`probe-contract` 为 `deny`（公共契约必须完整文档化）。
- 模块级 `//!` 文档说明职责与数据来源路径。
- 公共 API 用 `///` 简要说明；非显而易见的业务逻辑才加注释。
- 保持 diff 聚焦：不顺带重构无关代码。

## 测试

| 类型 | 位置 | 运行 |
| --- | --- | --- |
| 单元测试 | 各 crate `#[cfg(test)]` | `cargo test -p <crate>` |
| 契约测试 | `probe-runtime/tests/contract.rs` | 需 `form/schemas-json/` 存在 |
| 集成测试 | `probe-remote/tests/` | 默认忽略；见 remote README |

Fixture 扫描根目录写法见 `probe-runtime/tests/fixture.rs`。

## 二进制与 feature

| 二进制 | crate | 说明 |
| --- | --- | --- |
| `probe-asset` | probe-asset | 静态分文件扫描 |
| `probe-malware` | probe-malware | ClamAV → `malware.json` |
| `probe-host-cli` | probe-host-cli | 合并 `AssetReport` |
| `probe-remote` | probe-remote | SSH agent 模式 |

`probe-host-cli` features：`asset`（默认）、`malware`、`ingest`、`full`。

## 文档维护

修改公共 API 或 CLI 参数时，同步更新：

1. 对应 crate 的 `README.md`
2. `probe/README.md`（用户面向）
3. 必要时 `docs/ARCHITECTURE.md`

Crate `Cargo.toml` 中 `readme = "README.md"` 指向各 crate 目录下的 README。
