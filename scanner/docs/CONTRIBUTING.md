# scanner 开发指南

面向在 `cyber-posture/scanner` workspace 内贡献代码的说明。

## 环境

- Rust stable（`rustup default stable`）
- 可选：`x86_64-unknown-linux-musl` target（远端投放静态二进制）

```bash
cd scanner
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo doc --no-deps --workspace --document-private-items
```

## 架构速查

详见 [`ARCHITECTURE.md`](./ARCHITECTURE.md)。

```
domain crate (scanner-asset, scanner-malware)
    → scanner-runtime (Collector, run_scan_at)
        → scanner-contract (AssetReport, …)
```

**原则**：scanner 只采集；CVE 匹配在 form 侧完成。

## 新增采集器

1. 在 `scanner-asset`（或新 domain crate）实现 [`Collector`](../crates/scanner-runtime/src/collector.rs)。
2. 若产出新 asset 类型，**先**扩展 `form` Pydantic schema → 生成 JSON Schema → 更新 `scanner-contract`。
3. 将 collector 加入 `default_collectors()` 或 `scanner-cli::build_plan`。
4. 在 `scanner-runtime/tests/contract.rs` 补充契约校验。
5. 更新 `README.md` 与相关 crate README。

Host collector 必须排在计划首位，后续 collector 依赖 `ctx.host_id`。

## 数据契约

| 步骤 | 位置 |
| --- | --- |
| 编辑模型 | `form/src/form/schemas/` |
| 生成 JSON Schema | `form/schemas-json/` |
| Rust 镜像 | `scanner-contract/src/lib.rs` |
| 校验 | `cargo test -p scanner-runtime` |

分文件 JSON（`packages.json` 等）与 `AssetReport` 使用同一套类型。

## 代码风格

- 遵循 workspace `rustfmt` / `clippy`（`unsafe_code = deny`）。
- **文档 lint**：workspace 默认 `missing_docs = "warn"`；`scanner-contract` 为 `deny`（公共契约必须完整文档化）。
- 模块级 `//!` 文档说明职责与数据来源路径。
- 公共 API 用 `///` 简要说明；非显而易见的业务逻辑才加注释。
- 保持 diff 聚焦：不顺带重构无关代码。

## 测试

| 类型 | 位置 | 运行 |
| --- | --- | --- |
| 单元测试 | 各 crate `#[cfg(test)]` | `cargo test -p <crate>` |
| 契约测试 | `scanner-runtime/tests/contract.rs` | 需 `form/schemas-json/` 存在 |
| 集成测试 | `scanner-remote/tests/` | 默认忽略；见 remote README |

Fixture 扫描根目录写法见 `scanner-runtime/tests/fixture.rs`。

## 二进制与 feature

| 二进制 | crate | 说明 |
| --- | --- | --- |
| `scanner-asset` | scanner-asset | 静态分文件扫描 |
| `scanner-malware` | scanner-malware | ClamAV → `malware.json` |
| `scanner-cli` | scanner-cli | 合并 `AssetReport` |
| `scanner-remote` | scanner-remote | SSH agent 模式 |

`scanner-cli` features：`asset`（默认）、`malware`、`ingest`、`full`。

## 文档维护

修改公共 API 或 CLI 参数时，同步更新：

1. 对应 crate 的 `README.md`
2. `scanner/README.md`（用户面向）
3. 必要时 `docs/ARCHITECTURE.md`

Crate `Cargo.toml` 中 `readme = "README.md"` 指向各 crate 目录下的 README。
