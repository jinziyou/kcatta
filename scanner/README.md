# scanner

主机端 **资产与风险扫描器**，cyber-posture 平台的内视引擎。基于 Rust 构建。

## 当前状态（v0）

已落地：

- **数据契约 Rust 镜像**：`scanner_core::contract` 对齐 `form/src/form/schemas/` 中的 Pydantic 模型
- **端到端管道骨架**：`scanner-cli` 调用 `scanner_core::run_scan()` → 序列化为 JSON → 写 stdout / 文件
- **跨语言契约验证**（最重要的安全网）：集成测试 `tests/contract.rs` 用 `jsonschema` crate 将 Rust 输出对照 `form/schemas-json/AssetReport.schema.json` 校验，确保两端不漂移
- **真实 host 信息**：从 `/etc/hostname` + `/etc/os-release` 读取
- **mock 采集器**：packages / ports（占位真实实现）

尚未落地：

- 真实 package 采集（dpkg / rpm / apk 等）
- 真实 port 采集（`/proc/net/tcp[6]`）
- service / account / credential 采集
- 漏洞扫描、恶意代码扫描
- 上报客户端（HTTP 推送给 form）

## 仓库形态

Cargo workspace，按能力拆 crate：

```
scanner/
├── Cargo.toml                            # workspace root
└── crates/
    ├── scanner-core/                     # 库：契约 + 采集器 + 调度
    │   ├── src/
    │   │   ├── lib.rs                    # run_scan() 入口
    │   │   ├── contract.rs               # AssetReport / HostInfo / Asset / Vulnerability ...
    │   │   └── collectors/
    │   │       ├── mod.rs
    │   │       ├── host.rs               # /etc/hostname + /etc/os-release
    │   │       ├── packages.rs           # mock
    │   │       └── ports.rs              # mock
    │   └── tests/contract.rs             # JSON Schema 跨语言对赵
    └── scanner-cli/                      # 可执行入口
        └── src/main.rs
```

## 构建 & 测试

```bash
cd scanner

cargo build --workspace
cargo test  --workspace                                # 含跨语言契约验证
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all
```

## 跑一次扫描

```bash
cargo run -p scanner-cli -- --pretty                   # 彩印 JSON 到 stdout
cargo run -p scanner-cli -- --out /tmp/report.json     # 写入文件
```

输出形如：

```json
{
  "report_id": "report-<uuid>",
  "collected_at": "2026-05-28T...Z",
  "scanner_version": "0.1.0",
  "host": { "host_id": "...", "hostname": "...", "os": "...", ... },
  "assets": [
    { "kind": "package", "asset_id": "...", "name": "...", ... },
    { "kind": "port",    "asset_id": "...", "proto": "tcp", ... }
  ],
  "vulnerabilities": []
}
```

## 数据契约约定

- **源头**：所有类型的语义和字段以 `form/src/form/schemas/` 的 Pydantic 模型为准。
- **派生**：跨语言消费的标准是 `form/schemas-json/*.schema.json`。
- **Rust 镜像**：`scanner_core::contract` 手写——v0 类型少，自动生成器（typify）的复杂度不划算。
- **保护机制**：CI / 本地都跑 `cargo test`，集成测试会用 `jsonschema` 校验真实 `run_scan()` 输出，契约一旦漂移立即可见。
- **新增字段流程**：
  1. 在 Python 端 Pydantic 模型加字段
  2. `form-export-schemas` 重新生成 JSON Schema
  3. 在 `scanner_core::contract` 加对应 Rust 字段
  4. `cargo test` 验证

## 计划中的下一步

按 ROI：

1. 真实 `packages` 采集器（dpkg-query）
2. 真实 `ports` 采集器（`/proc/net/tcp[6]`）
3. 上报客户端（HTTP POST 给 form 的 `/ingest/asset-report`）
4. service / account / credential 采集
5. 漏洞扫描（先 trivy 桥接，再原生）
