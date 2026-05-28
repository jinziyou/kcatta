# scanner

主机端 **资产与风险扫描器**，cyber-posture 平台的内视引擎。基于 Rust 构建。

## 当前状态（v0）

已落地：

- **按功能域拆分的 workspace**：契约 / 调度 / 资产发现 / 漏洞&恶意代码占位 / 上报占位
- **`Collector` trait + `run_scan(plan)`**：`scanner-cli` 组装扫描计划，`scanner-runtime` 调度
- **数据契约**：`scanner-contract` 对齐 `form/src/form/schemas/`
- **跨语言契约验证**：`scanner-runtime` 与 `scanner-core` 集成测试对照 `form/schemas-json/`
- **真实 host 信息**：`scanner-asset` 从 `/etc/hostname` + `/etc/os-release` 读取
- **真实资产采集**：`dpkg-query` 枚举已安装包；`/proc/net/tcp[6]`、`udp[6]` 解析监听端口（含 PID / 进程名）

尚未落地：

- rpm / apk 等非 dpkg 包管理器
- service / account / credential 采集
- `scanner-vuln` / `scanner-malware` 真实引擎
- `scanner-ingest` HTTP 上报

## 仓库形态

Cargo workspace：**一 main（`scanner-cli`）+ 多 lib，由 runtime 调度**：

```
scanner/
├── Cargo.toml
└── crates/
    ├── scanner-contract/       # 契约类型（serde），无采集逻辑
    ├── scanner-runtime/        # Collector trait、ScanContext、run_scan()
    ├── scanner-asset/          # 资产发现：host、packages、ports、…
    ├── scanner-vuln/           # 漏洞扫描（v0 空实现 Collector）
    ├── scanner-malware/        # 恶意代码扫描（v0 空实现 Collector）
    ├── scanner-ingest/         # 上报 form（v0 占位）
    ├── scanner-core/           # 兼容门面：run_scan() = 默认 asset 计划
    └── scanner-cli/            # 二进制：组装 plan → run_scan → 输出 JSON
```

依赖方向（避免环）：

```
scanner-cli → scanner-runtime ← scanner-asset / scanner-vuln / scanner-malware
                    ↓
            scanner-contract
scanner-ingest → scanner-contract
scanner-core → scanner-runtime + scanner-asset (+ re-export contract)
```

### 组装扫描计划（CLI）

```rust
// 默认：仅 asset（host + mock packages + ports）
cargo run -p scanner-cli -- --pretty

// 启用漏洞 / 恶意代码占位 collector
cargo run -p scanner-cli --features full -- --pretty
```

### 扩展新域

1. 新建或扩展现有 crate（如 `scanner-asset/src/collectors/services.rs`）
2. 实现 `scanner_runtime::Collector`
3. 在 `scanner-asset::default_collectors()` 或 `scanner-cli::build_plan()` 注册

## 构建 & 测试

```bash
cd scanner

cargo build --workspace
cargo test  --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all
```

## 跑一次扫描

```bash
cargo run -p scanner-cli -- --pretty
cargo run -p scanner-cli -- --out /tmp/report.json
```

## 数据契约约定

- **源头**：`form/src/form/schemas/`（Pydantic）
- **派生**：`form/schemas-json/*.schema.json`
- **Rust 镜像**：`scanner-contract`
- **保护机制**：`cargo test` 校验 `run_scan` 输出
- **新增字段**：改 Pydantic → `form-export-schemas` → `scanner-contract` → `cargo test`

## 计划中的下一步

1. rpm / apk 包采集器（`scanner-asset`）
2. `scanner-ingest` 对接 form `/ingest/asset-report`
3. `scanner-vuln` trivy 桥接
4. `scanner-malware` 引擎集成
5. service / account / credential 采集器
