# collector

**网络流量采集器 / 威胁情报采集**，cyber-posture 平台的外视引擎。基于 Rust 构建。

## 当前状态（v0）

已落地：

- **数据契约 Rust 镜像**：`collector_core::contract` 对齐 `form/src/form/schemas/` 中的 Pydantic 模型（`FlowEvent` / `FlowBatch` / `FlowProto`）
- **端到端管道骨架**：`collector-cli` 调用 `collector_core::run_capture()` → 序列化为 JSON → 写 stdout / 文件
- **跨语言契约验证**（最重要的安全网）：集成测试 `tests/contract.rs` 用 `jsonschema` crate 将 Rust 输出对照 `form/schemas-json/FlowBatch.schema.json` 校验
- **mock 捕获后端**：合成 HTTPS / DNS / SSH / ICMP 四类典型流，覆盖 TCP/UDP/ICMP 协议与 Optional 字段组合

尚未落地：

- 真实抓包后端（pcap / AF_PACKET / eBPF）
- 协议解析增强（HTTP / TLS / DNS 深度字段）
- 威胁情报 IOC 匹配
- 上报客户端（HTTP 推送给 form）

## 仓库形态

Cargo workspace：

```
collector/
├── Cargo.toml                            # workspace root
└── crates/
    ├── collector-core/                   # 库：契约 + 捕获 + 调度
    │   ├── src/
    │   │   ├── lib.rs                    # run_capture() 入口
    │   │   ├── contract.rs               # FlowEvent / FlowBatch / FlowProto
    │   │   └── capture/
    │   │       ├── mod.rs
    │   │       └── mock.rs               # mock 生成 4 个典型流
    │   └── tests/contract.rs             # JSON Schema 跨语言对赵
    └── collector-cli/                    # 可执行入口
        └── src/main.rs
```

## 构建 & 测试

```bash
cd collector

cargo build --workspace
cargo test  --workspace                                # 含跨语言契约验证
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all
```

## 跑一次捕获

```bash
cargo run -p collector-cli -- --pretty                  # 彩印 JSON 到 stdout
cargo run -p collector-cli -- --out /tmp/batch.json     # 写入文件
```

输出形如：

```json
{
  "batch_id": "batch-<uuid>",
  "collected_at": "2026-05-28T...Z",
  "collector_id": "collector-<uuid>",
  "collector_version": "0.1.0",
  "flows": [
    { "flow_id": "...", "proto": "tcp",  "src_ip": "10.0.0.42", "dst_ip": "93.184.216.34", "dst_port": 443, "tls_sni": "example.com", "ja3": "...", ... },
    { "flow_id": "...", "proto": "udp",  "dst_port": 53,        "dns_query": "example.com", ... },
    { "flow_id": "...", "proto": "tcp",  "src_port": 40000,     "dst_port": 22, "app_proto": "SSH", ... },
    { "flow_id": "...", "proto": "icmp", "src_port": null,      "dst_port": null, ... }
  ]
}
```

## 数据契约约定

- **源头**：所有类型的语义和字段以 `form/src/form/schemas/` 的 Pydantic 模型为准。
- **派生**：跨语言消费的标准是 `form/schemas-json/FlowBatch.schema.json`。
- **Rust 镜像**：`collector_core::contract` 手写——v0 类型少，自动生成器（typify）的复杂度不划算。
- **保护机制**：CI / 本地都跑 `cargo test`，集成测试会用 `jsonschema` 校验真实 `run_capture()` 输出。
- **新增字段流程**：
  1. 在 Python 端 Pydantic 模型加字段
  2. `form-export-schemas` 重新生成 JSON Schema
  3. 在 `collector_core::contract` 加对应 Rust 字段
  4. `cargo test` 验证

## 计划中的下一步

按 ROI：

1. **真实 pcap 后端**：先用 `pcap` crate 实现 BPF 抓包 + 五元组聚合
2. **DNS / TLS 解析**：从 payload 提取 `dns_query` / `tls_sni` / `ja3`
3. **上报客户端**：HTTP POST 给 form 的 `/ingest/flow-batch`
4. **eBPF 后端**：使用 aya 在更低开销下抓取并聚合
