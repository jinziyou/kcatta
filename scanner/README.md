# scanner

主机端 **资产与风险扫描器**，cyber-posture 平台的内视引擎。基于 Rust 构建，利用其内存安全与高性能并发能力执行主机深度盘点与本地恶意代码扫描。

## 职责

- **资产发现**：操作系统软件包、运行服务、监听端口、计划任务、用户与凭据、SSH/API 密钥等敏感数据。
- **风险识别**：基线合规检查、已知漏洞匹配、可疑配置审计。
- **病毒/恶意代码扫描**：本地静态特征 + 行为指纹比对。
- **上报**：将结构化结果上报给 `form`。

## 仓库形态

本目录是一个 **Cargo workspace**（Rust monorepo），各子能力以独立 crate 形式组织在 `crates/` 下，便于按需裁剪与并行构建。

```
scanner/
├── Cargo.toml         # workspace 根
└── crates/            # 各子 crate（待添加）
```

## 新增 crate

```bash
cd scanner
cargo new --lib crates/<crate-name>
# 然后在 scanner/Cargo.toml 的 [workspace].members 中加入 "crates/<crate-name>"
```

## 构建 & 测试

```bash
cargo build --workspace
cargo test  --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all
```

## 计划中的初始 crate

> 仅作为规划占位，尚未实现。

- `scanner-core`：扫描调度内核与插件接口。
- `scanner-asset`：资产盘点采集器集合。
- `scanner-vuln`：漏洞/基线匹配引擎。
- `scanner-malware`：恶意代码扫描器。
- `scanner-cli`：可执行二进制入口。
