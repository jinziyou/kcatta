# agent-cli-common

posture agent 三个二进制的**共享 CLI 底座**——纯工具、无领域逻辑，零内部依赖（不可能成环）。

| 模块 | 职责 |
| --- | --- |
| `output` | 把可序列化值按 JSON 写到文件或 stdout，遵循 `--pretty`（各二进制输出路径复用） |
| `http`（feature `http`，默认开） | 阻塞 reqwest client 构造 + `get_text`，供 `posture-flow intel-sync` 下载 IOC feed。fusion **上报**在 `agent-ingest`，不在这里 |

```bash
cargo test -p agent-cli-common
# 仅要 output、不牵 reqwest：
cargo build -p agent-cli-common --no-default-features
```
