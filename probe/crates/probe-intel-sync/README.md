# probe-intel-sync

把远程威胁情报 IOC feed 下载为本地 JSON，供 [`probe-flow-cli`](../probe-flow-cli/README.md) `--intel` 离线匹配（bin: **`probe-intel-sync`**）。

与 form 的 `form-osv-sync` 一样**离线友好**：同步是独立、可定时（cron / systemd timer）的步骤；采集时只读本地库，匹配不联网。

## 二进制

```bash
# 同步 abuse.ch Feodo Tracker → data/feeds/feodo.json
cargo run -p probe-intel-sync -- --source feodo --out data/feeds/feodo.json

# 用同步好的库做匹配
cargo run -p probe-flow-cli -- --intel data/feeds/feodo.json --upload http://127.0.0.1:8000
```

## 参数

| 参数 | 说明 |
| --- | --- |
| `--source <NAME>` | feed 适配器，可重复；多源时输出合并。当前支持：`feodo` |
| `-o, --out <PATH>` | 输出 JSON（默认 `data/feeds/<source>.json`，多源为 `data/feeds/merged.json`） |
| `--feodo-url <URL>` | 覆盖 `feodo` 默认下载地址 |
| `--timeout <SEC>` | HTTP 超时秒数（默认 120） |

## 情报源

| source | 来源 | 映射 |
| --- | --- | --- |
| `feodo` | abuse.ch Feodo Tracker | 每条 IP → `type=ip` / `category=c2` / `severity=high` / `source=abuse.ch-feodo` |

新增情报源：在 [`probe-flow/src/intel/sync/`](../probe-flow/src/intel/sync/) 实现适配器（参考 `feodo.rs`），再接入 `--source` 分发。详见 [`../../docs/CONTRIBUTING.md`](../../docs/CONTRIBUTING.md)「新增情报源（网络域）」。
