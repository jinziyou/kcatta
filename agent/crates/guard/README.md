# agent-guard

kcatta 的**实时防护**能力：一个 crate = lib（防护引擎）+ `agent-guard` 守护进程。流水线：

```
sensor ──Detection──▶ decide ──Action──▶ respond(+safety) ──▶ report ──GuardEventBatch──▶ analyzer / 本地 NDJSON
```

- **检测**（Linux）：`fim`（inotify 文件完整性）、`behavior`（/proc 进程行为）默认开；
  `onaccess`（fanotify + 复用 `agent-host` 的内置查毒，需 `CAP_SYS_ADMIN`）、`network`/`ids`
  （复用 `agent-flow` 捕获 + `ThreatFeed` IOC 匹配）为可选 feature。
- **处置**：默认 `monitor`（只检测上报）。`enforce` + 单动作开关 + 严重度阈值 + 安全否决全部
  满足才动作；v1 enforce 限可逆隔离（永不删除、不碰系统前缀 / 运行中-mmap 文件）、网络阻断、
  阻断打开（FAN_DENY）；`kill` 仅搭骨架默认关闭。
- **安全**：关键路径 / 白名单 / PID1 / self 否决 + 幂等 ledger（防抖动）+ 本地审计落盘。

依赖全部走已缓存 crate：`nix`（fanotify/inotify/signalfd/kill，安全封装，满足 `unsafe_code = "deny"`）、
`sha2`、`std::sync::mpsc`、`/proc` 经 `std::fs`、JSON 配置经 `serde_json`——无 tokio/notify/procfs。
guard 经 feature 可选依赖 `agent-host`（onaccess）/ `agent-flow`（network），默认不牵入。

```bash
cargo run -p agent-guard -- --stdout                # 默认 monitor（FIM+行为），只写本地，无需 root
cargo run -p agent-guard -- --config /etc/kcatta/guard.json --stdout   # 独立 bin：本地 NDJSON/stdout，不上报
cargo run -p agent -- guard --upload http://127.0.0.1:8000 --stdout   # 上报经统一 agent
cargo test -p agent-guard --features all            # 流水线 + 安全 + 全传感器（无需 root）
cargo build -p agent-guard --no-default-features --features fim   # 精简：仅 FIM
cargo build -p agent-guard --features all           # 全机制（+pcap 需 libpcap-dev）
```

配置（JSON，缺省走安全默认）：`mode`(monitor|enforce)、各传感器开关与监听路径
（`onaccess.signatures` 加载额外查毒签名）、`response`（`allow_quarantine`/`allow_netblock` 默认关、
`severity_threshold`、`critical_paths`、`vault_dir`）、`report`（`audit_log`/`stdout`/`batch_max`/`flush_secs`）。
