# agent-respond

kcatta 的**实时防护**能力：一个 crate = lib（防护引擎）+ `agent-respond` 守护进程。流水线：

```
sensor ──Detection──▶ decide ──Action──▶ respond(+safety) ──▶ report ──GuardEventBatch──▶ analyzer / 本地 NDJSON
```

`Detection` 物理定义在 [`agent-contract`](../contract/src/detection.rs) 的内部阶段契约（非 Serde /
非 JSON wire）；`agent-detect` 与本 crate 均 re-export，不另定义副本。作为持续运行的部署
composition，本 crate 的 sensor adapters 负责读取事件：network/onaccess 调 detect 窄 API，
FIM/behavior 在 adapter 内直接规范化 Detection；decide/safety/action/report 边界仍独立。

- **检测**：`fim` 默认开，Linux 用 inotify、Windows 用 `notify`/ReadDirectoryChangesW；Linux 的
  `behavior`（/proc）默认开，`onaccess`（fanotify + 复用 `agent-detect::malware`，需
  `CAP_SYS_ADMIN`）、`network`/`ids`
  （复用 `agent-collect-trace` 捕获，再调用 `agent_detect::network::detect`）为可选 feature。
  IOC enrich 与轻量 IDS 规则均在 detect；respond 不实现第二份网络检测规则。
  network sensor 始终使用真实数据：`pcap` feature 存在时抓包，否则用 `winnet` 的 OS 连接表，
  不使用 synthetic mock。配置了 `network.intel` 时 feed 读取/解析失败即 fatal；未配置 feed 只允许
  `ids` feature 的 IDS-only 模式（空 IOC feed），否则视为配置错误。采集错误同样 fatal；单次阻塞
  捕获切片最多 5 秒，避免 shutdown 被任意大的窗口配置拖住。
- **处置**：默认 `monitor`（只检测上报）。deny-open / quarantine / netblock / kill 均需
  `enforce`、对应单动作开关、严重度阈值与 safety 全部通过；v1 enforce 提供阻断打开、可逆隔离
  与网络阻断，`kill` 仅搭骨架默认关闭。
- **安全**：关键路径 / 白名单 / PID1 / self 否决；普通 responder Action 有幂等 ledger（防抖动）；
  同步 deny-open 以 `pre_applied` 结果进入 pipeline；全部结果本地审计落盘。
  网络 IOC 只有命中 `dst_ip` 的 IP 指标能授权出站封禁；source-IP、domain、JA3 仅告警。
  当前端口 IDS 规则方向不充分，保留原始 src/dst 报告但不自动授权任一 IP 封禁。

on-access 另有显式 `response.allow_block_open`（默认 `false`；旧 JSON 缺字段仍安全兼容）。只有
`mode=enforce` 且该 gate 打开时才订阅 `FAN_OPEN_PERM`；命中后还要通过 severity threshold 与文件
safety veto 才写 `FAN_DENY`。扫描错误、空/超大文件、未授权或 safety 否决均 `FAN_ALLOW`；deny
写失败会立即尝试 allow；若 allow 写失败则 sensor fatal、关闭 fanotify group，不会伪装健康。
同步结果以 `SensorEvent.pre_applied` 交给 pipeline，准确上报
`BlockedOpen/Success|Failure`，且不会再触发第二次 quarantine。

启用的 FIM/on-access 若没有任何可监听路径会启动失败；配置启用了当前 build/platform 不支持的
sensor 也会明确报错。monitor/detect-only 不创建或重置 nft 表；enforce 的自有 nft 表在正常退出
时删除。最终所有 report sink 都失败时进程以非零状态报告未持久化事件数。

## 网络阻断后端：eBPF（feature `ebpf`）/ nft

网络阻断（netblock）处置默认走 `nft`。开启 **`ebpf` feature** 后，改用内核 **cgroup
connect4/6 eBPF 拦截器**（`agent-ebpf` crate 的 `guard-ebpf` bin，位于 `crates/ebpf`，
`guard_connect4`/`guard_connect6` 程序，依据 `BLOCKED_V4`/`BLOCKED_V6` map 拒绝目的 IP），
在 socket 层直接 deny 出站连接。该后端
**无需 `CONFIG_BPF_LSM`**（用的是 cgroup-connect，而非 LSM hook），运行时只需 cgroup-v2 +
`CAP_BPF`/root。任何加载/挂载失败都会**回退到 `nft`**，处置语义不变。

`guard-ebpf` 是 `agent-ebpf` crate（`crates/ebpf`）的 `no_std` bpf-target-only bin；该 crate
作为 workspace MEMBER 但其 bin 被排除在 `default-members` 之外，宿主 `cargo build`/`cargo test`
永不编译它；仅当 `ebpf` feature 打开时，由 `agent-respond` 的 `build.rs` 经 `rustup run nightly
cargo build -Z build-std=core --target bpfel-unknown-none` + `bpf-linker` 编译，再用
`include_bytes_aligned!` 嵌入。若工具链
缺失，`build.rs` 输出空桩 + warning（保证 CI `--all-features` 仍绿；此时 eBPF 后端在运行时报错并
回退到 nft）。注意 `ebpf` **不在** `all` 里，故 `cargo test --features all` 仍免工具链。

依赖包括 Linux 的安全 `nix` wrapper（fanotify/inotify/signalfd/kill）与 Windows target 的安全
`notify`（ReadDirectoryChangesW）/`ctrlc` wrapper，满足 `unsafe_code = "deny"`；无 tokio/procfs。
respond 默认 fim+behavior 只从 `agent-contract` 获得 `Detection`，不拉 detect 引擎；feature
`onaccess` / `network` 才启用可选 `agent-detect`，network 还依赖 `agent-collect-trace`；
`ebpf` feature 经 `build.rs` 嵌入 `guard-ebpf`，无新增运行期 crate。

```bash
cargo run -p agent-respond -- --stdout                # 默认 monitor（FIM+行为），只写本地，无需 root
cargo run -p agent-respond -- --config /etc/kcatta/guard.json --stdout   # 独立 bin：本地 NDJSON/stdout，不上报
cargo run -p agentd -- respond --upload https://agents.example:10443 --stdout   # 生产需 FORM_AGENT_CERT/KEY/CA
cargo test -p agent-respond --features all            # 流水线 + 安全 + 全传感器（无需 root，不含 ebpf）
cargo build -p agent-respond --no-default-features --features fim   # 精简：仅 FIM
cargo build -p agent-respond --features all           # 全机制（+pcap 需 libpcap-dev）
cargo build -p agent-respond --features ebpf          # 启用 eBPF 网络阻断后端（需 nightly+rust-src+bpf-linker）
```

> eBPF 构建期需 nightly + `rust-src` + `cargo install bpf-linker`；运行期需 `CAP_BPF`/root +
> cgroup-v2。该 feature 为 opt-in 且需特权，工具链/内核不满足时优雅回退到 nft；musl 部署构建不含 ebpf。

配置（JSON，缺省走安全默认）：`mode`(monitor|enforce)、各传感器开关与监听路径
（`onaccess.signatures` 加载额外查毒签名，可用 `onaccess.signatures_sha256` 绑定 64 位小写
SHA-256；network IOC 同理可用 `network.intel_sha256` 绑定 `network.intel`，格式/摘要不匹配均
fatal）、`response`（`allow_block_open`/`allow_quarantine`/
`allow_netblock` 默认关、
`severity_threshold`、`critical_paths`、`vault_dir`）、`report`（`audit_log`/
`audit_max_bytes`/`stdout`/`batch_max`/`flush_secs`）。`audit_max_bytes` 默认 64 MiB；追加会在独占锁内
检查预算，达到硬上限时原地清空旧内容并保留最新完整 batch，且每个 sink 只告警一次。单条 batch
本身超过预算时受控丢弃本地副本并只告警一次；不会因事件洪泛无限占用审计文件或错误日志空间。

Unix 本地审计逐级拒绝 symlink 与不可信祖先；父目录/日志分别要求 effective-UID owner、`0700`/
`0600`，日志还要求 regular file 且 `nlink=1`。旧 `0755`/`0644` 布局只有在同 owner、group/world
不可写且父目录不含其它条目时，才会在完整验证后通过已打开 fd 收紧权限。打开日志使用
`O_NOFOLLOW`，长度检查、原地轮转、追加与 `sync_data` 位于独占文件锁内。默认路径为
`/var/log/kcatta/guard-audit.ndjson`。

Windows/其它无法由标准库证明 owner-only DACL、reparse ancestry 与等价锁边界的平台默认禁用本地
审计并打印明确告警，不创建 `%ProgramData%\kcatta\guard-audit.ndjson`；Form sink 或显式 stdout
仍正常使用。若没有其它可用 sink，Reporter 自动回退 stdout，防护进程不会仅因本地审计不可验证
而启动失败。
