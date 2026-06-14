# agent-guard

kcatta 的**实时防护**能力：一个 crate = lib（防护引擎）+ `agent-guard` 守护进程。流水线：

```
sensor ──Detection──▶ decide ──Action──▶ respond(+safety) ──▶ report ──GuardEventBatch──▶ analyzer / 本地 NDJSON
```

- **检测**（Linux）：`fim`（inotify 文件完整性）、`behavior`（/proc 进程行为）默认开；
  `onaccess`（fanotify + 复用 `agent-host` 的内置查毒，需 `CAP_SYS_ADMIN`）、`network`/`ids`
  （复用 `agent-trace` 捕获 + `ThreatFeed` IOC 匹配）为可选 feature。
- **处置**：默认 `monitor`（只检测上报）。`enforce` + 单动作开关 + 严重度阈值 + 安全否决全部
  满足才动作；v1 enforce 限可逆隔离（永不删除、不碰系统前缀 / 运行中-mmap 文件）、网络阻断、
  阻断打开（FAN_DENY）；`kill` 仅搭骨架默认关闭。
- **安全**：关键路径 / 白名单 / PID1 / self 否决 + 幂等 ledger（防抖动）+ 本地审计落盘。

## 网络阻断后端：eBPF（feature `ebpf`）/ nft

网络阻断（netblock）处置默认走 `nft`。开启 **`ebpf` feature** 后，改用内核 **cgroup
connect4/6 eBPF 拦截器**（`crates/guard-ebpf`，`guard_connect4`/`guard_connect6` 程序，依据
`BLOCKED_V4`/`BLOCKED_V6` map 拒绝目的 IP），在 socket 层直接 deny 出站连接。该后端
**无需 `CONFIG_BPF_LSM`**（用的是 cgroup-connect，而非 LSM hook），运行时只需 cgroup-v2 +
`CAP_BPF`/root。任何加载/挂载失败都会**回退到 `nft`**，处置语义不变。

`guard-ebpf` 是 `no_std` 的 bpf-target crate，作为 workspace MEMBER 但被排除在
`default-members` 之外，宿主 `cargo build`/`cargo test` 永不编译它；仅当 `ebpf` feature 打开
时，由 `agent-guard` 的 `build.rs` 经 `rustup run nightly cargo build -Z build-std=core
--target bpfel-unknown-none` + `bpf-linker` 编译，再用 `include_bytes_aligned!` 嵌入。若工具链
缺失，`build.rs` 输出空桩 + warning（保证 CI `--all-features` 仍绿；此时 eBPF 后端在运行时报错并
回退到 nft）。注意 `ebpf` **不在** `all` 里，故 `cargo test --features all` 仍免工具链。

依赖全部走已缓存 crate：`nix`（fanotify/inotify/signalfd/kill，安全封装，满足 `unsafe_code = "deny"`）、
`sha2`、`std::sync::mpsc`、`/proc` 经 `std::fs`、JSON 配置经 `serde_json`——无 tokio/notify/procfs。
guard 经 feature 可选依赖 `agent-host`（onaccess）/ `agent-trace`（network），默认不牵入；
`ebpf` feature 经 `build.rs` 嵌入 `guard-ebpf`，无新增运行期 crate。

```bash
cargo run -p agent-guard -- --stdout                # 默认 monitor（FIM+行为），只写本地，无需 root
cargo run -p agent-guard -- --config /etc/kcatta/guard.json --stdout   # 独立 bin：本地 NDJSON/stdout，不上报
cargo run -p agentd -- guard --upload http://127.0.0.1:8000 --stdout   # 上报经统一 agent
cargo test -p agent-guard --features all            # 流水线 + 安全 + 全传感器（无需 root，不含 ebpf）
cargo build -p agent-guard --no-default-features --features fim   # 精简：仅 FIM
cargo build -p agent-guard --features all           # 全机制（+pcap 需 libpcap-dev）
cargo build -p agent-guard --features ebpf          # 启用 eBPF 网络阻断后端（需 nightly+rust-src+bpf-linker）
```

> eBPF 构建期需 nightly + `rust-src` + `cargo install bpf-linker`；运行期需 `CAP_BPF`/root +
> cgroup-v2。该 feature 为 opt-in 且需特权，工具链/内核不满足时优雅回退到 nft；musl 部署构建不含 ebpf。

配置（JSON，缺省走安全默认）：`mode`(monitor|enforce)、各传感器开关与监听路径
（`onaccess.signatures` 加载额外查毒签名）、`response`（`allow_quarantine`/`allow_netblock` 默认关、
`severity_threshold`、`critical_paths`、`vault_dir`）、`report`（`audit_log`/`stdout`/`batch_max`/`flush_secs`）。
