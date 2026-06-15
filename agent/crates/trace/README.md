# agent-trace

kcatta 的**追踪**能力：一个 crate = lib（网络捕获 + IOC 匹配 + feed 解析，被 guard 的 network
传感器复用；可选 eBPF 追踪器）+ `agent-trace` 二进制。产出 [`TraceBatch`](../contract/src/lib.rs)。

`TraceBatch` 现含**三条流**：`events`（网络五元组）、`file_events`（文件操作）、
`process_events`（进程调用）。网络流来自 `mock`（默认）/ `pcap`（feature）捕获；文件流与进程流
来自可选 **`ebpf` feature** 的 eBPF 追踪器。

**只采集、不分析、不上报**——`capture` 把 `TraceBatch` 写 stdout/`--out`；IOC 命中以 `ThreatMatch`
注入网络流事件，CVE 判定 / 跨源关联在 **analyzer** 侧；上报由统一 `agentd trace --upload`
（或 `agentd run`）负责。lib **不含 reqwest**：`intel-sync` 的 feed HTTP 下载在 bin 的 `cli` 里
（本地 `http_get_text`），feed 字节解析在 lib 的 `intel::sync`。

## 子命令

- `capture` — 捕获一轮（网络：`mock` 默认 / `pcap` feature 实时）→ IOC 匹配 → `TraceBatch`。
  加 `--ebpf` 时额外启动 eBPF 追踪器，把文件 / 进程事件填入 `file_events` / `process_events`
  （`--ebpf-duration N` 控制采集时长）。
- `intel-sync` — 下载 IOC feed 写本地 JSON，供 `capture --intel` 只读匹配（离线友好）。
  feed 的 JSON 格式示例见 [`examples/threat-feed.json`](../../examples/threat-feed.json)。

## eBPF feature

`ebpf` feature 开启时，eBPF 追踪器加载内核态程序（[`crates/ebpf`](../ebpf) 的 `trace-ebpf` bin），把
进程 exec/exit 与 file-open（openat）tracepoint 挂上，从 ring buffer 抽取事件并填入
`TraceBatch.file_events` / `process_events`。事件结构是 `crates/ebpf` 的 `agent_ebpf` 共享 lib 里的
`#[repr(C)]` POD（`ExecEvent` / `ExitEvent` / `FileEvent`），内核→用户态经 ring buffer 传递。

- **构建期**：需 nightly toolchain + `rust-src` + `cargo install bpf-linker`。`trace-ebpf` 是
  workspace 成员但被排除在 `default-members` 之外，所以普通 `cargo build` / `cargo test` 不会编译它；
  仅在 `ebpf` feature 打开时由 agent-trace 的 `build.rs` 用
  `rustup run nightly cargo build -Z build-std=core --target bpfel-unknown-none` + bpf-linker 编译，
  再用 `include_bytes_aligned!` 嵌入。若 toolchain 缺失，`build.rs` 产出空 stub + 警告，CI
  `--all-features` 仍绿（此时 eBPF 后端运行时报错，用户态优雅回退到 pcap/mock）。
- **运行期**：需 CAP_BPF / root + 带 BTF 的内核。**不**需要 `CONFIG_BPF_LSM`（用的是 tracepoint）。
  feature opt-in 且特权，缺失能力时优雅回退——网络流照常工作，文件 / 进程流为空。

`ebpf` feature 不在 musl deploy 构建里（deploy 仅含 agent-host / agent-trace / agentd）。

## 命令

```bash
cargo run -p agent-trace -- capture --pretty                              # 只写文件，不上报
cargo run -p agent-trace -- capture --intel data/feeds/feodo.json --out trace.json
cargo run -p agent-trace -- capture --intel examples/threat-feed.json --pretty   # feed 格式示例
sudo cargo run -p agent-trace --features pcap -- capture --pcap --iface eth0 --duration 30 --bpf "tcp port 443" --pretty
sudo cargo run -p agent-trace --features ebpf -- capture --ebpf --ebpf-duration 30 --pretty   # 网络 + 文件 + 进程
cargo run -p agent-trace -- intel-sync --source feodo --out data/feeds/feodo.json
cargo run -p agentd -- trace --upload http://127.0.0.1:8000 capture   # 上报经统一 agentd

cargo build -p agent-trace --features ebpf       # 需 nightly + rust-src + bpf-linker
cargo test -p agent-trace                        # mock 单元 + 契约测试
cargo test -p agent-trace --features pcap --lib  # 含 pcap parse 单元测试
```

威胁情报 IOC 匹配（IP / 域名父域 / JA3）在网络流域内完成，命中注入 `TraceEvent.threat_intel`。
契约校验：[`tests/contract.rs`](tests/contract.rs)（`TraceBatch` 三条流）。
