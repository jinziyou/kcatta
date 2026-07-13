# agent-collect-trace

kcatta 的 **collect/trace** 能力：核心 lib 按来源采集网络、文件与进程事实，CLI 组合采集、
可选 IOC detect 与输出。产出 [`TraceBatch`](../../contract/src/lib.rs)，现有 wire 与 CLI 参数不变。

核心接口为 `Source::collect(...) -> anyhow::Result<Vec<SourceResult>>`：一个来源一次可发出零到多组
`NetworkEvents` / `FileEvents` / `ProcessEvents`。三个 variant 分别进入 `TraceBatch` 的三个 Vec，
只保证每个同类 stream 内的 source/result/event 顺序，不定义跨 stream 全局顺序。当前来源模块为：

- `sources::NetworkSource`：由 `CaptureConfig` 选择 mock、pcap、eBPF cgroup-skb network
  （`--net-ebpf`）或 winnet 连接表（Windows IP Helper / Linux `/proc`）；
- feature-gated `sources::EbpfSource`：独立的文件/进程 tracepoint 来源（`--ebpf`），一次可发出
  file 与 process 两组结果。

CLI 是 composition/control plane，不是信息来源。

CLI 显式执行 `capture_sources`（collect）→ 可选 `agent_detect::ioc::ThreatFeed::enrich`（detect）。
显式 `--intel` 对任意后端生效；默认 mock 使用内置 demo feed；live 后端未给 feed 时保持原始事实；
`--no-intel` 强制只采集。`capture_batch` 是单 `NetworkSource` 便利入口；根级 `ThreatFeed` re-export、
`enrich_batch` 与 `run_capture_with_detect` 继续作为兼容 façade，因此 Cargo package 仍依赖 detect。

`TraceBatch` 现含**三条流**：`events`（网络五元组）、`file_events`（文件操作）、
`process_events`（进程调用）。网络流来自 `NetworkSource` 选择的 mock / pcap / eBPF network /
winnet；文件流与进程流来自可选 **`ebpf` feature** 的 `EbpfSource`。

**核心 Source 只采集；CLI 可组合本地 detect；crate 不上报**——`capture` 把 `TraceBatch` 写
stdout/`--out`；IOC 命中由 `agent-detect::ioc` 以 `ThreatMatch` 注入网络流事件，CVE 判定 /
跨源关联在 **analyzer** 侧；上报由统一 `agentd collect-trace --upload`
（或 `agentd run`）负责。Source/capture core 不含 HTTP；同 package 的 `cli::intel-sync` 使用
reqwest 下载 feed，feed 字节解析在 `intel::sync`。

## 子命令

- `capture` — 来源计划 → `capture_sources` →（按上述 feed 策略可选）`ThreatFeed::enrich` →
  `TraceBatch`。`--no-intel` 跳过 IOC。
  加 `--ebpf` 时额外启动 eBPF 追踪器，把文件 / 进程事件填入 `file_events` / `process_events`
  （`--ebpf-duration N` 控制采集时长）。
- `intel-sync` — 下载 IOC feed 写本地 JSON，供 `capture --intel` 只读匹配（离线友好）。
  feed 的 JSON 格式示例见 [`examples/threat-feed.json`](../../../examples/threat-feed.json)。

## eBPF feature

`ebpf` feature 开启时，eBPF 追踪器加载内核态程序（[`crates/ebpf`](../../ebpf) 的 `trace-ebpf` bin），把
进程 exec/exit 与 file-open（openat）tracepoint 挂上，从 ring buffer 抽取事件并填入
`TraceBatch.file_events` / `process_events`。事件结构是 `crates/ebpf` 的 `agent_ebpf` 共享 lib 里的
`#[repr(C)]` POD（`ExecEvent` / `ExitEvent` / `FileEvent` / `NetEvent`），内核→用户态经 ring buffer 传递。

- **构建期**：需 nightly toolchain + `rust-src` + `cargo install bpf-linker`。`trace-ebpf` 是
  workspace 成员但被排除在 `default-members` 之外，所以普通 `cargo build` / `cargo test` 不会编译它；
  仅在 `ebpf` feature 打开时由 agent-collect-trace 的 `build.rs` 用
  `rustup run nightly cargo build -Z build-std=core --target bpfel-unknown-none` + bpf-linker 编译，
  再用 `include_bytes_aligned!` 嵌入。若 toolchain 缺失，`build.rs` 产出空 stub + 警告，CI
  `--all-features` 仍绿；显式选择 `--ebpf` 时该 stub 会在运行期返回错误。
- **运行期**：需 CAP_BPF / root + 带 BTF 的内核。**不**需要 `CONFIG_BPF_LSM`（用的是 tracepoint）。
  feature opt-in 且特权；`EbpfSource` 加载失败会使本轮 `capture_sources` 返回错误，并不会自动
  降级为 network-only。需要 fallback 时不传 `--ebpf`。注意这是文件/进程 Source；
  `NetworkSource` 的 `--net-ebpf` 加载失败只会在同时启用 `pcap` feature 时回退到真实 pcap；
  未编译 pcap 时直接返回错误，绝不会把 live 请求静默替换为 synthetic mock。

`ebpf` feature 不在 musl deploy 构建里（deploy 仅含 agent-collect-host / agent-collect-trace / agentd）。

## 命令

```bash
cargo run -p agent-collect-trace -- capture --pretty                              # 只写文件，不上报
cargo run -p agent-collect-trace -- capture --intel data/feeds/feodo.json --out trace.json
cargo run -p agent-collect-trace -- capture --intel examples/threat-feed.json --pretty   # feed 格式示例
sudo cargo run -p agent-collect-trace --features pcap -- capture --pcap --iface eth0 --duration 30 --bpf "tcp port 443" --pretty
sudo cargo run -p agent-collect-trace --features ebpf -- capture --net-ebpf --duration 30 --pretty   # eBPF network；无 pcap fallback 时失败即报错
cargo run -p agent-collect-trace --features winnet -- capture --winnet --duration 5 --pretty         # 连接表
sudo cargo run -p agent-collect-trace --features ebpf -- capture --ebpf --ebpf-duration 30 --pretty   # 网络 + 文件 + 进程
cargo run -p agent-collect-trace -- intel-sync --source feodo --out data/feeds/feodo.json
cargo run -p agent-collect-trace -- intel-sync --source sslbl --source threatfox   # JA3 + 域名/ip:port，合并写 merged.json
cargo run -p agentd -- collect-trace --upload https://agents.example:10443 capture   # 生产需 FORM_AGENT_CERT/KEY/CA

cargo build -p agent-collect-trace --features ebpf       # 需 nightly + rust-src + bpf-linker
cargo test -p agent-collect-trace                        # mock 单元 + 契约测试
cargo test -p agent-collect-trace --features pcap --lib  # 含 pcap parse 单元测试
```

威胁情报 IOC 匹配（IP / 域名父域 / JA3）归 `agent-detect::ioc`，命中注入
`TraceEvent.threat_intel`。
契约校验：[`tests/contract.rs`](tests/contract.rs)（`TraceBatch` 三条流）。

**`intel-sync` 适配器**（abuse.ch，均无需鉴权）：`feodo`（IP C2 blocklist）、`sslbl`
（JA3 指纹黑名单——点亮 JA3 索引,abuse.ch 唯一 JA3 源,2021 后不再更新但仍服务）、
`threatfox`（domain + ip:port——点亮域名索引,url/hash 类型跳过）。多 `--source` 时按
`(type,value)` 去重合并。各适配器对不可信 feed 逐行/逐条容错:坏行跳过不毁整批。
