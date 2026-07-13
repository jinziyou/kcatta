# collect

Agent 的 **Collect** 层按信息来源组织，只产出资产侧事实或尚未检测的观测事件：

| crate / source | 信息来源 | 零到多结果 |
| --- | --- | --- |
| `host` / `FilesystemSource` | 扫描根中的文件、包库、服务/账户/容器元数据 | `HostInfo` + 多个非空 `Asset` 批次 |
| `trace` / `NetworkSource` | `CaptureConfig` 选择 mock/pcap、eBPF network 或 winnet 连接表 | 网络事件组 |
| `trace` / `EbpfSource`（feature `ebpf`） | 内核 tracepoint/ring buffer | 进程事件组 + 文件事件组 |

两条 collect 核心接口都允许一个 Source 每轮返回 `Result<Vec<SourceResult>>`，即成功时零到多组
结果。host 保持结果/资产顺序；trace 的三个 variant 分别进入三个 Vec，仅保证每个同类 stream 内的
source/result/event 顺序，不定义跨 stream 全局顺序。空结果不会改变 envelope。

CLI 与 `agentd` 属于 composition/control plane：它们选择来源、可选调用 `agent-detect`、组装/输出或
上报 envelope，不是信息来源。为保持现有 CLI 与调用方兼容，collect packages 仍保留
`run_scan_with_detect`、`enrich_batch`、`run_capture_with_detect` 等组合 façade，因此 Cargo 层面仍可能
存在 collect → detect 依赖；核心 Source 路径不产生 `Vulnerability` / `ThreatMatch`。

参见 [`host/README.md`](host/README.md)、[`trace/README.md`](trace/README.md) 与
[`../../docs/ARCHITECTURE.md`](../../docs/ARCHITECTURE.md)。
