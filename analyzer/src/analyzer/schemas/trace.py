"""Trace events collected by the eBPF collector: network, file, and process.

`TraceEvent` is the network (5-tuple) trace; `FileTraceEvent` and
`ProcessTraceEvent` are the file-operation and process-lifecycle streams the
eBPF tracer adds. All three travel in one :class:`~.envelope.TraceBatch`.
"""

from __future__ import annotations

from typing import Literal

from pydantic import Field, IPvAnyAddress

from .common import (
    MAX_NESTED_LIST_ITEMS,
    MAX_THREAT_MATCHES_PER_EVENT,
    CorrelationIdentifier,
    StrictModel,
    Timestamp,
)
from .threat import ThreatMatch


class TraceEvent(StrictModel):
    """A single observed network trace with traffic stats and any IOC matches."""

    trace_id: CorrelationIdentifier
    host_id: CorrelationIdentifier = Field(
        description="Identifies the vantage point that observed the trace "
        "(typically the collector host or interface)",
    )

    start_ts: Timestamp
    end_ts: Timestamp

    proto: Literal["tcp", "udp", "icmp", "other"]
    src_ip: IPvAnyAddress
    src_port: int | None = Field(default=None, ge=0, le=65535)
    dst_ip: IPvAnyAddress
    dst_port: int | None = Field(default=None, ge=0, le=65535)

    bytes_sent: int = Field(ge=0)
    bytes_recv: int = Field(ge=0)
    packets_sent: int = Field(default=0, ge=0)
    packets_recv: int = Field(default=0, ge=0)

    app_proto: str | None = Field(
        default=None,
        description="Detected application protocol: HTTP / DNS / TLS / SSH / ...",
    )
    dns_query: str | None = None
    tls_sni: str | None = None
    ja3: str | None = Field(default=None, description="JA3 TLS client fingerprint")

    threat_intel: list[ThreatMatch] = Field(
        default_factory=list,
        max_length=MAX_THREAT_MATCHES_PER_EVENT,
        description="IOC matches found by collector-side preliminary processing",
    )


class FileTraceEvent(StrictModel):
    """A single file-system operation observed by the eBPF tracer.

    Captured from kernel tracepoints / LSM hooks (open, write, unlink, rename,
    chmod, ...) and attributed to the process that performed it.
    """

    trace_id: CorrelationIdentifier
    host_id: CorrelationIdentifier = Field(description="Vantage point that observed the operation.")
    ts: Timestamp

    pid: int = Field(ge=0, description="PID of the process performing the operation.")
    comm: CorrelationIdentifier = Field(
        description="Short process name (kernel TASK_COMM, <=16 bytes)."
    )
    uid: int | None = Field(default=None, ge=0, description="Acting user id when known.")

    op: Literal["open", "create", "write", "unlink", "rename", "chmod", "link", "symlink", "mkdir"]
    path: str = Field(description="Primary target path of the operation.")
    target_path: str | None = Field(
        default=None, description="Second path for link / rename operations."
    )
    ret: int | None = Field(
        default=None, description="Syscall return value (fd or -errno) when captured."
    )

    threat_intel: list[ThreatMatch] = Field(
        default_factory=list,
        max_length=MAX_THREAT_MATCHES_PER_EVENT,
        description="IOC matches (known-bad path / hash) from collector-side processing.",
    )


class ProcessTraceEvent(StrictModel):
    """A process lifecycle event observed by the eBPF tracer.

    Captured from sched_process_exec / sched_process_exit tracepoints: program
    invocations (execve) and their exits, with parent and cgroup attribution.
    """

    trace_id: CorrelationIdentifier
    host_id: CorrelationIdentifier = Field(description="Vantage point that observed the event.")
    ts: Timestamp

    event_type: Literal["exec", "exit"]
    pid: int = Field(ge=0)
    ppid: int | None = Field(default=None, ge=0, description="Parent PID when known.")
    uid: int | None = Field(default=None, ge=0, description="Acting user id when known.")

    comm: CorrelationIdentifier = Field(
        description="Short process name (kernel TASK_COMM, <=16 bytes)."
    )
    exe: str | None = Field(default=None, description="Resolved executable path for exec events.")
    argv: list[str] = Field(
        default_factory=list,
        max_length=MAX_NESTED_LIST_ITEMS,
        description="Command-line arguments for exec events.",
    )
    cgroup: str | None = Field(
        default=None, description="cgroup / container id for workload attribution."
    )
    exit_code: int | None = Field(default=None, description="Exit code for exit events.")

    threat_intel: list[ThreatMatch] = Field(
        default_factory=list,
        max_length=MAX_THREAT_MATCHES_PER_EVENT,
        description="IOC matches (known-bad binary hash / name) from collector-side processing.",
    )
