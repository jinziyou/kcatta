"""Network flow events collected by collector."""

from __future__ import annotations

from typing import Literal

from pydantic import Field, IPvAnyAddress

from .common import StrictModel, Timestamp
from .threat import ThreatMatch


class FlowEvent(StrictModel):
    flow_id: str
    host_id: str = Field(
        description="Identifies the vantage point that observed the flow "
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
        description="IOC matches found by collector-side preliminary processing",
    )
