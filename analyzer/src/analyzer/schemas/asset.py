"""Asset findings reported by scanner.

`Asset` is a discriminated union keyed on `kind`. Adding a new asset
type means: (1) create a new `_AssetBase` subclass with a unique
`kind: Literal["..."]`, (2) add it to the `Asset` union, (3) bump the
contract version.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal

from pydantic import Field

from .common import MAX_NESTED_LIST_ITEMS, StrictModel, Timestamp, WireIdentifier


class CredentialKind(StrEnum):
    """Kind of credential material discovered on a host."""

    SSH_KEY = "ssh_key"
    API_KEY = "api_key"
    PASSWORD = "password"
    TOKEN = "token"


class _AssetBase(StrictModel):
    asset_id: WireIdentifier = Field(description="Stable identifier assigned by the scanner")
    parent_asset_id: WireIdentifier | None = Field(
        default=None,
        description="Parent asset_id when this row came from a nested (container rootfs) scan",
    )


class Package(_AssetBase):
    """An installed software package detected on the host."""

    kind: Literal["package"] = "package"
    name: str
    version: str
    source: str | None = Field(
        default=None,
        description="Package manager, e.g. apt / yum / pip / npm",
    )
    source_name: str | None = Field(
        default=None,
        description="Source package name when the package manager exposes it",
    )
    source_version: str | None = Field(
        default=None,
        description="Source package version used to build the installed binary package",
    )
    install_path: str | None = None
    ecosystem: str | None = Field(
        default=None,
        description=(
            "OSV ecosystem for vulnerability matching, e.g. 'Debian:12', "
            "'PyPI', 'npm'. When unset, detection falls back to the host's "
            "ecosystem derived from host.os."
        ),
    )


class Service(_AssetBase):
    """A system service (daemon) and its current run state."""

    kind: Literal["service"] = "service"
    name: str
    status: str = Field(description="running / stopped / failed / ...")
    exec_path: str | None = None


class Port(_AssetBase):
    """A listening network port and the process bound to it."""

    kind: Literal["port"] = "port"
    proto: Literal["tcp", "udp"]
    port: int = Field(ge=0, le=65535)
    listen_addr: str
    process_name: str | None = None
    pid: int | None = Field(default=None, ge=0)


class Account(_AssetBase):
    """A local user account present on the host."""

    kind: Literal["account"] = "account"
    username: str
    uid: int | None = None
    shell: str | None = None
    last_login: Timestamp | None = None


class Credential(_AssetBase):
    """A credential artifact found on the host, referenced only by its public fingerprint."""

    kind: Literal["credential"] = "credential"
    credential_kind: CredentialKind
    fingerprint: str = Field(
        description="Public fingerprint or hash; the secret itself MUST NEVER be transmitted",
    )
    path: str | None = None
    owner: str | None = None


class Container(_AssetBase):
    """A container workload discovered from static runtime metadata."""

    kind: Literal["container"] = "container"
    name: str
    runtime: str = Field(
        description="Container runtime, e.g. docker / podman / containerd / kubernetes",
    )
    image: str | None = Field(
        default=None, description="Image reference when known from static metadata"
    )
    status: str | None = Field(
        default=None, description="Last known state, e.g. running / exited / created"
    )
    container_id: str | None = Field(
        default=None, description="Runtime container id when available"
    )
    config_path: str | None = Field(
        default=None, description="Path to the static metadata file under scan_root"
    )
    rootfs_path: str | None = Field(
        default=None,
        description="Merged container rootfs path under scan_root when resolved statically",
    )


class Image(_AssetBase):
    """A container image present in local runtime storage (a pulled image that
    may never have run), discovered from static on-disk metadata."""

    kind: Literal["image"] = "image"
    name: str = Field(
        description="Primary image reference (e.g. nginx:1.25), or short image id when untagged"
    )
    runtime: str = Field(description="Image store / runtime, e.g. docker / podman")
    image_id: str | None = Field(
        default=None, description="Content-addressable image id (e.g. sha256:...)"
    )
    tags: list[str] = Field(
        default_factory=list,
        max_length=MAX_NESTED_LIST_ITEMS,
        description="All repository tags / names for this image",
    )
    created: str | None = Field(
        default=None, description="Image creation time from the image config, when available"
    )


class SecurityProduct(_AssetBase):
    """Endpoint security product and the protection state observed on a host."""

    kind: Literal["security_product"] = "security_product"
    name: str
    vendor: str
    status: Literal["active", "passive", "disabled", "unavailable"]
    mode: str | None = Field(
        default=None,
        description="Vendor-specific running mode, for example Normal or Passive Mode",
    )
    product_version: str | None = None
    engine_version: str | None = None
    signature_version: str | None = None
    signature_updated_at: Timestamp | None = None
    signatures_out_of_date: bool | None = None
    real_time_protection: bool | None = None
    behavior_monitor: bool | None = None
    ioav_protection: bool | None = None
    tamper_protection: bool | None = None
    cloud_protection: bool | None = None
    last_quick_scan_at: Timestamp | None = None
    last_full_scan_at: Timestamp | None = None


Asset = Annotated[
    Package | Service | Port | Account | Credential | Container | Image | SecurityProduct,
    Field(discriminator="kind"),
]
