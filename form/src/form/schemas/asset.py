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

from .common import StrictModel, Timestamp


class CredentialKind(StrEnum):
    SSH_KEY = "ssh_key"
    API_KEY = "api_key"
    PASSWORD = "password"
    TOKEN = "token"


class _AssetBase(StrictModel):
    asset_id: str = Field(description="Stable identifier assigned by the scanner")


class Package(_AssetBase):
    kind: Literal["package"] = "package"
    name: str
    version: str
    source: str | None = Field(
        default=None,
        description="Package manager, e.g. apt / yum / pip / npm",
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
    kind: Literal["service"] = "service"
    name: str
    status: str = Field(description="running / stopped / failed / ...")
    exec_path: str | None = None


class Port(_AssetBase):
    kind: Literal["port"] = "port"
    proto: Literal["tcp", "udp"]
    port: int = Field(ge=0, le=65535)
    listen_addr: str
    process_name: str | None = None
    pid: int | None = Field(default=None, ge=0)


class Account(_AssetBase):
    kind: Literal["account"] = "account"
    username: str
    uid: int | None = None
    shell: str | None = None
    last_login: Timestamp | None = None


class Credential(_AssetBase):
    kind: Literal["credential"] = "credential"
    credential_kind: CredentialKind
    fingerprint: str = Field(
        description="Public fingerprint or hash; the secret itself MUST NEVER be transmitted",
    )
    path: str | None = None
    owner: str | None = None


Asset = Annotated[
    Package | Service | Port | Account | Credential,
    Field(discriminator="kind"),
]
