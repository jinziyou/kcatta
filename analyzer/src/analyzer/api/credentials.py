"""Access-credential management — lifecycle for the durable keys targets use.

kcatta does not keep a separate credential vault: a target's durable secret is a
tool-managed SSH key on the analyzer host (or an operator-provided identity-file
path). This router exposes the *management* of those existing keys — list,
test, rotate, revoke — derived from the target registry, without ever persisting
a new plaintext secret.

Credentials are addressed by a stable ``credential_id`` derived from the key
path, and every operation is resolved back to a *registered* target: the API can
only act on credentials some target actually references, never an arbitrary host.
"""

from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request, status

from ..deploy import bootstrap
from ..schemas import (
    CredentialActionRequest,
    CredentialInfo,
    CredentialMode,
    CredentialRevokeResult,
    CredentialTestResult,
    ScanTarget,
)
from .scans import _dedup_newest

router = APIRouter(tags=["credentials"])


def _credential_id(group_key: str) -> str:
    """Stable, URL-safe id for a credential (non-secret hash of its logical identity)."""
    return "cred-" + hashlib.sha256(group_key.encode("utf-8")).hexdigest()[:16]


def _key_path_for(target: ScanTarget) -> str | None:
    """Server-side key path a target's durable credential lives at, or None.

    ``managed_key`` → the deterministic managed-key path; ``identity`` → the
    operator path. ``none`` (local) and malformed addresses have no manageable
    credential.
    """
    try:
        if target.credential_mode == CredentialMode.MANAGED_KEY:
            return str(bootstrap.managed_key_path(target.address, target.port))
        if target.credential_mode == CredentialMode.IDENTITY and target.identity_path:
            return target.identity_path
    except ValueError:
        # Address not in user@host form → can't resolve a managed key path.
        return None
    return None


def _build_credentials(records: list[dict]) -> list[CredentialInfo]:
    """Group registered targets into the distinct credentials they reference."""
    groups: dict[str, dict] = {}
    for record in records:
        try:
            target = ScanTarget.model_validate(record)
        except Exception:  # noqa: BLE001 - a corrupt row must not break the listing
            continue
        key_path = _key_path_for(target)
        if key_path is None:
            continue
        # Group by the LOGICAL identity (mode + endpoint + key), not the key path
        # alone: two targets that share an identity file but differ by address must
        # stay distinct rows (else test/rotate/revoke would act on only the first
        # address), and the sanitized managed-key filename could otherwise collide
        # two genuinely different endpoints.
        gkey = f"{target.credential_mode.value}:{target.address}:{target.port}:{key_path}"
        group = groups.setdefault(
            gkey,
            {
                "gkey": gkey,
                "credential_mode": target.credential_mode,
                "address": target.address,
                "port": target.port,
                "key_path": key_path,
                "target_ids": [],
                "target_names": [],
            },
        )
        group["target_ids"].append(target.target_id)
        group["target_names"].append(target.name)

    out: list[CredentialInfo] = []
    for group in groups.values():
        key = Path(group["key_path"])
        exists = key.is_file()
        out.append(
            CredentialInfo(
                credential_id=_credential_id(group["gkey"]),
                credential_mode=group["credential_mode"],
                address=group["address"],
                port=group["port"],
                key_path=group["key_path"],
                exists=exists,
                fingerprint=bootstrap.key_fingerprint(key) if exists else None,
                target_ids=group["target_ids"],
                target_names=group["target_names"],
            )
        )
    return out


def _list_credentials(request: Request) -> list[CredentialInfo]:
    # Over-fetch rows then dedup to newest-per-target: the store is append-only and
    # re-registrations append rows, so a fixed window counts rows, not distinct
    # targets. A wide window keeps churned-but-current targets from silently
    # dropping out of credential resolution (test/rotate/revoke go through here).
    records = _dedup_newest(request.app.state.scan_target_store.tail(5000), "target_id")
    return _build_credentials(records)


def _resolve(request: Request, credential_id: str) -> CredentialInfo:
    for cred in _list_credentials(request):
        if cred.credential_id == credential_id:
            return cred
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="credential not found")


def _require_managed(cred: CredentialInfo, action: str) -> None:
    if cred.credential_mode != CredentialMode.MANAGED_KEY:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"only managed-key credentials can be {action}; "
                f"identity keys are operator-managed (mode is {cred.credential_mode.value})"
            ),
        )


@router.get("/credentials", response_model=list[CredentialInfo])
async def list_credentials(request: Request) -> list[CredentialInfo]:
    """List the durable access credentials registered targets reference."""
    return _list_credentials(request)


@router.get("/credentials/{credential_id}", response_model=CredentialInfo)
async def get_credential(credential_id: str, request: Request) -> CredentialInfo:
    """Fetch a single credential's status (mode, fingerprint, targets using it)."""
    return _resolve(request, credential_id)


@router.post("/credentials/{credential_id}/test", response_model=CredentialTestResult)
async def test_credential(credential_id: str, request: Request) -> CredentialTestResult:
    """Probe whether the credential can still authenticate to its target."""
    cred = _resolve(request, credential_id)
    if not cred.exists:
        return CredentialTestResult(ok=False, detail="key is missing on the analyzer host")
    identity = Path(cred.key_path) if cred.credential_mode == CredentialMode.IDENTITY else None
    try:
        ok = await asyncio.to_thread(
            bootstrap.can_authenticate, cred.address, cred.port, identity
        )
    except ValueError as exc:  # malformed address
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc
    return CredentialTestResult(
        ok=ok,
        detail="key authentication succeeded" if ok else "key authentication failed",
    )


@router.post("/credentials/{credential_id}/rotate", response_model=CredentialInfo)
async def rotate_credential(
    credential_id: str, payload: CredentialActionRequest, request: Request
) -> CredentialInfo:
    """Rotate a managed key: generate a fresh keypair, install + verify, swap in.

    Reuses the current key to authenticate when it still works (no password);
    otherwise a one-time ``password`` is required (and never persisted).
    """
    cred = _resolve(request, credential_id)
    _require_managed(cred, "rotated")
    try:
        await asyncio.to_thread(bootstrap.rotate_key, cred.address, cred.port, payload.password)
    except Exception as exc:  # noqa: BLE001 - surface rotation failure to the caller
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY, detail=f"key rotation failed: {exc}"
        ) from exc
    # Return the refreshed view (new fingerprint); fall back to the pre-rotate
    # descriptor if the credential somehow no longer resolves.
    for refreshed in _list_credentials(request):
        if refreshed.credential_id == credential_id:
            return refreshed
    return cred


@router.post("/credentials/{credential_id}/revoke", response_model=CredentialRevokeResult)
async def revoke_credential(
    credential_id: str, payload: CredentialActionRequest, request: Request
) -> CredentialRevokeResult:
    """Revoke a managed key: remove it from the target's authorized_keys and delete
    the local key files. Targets that referenced it become unscannable until
    re-registered with a fresh bootstrap."""
    cred = _resolve(request, credential_id)
    _require_managed(cred, "revoked")
    if not cred.exists:
        return CredentialRevokeResult(
            revoked=False,
            key_deleted=False,
            detail="managed key already absent on the analyzer host; nothing to revoke",
        )
    try:
        removed = await asyncio.to_thread(
            bootstrap.revoke_key, cred.address, cred.port, None, payload.password
        )
    except Exception as exc:  # noqa: BLE001 - surface revoke failure to the caller
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY, detail=f"key revoke failed: {exc}"
        ) from exc
    deleted = await asyncio.to_thread(_delete_key_files, Path(cred.key_path))
    detail = (
        "managed key removed from target"
        if removed
        else "managed key was already absent on target"
    )
    if deleted:
        detail += "; local key files deleted"
    return CredentialRevokeResult(revoked=removed, key_deleted=deleted, detail=detail)


def _delete_key_files(key: Path) -> bool:
    """Delete the local private + public key files; return True if anything was removed."""
    pub = key.with_name(key.name + ".pub")
    deleted = False
    for path in (key, pub):
        if path.exists():
            path.unlink()
            deleted = True
    return deleted
