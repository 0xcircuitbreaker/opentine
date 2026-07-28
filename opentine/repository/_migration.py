"""Strict conversion of portable v2 artifacts into v3 repository objects."""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import TYPE_CHECKING, Any

from opentine._artifact_io import parse_artifact_json
from opentine.repository._migration_preflight import preflight_v2

if TYPE_CHECKING:
    from opentine.repository.runs import RunObjectResult
    from opentine.repository.store import Repo


def migrate_v2(
    repo: Repo,
    path: str | Path,
    *,
    ref: str | None = None,
    hmac_key: bytes | None = None,
    public_key: Any | None = None,
    trust_embedded: bool = False,
    strict: bool = True,
) -> RunObjectResult:
    from opentine.graph import Run, _run_from_dict
    from opentine.repository.runs import _put_run, read_artifact_bytes

    raw = read_artifact_bytes(path)
    data = parse_artifact_json(raw)
    if not isinstance(data, dict):
        raise ValueError("v3 repository migration requires a .tine object")
    if type(data.get("format_version")) is not int or data["format_version"] != 2:
        raise ValueError("v3 repository migration requires a .tine v2 source")
    integrity = Run.verify_integrity(data)
    signature = Run.verify_signature(
        data,
        hmac_key=hmac_key,
        public_key=public_key,
        trust_embedded=trust_embedded,
    )
    if strict:
        from opentine.signing import SignatureError

        if not integrity.ok:
            raise SignatureError(f"refusing to migrate a tampered v2 artifact: {integrity.reason}")
        verification_requested = hmac_key is not None or public_key is not None or trust_embedded
        if verification_requested and signature.state not in ("verified", "verified-tofu"):
            raise SignatureError(
                f"refusing to migrate: signature not verified (state={signature.state})"
            )
    verification = {
        "integrity": asdict(integrity),
        "signature": asdict(signature),
        "scope": "original-v2-artifact",
    }
    run = _run_from_dict(data)
    preflight_v2(repo, run, raw, verification, ref=ref)
    legacy_blob = repo.put("blob", raw, redact=False)
    return _put_run(
        repo,
        run,
        ref=ref,
        legacy_blob=legacy_blob,
        legacy_verification=verification,
    )
