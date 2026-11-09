"""The OMS model-signature factor in a run's ``assurance`` object (0.48, SPEC 4.26).

``tine verify RUN --model-signature BUNDLE --model PATH --model-pubkey PEM``
checks an OpenSSF Model Signing bundle over the model files given and records
the outcome in ``assurance.factors``; a factor that does not verify fails the
``model-signature`` check, so the run does not verify. The factor never raises
the assurance tier, and it is not bound to the run: it says the given files are
what the key signed, not that the run used them (SPEC 4.26).
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from opentine._signed_record import RecordError

#: A bundle is a small JSON document; refuse anything larger before parsing.
MAX_BUNDLE_BYTES = 4 << 20


def add_model_signature_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--model-signature",
        metavar="BUNDLE",
        help="Check this OMS (OpenSSF model signing) bundle as an assurance factor",
    )
    parser.add_argument(
        "--model", dest="model_path", metavar="PATH", help="The model file or directory it signs"
    )
    parser.add_argument(
        "--model-pubkey",
        metavar="FILE",
        help="The P-256 public key (PEM) the bundle is signed with",
    )


def _read(path: str, limit: int) -> bytes:
    with Path(path).open("rb") as handle:
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise RecordError("oms.malformed", f"{path} exceeds {limit} bytes")
    return data


def model_signature(args: Any) -> dict[str, Any] | None:
    """The factor for ``--model-signature``, or ``None`` when it was not asked for."""
    bundle_path = getattr(args, "model_signature", None)
    if not bundle_path:
        for flag, name in (("--model", "model_path"), ("--model-pubkey", "model_pubkey")):
            if getattr(args, name, None):
                raise ValueError(f"{flag} has no effect without --model-signature")
        return None
    from opentine import _oms
    from opentine._pyz import _p256

    factor: dict[str, Any] = {"factor": _oms.FACTOR, "bundle": Path(bundle_path).as_posix()}
    try:
        try:
            bundle = json.loads(_read(bundle_path, MAX_BUNDLE_BYTES).decode("utf-8"))
        except (RecursionError, UnicodeDecodeError, ValueError) as exc:
            raise RecordError("oms.malformed", f"OMS bundle is not JSON: {exc}") from exc
        key_file = getattr(args, "model_pubkey", None)
        try:
            key = _p256.public_key(_read(key_file, 64 << 10)) if key_file else None
        except ValueError as exc:
            raise RecordError("oms.no-key", f"--model-pubkey is not a P-256 key: {exc}") from exc
        model = getattr(args, "model_path", None)
        files = _oms.digest_dir(model, skip=(Path(bundle_path),)) if model else None
        result = _oms.check(bundle, files, key)
    except OSError as exc:
        return {**factor, "ok": False, "reason": "oms.unreadable", "detail": str(exc)}
    except RecordError as exc:
        return {**factor, "ok": False, "reason": exc.code, "detail": str(exc)}
    detail = result["label"] + ("" if files is not None else "; model files not checked (--model)")
    return {**factor, **result, "ok": True, "reason": None, "detail": detail,
            "files_checked": files is not None}  # fmt: skip


def factors(args: Any) -> list[dict[str, Any]]:
    found = model_signature(args)
    return [found] if found else []


__all__ = ["MAX_BUNDLE_BYTES", "add_model_signature_args", "factors", "model_signature"]
