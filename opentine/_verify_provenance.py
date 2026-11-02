"""The ``provenance`` check of ``tine verify --offline`` (SPEC 8.2, 9.9).

A v4 run may record ``upgraded_from`` inside its payload, so the root -- and a
``tine-sig/3`` over it -- covers the record. Without the source, the record is
reported as a *claim* (``provenance.recorded``, ``unavailable-offline``): the
signature state in it is what the upgrader saw, not something this run shows.
With ``--source PATH`` the source is re-hashed and its signature re-verified
(``provenance.source-match`` / ``provenance.source-mismatch``). Never required.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from opentine._verify_report import Check

_NONE = "none"


def _none(detail: str) -> Check:
    return Check("provenance", "not-applicable", "provenance.none", detail, _NONE)


def _record(path: Path) -> dict[str, Any] | None:
    from opentine._artifact_io import read_artifact_json
    from opentine._format_v4 import is_v4_artifact
    from opentine._provenance_v4 import recorded

    try:
        data = read_artifact_json(path)
    except (OSError, RecursionError, ValueError):
        return None
    if not is_v4_artifact(data):
        return None
    entry = data["objects"].get(data["root"]) if isinstance(data.get("objects"), dict) else None
    return recorded(entry.get("body")) if isinstance(entry, dict) else None


def _claim(record: dict[str, Any]) -> str:
    block = record["signature"]
    return (
        f"upgraded from {record['format']} {record['digest']} by {record['tool']} at "
        f"{record['upgraded_at']}; source signature then: {block['state']} "
        f"(scheme {block['scheme'] or '-'}, {block['trust_basis']}) -- a recorded claim"
    )


def _repo_source(record: dict[str, Any], source: Path) -> Check:
    from opentine.repository import Repo

    try:
        found = Repo.open(source).get(record["digest"]).object_type == "run"
    except (OSError, KeyError, ValueError):
        found = False
    basis = f"v3 repository {source.name}: run oid re-derived from its stored bytes"
    if not found:
        detail = f"{record['digest']} is not a run in {source}"
        return Check("provenance", "fail", "provenance.source-mismatch", detail, basis)
    return Check("provenance", "pass", "provenance.source-match", _claim(record), basis)


def _file_source(args: argparse.Namespace, record: dict[str, Any], source: Path) -> Check:
    from opentine._provenance_source import read_source, signature_claim

    try:
        actual, data = read_source(source)
    except (OSError, RecursionError, UnicodeDecodeError, ValueError) as exc:
        detail = f"--source is unreadable: {exc}"
        return Check("provenance", "fail", "provenance.source-mismatch", detail, _NONE)
    basis = f"--source re-hashed: sha256 {actual}"
    if actual != record["digest"]:
        detail = f"source sha256 {actual} is not the recorded {record['digest']}"
        return Check("provenance", "fail", "provenance.source-mismatch", detail, basis)
    now = signature_claim(args, source, data)
    then = record["signature"]["state"]
    if then in ("verified", "verified-tofu") and now["state"] in ("mismatch", "error"):
        detail = f"recorded source signature {then}, re-verified now: {now['state']}"
        return Check("provenance", "fail", "provenance.source-mismatch", detail, basis)
    detail = f"{_claim(record)}; source signature re-verified now: {now['state']}"
    return Check("provenance", "pass", "provenance.source-match", detail, basis)


def provenance_check(args: argparse.Namespace, path: Path, integrity_ok: bool) -> Check:
    if not integrity_ok:
        return _none("not checked: the digest already failed")
    record = _record(path)
    if record is None:
        return _none("the run records no upgraded_from")
    source = getattr(args, "provenance_source", None)
    if not source:
        detail = f"{_claim(record)}; pass --source PATH to re-check it"
        basis = "none: a claim recorded at upgrade time, source not supplied"
        return Check("provenance", "unavailable-offline", "provenance.recorded", detail, basis)
    from opentine._provenance_v4 import REPO_FORMAT

    if record["format"] == REPO_FORMAT:
        return _repo_source(record, Path(source))
    return _file_source(args, record, Path(source))


__all__ = ["provenance_check"]
