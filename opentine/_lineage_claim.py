"""Reading ``opentine.lineage.variant`` records into index rows (0.58).

There is one claim convention and one schema: the one ``tine lineage record``
signs and ``tine lineage check`` judges (:mod:`opentine._lineage`,
docs/LINEAGE.md). This module turns one record of the lineage folder into the
rows of the derived index; it never judges trust beyond whether the signature
holds (``check`` does). Evidence rows are ``(kind, ref, detail)``:

``artifact``  each artifact digest (detail: its name)
``mutation``  the mutation run
``eval``      each justifying eval id (detail: its ``verdicts_sha256``)
``dataset`` / ``judge`` / ``signer``
              read from that eval's filed verdicts, when present
``selector``, ``policy``, ``loop``
``decision``  the cited decision's sha256, and its 0.57 promotion inputs
              (``approver``, ``policy``, ``eval``, ``compare``) when filed
"""

from __future__ import annotations

from typing import Any

from opentine._lineage import ARTIFACTS, CONVENTION, DIGEST_RE

# A 0.57 promotion input uri prefix -> the evidence kind ``why`` reports.
_INPUT_KINDS = {"eval": "eval", "approval": "approver", "policy": "policy", "compare": "compare"}


def is_lineage(payload: Any) -> bool:
    claim = payload.get("claim") if isinstance(payload, dict) else None
    return isinstance(claim, dict) and claim.get("convention") == CONVENTION


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _json(raw: bytes | None) -> Any:
    from opentine._lineage_check import _loads

    try:
        return None if raw is None else _loads(raw)
    except (ValueError, UnicodeDecodeError):
        return None


def _verdicts(raw: bytes | None, add: Any, eval_id: str) -> None:
    for line in (raw or b"").decode("utf-8", "replace").split("\n"):
        verdict = _json(line.encode("utf-8")) if line.strip() else None
        if not isinstance(verdict, dict):
            continue
        add("dataset", verdict.get("dataset"), eval_id)
        judge = _text(verdict.get("judge_run")) or _text(verdict.get("scorer"))
        version = _text(verdict.get("scorer_version"))
        add("judge", f"{judge}@{version}" if judge and version else judge, eval_id)
        add("signer", verdict.get("signer"), eval_id)


def _decision(document: Any, add: Any) -> None:
    said = document.get("claim") if isinstance(document, dict) else None
    for row in (said.get("inputs") if isinstance(said, dict) else None) or []:
        uri = row.get("uri") if isinstance(row, dict) else None
        if not _text(uri) or ":" not in uri:
            continue
        prefix, rest = uri.split(":", 1)
        digest = row.get("digest") if isinstance(row.get("digest"), dict) else {}
        add(_INPUT_KINDS.get(prefix, "input"), rest, _text(digest.get("sha256")) or "")


def evidence(claim: dict[str, Any], files: dict[str, bytes]) -> list[tuple[str, str, str]]:
    """``(kind, ref, detail)`` rows, sorted and de-duplicated."""
    rows: set[tuple[str, str, str]] = set()

    def add(kind: str, ref: Any, detail: str = "") -> None:
        if _text(ref):
            rows.add((kind, ref, detail))

    artifacts = claim.get("artifacts")
    for name in ARTIFACTS if isinstance(artifacts, dict) else ():
        add("artifact", artifacts.get(name), name)
    add("mutation", claim.get("mutation_run"))
    for entry in claim.get("evals") if isinstance(claim.get("evals"), list) else []:
        if isinstance(entry, dict) and _text(entry.get("eval")):
            add("eval", entry["eval"], _text(entry.get("verdicts_sha256")) or "")
            _verdicts(files.get(f"evals/{entry['eval'][7:]}.jsonl"), add, entry["eval"])
    add("selector", claim.get("selector"))
    add("policy", claim.get("policy"))
    add("loop", claim.get("loop"))
    cited = claim.get("decision")
    digest = cited.get("sha256") if isinstance(cited, dict) else None
    if _text(digest):
        add("decision", digest)
        _decision(_json(files.get(f"decisions/{digest}.json")), add)
    return sorted(rows)


def rows(oid: str, payload: Any, files: dict[str, bytes] | None = None) -> dict[str, Any] | None:
    """The index rows one lineage record contributes, or ``None``.

    ``signed`` is true only when the record is Ed25519-signed by its ``signer``
    and verifies (the same test ``check`` applies): a copied or garbage
    signature block counts as unsigned. It says the record is intact, not that
    its signer is trusted.
    """
    from opentine._lineage_check import _signed

    if not is_lineage(payload):
        return None
    claim = payload["claim"]
    variant = claim.get("variant")
    if not isinstance(variant, str) or not DIGEST_RE.fullmatch(variant):
        return None
    given = claim.get("parents") if isinstance(claim.get("parents"), list) else []
    parents = sorted(
        {p for p in given if isinstance(p, str) and DIGEST_RE.fullmatch(p)} - {variant}
    )
    try:
        signed = bool(_signed(payload))
    except Exception:  # noqa: BLE001 - an unverifiable block is not a signature
        signed = False
    return {
        "variant": variant,
        "oid": oid,
        "signer": _text(payload.get("signer")) or "",
        "signed": int(signed),
        "loop": _text(claim.get("loop")) or "",
        "parents": parents,
        "evidence": evidence(claim, files or {}),
    }


def folder_rows(files: dict[str, bytes]) -> list[dict[str, Any]]:
    """Rows for every record in a lineage folder; ``oid`` is ``sha256:`` of its bytes.

    A record filed under another name than its variant id is skipped: the
    folder is addressed by variant id (``check`` reports it as unknown/invalid).
    """
    import hashlib

    out = []
    for path, raw in sorted(files.items()):
        if not (path.startswith("variants/") and path.endswith(".json")):
            continue
        row = rows("sha256:" + hashlib.sha256(raw).hexdigest(), _json(raw), files)
        if row is not None and path == f"variants/{row['variant'][7:]}.json":
            out.append(row)
    return out


__all__ = ["evidence", "folder_rows", "is_lineage", "rows"]
