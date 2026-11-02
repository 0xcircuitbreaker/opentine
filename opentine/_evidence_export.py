"""The evidence directory ``tine evidence export`` writes.

Layout (every path relative to ``--out``)::

    MANIFEST.sha256      sha256sum lines for every file below except itself
                         and custody.jsonl, sorted by path
    custody.jsonl        one tine-custody/1 record (optionally Ed25519-signed)
    timeline.jsonl/.csv  one row per step: run, index, step id, kind, tool, time
    verify-report.json   tine-evidence-verify/1: each run's offline report
    trust/               the keys and policy the verification used
    runs/                the run files, byte for byte

Everything is a pure function of the runs and the flags except the custody
record's ``exported_at``; that is why custody.jsonl sits outside the manifest
and instead names the manifest's own SHA-256. The custody signature is Ed25519
over ``b"opentine.custody.v1:" + canonical_json(record without "signature")``.
Host-specific facts (hostname, absolute paths) are never written.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from opentine.kernel import canonical_json

CUSTODY_SCHEMA = "tine-custody/1"
REPORT_SCHEMA = "tine-evidence-verify/1"
CUSTODY_DOMAIN = b"opentine.custody.v1:"
TIMELINE_FIELDS = ("run_id", "index", "step_id", "kind", "tool", "timestamp", "time", "duration")
_UNSIGNED = ("MANIFEST.sha256", "custody.jsonl")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode()


def _tool(step: dict[str, Any]) -> str:
    for source in (step.get("inputs"), step.get("tool_info")):
        if isinstance(source, dict):
            for key in ("tool", "name"):
                if isinstance(source.get(key), str):
                    return source[key]
    return ""


def timeline_rows(run_id: str, data: Any) -> list[dict[str, Any]]:
    graph = data.get("graph") if isinstance(data, dict) else None
    steps = graph.get("steps") if isinstance(graph, dict) else None
    order = graph.get("order") if isinstance(graph, dict) else None
    if not isinstance(steps, dict) or not isinstance(order, list):
        return []
    rows = []
    for index, key in enumerate(order):
        step = steps.get(key) if isinstance(key, str) else None
        if not isinstance(step, dict):
            continue
        stamp = step.get("timestamp")
        number = stamp if isinstance(stamp, int | float) and not isinstance(stamp, bool) else None
        when = datetime.fromtimestamp(number, tz=UTC).isoformat() if number is not None else ""
        rows.append(
            {
                "run_id": run_id,
                "index": index,
                "step_id": key,
                "kind": str(step.get("kind", "")),
                "tool": _tool(step),
                "timestamp": number,
                "time": when,
                "duration": step.get("duration"),
            }
        )
    return rows


def _csv(rows: list[dict[str, Any]]) -> bytes:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=TIMELINE_FIELDS, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue().encode("utf-8")


def manifest_text(out: Path) -> bytes:
    lines = []
    for path in sorted(p for p in out.rglob("*") if p.is_file()):
        rel = path.relative_to(out).as_posix()
        if rel not in _UNSIGNED:
            lines.append(f"{_sha(path.read_bytes())}  {rel}\n")
    return "".join(lines).encode("utf-8")


def custody_record(
    *, operator: str, version: str, runs: list[dict[str, Any]], manifest: bytes, signing_key: Any
) -> dict[str, Any]:
    from opentine._signing_pins import key_fingerprint

    record: dict[str, Any] = {
        "schema": CUSTODY_SCHEMA,
        "exported_by": operator,
        "exported_at": datetime.now(tz=UTC).isoformat(),
        "opentine_version": version,
        "manifest_sha256": _sha(manifest),
        "runs": runs,
    }
    if signing_key is not None:
        public = signing_key.public_key().public_bytes_raw()
        signature = signing_key.sign(CUSTODY_DOMAIN + canonical_json(record))
        record["signature"] = {
            "algorithm": "ed25519",
            "public_key": public.hex(),
            "key_fingerprint": key_fingerprint(public),
            "value": signature.hex(),
        }
    return record


def write_evidence(
    out: Path,
    runs: list[tuple[Path, Any, dict[str, Any]]],
    *,
    trust_files: dict[str, Path],
    operator: str,
    version: str,
    signing_key: Any = None,
) -> dict[str, Any]:
    """Write the directory; *runs* is ``[(source path, artifact dict, report)]``."""
    (out / "runs").mkdir(parents=True)
    reports, rows, listed = [], [], []
    for source, data, report in runs:
        run_id = data.get("run_id") if isinstance(data, dict) else None
        run_id = run_id if isinstance(run_id, str) else source.stem
        target = out / "runs" / source.name
        raw = source.read_bytes()
        target.write_bytes(raw)
        rel = f"runs/{source.name}"
        reports.append({**report, "path": rel})
        rows += timeline_rows(run_id, data)
        listed.append({"run_id": run_id, "file": rel, "sha256": _sha(raw)})
    ok = all(r["ok"] for r in reports)
    document = {"schema": REPORT_SCHEMA, "ok": ok, "runs": reports}
    (out / "verify-report.json").write_bytes(_json(document))
    (out / "timeline.jsonl").write_bytes(b"".join(canonical_json(r) + b"\n" for r in rows))
    (out / "timeline.csv").write_bytes(_csv(rows))
    trust = out / "trust"
    trust.mkdir()
    for name, path in sorted(trust_files.items()):
        shutil.copyfile(path, trust / name)
    if signing_key is not None:
        public = signing_key.public_key().public_bytes_raw().hex()
        (trust / "custody-signer.pub").write_text(public + "\n", encoding="utf-8")
    manifest = manifest_text(out)
    (out / "MANIFEST.sha256").write_bytes(manifest)
    record = custody_record(
        operator=operator, version=version, runs=listed, manifest=manifest, signing_key=signing_key
    )
    (out / "custody.jsonl").write_bytes(canonical_json(record) + b"\n")
    return {"ok": ok, "runs": len(listed), "signed": signing_key is not None}


def verify_custody(record: dict[str, Any]) -> bool:
    """Whether a custody record's Ed25519 signature verifies under its own key."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    block = record.get("signature")
    if not isinstance(block, dict):
        return False
    body = {k: v for k, v in record.items() if k != "signature"}
    try:
        key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(block["public_key"]))
        key.verify(bytes.fromhex(block["value"]), CUSTODY_DOMAIN + canonical_json(body))
    except (InvalidSignature, KeyError, TypeError, ValueError):
        return False
    return True


__all__ = [
    "CUSTODY_DOMAIN",
    "CUSTODY_SCHEMA",
    "REPORT_SCHEMA",
    "manifest_text",
    "timeline_rows",
    "verify_custody",
    "write_evidence",
]
