"""Experiment manifests and reproduce reports in the query index (0.67).

Both are signed file conventions (docs/EXPERIMENTS.md), not objects, so the
index reads them from files: every ``*.json`` under ``.tine/experiments`` and
under each folder given with ``tine query index --experiments DIR``
(remembered in ``meta`` like the eval folders). A file that is neither
convention is skipped. A row's ``oid`` is the document digest
(:func:`opentine._experiment.digest`, signature included), so ``--verify``
can tell when the file behind a row changed.

Tables: ``experiments`` (one row per manifest), ``experiment_results`` (one row
per manifest result row; its ``oid`` is the manifest digest and ``id`` names
the row, so ``--verify`` checks a result row by both) and
``reproductions`` (one row per reproduce report).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from opentine._query_values import integer as _int
from opentine._query_values import number as _num
from opentine._query_values import text as _text

COLUMNS: dict[str, tuple[str, ...]] = {
    "experiments": ("oid", "source", "experiment", "signer", "signed", "model",
                    "model_version", "result_rows", "passed_rows", "usd", "created_at"),
    "experiment_results": ("oid", "experiment", "id", "verdict", "path", "score", "passed"),
    "reproductions": ("oid", "source", "experiment", "manifest", "signer", "signed", "sample",
                      "agreed", "disagreed", "verdict", "tolerance", "repeats", "created_at"),
}  # fmt: skip
TABLES = tuple(COLUMNS)


def experiment_files(store: Path, dirs: list[str]) -> dict[str, bytes]:
    """``{source: bytes}`` for every ``*.json`` of ``.tine/experiments`` and each DIR."""
    out: dict[str, bytes] = {}
    roots = [(Path(store) / "experiments", "experiments/")]
    roots += [(Path(d), Path(d).as_posix() + "/") for d in dirs]
    for root, prefix in roots:
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*.json")):
            if path.is_file():
                out[prefix + path.relative_to(root).as_posix()] = path.read_bytes()
    return out


def source_path(store: Path, source: str) -> Path:
    return Path(store) / source if source.startswith("experiments/") else Path(source)


def document_rows(source: str, raw: bytes) -> dict[str, list[dict[str, Any]]]:
    """``{table: rows}`` one experiment file contributes (``{}`` for any other file)."""
    from opentine import _experiment as exp
    from opentine import _reproduce as rp

    try:
        doc = json.loads(raw)
    except ValueError:
        return {}
    if not isinstance(doc, dict):
        return {}
    signed = int(doc.get("signature") is not None and _verifies(doc))
    if doc.get("convention") == exp.CONVENTION:
        if exp.problems(doc):
            return {}
        oid = exp.digest(doc)
        results = doc["results"]
        model = doc["model"] if isinstance(doc.get("model"), dict) else {}
        compute = doc["compute"] if isinstance(doc.get("compute"), dict) else {}
        head = {"oid": oid, "source": source, "experiment": _text(doc.get("experiment")),
                "signer": _text(doc.get("signer")), "signed": signed,
                "model": _text(model.get("id")), "model_version": _text(model.get("version")),
                "result_rows": len(results),
                "passed_rows": sum(r.get("passed") is True for r in results),
                "usd": _num(compute.get("usd")),
                "created_at": _text(doc.get("created_at"))}  # fmt: skip
        rows = [{"oid": oid, "experiment": head["experiment"], "id": _text(r.get("id")),
                 "verdict": _text(r.get("verdict")), "path": _text(r.get("path")),
                 "score": _num(r.get("score")), "passed": int(r.get("passed") is True)}
                for r in results]  # fmt: skip
        return {"experiments": [head], "experiment_results": rows}
    if doc.get("convention") == rp.CONVENTION and not set(rp.FIELDS) - set(doc):
        selection = doc["selection"] if isinstance(doc.get("selection"), dict) else {}
        return {"reproductions": [{
            "oid": exp.digest(doc, rp.DOMAIN), "source": source,
            "experiment": _text(doc.get("experiment")), "manifest": _text(doc.get("manifest")),
            "signer": _text(doc.get("signer")), "signed": signed,
            "sample": _int(selection.get("k")), "agreed": _int(doc.get("agreed")),
            "disagreed": _int(doc.get("disagreed")), "verdict": _text(doc.get("verdict")),
            "tolerance": _num(doc.get("tolerance")), "repeats": _int(doc.get("repeats")),
            "created_at": _text(doc.get("created_at"))}]}  # fmt: skip
    return {}


def _verifies(doc: dict[str, Any]) -> bool:
    from opentine import _experiment as exp
    from opentine import _reproduce as rp

    try:
        if doc.get("convention") == rp.CONVENTION:
            return rp.verify_report(doc) is None
        return exp.verify(doc) is None
    except Exception:  # noqa: BLE001 - a malformed signature block is indexed unsigned
        return False


def rows(files: dict[str, bytes]) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {name: [] for name in TABLES}
    for source, raw in sorted(files.items()):
        for name, found in document_rows(source, raw).items():
            out[name] += found
    return out


def derive(store: Path, dirs: list[str], table: str, oid: str, db: Any,
           row: dict[str, Any]) -> tuple[dict[str, Any] | None, str | None]:  # fmt: skip
    """The row the file behind *oid* derives now, or ``(None, why)`` (for ``--verify``)."""
    if table == "experiment_results":
        hit = db.execute("SELECT source FROM experiments WHERE oid = ?", (oid,)).fetchone()
    else:
        hit = db.execute(f"SELECT source FROM {table} WHERE oid = ?", (oid,)).fetchone()
    source = hit[0] if hit else None
    files = experiment_files(store, dirs)
    if source not in files:
        return None, "the source is not an indexed experiment file"
    found = document_rows(source, source_path(store, source).read_bytes())
    parent = "experiments" if table == "experiment_results" else table
    if not found.get(parent) or found[parent][0]["oid"] != oid:
        return None, "the experiment file changed"
    if table != "experiment_results":
        return found[table][0], None
    if "id" not in row:  # a result row without its id: check the manifest it came from
        return {k: found[parent][0][k] for k in ("oid", "experiment", "signer", "signed")}, None
    match = [r for r in found[table] if r["id"] == row.get("id")]
    if not match:
        return None, "the manifest has no result row with that id"
    return {**match[0], "signer": found[parent][0]["signer"],
            "signed": found[parent][0]["signed"]}, None  # fmt: skip


__all__ = ["COLUMNS", "TABLES", "derive", "document_rows", "experiment_files", "rows",
           "source_path"]  # fmt: skip
