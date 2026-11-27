"""Epochs and coverage for ``tine eval run`` (0.86).

``--epochs N`` scores every item N times: an outputs line names its ``epoch``
(0..N-1) and the verdict's ``item`` is ``ID@eK``. Without
``--continue-on-error`` a missing output or a scorer error still aborts the
run; with it, the item is recorded as *skipped* (no output) or *errored* (the
scorer raised) and the run goes on.

Every run writes ``coverage.json`` beside the verdicts: an existing
``attestation`` (tine-attest/2) signed by the eval key, targeting the eval id,
whose claim follows ``opentine.eval-coverage/1``::

    {"schema": "opentine.eval-coverage/1", "eval": "sha256:HEX",
     "dataset": "sha256:HEX", "epochs": N, "planned": P, "scored": S,
     "skipped": ["ID@eK", ...], "errored": ["ID@eK", ...],
     "cluster_key": null | "FIELD", "clusters": {"ID": "VALUE", ...},
     "plan_sha256": null | HEX}

``planned`` counts items times epochs; ``scored`` the verdicts. ``plan_sha256``
binds the run to the ``opentine.eval-plan/1`` it was run under (``--plan``), so a
plan written or edited after the run names another digest.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

COVERAGE = "opentine.eval-coverage/1"
FILE = "coverage.json"
EPOCH_RE = re.compile(r"(.+)@e([0-9]{1,3})")
FIELDS = ("schema", "eval", "dataset", "epochs", "planned", "scored", "skipped", "errored",
          "cluster_key", "clusters", "plan_sha256")  # fmt: skip


def unit_id(item: str, epoch: int, epochs: int) -> str:
    return item if epochs == 1 else f"{item}@e{epoch}"


def base_id(item: str, epochs: int) -> str:
    if epochs == 1:
        return item
    found = EPOCH_RE.fullmatch(item)
    return found.group(1) if found else item


def expand(items: list[dict[str, Any]], outputs: dict[str, Any] | None, epochs: int,
           default_run: str | None, lenient: bool) -> list[tuple]:  # fmt: skip
    """``(verdict item id, dataset item, {output, run} | None)`` per item and epoch."""
    from opentine._eval_dataset import DatasetError

    rows = []
    for item in items:
        for epoch in range(epochs):
            vid = unit_id(item["id"], epoch, epochs)
            fallback = item if epochs == 1 else None
            given = fallback if outputs is None else outputs.get(vid, fallback)
            if given is None or "output" not in given:
                if not lenient:
                    raise DatasetError(f"item {vid!r} has no output to score")
                rows.append((vid, item, None))
                continue
            run = given.get("run") or item.get("run") or default_run
            if not run:
                raise DatasetError(f"item {vid!r} names no run: pass --run or --from-run items")
            rows.append((vid, item, {"output": given["output"], "run": run}))
    return rows


def keyed_outputs(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Outputs lines keyed by verdict item id (``ID`` or ``ID@eK`` from ``epoch``)."""
    out = {}
    for row in rows:
        epoch = row.get("epoch")
        key = str(row["id"]) if epoch is None else f"{row['id']}@e{int(epoch)}"
        out[key] = row
    return out


def clusters(items: list[dict[str, Any]], key: str | None) -> dict[str, str]:
    """``{item id: cluster}`` from each item's ``metadata`` field *key* (or a top-level one)."""
    from opentine._eval_dataset import DatasetError

    if key is None:
        return {}
    found = {}
    for item in items:
        value = item.get(key)
        if value is None and isinstance(item.get("metadata"), dict):
            value = item["metadata"].get(key)
        if not isinstance(value, (str, int)) or isinstance(value, bool):
            raise DatasetError(f"item {item['id']!r} has no {key!r} cluster value")
        found[item["id"]] = str(value)
    return found


def sign(private: Any, *, at: str, **fields: Any) -> dict[str, Any]:
    from opentine._eval_plan import _sign

    claim = {"schema": COVERAGE, **fields}
    if set(claim) != set(FIELDS):
        raise ValueError(f"coverage has exactly the {COVERAGE} fields")
    return _sign(private, claim, fields["eval"], at)


def read(folder: Path, signers: set[str]) -> dict[str, Any] | None:
    """The verified coverage claim of an eval folder, or ``None`` when absent or bad.

    It must be signed by one of the eval's verdict signers and name the eval.
    """
    from opentine._eval_plan import load
    from opentine._promote_pins import _who

    path = Path(folder) / FILE
    if not path.is_file():
        return None
    try:
        doc = load(path)
    except (OSError, ValueError, RecursionError):
        return None
    claim = doc.get("claim") if isinstance(doc, dict) else None
    if not isinstance(claim, dict) or claim.get("schema") != COVERAGE or set(claim) != set(FIELDS):
        return None
    if _who(doc) not in signers or doc.get("target_id") != claim.get("eval"):
        return None
    return claim


__all__ = ["COVERAGE", "FILE", "base_id", "clusters", "expand", "keyed_outputs", "read", "sign",
           "unit_id"]  # fmt: skip
