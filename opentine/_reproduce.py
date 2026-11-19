"""``tine reproduce``: rerun a seeded sample of an experiment (0.67).

The sample is ``random.Random(seed).sample`` over the manifest's result-row ids
in sorted order; the seed defaults to the first 13 hex digits of the manifest
digest, so the same manifest always selects the same rows, and the report
records seed, k, population and the chosen ids.

A *runner* reruns one row: ``runner(manifest, row) -> {"score": 0..1,
"observed": {field: value}}``. ``observed`` may name ``model``, ``sampling``,
``seed``, ``code_digest`` and ``container_digest``; a value that differs from
the manifest (a seed not among ``seeds``) marks that field nondeterministic, as
do two repeats of the same row that score differently (``score``). A manifest
with no seeds, or with a nonzero ``temperature`` and no seeds, is reported
nondeterministic on ``seeds``/``sampling`` up front. ``verdict`` (built in)
rescores from the referenced verdict file; ``FILE.py:FUNC`` or ``MODULE:FUNC``
plugs in a real one.

The report (``opentine.reproduce-report/1``) is signed like a manifest, under
its own domain. ``verdict`` is ``agree`` when every sampled row's rerun score is
within ``tolerance`` of the row's stated score.
"""

from __future__ import annotations

import importlib
import importlib.util
import json
import random
from collections.abc import Callable
from decimal import Decimal
from pathlib import Path
from typing import Any

from opentine import _experiment as exp
from opentine import _signed_doc

CONVENTION = "opentine.reproduce-report/1"
DOMAIN = b"opentine.reproduce-report.v1:"
FIELDS = ("convention", "experiment", "manifest", "runner", "selection", "tolerance",
          "repeats", "rows", "agreed", "disagreed", "verdict", "nondeterministic",
          "created_at", "signer")  # fmt: skip
OBSERVED = ("model", "sampling", "seed", "code_digest", "container_digest")
Runner = Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]]


def default_seed(manifest: dict[str, Any]) -> int:
    return int(exp.digest(manifest)[7:20], 16)


def select(manifest: dict[str, Any], k: int, seed: int | None = None) -> dict[str, Any]:
    """``{seed, k, population, ids}``: the recorded, deterministic sample."""
    if k < 1:
        raise ValueError("--sample is at least 1")
    ids = sorted(row["id"] for row in manifest["results"])
    seed = default_seed(manifest) if seed is None else seed
    if not 0 <= seed < 2**53:
        raise ValueError("--seed is in 0..2**53-1")
    chosen = sorted(random.Random(seed).sample(ids, min(k, len(ids))))
    return {"seed": seed, "k": k, "population": len(ids), "ids": chosen}


def _verdict_runner(base: Path) -> Runner:
    def run(manifest: dict[str, Any], row: dict[str, Any]) -> dict[str, Any]:
        verdict = json.loads((base / row["path"]).read_bytes())
        return {"score": verdict["score"], "observed": {}}

    return run


def load_runner(spec: str, base: Path) -> Runner:
    """``verdict``, ``FILE.py:FUNC`` or ``MODULE:FUNC``."""
    if spec == "verdict":
        return _verdict_runner(base)
    where, sep, name = spec.rpartition(":")
    if not sep or not where or not name.isidentifier():
        raise ValueError(f"runner {spec!r}: use verdict, FILE.py:FUNC or MODULE:FUNC")
    if where.endswith(".py"):
        file = Path(where).resolve()
        unique = "opentine_reproduce_runner_" + exp.digest({"p": file.as_posix()})[7:23]
        loader = importlib.util.spec_from_file_location(unique, file)
        if loader is None or loader.loader is None:
            raise ValueError(f"runner {spec!r}: cannot load {where}")
        module = importlib.util.module_from_spec(loader)
        loader.loader.exec_module(module)
    else:
        module = importlib.import_module(where)
    func = getattr(module, name, None)
    if not callable(func):
        raise ValueError(f"runner {spec!r}: {name} is not callable")
    return func


def _score(value: Any) -> Decimal:
    number = Decimal(str(value))
    if not number.is_finite():
        raise ValueError(f"runner returned score {value!r}")
    return number


def _drift(manifest: dict[str, Any], observed: dict[str, Any]) -> set[str]:
    out: set[str] = set()
    for name in OBSERVED:
        if name not in observed:
            continue
        value = observed[name]
        if name == "seed":
            if value not in manifest["seeds"]:
                out.add("seeds")
        elif value != manifest[name]:
            out.add(name)
    return out


def declared(manifest: dict[str, Any]) -> set[str]:
    """Fields the manifest itself leaves nondeterministic."""
    out: set[str] = set()
    if not manifest["seeds"]:
        out.add("seeds")
        if manifest["sampling"].get("temperature") not in (None, 0, 0.0):
            out.add("sampling")
    return out


def rerun(manifest: dict[str, Any], runner: Runner, selection: dict[str, Any], *,
          tolerance: Decimal, repeats: int = 2) -> dict[str, Any]:  # fmt: skip
    """The unsigned report body's rows, tallies and nondeterministic fields."""
    if repeats < 1:
        raise ValueError("--repeats is at least 1")
    by_id = {row["id"]: row for row in manifest["results"]}
    fields = declared(manifest)
    rows: list[dict[str, Any]] = []
    for rid in selection["ids"]:
        row = by_id[rid]
        scores: list[Decimal] = []
        for _ in range(repeats):
            out = runner(manifest, row)
            if not isinstance(out, dict) or "score" not in out:
                raise ValueError(f"runner returned no score for {rid}")
            scores.append(_score(out["score"]))
            observed = out.get("observed") or {}
            fields |= _drift(manifest, observed if isinstance(observed, dict) else {})
        if len(set(scores)) > 1:
            fields.add("score")
        delta = max(abs(s - Decimal(row["score"])) for s in scores)
        rows.append({"id": rid, "expected": row["score"], "observed": [str(s) for s in scores],
                     "delta": str(delta), "agree": delta <= tolerance})  # fmt: skip
    agreed = sum(1 for r in rows if r["agree"])
    return {"rows": rows, "agreed": agreed, "disagreed": len(rows) - agreed,
            "verdict": "agree" if agreed == len(rows) else "disagree",
            "nondeterministic": sorted(fields)}  # fmt: skip


def report(manifest: dict[str, Any], runner_spec: str, runner: Runner, k: int, *,
           seed: int | None, tolerance: str, repeats: int, key: Any,
           at: str | None = None) -> dict[str, Any]:  # fmt: skip
    """The signed ``opentine.reproduce-report/1``."""
    from opentine._signing_keys import load_ed25519_private
    from opentine._signing_pins import key_fingerprint

    tol = Decimal(tolerance)
    if not tol.is_finite() or tol < 0:
        raise ValueError("--tolerance is a non-negative number")
    selection = select(manifest, k, seed)
    doc: dict[str, Any] = {
        "convention": CONVENTION, "experiment": manifest["experiment"],
        "manifest": exp.digest(manifest), "runner": runner_spec, "selection": selection,
        "tolerance": str(tol), "repeats": repeats,
        **rerun(manifest, runner, selection, tolerance=tol, repeats=repeats),
        "created_at": at or exp.now(),
    }  # fmt: skip
    private = load_ed25519_private(key)
    doc["signer"] = key_fingerprint(private.public_key().public_bytes_raw())
    signed = {n: doc[n] for n in FIELDS}
    doc["signature"] = _signed_doc.sign(
        DOMAIN, signed, private, signer=doc["signer"], signed_at=doc["created_at"]
    )
    return doc


def verify_report(doc: dict[str, Any]) -> str | None:
    if doc.get("convention") != CONVENTION or set(FIELDS) - set(doc):
        return "not an opentine.reproduce-report/1 document"
    return exp.verify(doc, DOMAIN, FIELDS)


__all__ = ["CONVENTION", "DOMAIN", "FIELDS", "declared", "default_seed", "load_runner",
           "report", "rerun", "select", "verify_report"]  # fmt: skip
