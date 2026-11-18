"""Access records and exposure budgets for sealed holdouts (0.60).

``tine dataset unseal`` writes, *before* it decrypts anything, an attestation
whose claim follows ``opentine.holdout.access/1``::

    {"schema": "opentine.holdout.access/1", "holdout": NAME, "root": HEX,
     "sequence": K, "previous": HEX|null, "run": RUN, "why": TEXT,
     "purpose": "eval"|"other", "items": [INDEX...], "over_budget": BOOL}

signed by an ``eval``-role key from the owner-pinned key roles. Records chain
(``previous`` is the sha256 of record ``K-1``'s bytes), so a removed record
breaks the chain. The exposure of a holdout is the number of valid records
(``unseals``) and the distinct items they revealed (``revealed``). Unseal
refuses when the budget would be exceeded, unless ``--exceed-budget`` records
the overrun; ``tine promote --sealed-holdout`` then refuses with
``promote.holdout-exposed`` (also on a broken chain). ``tine eval run
--holdout`` refuses with ``eval.holdout-touched`` when a scored run's closure
touched holdout items: a non-eval access record names the run, an item's
text is in the run, or 5-word shingles of an item are contained in the run at
or above :data:`CONTAINMENT` (recorded in the refusal).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from opentine._holdout import HoldoutError, load, open_items, require_role, sign, signer
from opentine._holdout_hold import access_target, keep
from opentine._holdout_touch import CONTAINMENT, norm, run_flat, run_text, touched

ACCESS = "opentine.holdout.access/1"
PURPOSES = ("eval", "other")


def _raw_records(folder: Path, repo: Path | None, root_hex: str) -> list[bytes]:
    """The access records in the folder and their held copies, one per distinct byte string."""
    from opentine._holdout_hold import kept
    from opentine.repository._holds import HOLDOUT_ACCESS, HoldError

    found = {}
    for path in sorted((Path(folder) / "access").glob("*.json")):
        raw = path.read_bytes()
        found[hashlib.sha256(raw).hexdigest()] = raw
    try:
        for _, raw in kept(repo, f"{HOLDOUT_ACCESS}{root_hex}:"):
            found[hashlib.sha256(raw).hexdigest()] = raw
    except HoldError as exc:  # fail closed: never count fewer records than were held
        raise HoldoutError("holdout.holds", str(exc)) from exc
    return [found[k] for k in sorted(found)]


def _parse(raw: bytes) -> Any:
    try:
        return json.loads(raw.decode("utf-8"))
    except ValueError:
        return None


def exposure(folder: Path, repo: Path | None = None) -> dict[str, Any]:
    """``{unseals, revealed, over_budget, chain_ok, records}`` from the valid records.

    The records are the union of the folder's files and their held copies
    (:mod:`opentine._holdout_hold`), so deleting a file lowers nothing. A
    record that is not validly signed by an allowed key is ignored; two valid
    records that claim one sequence break the chain (fail closed).
    """
    found = load(folder)
    require_role(repo, found["signer"], "dataset")  # a re-signed budget counts for nothing
    claim = found["claim"]
    allowed = _eval_keys(repo)
    valid = []
    for raw in _raw_records(folder, repo, claim["root"]):
        doc = _parse(raw)
        rec = doc.get("claim") if isinstance(doc, dict) else None
        who = signer(doc)
        if (isinstance(rec, dict) and rec.get("schema") == ACCESS
                and rec.get("root") == claim["root"] and who is not None
                and type(rec.get("sequence")) is int
                and (allowed is None or who in allowed)):  # fmt: skip
            valid.append((rec["sequence"], hashlib.sha256(raw).hexdigest(), rec, who))
    revealed: set[int] = set()
    rows, previous, chain_ok, over = [], None, True, False
    for sequence, sha, rec, who in sorted(valid, key=lambda v: (v[0], v[1])):
        if sequence != len(rows) or rec.get("previous") != previous:
            chain_ok = False
        previous = sha
        revealed |= {int(i) for i in rec.get("items", [])}
        over = over or bool(rec.get("over_budget"))
        rows.append({"sequence": sequence, "run": rec.get("run"), "signer": who,
                     "purpose": rec.get("purpose"), "items": len(rec.get("items", [])),
                     "sha256": sha})  # fmt: skip
    budget = claim["budget"]
    over = over or len(rows) > budget["max_unseals"] or len(revealed) > budget["max_items"]
    return {"holdout": claim["holdout"], "root": claim["root"], "unseals": len(rows),
            "revealed": len(revealed), "budget": budget, "over_budget": over,
            "chain_ok": chain_ok, "records": rows, "_previous": previous,
            "_revealed": revealed}  # fmt: skip


def _eval_keys(repo: Path | None) -> set[str] | None:
    from opentine._promote_pins import roles

    try:
        held = roles(repo)
    except Exception:  # noqa: BLE001 - unreadable roles: count every signed record
        return None
    return set(held.get("eval", [])) if held else None


def unseal(folder: Path, master: bytes, key: Any, *, repo: Path | None, run: str, why: str,
           purpose: str, indices: list[int] | None, at: str, out: Path,
           exceed_budget: bool = False) -> dict[str, Any]:  # fmt: skip
    """Record the access, then release *indices* (all when ``None``) to *out* as JSONL."""
    from opentine._signing_pins import key_fingerprint

    who = key_fingerprint(key.public_key().public_bytes_raw())
    require_role(repo, who, "eval")
    claim = load(folder)["claim"]
    if purpose not in PURPOSES or not why.strip() or not run.strip():
        raise HoldoutError("holdout.access", "unseal needs --run, --why and --purpose")
    wanted = list(range(claim["items"])) if indices is None else sorted(set(indices))
    if any(i < 0 or i >= claim["items"] for i in wanted):
        raise HoldoutError("holdout.access", f"items are 0..{claim['items'] - 1}")
    state = exposure(folder, repo)
    if not state["chain_ok"]:
        raise HoldoutError("holdout.chain", "the access records do not chain; rotate")
    budget = claim["budget"]
    after = len(state["_revealed"] | set(wanted))
    over = state["unseals"] + 1 > budget["max_unseals"] or after > budget["max_items"]
    if over and not exceed_budget:
        raise HoldoutError("holdout.budget-exceeded", f"{state['unseals']} unseal(s) and "
                           f"{state['revealed']} item(s) revealed of {budget}; this unseal "
                           "would exceed it (rotate, or --exceed-budget to record it)")  # fmt: skip
    record = {"schema": ACCESS, "holdout": claim["holdout"], "root": claim["root"],
              "sequence": state["unseals"], "previous": state["_previous"], "run": run,
              "why": why, "purpose": purpose, "items": wanted, "over_budget": over}  # fmt: skip
    path = Path(folder) / "access" / f"{state['unseals']:06d}.json"
    valid = {row["sha256"] for row in state["records"]}
    if path.exists() and hashlib.sha256(path.read_bytes()).hexdigest() in valid:
        raise HoldoutError("holdout.access", f"{path} exists: a concurrent unseal")
    # A file there that no allowed key signed is a squatter: it is replaced, never obeyed.
    data = _record_bytes(sign(key, record, f"sha256:{claim['root']}", at))
    keep(repo, access_target(claim["root"], state["unseals"]), data)  # first: a lost file counts
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    items = open_items(folder, master, wanted)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8", newline="\n") as handle:
        for item in items:
            handle.write(json.dumps(item, sort_keys=True) + "\n")
    return {"holdout": claim["holdout"], "root": claim["root"], "run": run, "purpose": purpose,
            "items": len(items), "out": Path(out).as_posix(), "over_budget": over,
            "access": path.as_posix(), "access_sha256": hashlib.sha256(data).hexdigest(),
            "signer": who}  # fmt: skip


def _record_bytes(document: Any) -> bytes:
    return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")


def promote_refusals(folders: list[Path], repo: Path | None) -> list[dict[str, str]]:
    """``promote.holdout-exposed`` for each sealed holdout over budget or broken."""
    from opentine._promote_checks import refusal

    out = []
    for folder in folders:
        try:
            state = exposure(folder, repo)
        except HoldoutError as exc:
            out.append(refusal("promote.holdout-exposed", f"{folder}: {exc}"))
            continue
        if state["over_budget"] or not state["chain_ok"]:
            why = "its access records do not chain" if not state["chain_ok"] else (
                f"{state['unseals']} unseal(s), {state['revealed']} item(s) revealed "
                f"exceed {state['budget']}")  # fmt: skip
            out.append(refusal("promote.holdout-exposed", f"{state['holdout']}: {why}"))
    return out


__all__ = [
    "ACCESS",
    "CONTAINMENT",
    "exposure",
    "norm",
    "run_flat",
    "run_text",
    "promote_refusals",
    "touched",
    "unseal",
]
