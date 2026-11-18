"""Access records and exposure budgets for sealed holdouts (0.61).

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
import re
import unicodedata
from pathlib import Path
from typing import Any

from opentine._holdout import HoldoutError, dump, load, open_items, require_role, sign, signer

ACCESS = "opentine.holdout.access/1"
PURPOSES = ("eval", "other")
CONTAINMENT = 0.8
SHINGLE = 5
MIN_EXACT = 16
_WORD = re.compile(r"\w+")
# Common Cyrillic/Greek letters that render like Latin ones (casefolded forms).
_LOOKALIKE = str.maketrans("аеорсухіјѕԁɡοαν", "aeopcyxijsdgoav")


def exposure(folder: Path, repo: Path | None = None) -> dict[str, Any]:
    """``{unseals, revealed, over_budget, chain_ok, records}`` from the valid records."""
    found = load(folder)
    require_role(repo, found["signer"], "dataset")  # a re-signed budget counts for nothing
    claim = found["claim"]
    allowed = _eval_keys(repo)
    revealed: set[int] = set()
    rows, previous, chain_ok, over = [], None, True, False
    for path in sorted((Path(folder) / "access").glob("*.json")):
        raw = path.read_bytes()
        try:
            doc = json.loads(raw.decode("utf-8"))
        except ValueError:
            chain_ok = False
            continue
        rec = doc.get("claim") if isinstance(doc, dict) else None
        who = signer(doc)
        good = (isinstance(rec, dict) and rec.get("schema") == ACCESS
                and rec.get("root") == claim["root"] and who is not None
                and (allowed is None or who in allowed))  # fmt: skip
        if not good:
            continue
        if rec.get("sequence") != len(rows) or rec.get("previous") != previous:
            chain_ok = False
        previous = hashlib.sha256(raw).hexdigest()
        revealed |= {int(i) for i in rec.get("items", [])}
        over = over or bool(rec.get("over_budget"))
        rows.append({"sequence": rec.get("sequence"), "run": rec.get("run"), "signer": who,
                     "purpose": rec.get("purpose"), "items": len(rec.get("items", [])),
                     "sha256": previous})  # fmt: skip
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
    if path.exists():
        raise HoldoutError("holdout.access", f"{path} exists: a concurrent unseal")
    data = dump(path, sign(key, record, f"sha256:{claim['root']}", at))
    items = open_items(folder, master, wanted)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8", newline="\n") as handle:
        for item in items:
            handle.write(json.dumps(item, sort_keys=True) + "\n")
    return {"holdout": claim["holdout"], "root": claim["root"], "run": run, "purpose": purpose,
            "items": len(items), "out": Path(out).as_posix(), "over_budget": over,
            "access": path.as_posix(), "access_sha256": hashlib.sha256(data).hexdigest(),
            "signer": who}  # fmt: skip


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


def norm(text: str) -> str:
    """NFKC, casefolded, lookalikes folded, only letters and digits: what a match compares."""
    folded = unicodedata.normalize("NFKC", text).casefold().translate(_LOOKALIKE)
    return "".join(ch for ch in folded if ch.isalnum())


def shingles(text: str) -> set[tuple[str, ...]]:
    folded = unicodedata.normalize("NFKC", text).casefold().translate(_LOOKALIKE)
    words = _WORD.findall(folded)
    return {tuple(words[i : i + SHINGLE]) for i in range(len(words) - SHINGLE + 1)}


def item_texts(item: dict[str, Any]) -> list[str]:
    values = [item.get("input"), item.get("expected")]
    return [v if isinstance(v, str) else json.dumps(v, sort_keys=True)
            for v in values if v is not None]  # fmt: skip


def run_text(run: Any) -> str:
    parts = [run.user_prompt or ""] if hasattr(run, "user_prompt") else []
    for step in run.steps:
        parts.append(json.dumps([step.inputs, step.outputs, step.error, step.tool_info],
                                sort_keys=True, ensure_ascii=False, default=str))  # fmt: skip
    return "\n".join(parts)


def _strings(value: Any) -> list[str]:
    """Leaf strings of nested dicts and lists, depth first, without recursion."""
    out, stack = [], [value]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            out.append(item)
        elif isinstance(item, dict):
            stack.extend(reversed(list(item.values())))
        elif isinstance(item, (list, tuple)):
            stack.extend(reversed(item))
    return out


def run_flat(run: Any) -> str:
    """:func:`norm` of a run's string values only, so a marker split across fields joins."""
    parts = [run.user_prompt or ""] if hasattr(run, "user_prompt") else []
    for step in run.steps:
        parts += _strings([step.inputs, step.outputs, step.error, step.tool_info])
    return norm("".join(parts))


def touched(folder: Path, items: list[dict[str, Any]], runs: dict[str, str],
            repo: Path | None) -> list[dict[str, str]]:  # fmt: skip
    """``eval.holdout-touched`` refusals: *runs* maps run id to its closure's text."""
    state = exposure(folder, repo)
    readers = {row["run"] for row in state["records"] if row["purpose"] != "eval"}
    out = []
    for run, text in sorted(runs.items()):
        if run in readers:
            out.append(
                {
                    "code": "eval.holdout-touched",
                    "run": run,
                    "detail": "a non-eval access record unsealed holdout items for it",
                }
            )
            continue
        grams, flat = shingles(text), norm(text)
        for item in items:
            for value in item_texts(item):
                key = norm(value)
                exact = len(key) >= MIN_EXACT and key in flat
                mine = shingles(value)
                share = len(mine & grams) / len(mine) if mine else 0.0
                if exact or share >= CONTAINMENT:
                    how = "in clear" if exact else f"5-gram containment {share:.2f}"
                    out.append({"code": "eval.holdout-touched", "run": run,
                                "detail": f"item {item.get('id')} {how} (threshold "
                                          f"{CONTAINMENT})"})  # fmt: skip
                    break
            else:
                continue
            break
    return out


__all__ = [
    "ACCESS",
    "CONTAINMENT",
    "exposure",
    "norm",
    "run_flat",
    "promote_refusals",
    "touched",
    "unseal",
]
