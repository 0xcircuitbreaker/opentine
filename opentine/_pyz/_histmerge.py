"""The pyz's own port of the history merge and its record check (0.69, F2).

Ports :func:`opentine._history_merge.merge` and
:func:`opentine._history_merge_record.check` without importing either: the
merge is written again here and the ``tine-attest/2`` verdict is
:func:`._conform_sig.verify_block`. ``tests/data/history_merge.json`` is the
shared fixture the reference, this module and ``ts/verifier/src/histmerge.ts``
answer field for field. It is a CLI-level check outside the frozen vector
families: the pyz ``verify`` gives the claim no verdict.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

from .. import kernel
from . import _conform_sig

FORMAT = "opentine-history-snapshot/1"
DOMAIN = b"opentine.history-snapshot.v1:"
CONVENTION = "opentine.history-merge/1"
CLAIM = ("convention", "base", "sides", "merged", "conflicts", "target")
GUARDS = ("loop-stop:", "integrity-taint:", "memory-quarantine:")
KINDS = ("ref-diverged", "label-moved", "promotion-diverged", "lineage-id", "hold-weakened",
         "held-target")  # fmt: skip
RUN = re.compile(r"run:sha256:[0-9a-f]{64}")
HEX = re.compile(r"[0-9a-f]{64}")
_NONE = {"current": None, "history": []}
_LABEL = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
_LINEAGE = re.compile(r"sha256:[0-9a-f]{64}")


def _canon(value: Any) -> bytes:
    return kernel.canonical_json(value)


def normalize(snap: Any) -> dict:
    keys = {"format", "refs", "labels", "lineage", "holds"}
    if not isinstance(snap, dict) or snap.get("format") != FORMAT or set(snap) != keys:
        raise ValueError("not an opentine-history-snapshot/1")
    for name in ("refs", "lineage"):
        if not isinstance(snap[name], dict) or not all(
            isinstance(k, str) and isinstance(v, str) and k and v for k, v in snap[name].items()
        ):
            raise ValueError(f"{name} maps names to strings")
    if not all(_LINEAGE.fullmatch(k) for k in snap["lineage"]):
        raise ValueError("lineage ids are sha256:HEX")
    if isinstance(snap["labels"], dict) and not all(_LABEL.fullmatch(k) for k in snap["labels"]):
        raise ValueError("label names are [a-z0-9][a-z0-9._-]{0,63}")
    labels = {}
    for name, state in (snap["labels"] if isinstance(snap["labels"], dict) else {}).items():
        if not isinstance(state, dict) or set(state) != {"current", "history"}:
            raise ValueError("a label is {current, history}")
        if state["current"] is not None and not isinstance(state["current"], str):
            raise ValueError("a label's current is a string or null")
        if not isinstance(state["history"], list) or not all(
            isinstance(h, str) for h in state["history"]
        ):
            raise ValueError("a label's history is a list of strings")
        labels[name] = {"current": state["current"], "history": list(state["history"])}
    if not isinstance(snap["labels"], dict):
        raise ValueError("labels is an object")
    holds = snap["holds"]
    if not isinstance(holds, list) or not all(
        isinstance(h, list) and len(h) == 2 and all(isinstance(x, str) for x in h) for h in holds
    ):
        raise ValueError("holds is a list of pairs")
    pairs = sorted({(h[0], h[1]) for h in holds})
    if len(pairs) != len(holds):
        raise ValueError("holds are unique")
    return {"format": FORMAT, "refs": dict(snap["refs"]), "labels": labels,
            "lineage": dict(snap["lineage"]), "holds": [list(p) for p in pairs]}  # fmt: skip


def digest(snap: Any) -> str:
    return "sha256:" + hashlib.sha256(DOMAIN + _canon(normalize(snap))).hexdigest()


def _row(kind: str, key: str, base: Any, a: Any, b: Any) -> dict:
    return {"kind": kind, "key": key, "base": base, "sides": sorted([a, b], key=_canon)}


def _pick(base: Any, a: Any, b: Any) -> tuple[Any, bool]:
    if a == b:
        return a, False
    if a == base:
        return b, False
    if b == base:
        return a, False
    return base, True


def _prefix(longer: list, shorter: list) -> bool:
    return longer[: len(shorter)] == shorter


def merge(base: Any, ours: Any, theirs: Any) -> dict:
    b, o, t = normalize(base), normalize(ours), normalize(theirs)
    rows: list[dict] = []
    hb, ho, ht = ({(h[0], h[1]) for h in s["holds"]} for s in (b, o, t))
    guarded: set = set()
    for target, oid in hb | ho | ht:
        if target.startswith(GUARDS):
            guarded |= {oid, target.split(":", 1)[1]}
    refs = {}
    for name in sorted(set(b["refs"]) | set(o["refs"]) | set(t["refs"])):
        vb = b["refs"].get(name)
        vo, vt = o["refs"].get(name, vb), t["refs"].get(name, vb)
        value, clash = _pick(vb, vo, vt)
        if clash:
            rows.append(_row("ref-diverged", name, vb, vo, vt))
        elif value != vb and value in guarded:
            rows.append(_row("held-target", "refs/" + name, vb, vo, vt))
            value = vb
        if value is not None:
            refs[name] = value
    labels = {}
    for name in sorted(set(b["labels"]) | set(o["labels"]) | set(t["labels"])):
        sb, so, st = (s["labels"].get(name, _NONE) for s in (b, o, t))
        hist = (so["history"], st["history"])
        if not (_prefix(hist[0], sb["history"]) and _prefix(hist[1], sb["history"])) or not (
            _prefix(hist[0], hist[1]) or _prefix(hist[1], hist[0])
        ):
            rows.append(_row("promotion-diverged", name, sb, so, st))
            state = sb
        else:
            current, clash = _pick(sb["current"], so["current"], st["current"])
            state = {"current": current, "history": list(max(hist, key=len))}
            if clash:
                rows.append(_row("label-moved", name, sb, so, st))
                state = sb
            elif current != sb["current"] and current in guarded:
                rows.append(_row("held-target", "labels/" + name, sb, so, st))
                state = sb
        if state != _NONE:
            labels[name] = {"current": state["current"], "history": list(state["history"])}
    lineage = {}
    for ident in sorted(set(b["lineage"]) | set(o["lineage"]) | set(t["lineage"])):
        values = [s["lineage"].get(ident) for s in (b, o, t)]
        found = {v for v in values if v is not None}
        if len(found) > 1:
            rows.append(_row("lineage-id", ident, *values))
            if values[0] is not None:
                lineage[ident] = values[0]
        else:
            lineage[ident] = found.pop()
    for target, oid in sorted(hb - (ho & ht)):
        rows.append(_row("hold-weakened", target, oid, (target, oid) in ho, (target, oid) in ht))
    merged = {"format": FORMAT, "refs": refs, "labels": labels, "lineage": lineage,
              "holds": [list(h) for h in sorted(hb | ho | ht)]}  # fmt: skip
    rows.sort(key=lambda r: (KINDS.index(r["kind"]), r["key"], _canon(r)))
    sides = sorted([digest(o), digest(t)], key=_canon)
    return {"merged": merged, "conflicts": rows,
            "digests": {"base": digest(b), "sides": sides, "merged": digest(merged)}}  # fmt: skip


def _signature(record: dict, public_key: bytes | None) -> tuple[bool, str]:
    block = record.get("signature")
    if not isinstance(block, dict):
        return False, "unsigned"
    raw = block.get("public_key")
    if block.get("alg") != "ed25519" or not (isinstance(raw, str) and HEX.fullmatch(raw)):
        return False, "error"
    if "sha256:" + hashlib.sha256(bytes.fromhex(raw)).hexdigest() != record.get("signer"):
        return False, "mismatch"
    keys = {"hmac_key": None, "public_key": public_key, "trust_embedded": public_key is None}
    found = _conform_sig.verify_block(
        block, lambda header: _conform_sig.attest_message(record, header),
        ("tine-attest/1", "tine-attest/2"), "attestation", keys,
    )  # fmt: skip
    return bool(found["ok"]), str(found["state"])


def check(record: Any, base: Any, ours: Any, theirs: Any, public_key: bytes | None = None) -> dict:
    claim = record.get("claim") if isinstance(record, dict) else None
    if not isinstance(claim, dict) or claim.get("convention") != CONVENTION:
        raise ValueError("history-merge.malformed: not an opentine.history-merge/1 claim")
    if set(claim) != set(CLAIM) or not isinstance(claim["conflicts"], list):
        raise ValueError("history-merge.malformed: the claim's fields")
    if not (isinstance(record.get("target_id"), str) and RUN.fullmatch(record["target_id"])):
        raise ValueError("history-merge.malformed: the record targets a run")
    result = merge(base, ours, theirs)
    found = result["digests"]
    merged_ok = (claim["merged"] == found["merged"] and claim["base"] == found["base"]
                 and claim["sides"] == found["sides"])  # fmt: skip
    conflicts_ok = claim["conflicts"] == result["conflicts"]
    signed, state = _signature(record, public_key)
    return {"ok": bool(signed and merged_ok and conflicts_ok), "signature": state,
            "merged": found["merged"], "merged_matches": merged_ok,
            "conflicts_match": conflicts_ok, "conflicts": len(result["conflicts"])}  # fmt: skip


__all__ = ["check", "digest", "merge", "normalize"]
