"""0.69: 1k seeded random branch/merge cases for the history merge (count-based, no clocks).

Each case draws a base snapshot and two sides edited from it, then checks:
the merge is commutative (merged snapshot, digests and conflicts), it is
deterministic under key order, a conflict-free merge keeps every side's change,
no base hold is ever lost, a guarded object never gains a name, and the signed
record of the merge verifies whichever side is called "ours".
"""

from __future__ import annotations

import random

from opentine import _history_merge as hm
from opentine._history_merge_record import check, sign
from tests.promote_helpers import key

CASES = 1000
SEED = 69
RUNS = [f"run:sha256:{i:064x}" for i in range(1, 9)]
REFS = ["heads/main", "heads/a", "heads/b", "tags/v1"]
LABELS = ["prod", "canary"]
IDS = [f"sha256:{i:064x}" for i in range(20, 26)]
HEXES = [f"{i:064x}" for i in range(40, 46)]


def _base(rng: random.Random) -> dict:
    snap = hm.empty()
    snap["refs"] = {r: rng.choice(RUNS) for r in REFS if rng.random() < 0.6}
    snap["labels"] = {
        name: {"current": rng.choice(RUNS), "history": rng.sample(HEXES, rng.randint(0, 2))}
        for name in LABELS if rng.random() < 0.5
    }  # fmt: skip
    snap["lineage"] = {i: rng.choice(HEXES) for i in IDS if rng.random() < 0.4}
    snap["holds"] = sorted([[f"run:{r}", r] for r in rng.sample(RUNS, rng.randint(0, 2))])
    return snap


def _edit(rng: random.Random, base: dict) -> dict:
    snap = hm.normalize(base)
    for ref in REFS:
        if rng.random() < 0.25:
            snap["refs"][ref] = rng.choice(RUNS)
        elif ref in snap["refs"] and rng.random() < 0.05:
            del snap["refs"][ref]  # a deletion is never merged
    for name in LABELS:
        if rng.random() < 0.25:
            state = snap["labels"].get(name, {"current": None, "history": []})
            history = list(state["history"])
            if rng.random() < 0.15:
                history = history[:-1]  # a rewritten history diverges
            history.append(rng.choice(HEXES))
            snap["labels"][name] = {"current": rng.choice(RUNS), "history": history}
    for ident in IDS:
        if rng.random() < 0.15:
            snap["lineage"][ident] = rng.choice(HEXES)
    holds = {tuple(h) for h in snap["holds"]}
    if holds and rng.random() < 0.1:
        holds.discard(sorted(holds)[0])  # one side weakens a hold
    if rng.random() < 0.2:
        run = rng.choice(RUNS)
        holds.add((rng.choice(hm.GUARDS) + run, run))
    snap["holds"] = [list(h) for h in sorted(holds)]
    return snap


def _shuffled(rng: random.Random, snap: dict) -> dict:
    def shuffle(table: dict) -> dict:
        items = list(table.items())
        rng.shuffle(items)
        return dict(items)

    holds = list(snap["holds"])
    rng.shuffle(holds)
    return {"format": snap["format"], "refs": shuffle(snap["refs"]),
            "labels": shuffle(snap["labels"]), "lineage": shuffle(snap["lineage"]),
            "holds": holds}  # fmt: skip


def _changed(base: dict, side: dict, merged: dict) -> None:
    for ref, oid in side["refs"].items():
        if base["refs"].get(ref) != oid:
            assert merged["refs"][ref] == oid
    for ident, digest in side["lineage"].items():
        assert merged["lineage"][ident] == digest


def test_random_branch_merges_are_commutative_and_never_weaken_holds() -> None:
    rng = random.Random(SEED)
    signer = key("69" * 32)
    clean = conflicting = 0
    for case in range(CASES):
        base = _base(rng)
        ours, theirs = _edit(rng, base), _edit(rng, base)
        one, two = hm.merge(base, ours, theirs), hm.merge(base, theirs, ours)
        assert one == two, case
        again = hm.merge(_shuffled(rng, base), _shuffled(rng, ours), _shuffled(rng, theirs))
        assert again == one, case
        merged = one["merged"]
        holds = {tuple(h) for h in merged["holds"]}
        assert {tuple(h) for h in base["holds"]} <= holds
        assert {tuple(h) for h in ours["holds"]} | {tuple(h) for h in theirs["holds"]} <= holds
        assert set(base["refs"]) <= set(merged["refs"])
        if one["conflicts"]:
            conflicting += 1
            kinds = [hm.KINDS.index(c["kind"]) for c in one["conflicts"]]
            assert kinds == sorted(kinds)
        else:
            clean += 1
            _changed(base, ours, merged)
            _changed(base, theirs, merged)
        if case % 50 == 0:
            record = sign(signer, one, subject=RUNS[0], target=None, at="2026-12-01T00:00:00Z")
            assert check(record, base, theirs, ours)["ok"]
            assert check(record, base, ours, theirs)["ok"]
    assert clean > 100 and conflicting > 100  # both regimes are exercised


def test_conflicts_are_reported_deterministically_and_keep_the_base() -> None:
    a, b, c = RUNS[:3]
    base = hm.empty()
    base["refs"] = {"heads/main": a}
    base["labels"] = {"prod": {"current": a, "history": [HEXES[0]]}}
    base["holds"] = [["loop-stop:l1", a]]
    ours, theirs = hm.normalize(base), hm.normalize(base)
    ours["refs"]["heads/main"], theirs["refs"]["heads/main"] = b, c
    ours["labels"]["prod"] = {"current": b, "history": [HEXES[0], HEXES[1]]}
    theirs["labels"]["prod"] = {"current": c, "history": [HEXES[0], HEXES[2]]}
    ours["lineage"], theirs["lineage"] = {IDS[0]: HEXES[0]}, {IDS[0]: HEXES[1]}
    theirs["holds"] = []
    found = hm.merge(base, ours, theirs)
    assert [(c["kind"], c["key"]) for c in found["conflicts"]] == [
        ("ref-diverged", "heads/main"), ("promotion-diverged", "prod"),
        ("lineage-id", IDS[0]), ("hold-weakened", "loop-stop:l1")]  # fmt: skip
    merged = found["merged"]
    assert merged["refs"]["heads/main"] == a and merged["labels"]["prod"]["current"] == a
    assert merged["holds"] == [["loop-stop:l1", a]] and IDS[0] not in merged["lineage"]


def test_a_taint_added_on_one_side_stops_the_other_side_promoting_that_run() -> None:
    a, bad = RUNS[0], RUNS[5]
    base = hm.empty()
    base["labels"] = {"prod": {"current": a, "history": [HEXES[0]]}}
    ours, theirs = hm.normalize(base), hm.normalize(base)
    ours["holds"] = [["integrity-taint:" + bad, "attestation:sha256:" + "e" * 64]]
    theirs["labels"]["prod"] = {"current": bad, "history": [HEXES[0], HEXES[1]]}
    theirs["refs"] = {"heads/main": bad}
    found = hm.merge(base, ours, theirs)
    assert [(c["kind"], c["key"]) for c in found["conflicts"]] == [
        ("held-target", "labels/prod"), ("held-target", "refs/heads/main")]  # fmt: skip
    assert found["merged"]["labels"]["prod"]["current"] == a
    assert "heads/main" not in found["merged"]["refs"]
