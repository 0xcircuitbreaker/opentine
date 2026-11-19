"""Build ``tests/data/history_merge.json``: the shared history-merge fixture (0.69).

Seeded, count-based cases (base, two sides, the signed record and what every
implementation must answer), plus hand-made edits: a record whose conflicts were
edited, one checked under another key, an unsigned one and the sides swapped.
The reference (:mod:`opentine._history_merge_record`), the pyz
(``opentine/_pyz/_histmerge.py``) and the TS verifier (``ts/verifier/src/histmerge.ts``)
answer every case identically. Regenerate with
``python -m tests.test_069_history_merge_fixture``.
"""

from __future__ import annotations

import copy
import random

from opentine import _history_merge as hm
from opentine._history_merge_record import check, sign
from tests.promote_helpers import key

SEED = 690
RANDOM_CASES = 24
AT = "2026-12-01T00:00:00Z"
SIGNER, OTHER = "69" * 32, "96" * 32
SUBJECT = "run:sha256:" + "ab" * 32


def _public(seed: str) -> str:
    return key(seed).public_key().public_bytes_raw().hex()


def _expect(record: dict, base: dict, ours: dict, theirs: dict, public: str | None) -> dict:
    found = check(record, base, ours, theirs, bytes.fromhex(public) if public else None)
    merged = hm.merge(base, ours, theirs)
    return {**found, "merged_snapshot": merged["merged"],
            "conflict_rows": merged["conflicts"]}  # fmt: skip


def _case(ident: str, base: dict, ours: dict, theirs: dict, record: dict,
          public: str | None = None) -> dict:  # fmt: skip
    expect = _expect(record, base, ours, theirs, public)
    return {"id": ident, "base": base, "ours": ours, "theirs": theirs, "record": record,
            "public_key": public, "expect": expect}  # fmt: skip


def _every_kind() -> dict[str, tuple[dict, dict, dict]]:
    """Hand-made merges: every conflict kind, and a taint that stops a promotion."""
    a, b, c = (f"run:sha256:{i:064x}" for i in (1, 2, 3))
    h = [f"{i:064x}" for i in (40, 41, 42)]
    base = hm.empty()
    base["refs"] = {"heads/main": a}
    base["labels"] = {"prod": {"current": a, "history": [h[0]]},
                      "canary": {"current": a, "history": [h[0]]}}  # fmt: skip
    base["holds"] = [["loop-stop:l1", a]]
    ours, theirs = hm.normalize(base), hm.normalize(base)
    ours["refs"]["heads/main"], theirs["refs"]["heads/main"] = b, c
    ours["labels"]["prod"] = {"current": b, "history": [h[0], h[1]]}
    theirs["labels"]["prod"] = {"current": c, "history": [h[0], h[2]]}
    ours["labels"]["canary"] = {"current": b, "history": [h[0], h[1]]}
    theirs["labels"]["canary"] = {"current": c, "history": [h[0], h[1]]}
    ident = "sha256:" + "20" * 32
    ours["lineage"], theirs["lineage"] = {ident: h[0]}, {ident: h[1]}
    theirs["holds"] = []
    taint_base = hm.empty()
    taint_base["labels"] = {"prod": {"current": a, "history": [h[0]]}}
    tainted, promoted = hm.normalize(taint_base), hm.normalize(taint_base)
    tainted["holds"] = [["integrity-taint:" + c, "attestation:sha256:" + "e" * 64]]
    promoted["labels"]["prod"] = {"current": c, "history": [h[0], h[1]]}
    promoted["refs"] = {"heads/main": c}
    return {"every-kind": (base, ours, theirs), "taint": (taint_base, tainted, promoted)}


def build_fixture() -> dict:
    from tests.test_069_history_merge_property import _base, _edit

    rng = random.Random(SEED)
    signer = key(SIGNER)
    cases = []
    for n in range(RANDOM_CASES):
        base = _base(rng)
        ours, theirs = _edit(rng, base), _edit(rng, base)
        record = sign(signer, hm.merge(base, ours, theirs), subject=SUBJECT,
                      target="heads/main" if n % 2 else None, at=AT)  # fmt: skip
        cases.append(_case(f"random-{n:02d}", base, ours, theirs, record,
                           _public(SIGNER) if n % 3 == 0 else None))  # fmt: skip
    for ident, (base, ours, theirs) in _every_kind().items():
        record = sign(signer, hm.merge(base, ours, theirs), subject=SUBJECT, target=None, at=AT)
        cases.append(_case(ident, base, ours, theirs, record))
    first = cases[1]
    base, ours, theirs = first["base"], first["ours"], first["theirs"]
    record = first["record"]
    cases.append(_case("swapped-sides", base, theirs, ours, record))
    edited = copy.deepcopy(record)
    edited["claim"]["conflicts"] = [{"kind": "lineage-id", "key": "x", "base": None,
                                     "sides": ["a", "b"]}]  # fmt: skip
    cases.append(_case("edited-conflicts", base, ours, theirs, edited))
    cases.append(_case("other-key", base, ours, theirs, record, _public(OTHER)))
    unsigned = {k: v for k, v in record.items() if k != "signature"}
    cases.append(_case("unsigned", base, ours, theirs, unsigned))
    wrong = copy.deepcopy(theirs)
    wrong["refs"]["heads/extra"] = SUBJECT
    cases.append(_case("other-snapshot", base, ours, wrong, record))
    return {"format": "opentine-history-merge-fixture/1", "cases": cases}


__all__ = ["build_fixture"]
