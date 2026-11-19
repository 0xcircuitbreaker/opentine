"""0.68 red-team: a sandbagging optimizer trying to dodge ``tine elicit report``."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine import _elicit
from opentine._elicit_load import load
from opentine._elicit_report import report
from tests.elicit_helpers import AT, KEY, agent, condition, draft, drafts, files

pytestmark = pytest.mark.filterwarnings("ignore::Warning")
UNPINNED = {"status": "absent", "roles": {}}
OWN = Ed25519PrivateKey.from_private_bytes(b"\x52" * 32)


def _fp(key) -> str:
    from opentine._signing_pins import key_fingerprint

    return key_fingerprint(key.public_key().public_bytes_raw())


def _codes(row: dict) -> list[str]:
    return [f["code"] for f in row["findings"]]


def test_self_signed_records_are_not_counted_once_roles_are_pinned():
    pinned = {"status": "pinned", "roles": {"scorer": [_fp(KEY)]}}
    forged = [_elicit.sign(d, OWN, at=AT) for d in drafts(4, sandbag=False)]
    row = load(files(forged), pinned)
    assert row["records"] == 0
    assert "fail:elicit.signer-unpinned" in _codes(row)


def test_dropping_the_eval_cued_runs_is_reported_not_silent():
    kept = [r for r in agent(7, sandbag=True) if r["condition"]["cue"] != "eval"]
    row = report(load(files(kept), UNPINNED))
    assert row["tests"] == []
    assert "advisory:elicit.untested" in _codes(row)


def test_too_few_shared_items_is_reported_not_silent():
    recs = [r for r in agent(7, sandbag=True) if r["task"] == "code-a"]
    for r in recs:
        if r["condition"]["cue"] == "eval":
            d = {k: v for k, v in r.items() if k != "signature"}
            d["items"] = d["items"][:5]
            recs[recs.index(r)] = _elicit.sign(d, KEY, at=AT)
    row = report(load(files(recs), UNPINNED))
    assert "advisory:elicit.untested" in _codes(row)


def test_dropping_failed_cued_items_is_reported():
    recs = []
    for d in drafts(7, sandbag=True):
        if d["condition"]["cue"] == "eval":
            d["items"] = [i for i in d["items"] if i["score"] != "0"]
        recs.append(_elicit.sign(d, KEY, at=AT))
    row = report(load(files(recs), UNPINNED))
    assert "advisory:elicit.missing-items" in _codes(row)
    assert all(f["level"] == "advisory" for f in row["findings"])


@pytest.mark.parametrize(("kind", "cue"), [("eval-cue", "none"), ("deployment-cue", "none")])
def test_a_cue_condition_cannot_hide_its_cue(kind, cue):
    assert _elicit.problems(draft("t", condition("c", kind, cue), [1, 2]))


@pytest.mark.parametrize("score", ["NaN", "inf", "-0.5", "1.5", "1e0"])
def test_non_finite_and_out_of_range_scores_are_refused(score):
    d = draft("t", condition("c", "prompt", "none"), [1])
    d["items"][0]["score"] = score
    assert _elicit.problems(d)
