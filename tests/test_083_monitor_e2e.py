"""0.83 end to end: a collusion protocol run is signed, queryable, held and reviewed.

Acceptance: ``tine monitor protocol-run`` produces signed verdicts with
detection rates and confidence intervals; ``--record`` holds them; ``tine query``
lists them with a per-row signature flag; a failed protocol opens a
``collusion`` item in the oversight queue, and a cleared one opens none; a held
line that no longer checks is listed (fail closed); a held verdict cannot be
released. Counts only, no clocks.
"""

from __future__ import annotations

import json

import pytest

from opentine import _collusion_record, _oversight_policy, _oversight_queue
from opentine._signing_pins import key_fingerprint
from opentine.repository import Repo
from opentine.repository._holds import COLLUSION_VERDICT, HoldError, holds_path, read_holds
from opentine.repository._holds import release as release_hold
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401
from tests.test_083_collusion_protocol import POLICY, SCORER, _pin, _run, _secret, _sign, _tine
from tests.test_083_collusion_protocol import room as room  # noqa: F401 - fixture

pytestmark = pytest.mark.filterwarnings("ignore::Warning")


def _pin_oversight(repo: Repo) -> None:
    fpr = key_fingerprint(SCORER.public_key().public_bytes_raw())
    text = (f'version = 1\n[tiers.high]\nk = 1\napprovers = ["{fpr}"]\n'
            '[[route]]\nsource = "collusion"\ntier = "high"\n').encode()  # fmt: skip
    (repo.path / "oversight.toml").write_bytes(text)
    doc = _oversight_policy.sign(POLICY, text, "2026-11-25T00:00:00Z")
    (repo.path / "oversight.sig.json").write_bytes(json.dumps(doc).encode("utf-8"))


def _collusion_items(repo: Repo) -> list[str]:
    return [i["item"] for i in _oversight_queue.queue(repo)["items"]
            if i["source"] == "collusion"]  # fmt: skip


def test_a_failed_protocol_is_signed_queryable_held_and_reviewed(room, capsys):
    _pin(room)
    repo = Repo.open(room / "r")
    _pin_oversight(repo)
    assert _sign(capsys, room)[0] == 0
    evals = room / "evals"
    evals.mkdir()
    key = ("--key", str(room / "scorer.key"))
    code, row = _run(capsys, room, "honest.json", *_secret(room), *key, "--record")
    assert code == 0 and row["cleared"] and len(row["recorded"]) == 6
    assert _collusion_items(repo) == []

    code, row = _run(capsys, room, "colluding.json", *_secret(room), *key, "--record",
                     "--verdicts", str(evals / "verdicts.jsonl"))  # fmt: skip
    c = row["collusion"]
    assert code == 0 and not row["cleared"] and c["flagged"] == c["trials"] == 20
    assert c["rate"] is not None and c["wilson"] and c["clopper_pearson"][1] == "1.000000"
    overall = f"collusion:{row['recorded'][0]}"
    assert _collusion_items(repo) == [overall]
    code, body = _tine(capsys, "oversight", "queue", "--repo", str(room / "r"))
    assert code == 0 and overall in [i["item"] for i in body["items"]]

    assert _tine(capsys, "query", "index", "--rebuild", "--evals", str(evals),
                 "--repo", str(room / "r"))[0] == 0  # fmt: skip
    code, body = _tine(capsys, "query", "SELECT item, passed, signed FROM evals ORDER BY item",
                       "--repo", str(room / "r"), "--verify")  # fmt: skip
    assert code == 0 and len(body["rows"]) == 6
    assert all(r["signed"] == 1 for r in body["rows"])

    targets = [r for r in read_holds(holds_path(repo))
               if r["target"].startswith(COLLUSION_VERDICT)]  # fmt: skip
    assert len(targets) == 12
    with pytest.raises(HoldError):
        release_hold(repo, targets[0]["target"])


def test_a_held_line_that_no_longer_checks_is_listed(room, capsys):
    _pin(room)
    repo = Repo.open(room / "r")
    assert _sign(capsys, room)[0] == 0
    code, row = _run(capsys, room, "honest.json", *_secret(room), "--key",
                     str(room / "scorer.key"), "--verdicts", str(room / "v.jsonl"))  # fmt: skip
    line = json.loads((room / "v.jsonl").read_bytes().split(b"\n")[0])
    forged = {**line, "claim": {**line["claim"], "flagged": 1}}
    oid = _collusion_record.record(repo, [forged])[0]
    assert [i["item"] for i in _collusion_record.items(repo)] == [f"collusion:{oid}"]


def test_record_needs_a_key(room, capsys):
    _pin(room)
    assert _sign(capsys, room)[0] == 0
    code, row = _run(capsys, room, "honest.json", *_secret(room), "--record")
    assert code != 0 and "need --key" in row["error"]["message"]
