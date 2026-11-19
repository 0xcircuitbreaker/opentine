"""0.64 end to end: the gate writes, the queue reads the same records, fatigue is advisory.

1. ``tine promote`` on a routed label is refused until k distinct pinned
   approvers sign; an optimizer-key approval never counts.
2. ``tine oversight queue --json`` (and ``tine ui --repo``'s
   ``/api/oversight/queue``) is rebuilt from the decision annotations the gate
   reads, and its state agrees with the gate's verdict at every step.
3. ``tine oversight fatigue`` measures time to decision from record timestamps
   and an injected clock, and exits 0 whatever it finds.
"""

from __future__ import annotations

import json
import threading
import urllib.request
from pathlib import Path

import pytest

from opentine import _oversight, _oversight_policy, _oversight_queue
from opentine._ui_server import Catalog, make_server
from opentine.repository import Repo
from tests.key_roles_helpers import isolated_trust_config, pin_roles  # noqa: F401
from tests.promote_helpers import RUN_B, fingerprint, key, write_key
from tests.test_057_promote_pins import _sign_policy
from tests.test_058_promote import Room, _codes, _good, _tine

pytestmark = pytest.mark.filterwarnings("ignore::Warning")

SIGNER, OPTIMIZER, A1, A2, A3 = "9e" * 32, "1f" * 32, "2a" * 32, "3b" * 32, "4c" * 32
ITEM = f"promotion:prod:{RUN_B}"
OPENED, VIEWED, FIRST, SECOND = (f"2026-12-03T10:{m:02d}:00Z" for m in (0, 1, 2, 5))
NOW = "2026-12-03T11:00:00Z"


@pytest.fixture
def setup(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", (tmp_path / "config").as_posix())
    monkeypatch.chdir(tmp_path)
    room, repo = Room(tmp_path), Repo.init(tmp_path / "r")
    approvers = [fingerprint(s) for s in (A1, A2, A3)]
    roles = {"policy": [fingerprint(SIGNER)], "optimizer": [fingerprint(OPTIMIZER)],
             "approver": approvers}  # fmt: skip
    lines = ["version = 1", "[roles]"] + [f"{r} = {json.dumps(k)}" for r, k in roles.items()]
    (repo.path / "key-roles.toml").write_bytes(("\n".join(lines) + "\n").encode("utf-8"))
    pin_roles(repo.path)
    listed = [*approvers, fingerprint(OPTIMIZER)]  # the optimizer is listed: it still never counts
    text = (
        f"version = 1\n[tiers.high]\nk = 2\napprovers = {json.dumps(listed)}\n"
        '[[route]]\nsource = "promotion"\nlabel = "prod*"\ntier = "high"\n'
    )
    (repo.path / "oversight.toml").write_bytes(text.encode("utf-8"))
    doc = _oversight_policy.sign(key(SIGNER), text.encode("utf-8"), OPENED)
    (repo.path / "oversight.sig.json").write_bytes(json.dumps(doc).encode("utf-8"))
    return room, repo


def _decide(capsys, room: Room, verb: str, seed: str, *extra: str) -> tuple[int, dict]:
    path = write_key(room.base / f"{seed[:2]}.key", seed).as_posix()
    return _tine(capsys, "oversight", verb, ITEM, "--key", path, "--repo", "r", "--json", *extra)


def _ui(root: Path) -> dict:
    server = make_server(Catalog([], repo=root))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_address[1]}/api/oversight/queue"
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(url, timeout=10) as res:
            return json.loads(res.read())
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=10)


def _queue(capsys) -> dict:
    code, body = _tine(capsys, "oversight", "queue", "--repo", "r", "--json")
    assert code == 0
    return body


def test_gate_queue_and_fatigue_agree_end_to_end(setup, capsys):
    room, repo = setup
    signed = _sign_policy(room, capsys, SIGNER, "signed.json")
    args = [*_good(room, capsys), "--repo", "r", "--policy-attestation", signed]
    assert _decide(capsys, room, "request", A1, "--at", OPENED)[0] == 0
    code, row = room.promote(capsys, RUN_B, *args)
    assert code == 1 and _codes(row) == {"promote.oversight-insufficient"}
    assert _queue(capsys)["items"][0]["state"] == "pending"

    # 1. the optimizer key is refused at the CLI, and an approval it writes by hand never counts
    code, body = _decide(capsys, room, "approve", OPTIMIZER)
    assert code != 0 and "oversight.key-separation" in json.dumps(body)
    bind = {"label": "prod", "candidate": RUN_B, "previous": None, "sequence": 0}
    _oversight.decide(repo, ITEM, "approve", key(OPTIMIZER), bind=bind, at=FIRST)
    code, _ = _decide(capsys, room, "approve", A2, "--viewed", RUN_B, "--viewed-at", VIEWED,
                      "--at", FIRST)  # fmt: skip
    assert code == 0
    code, row = room.promote(capsys, RUN_B, *args)
    assert code == 1 and _codes(row) == {"promote.oversight-key-separation"}
    item = _queue(capsys)["items"][0]
    assert item["state"] == "pending" and item["tiers"][0]["approvals"] == 1
    assert [u["why"] for u in item["uncounted"]] == ["key-separation"]

    # 2. k distinct approvers: the queue says approved from the records the gate reads
    assert _decide(capsys, room, "approve", A3, "--at", SECOND)[0] == 0
    shown = _queue(capsys)
    assert shown["items"][0]["state"] == "approved" and shown["counts"]["approved"] == 1
    assert _oversight_queue.queue(repo, from_objects=True)["digest"] == shown["digest"]
    assert _ui(repo.path.parent) == shown
    code, row = room.promote(capsys, RUN_B, *args)
    assert code == 0, row.get("refusals")
    after = _queue(capsys)  # the promoted item is judged as it stood when it moved
    assert after["items"][0]["state"] == "approved"

    # 3. fatigue: record timestamps and an injected clock; advisory, exit 0
    code, out = _tine(capsys, "oversight", "fatigue", "--repo", "r", "--at", NOW, "--json")
    assert code == 0 and out["advisory"] is True and out["queue"] == after["digest"]
    assert (out["approvals"], out["rubber_stamps"]) == (2, 1)  # A3 recorded no viewed evidence
    assert out["median_seconds_to_decision"] == 210.0  # (120 + 300) / 2 after the request
    code, quick = _tine(capsys, "oversight", "fatigue", "--repo", "r", "--min-review-seconds",
                        "90", "--at", NOW, "--json")  # fmt: skip
    assert code == 0 and quick["rubber_stamps"] == 2  # A2 decided 60 s after viewing
