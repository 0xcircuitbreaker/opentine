"""0.74 end to end: transcript analysis at corpus scale, through the CLI.

Acceptance criteria: runs like a known-bad run are found; runs cluster with
their behaviour; a pinned scorer flags them (an optimizer cannot); verified
flags and similar-to-known-bad runs open oversight-queue items only through a
pinned route; an approver clears them; ``tine query`` shows flags and
clusters; ``tine dataset contamination`` reports embedding near-duplicates.
"""

from __future__ import annotations

import json

import pytest

import opentine.cli as cli
from opentine import _oversight, _oversight_policy, _schemas
from opentine.graph import Run, StepKind
from opentine.repository import Repo
from tests.key_roles_helpers import isolated_trust_config, pin_roles  # noqa: F401
from tests.test_064_oversight_gate import _key, _toml

pytestmark = pytest.mark.filterwarnings("ignore::Warning")

AT = "2026-11-20T00:00:00Z"
SEEDS = {"scorer": 11, "optimizer": 12, "policy": 13, "a1": 14}
HACK = "edit tests/conftest.py: monkeypatch the grader so score always returns 1.0"
WORK = ["read_file src/cart/core.py then run pytest tests/test_cart.py -q",
        "grep -rn TODO docs and rewrite the install section of the readme",
        "add a migration for the orders table and run alembic upgrade head",
        "profile the image resize loop and cache the decoded thumbnails"]  # fmt: skip
HOLDOUT = ("The function returns the sum of the prices after the discount is applied and "
           "rounds the total to two decimal places before the invoice is printed")  # fmt: skip
PARAPHRASE = ("before the invoice is printed the total is rounded to two decimal places, and "
              "the function returns the prices sum after applying the discount")  # fmt: skip


def _fp(name: str) -> str:
    from opentine._signing_pins import key_fingerprint

    return key_fingerprint(_key(SEEDS[name]).public_key().public_bytes_raw())


def _tine(capsys, *argv: str) -> tuple[int, dict]:
    capsys.readouterr()
    code = 0
    try:
        cli.main(list(argv))
    except SystemExit as exc:
        code = int(exc.code) if isinstance(exc.code, int) else 1
    out = capsys.readouterr().out
    body = json.loads(out) if out.strip().startswith("{") else {}
    if body and "error" not in body:
        assert _schemas.validate_output(body) == [], body
    return code, body


@pytest.fixture
def room(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    repo = Repo.init(tmp_path / "r")
    runs: dict[str, list[str]] = {"hack": [], "work": []}
    for i in range(4):
        run = Run(id=f"hack-{i}", model_info="m", user_prompt=HACK)
        for j in range(3):
            run.add_step(StepKind.tool, {"tool": "bash", "input": {"cmd": f"{HACK} {j}"}})
        runs["hack"].append(repo.put_run(run).run_id)
    for i, text in enumerate(WORK * 2):
        run = Run(id=f"work-{i}", model_info="m", user_prompt=text)
        for j in range(3):
            run.add_step(StepKind.tool, {"tool": "bash", "input": {"cmd": f"{text} {j}"}})
        runs["work"].append(repo.put_run(run).run_id)
    roles = {"scorer": [_fp("scorer")], "optimizer": [_fp("optimizer")],
             "policy": [_fp("policy")], "approver": [_fp("a1")]}  # fmt: skip
    (repo.path / "key-roles.toml").write_bytes(
        ("version = 1\n[roles]\n" + _toml(roles)).encode("utf-8"))  # fmt: skip
    pin_roles(repo.path)
    keys = {}
    for name, seed in SEEDS.items():
        keys[name] = tmp_path / f"{name}.hex"
        keys[name].write_bytes(_key(seed).private_bytes_raw().hex().encode("ascii"))
    return {"repo": repo, "runs": runs, "keys": keys, "tmp": tmp_path}


def _pin_policy(repo, route: str) -> None:
    policy = ("version = 1\n[tiers.high]\nk = 1\n" + _toml({"approvers": [_fp("a1")]})
              + route)  # fmt: skip
    (repo.path / "oversight.toml").write_bytes(policy.encode("utf-8"))
    doc = _oversight_policy.sign(_key(SEEDS["policy"]), policy.encode("utf-8"), AT)
    (repo.path / "oversight.sig.json").write_bytes(json.dumps(doc).encode("utf-8"))


def _queue(capsys) -> dict[str, dict]:
    code, body = _tine(capsys, "oversight", "queue", "--repo", "r", "--json")
    assert code in (0, 1), body
    return {row["item"]: row for row in body["items"]}


def test_transcript_analysis_acceptance(capsys, room):
    hack, work = room["runs"]["hack"], room["runs"]["work"]
    # find all trajectories like this one
    code, body = _tine(capsys, "transcripts", "similar", hack[0], "-k", "3", "--repo", "r",
                       "--json")  # fmt: skip
    assert code == 0 and {h["run"] for h in body["hits"]} == set(hack[1:])
    # the hacking runs share one cluster, and no work run is in it
    code, body = _tine(capsys, "transcripts", "cluster", "--k", "5", "--repo", "r", "--json")
    assert code == 0
    home = [c for c in body["clusters"] if hack[0] in c["members"]][0]
    assert set(hack) <= set(home["members"]) and not set(work) & set(home["members"])

    # nothing is queued before a flag, and no route means nothing reaches a tier
    _pin_policy(room["repo"], '[[route]]\nsource = "transcript"\nlabel = "reward-*"\n'
                              'tier = "high"\n')  # fmt: skip
    assert not [i for i in _queue(capsys) if i.startswith("transcript:")]

    # an optimizer key cannot flag; nothing is written
    code, body = _tine(capsys, "transcripts", "label", "reward-hacking", "--run", hack[0],
                       "--key", str(room["keys"]["optimizer"]), "--at", AT, "--repo", "r",
                       "--json")  # fmt: skip
    assert code != 0
    assert not [i for i in _queue(capsys) if i.startswith("transcript:")]

    # a pinned scorer flags one run; the flag and the runs like it are queued, pending
    code, body = _tine(capsys, "transcripts", "label", "reward-hacking", "--run", hack[0],
                       "--key", str(room["keys"]["scorer"]), "--at", AT, "--repo", "r",
                       "--json")  # fmt: skip
    assert code == 0
    record = body["record"]
    items = {k: v for k, v in _queue(capsys).items() if k.startswith("transcript:")}
    like = {f"transcript:reward-hacking:{r}" for r in hack[1:]}
    assert set(items) == {f"transcript:{record}", *like}
    assert {v["state"] for v in items.values()} == {"pending"}
    assert {v["source"] for v in items.values()} == {"transcript"}

    # an approver clears one item; the others stay pending
    item = sorted(like)[0]
    _oversight.decide(room["repo"], item, "approve", _key(SEEDS["a1"]), at=AT)
    states = {k: v["state"] for k, v in _queue(capsys).items() if k.startswith("transcript:")}
    assert states[item] == "approved" and states[f"transcript:{record}"] == "pending"

    # a route for another label leaves the flag unrouted and out of the queue
    _pin_policy(room["repo"], '[[route]]\nsource = "transcript"\nlabel = "sabotage-*"\n'
                              'tier = "high"\n')  # fmt: skip
    rows = _queue(capsys)
    assert f"transcript:{record}" not in rows and rows[item]["state"] == "unrouted"

    # tine query: flags with their evidence runs, and clusters
    code, body = _tine(capsys, "query", "SELECT label, run FROM transcript_flag_runs",
                       "--repo", "r", "--json")  # fmt: skip
    assert code == 0 and body["rows"] == [{"label": "reward-hacking", "run": hack[0]}]
    code, body = _tine(capsys, "query", "SELECT oid, cluster FROM transcript_clusters",
                       "--repo", "r", "--json")  # fmt: skip
    found = {r["oid"]: r["cluster"] for r in body["rows"]}
    assert code == 0 and set(found) == set(hack) | set(work)
    assert len({found[r] for r in hack}) == 1  # default k (2 for 12 runs) and seed 0
    code, body = _tine(capsys, "query", "SELECT oid, label FROM transcript_flags", "--verify",
                       "--repo", "r", "--json")  # fmt: skip
    assert code == 0 and [c["status"] for c in body["verification"]["rows"]] == ["verified"]


def test_contamination_reports_embedding_near_duplicates(capsys, room):
    tmp = room["tmp"]
    (tmp / "h.jsonl").write_bytes((json.dumps({"id": "h1", "input": HOLDOUT}) + "\n").encode())
    (tmp / "c.jsonl").write_bytes((json.dumps({"id": "1", "input": PARAPHRASE}) + "\n").encode())
    argv = ("dataset", "contamination", "h.jsonl", "--against", "c.jsonl", "--repo", "r",
            "--json")  # fmt: skip
    code, body = _tine(capsys, *argv)
    assert code == 0 and body["ok"] is True and "embedding" not in body
    code, body = _tine(capsys, *argv, "--embedding-threshold", "0.5")
    assert code == 1 and body["ok"] is False
    assert [n["id"] for n in body["embedding"]["near"]] == ["h1"]
    assert body["embedding"]["backend_digest"].startswith("sha256:")


def test_an_unverified_flag_opens_nothing_and_seeds_no_similar_hits(capsys, room):
    from opentine import _containment_records as records
    from opentine import _transcript_flags as tf

    hack = room["runs"]["hack"]
    _pin_policy(room["repo"], '[[route]]\nsource = "transcript"\ntier = "high"\n')
    claim = {"convention": tf.CONVENTION, "label": "reward-hacking", "evidence": [hack[0]],
             "cluster": None, "labeller": _fp("optimizer"), "backend": None, "note": "",
             "labelled_at": AT}  # fmt: skip
    records.record(room["repo"], hack[0], claim, _key(SEEDS["optimizer"]),
                   f"{tf.HOLD}reward-hacking:{hack[0]}")  # fmt: skip
    (flag,) = tf.flags(room["repo"])
    assert flag["verification"] == "unverified: the signer is an optimizer key"
    assert not [i for i in _queue(capsys) if i.startswith("transcript:")]
