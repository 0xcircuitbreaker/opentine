"""0.72 acceptance, end to end: weight custody and model organisms reach review and query.

1. A tagged checkpoint is created and copied with signed, held, chained events;
   the weights themselves are never stored.
2. A copy no event explains (an observed location) and a load from an unrecorded
   location are custody gaps: ``tine custody check`` exits 1 and the event behind
   each ``fail:`` finding is an item of the oversight queue (source ``custody``).
3. ``tine custody gate`` denies an unapproved load of the tagged artifact; the
   refusal is held (``tine hold release`` refuses it) and queued for review, as is
   a refused ``tine organism gate`` access.
4. ``tine query`` shows every custody event and organism record, and ``--verify``
   marks pinned signers verified.
5. An optimizer-signed approval opens nothing; a pinned policy approval does.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import types

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import opentine.cli as cli
from opentine import _organism, _organism_gate, _oversight_policy, _oversight_queue, _schemas
from opentine import _weight_custody as wc
from opentine._cli_custody_weights import gate
from opentine._signing_pins import key_fingerprint
from opentine._weight_custody_review import REFUSAL, REFUSED_HOLD
from opentine.repository import Repo
from opentine.repository._holds import HoldError, holds_path, read_holds, release
from tests.key_roles_helpers import isolated_trust_config, pin_roles  # noqa: F401

pytestmark = pytest.mark.filterwarnings("ignore::Warning")

AT = "2026-12-05T10:00:00Z"
SEEDS = {"runner": 0x61, "policy": 0x62, "optimizer": 0x63, "a1": 0x64, "a2": 0x65}
WEIGHTS = b"\x00\x01organism weights" * 512
ORG = "sha256:" + hashlib.sha256(b"a second organism\n").hexdigest()


def _key(name: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes([SEEDS[name]]) * 32)


def _fpr(name: str) -> str:
    return key_fingerprint(_key(name).public_key().public_bytes_raw())


@pytest.fixture
def room(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    repo = Repo.init(tmp_path / "r")
    roles = {"runner": [_fpr("runner")], "policy": [_fpr("policy")],
             "optimizer": [_fpr("optimizer")], "approver": [_fpr("a1"), _fpr("a2")]}  # fmt: skip
    text = "version = 1\n[roles]\n" + "".join(f"{k} = {json.dumps(v)}\n" for k, v in roles.items())
    (repo.path / "key-roles.toml").write_bytes(text.encode("utf-8"))
    pin_roles(repo.path)
    policy = ('version = 1\n[tiers.high]\nk = 1\napprovers = ["' + _fpr("a1") + '"]\n'
              '[[route]]\nsource = "custody"\ntier = "high"\n'
              '[[route]]\nsource = "organism"\ntier = "high"\n')  # fmt: skip
    (repo.path / "oversight.toml").write_bytes(policy.encode("utf-8"))
    doc = _oversight_policy.sign(_key("policy"), policy.encode("utf-8"), AT)
    (repo.path / "oversight.sig.json").write_bytes(json.dumps(doc).encode("utf-8"))
    keys = {}
    for name in SEEDS:
        keys[name] = tmp_path / f"{name}.hex"
        keys[name].write_bytes(_key(name).private_bytes_raw().hex().encode("ascii"))
    weights = tmp_path / "w.safetensors"
    weights.write_bytes(WEIGHTS)
    return {"repo": repo, "where": repo.path.parent.as_posix(), "keys": keys, "w": weights}


def _tine(capsys, *argv: str) -> tuple[int, dict]:
    capsys.readouterr()
    code = 0
    try:
        cli.main(list(argv))
    except SystemExit as exc:
        code = exc.code or 0
    body = json.loads(capsys.readouterr().out)
    assert _schemas.validate_output(body) == []
    return code, body


def _rec(capsys, room, event, location, *extra, key="runner"):
    code, body = _tine(capsys, "custody", "record", event, location, "--artifact", "mo-1",
                       "--sign-key", room["keys"][key].as_posix(), "--repo", room["where"],
                       "--json", *extra)  # fmt: skip
    assert code == 0, body
    return body


def _gate(room, path: str) -> dict:
    payload = {"session_id": "s1", "tool_name": "Bash",
               "tool_input": {"command": f"python load.py {path}"}}  # fmt: skip
    sink = io.BytesIO()
    args = types.SimpleNamespace(repo=room["where"], agent="claude-code")
    assert gate(args, io.BytesIO(json.dumps(payload).encode("utf-8")), sink) == 0
    return json.loads(sink.getvalue())


def _custody_items(repo) -> dict[str, str]:
    queue = _oversight_queue.queue(repo)
    return {i["item"]: i["state"] for i in queue["items"] if i["source"] == "custody"}


def test_custody_gaps_and_refused_loads_reach_oversight_and_query(room, capsys):
    repo, where, w = room["repo"], room["where"], room["w"].as_posix()
    digest = "sha256:" + hashlib.sha256(WEIGHTS).hexdigest()
    # 1. created (tagged) and copied: signed, chained, held; no weight bytes stored
    created = _rec(capsys, room, "created", "s3://lab/mo-1", "--file", w,
                   "--tag", "model-organism")["record"]  # fmt: skip
    copied = _rec(capsys, room, "copied", "/scratch/mo-1", "--digest", digest)["record"]
    assert not any(WEIGHTS[:32] in p.read_bytes() for p in repo.path.rglob("*") if p.is_file())
    code, body = _tine(capsys, "custody", "check", "mo-1", "--repo", where, "--json")
    assert code == 0 and body["tagged"] is True and _custody_items(repo) == {}

    # 2. a load from a location no event put the weights at is a gap, and is queued
    loaded = _rec(capsys, room, "loaded", "/tmp-copy/mo-1", "--digest", digest)["record"]
    code, body = _tine(capsys, "custody", "check", "mo-1", "--repo", where, "--json")
    codes = {(f["code"], f["record"]) for f in body["findings"]}
    assert code == 1
    assert {("fail:custody-gap", loaded), ("fail:custody-unapproved-load", loaded)} <= codes
    assert _custody_items(repo) == {f"custody:{loaded}": "pending"}

    # 3. the gate denies the load; the refusal is held, unreleasable and queued
    deny = _gate(room, "/scratch/mo-1")["hookSpecificOutput"]
    assert deny["permissionDecision"] == "deny"
    refusals = [r for r in read_holds(holds_path(repo)) if r["target"].startswith(REFUSED_HOLD)]
    assert [r["target"] for r in refusals] == [REFUSED_HOLD + "mo-1"]
    entry = json.loads(bytes(repo.get(refusals[0]["oid"]).body))
    assert entry["convention"] == REFUSAL and entry["tool"] == "Bash"
    assert _schemas.validate(entry, "opentine-weight-custody-refusal-1")[1] == []
    with pytest.raises(HoldError, match="never released"):
        release(repo, REFUSED_HOLD + "mo-1")
    assert f"custody:{refusals[0]['oid']}" in _custody_items(repo)
    # ... and so is a refused organism-gate access
    _organism.tag(repo, ORG, _key("policy"), names=["org2.bin"], reason="probe", at=AT)
    args = argparse.Namespace(agent="claude-code", run="s1", fail_closed=False, repo=where)
    out = io.BytesIO()
    call = {"session_id": "s1", "tool_name": "Bash", "tool_input": {"command": "cat org2.bin"}}
    _organism_gate.run(args, io.BytesIO(json.dumps(call).encode("utf-8")), out)
    assert json.loads(out.getvalue())["hookSpecificOutput"]["permissionDecision"] == "deny"
    access = [r["oid"] for r in read_holds(holds_path(repo))
              if r["target"].startswith("organism:access:")]  # fmt: skip
    assert len(access) == 1 and f"custody:{access[0]}" in _custody_items(repo)

    # 4. tine query shows every custody event and the organism tag, verified by pinned roles
    assert _tine(capsys, "query", "index", "--rebuild", "--repo", where, "--json")[0] == 0
    code, body = _tine(capsys, "query", "SELECT oid, event, seq, location FROM weight_custody "
                       "ORDER BY seq", "--repo", where, "--verify", "--json")  # fmt: skip
    assert code == 0, body
    assert [(r["oid"], r["event"]) for r in body["rows"]] == [
        (created, "created"), (copied, "copied"), (loaded, "loaded")]  # fmt: skip
    assert body["verification"]["counts"]["verified"] == 3
    code, body = _tine(capsys, "query", "SELECT record, artifact FROM organism_records",
                       "--repo", where, "--json")  # fmt: skip
    assert [(r["record"], r["artifact"]) for r in body["rows"]] == [("tag", ORG)]

    # 5. an optimizer approval opens nothing; a pinned policy approval opens the gate
    _rec(capsys, room, "approved", "s3://lab/mo-1", "--digest", digest, key="optimizer")
    assert _gate(room, "/scratch/mo-1")["hookSpecificOutput"]["permissionDecision"] == "deny"
    _rec(capsys, room, "approved", "s3://lab/mo-1", "--digest", digest, key="policy")
    assert _gate(room, "/scratch/mo-1") == {}
    assert len(wc.events(repo, "mo-1")) == 5
