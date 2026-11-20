"""0.72: model-organism tags, load approvals, the hook gate and the access log."""

from __future__ import annotations

import argparse
import hashlib
import io
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine import (
    _organism,
    _organism_gate,
    _organism_registry,
    _oversight,
    _oversight_policy,
    _schemas,
    cli,
)
from opentine._signing_pins import key_fingerprint
from opentine.repository import Repo
from opentine.repository._holds import HoldError, holds_path, release
from tests.key_roles_helpers import isolated_trust_config, pin_roles  # noqa: F401

pytestmark = pytest.mark.filterwarnings("ignore::Warning")

AT = "2026-12-05T10:00:00Z"
WEIGHTS = b"pretend weights of a sleeper-agent checkpoint\n"
ART = "sha256:" + hashlib.sha256(WEIGHTS).hexdigest()
SEEDS = {"policy": 1, "a1": 2, "a2": 3, "optimizer": 4, "monitor": 5, "curator": 6, "x": 7}


def _key(name: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes([SEEDS[name]]) * 32)


def _fpr(name: str) -> str:
    return key_fingerprint(_key(name).public_key().public_bytes_raw())


def _toml(rows: dict[str, list[str]]) -> str:
    return "".join(f"{k} = {json.dumps(v)}\n" for k, v in rows.items())


@pytest.fixture
def repo(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    repo = Repo.init(tmp_path / "r")
    approvers = [_fpr("a1"), _fpr("a2"), _fpr("monitor")]
    roles = {"optimizer": [_fpr("optimizer")], "monitor": [_fpr("monitor")],
             "policy": [_fpr("policy"), _fpr("optimizer")], "curator": [_fpr("curator")],
             "approver": approvers}  # fmt: skip
    (repo.path / "key-roles.toml").write_bytes(
        ("version = 1\n[roles]\n" + _toml(roles)).encode("utf-8"))  # fmt: skip
    pin_roles(repo.path)
    policy = ("version = 1\n[tiers.high]\nk = 2\n" + _toml({"approvers": approvers[:2]})
              + '[[route]]\nsource = "organism"\ntier = "high"\n')  # fmt: skip
    (repo.path / "oversight.toml").write_bytes(policy.encode("utf-8"))
    doc = _oversight_policy.sign(_key("policy"), (repo.path / "oversight.toml").read_bytes(), AT)
    (repo.path / "oversight.sig.json").write_bytes(json.dumps(doc).encode("utf-8"))
    return repo


def _tag(repo, names=("ckpt/sleeper.safetensors",)) -> str:
    return _organism.tag(repo, ART, _key("policy"), names=list(names), reason="sleeper", at=AT)


def _call(path: str) -> dict:
    return {"name": "Bash", "arguments": {"command": f"python load.py --ckpt={path}"}}


def _hook(repo, payload: dict, **extra) -> dict:
    args = argparse.Namespace(agent=extra.get("agent", "claude-code"), run=extra.get("run"),
                              fail_closed=False, repo=repo.path.parent.as_posix())  # fmt: skip
    out = io.BytesIO()
    _organism_gate.run(args, io.BytesIO(json.dumps(payload).encode("utf-8")), out)
    return json.loads(out.getvalue())


def _claude(session: str, path: str) -> dict:
    return {"session_id": session, "tool_name": "Bash",
            "tool_input": {"command": f"torch.load('/data/{path}')"}}  # fmt: skip


def test_loading_a_tagged_artifact_without_approval_is_refused_by_the_hook(repo):
    _tag(repo)
    body = _hook(repo, _claude("s1", "ckpt/sleeper.safetensors"))
    decision = body["hookSpecificOutput"]
    assert decision["permissionDecision"] == "deny"
    assert "organism:" in decision["permissionDecisionReason"]
    assert _hook(repo, _claude("s1", "ckpt/benign.safetensors")) == {}
    rows = _organism_registry.accesses(repo, ART)
    assert [(a["run"], a["outcome"]) for a in rows] == [("s1", "refused")]


def test_an_approval_is_bound_to_the_artifact_and_the_requesting_run(repo):
    _tag(repo)
    oid = _organism.approve(repo, ART, "s1", _key("a1"), why="probe study", at=AT)
    assert _hook(repo, _claude("s1", "ckpt/sleeper.safetensors")) == {}
    other = _hook(repo, _claude("s2", "ckpt/sleeper.safetensors"))
    assert other["hookSpecificOutput"]["permissionDecision"] == "deny"
    by_digest = {"protocol": "opentine-monitor/1", "session": "s2", "run": "s1",
                 "tool": {"name": "load", "input": {"digest": ART}}}  # fmt: skip
    assert _hook(repo, by_digest, agent="generic")["decision"] == "block"  # payload run ignored
    rows = _organism_registry.accesses(repo, ART)
    assert sorted((a["run"], a["outcome"], a["approval"]) for a in rows) == [
        ("s1", "allowed", oid),
        ("s2", "refused", None),
        ("s2", "refused", None),
    ]


@pytest.mark.parametrize("name", ["optimizer", "monitor", "x"])
def test_approvals_need_a_pinned_approver_key_without_banned_roles(repo, name):
    _tag(repo)
    with pytest.raises(_organism.OrganismError, match="organism.role"):
        _organism.approve(repo, ART, "s1", _key(name), why="w")


def test_tags_need_a_pinned_policy_or_curator_key_that_is_not_an_optimizer(repo):
    with pytest.raises(_organism.OrganismError, match="organism.role"):
        _tag_with(repo, "optimizer")
    with pytest.raises(_organism.OrganismError, match="organism.role"):
        _tag_with(repo, "a1")
    _tag_with(repo, "curator")
    assert _organism.tagged(repo, ART)["tagged"]


def _tag_with(repo, name: str) -> str:
    return _organism.tag(repo, ART, _key(name), names=[], reason="r", at=AT)


def test_every_record_is_held_and_release_is_refused(repo):
    tag = _tag(repo)
    _hook(repo, _claude("s1", "ckpt/sleeper.safetensors"))
    targets = {json.dumps(r) for r in json.loads(holds_path(repo).read_bytes())["holds"]}
    assert any("organism:access:" in t for t in targets)
    with pytest.raises(HoldError, match="model-organism"):
        release(repo, tag)


def test_an_unreadable_registry_refuses_every_call(repo):
    _tag(repo)
    holds_path(repo).write_bytes(b"{not json")
    body = _hook(repo, _claude("s1", "ckpt/benign.safetensors"))
    assert body["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "unreadable" in body["hookSpecificOutput"]["permissionDecisionReason"]


def test_untagging_needs_k_of_n_oversight_approval(repo):
    tag = _tag(repo)
    with pytest.raises(_organism.OrganismError, match="untag-unapproved"):
        _organism.untag(repo, ART, _key("policy"))
    item = _organism.item(tag)
    _oversight.decide(repo, item, "approve", _key("a1"), at=AT)
    with pytest.raises(_organism.OrganismError, match="untag-unapproved"):
        _organism.untag(repo, ART, _key("policy"))  # 1 of 2
    _oversight.decide(repo, item, "approve", _key("a2"), at=AT)
    _organism.untag(repo, ART, _key("policy"), at=AT)
    assert not _organism.tagged(repo, ART)["tagged"]
    assert _hook(repo, _claude("s9", "ckpt/sleeper.safetensors")) == {}
    _oversight.decide(repo, item, "reject", _key("a2"), at="2026-12-06T00:00:00Z")
    assert _organism.tagged(repo, ART)["tagged"]  # the untag no longer has its k approvals


def test_the_mcp_guard_answers_a_refused_call_and_relays_the_rest(repo):
    _tag(repo)
    guard = _organism_gate.OrganismMcpGuard(repo, "mcp-1")
    calls = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": _call("/x/ckpt/sleeper.safetensors"),
        },
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": _call("/x/ok.bin")},
    ]
    forward, back, blocked = guard.check(json.dumps(calls).encode("utf-8") + b"\n")
    assert [m["id"] for m in json.loads(forward)] == [2]
    reply = json.loads(back)[0]
    assert reply["id"] == 1 and reply["error"]["code"] == _organism_gate.ERROR_CODE
    assert reply["error"]["data"]["opentine.organism"]["artifacts"] == [ART]
    assert blocked is not None and guard.denied == 1
    untouched = json.dumps({"jsonrpc": "2.0", "id": 3, "method": "tools/list"}).encode()
    assert guard.check(untouched) == (untouched, None, None)
    assert _organism_gate.OrganismMcpGuard(None, "r").check(forward)[0] is None


def _tine(capsys, *argv: str) -> tuple[int, dict]:
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


def test_cli_tag_approve_status_json(repo, tmp_path, capsys):
    weights = tmp_path / "sleeper.safetensors"
    weights.write_bytes(WEIGHTS)
    keys = {}
    for name in ("policy", "a1"):
        keys[name] = tmp_path / f"{name}.key"
        keys[name].write_bytes(_key(name).private_bytes_raw().hex().encode("ascii"))
    code, body = _tine(capsys, "organism", "tag", weights.as_posix(), "--reason", "sleeper",
                       "--key", keys["policy"].as_posix(), "--repo", "r", "--json")  # fmt: skip
    assert code == 0 and body["artifact"] == ART
    code, body = _tine(capsys, "organism", "approve", ART, "--run", "s1", "--why", "study",
                       "--key", keys["a1"].as_posix(), "--repo", "r", "--json")  # fmt: skip
    assert code == 0
    assert _hook(repo, _claude("s2", weights.as_posix())) != {}
    code, body = _tine(capsys, "organism", "status", "--repo", "r", "--json")
    row = body["artifacts"][0]
    assert code == 0 and row["tagged"] and row["names"] == [weights.as_posix()]
    assert row["tags"][0]["verification"] == "verified" and row["approvals"][0]["valid"]
    assert [a["outcome"] for a in row["accesses"]] == ["refused"]
