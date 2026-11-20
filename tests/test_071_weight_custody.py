"""0.71: checkpoint and weight custody: digests only, signed chained events, gaps, load gate."""

from __future__ import annotations

import io
import json
import types

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import opentine.cli as cli
from opentine import _schemas
from opentine import _weight_custody as wc
from opentine import _weight_custody_check as wcc
from opentine._cli_custody_weights import gate
from opentine.repository import Repo
from opentine.repository._holds import HoldError, edit_holds, holds_path, release
from tests.key_roles_helpers import isolated_trust_config, pin_roles  # noqa: F401

pytestmark = pytest.mark.filterwarnings("ignore::Warning")

RUNNER = Ed25519PrivateKey.from_private_bytes(b"\x51" * 32)
APPROVER = Ed25519PrivateKey.from_private_bytes(b"\x52" * 32)
DATA = "sha256:" + "d" * 64


@pytest.fixture
def repo(tmp_path):
    return Repo.init(tmp_path / "r")


@pytest.fixture
def files(tmp_path):
    out = {}
    for name, key in (("runner", RUNNER), ("approver", APPROVER)):
        out[name] = tmp_path / f"{name}.hex"
        out[name].write_bytes(key.private_bytes_raw().hex().encode("ascii"))
    weights = tmp_path / "w.safetensors"
    weights.write_bytes(b"\x00\x01weights" * 1000)
    out["weights"] = weights
    return out


def _pin(repo):
    runner = RUNNER.public_key().public_bytes_raw().hex()
    policy = APPROVER.public_key().public_bytes_raw().hex()
    (repo.path / "key-roles.toml").write_bytes(
        f'version = 1\n[roles]\nrunner = ["{runner}"]\npolicy = ["{policy}"]\n'.encode()
    )
    pin_roles(repo.path)


def _cli(capsys, *argv):
    capsys.readouterr()
    code = 0
    try:
        cli.main(list(argv))
    except SystemExit as exc:
        code = exc.code or 0
    body = json.loads(capsys.readouterr().out)
    assert _schemas.validate_output(body) == []
    return code, body


def _rec(capsys, repo, files, event, location, *extra, key="runner"):
    return _cli(capsys, "custody", "record", event, location, "--artifact", "ckpt-7",
                "--sign-key", str(files[key]), "--repo", str(repo.path.parent), "--json",
                *extra)  # fmt: skip


def _gate(repo, payload):
    sink = io.BytesIO()
    args = types.SimpleNamespace(repo=str(repo.path.parent), agent="claude-code")
    assert gate(args, io.BytesIO(payload), sink) == 0
    return json.loads(sink.getvalue())


def test_the_digest_streams_and_honours_the_cap(files):
    digest, size = wc.file_digest(files["weights"])
    assert digest.startswith("sha256:") and size == 9000
    with pytest.raises(ValueError, match="digest cap"):
        wc.file_digest(files["weights"], max_bytes=8999)


def test_a_clean_chain_has_no_gaps_and_weights_are_not_stored(repo, files, capsys):
    _pin(repo)
    w = str(files["weights"])
    code, body = _rec(capsys, repo, files, "created", "s3://lab/ckpt-7", "--file", w,
                      "--data", DATA, "--lineage", "node-3")  # fmt: skip
    assert code == 0 and body["seq"] == 0 and body["prev"] is None and body["size"] == 9000
    first = body["record"]
    code, body = _rec(capsys, repo, files, "copied", "/scratch/ckpt-7", "--file", w)
    assert body["prev"] == first and body["seq"] == 1
    _rec(capsys, repo, files, "loaded", "/scratch/ckpt-7", "--file", w)
    code, body = _cli(capsys, "custody", "check", "ckpt-7", "--repo", str(repo.path.parent),
                      "--json")  # fmt: skip
    assert code == 0 and body["ok"] and body["findings"] == []
    assert sorted(body["locations"]) == ["/scratch/ckpt-7", "s3://lab/ckpt-7"]
    stored = b"".join(p.read_bytes() for p in repo.path.rglob("*") if p.is_file())
    assert b"\x00\x01weights" * 4 not in stored
    code, body = _cli(capsys, "custody", "chain", "ckpt-7", "--repo", str(repo.path.parent),
                      "--json")  # fmt: skip
    assert [e["event"] for e in body["events"]] == ["created", "copied", "loaded"]
    assert body["events"][0]["claim"]["data"] == [DATA]
    assert all(e["verification"] == "verified" and not e["problems"] for e in body["events"])


def test_a_copy_without_an_event_is_a_gap(repo, files, capsys, tmp_path):
    _pin(repo)
    w = str(files["weights"])
    _rec(capsys, repo, files, "created", "s3://lab/ckpt-7", "--file", w)
    code, body = _cli(capsys, "custody", "check", "ckpt-7", "--file", f"/mnt/x={w}",
                      "--repo", str(repo.path.parent), "--json")  # fmt: skip
    assert code == 1 and [f["code"] for f in body["findings"]] == ["fail:custody-gap"]
    _rec(capsys, repo, files, "loaded", "/mnt/x", "--file", w)  # never copied there
    code, body = _cli(capsys, "custody", "check", "ckpt-7", "--repo", str(repo.path.parent),
                      "--json")  # fmt: skip
    assert code == 1 and "copied without a copy event" in body["findings"][0]["message"]


def test_a_load_without_create_or_copy_is_a_gap(repo, files, capsys):
    _pin(repo)
    _rec(capsys, repo, files, "loaded", "/scratch/ckpt-7", "--file", str(files["weights"]))
    body = wcc.check(repo, "ckpt-7")
    assert not body["ok"]
    assert {f["code"] for f in body["findings"]} == {"fail:custody-gap"}
    assert len(body["findings"]) == 2  # not created first; loaded from an unknown location


def test_a_dropped_event_breaks_the_chain_and_holds_are_never_released(repo, files, capsys):
    _pin(repo)
    w = str(files["weights"])
    for event, where in (("created", "a"), ("copied", "b"), ("loaded", "b")):
        _rec(capsys, repo, files, event, where, "--file", w)
    with pytest.raises(HoldError, match="weight custody"):
        release(repo, "custody:weights:ckpt-7:00000001")
    edit_holds(holds_path(repo),
               lambda rows: [r for r in rows if not r["target"].endswith(":00000001")])  # fmt: skip
    codes = {f["code"] for f in wcc.check(repo, "ckpt-7")["findings"]}
    assert "fail:custody-chain-broken" in codes


def test_an_unpinned_signer_is_advisory_unless_strict(repo, files, capsys):
    _rec(capsys, repo, files, "created", "a", "--file", str(files["weights"]))
    body = wcc.check(repo, "ckpt-7")
    assert body["ok"] and [f["code"] for f in body["findings"]] == [
        "advisory:custody.signer-unpinned"
    ]
    assert not wcc.check(repo, "ckpt-7", strict=True)["ok"]


def test_a_tagged_artifact_load_without_approval_is_refused_by_the_hook(repo, files, capsys):
    _pin(repo)
    w = str(files["weights"])
    digest = wc.file_digest(files["weights"])[0]
    _rec(capsys, repo, files, "created", "/models/organism-1", "--file", w,
         "--tag", "model-organism")  # fmt: skip
    call = {"session_id": "s", "tool_name": "Bash",
            "tool_input": {"command": "python serve.py --weights /models/organism-1"}}  # fmt: skip
    out = _gate(repo, json.dumps(call).encode())
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert _gate(repo, b'{"tool_name": "Bash", "tool_input": {"command": "ls"}}') == {}
    assert "deny" in json.dumps(_gate(repo, b"not json"))  # fails closed
    _rec(capsys, repo, files, "loaded", "/models/organism-1", "--file", w)
    codes = [f["code"] for f in wcc.check(repo, "ckpt-7")["findings"]]
    assert codes == ["fail:custody-unapproved-load"]
    # an approval signed by a runner (not a pinned policy key) does not count
    _rec(capsys, repo, files, "approved", "review-42", "--digest", digest)
    assert "deny" in json.dumps(_gate(repo, json.dumps(call).encode()))
    _rec(capsys, repo, files, "approved", "review-43", "--digest", digest, key="approver")
    assert _gate(repo, json.dumps(call).encode()) == {}
    _rec(capsys, repo, files, "loaded", "/models/organism-1", "--file", w)
    later = [f for f in wcc.check(repo, "ckpt-7")["findings"] if f["code"].startswith("fail:")]
    assert len(later) == 1  # only the first, unapproved load


def test_bad_fields_are_refused(repo, files):
    for kwargs in ({"tags": ["model-organism"], "digest": "sha256:" + "0" * 64},
                   {"digest": "md5:abc"}, {"digest": None}, {"data": ["nope"]}):  # fmt: skip
        event = "copied" if "tags" in kwargs else "created"
        with pytest.raises(ValueError):
            wc.record(repo, "ckpt-7", event, RUNNER, location="a", **kwargs)
    with pytest.raises(ValueError):
        wc.record(repo, "bad name", "created", RUNNER, location="a", digest=DATA)
