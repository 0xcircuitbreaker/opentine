"""0.83: interpretability artifacts are held blobs keyed to checkpoints under 0.72 custody.

1. ``tine interp store`` keeps the bytes as a content-addressed blob and a signed,
   held record; neither can be released, and ``list`` verifies a pinned runner.
2. Custody denial is honoured (D13): an artifact tagged on its record, or whose
   checkpoint is a tagged model organism, is not exported without an approval
   bound to the run; every read of it, allowed or refused, is logged.
3. Bytes that no longer match the recorded digest fail with ``digest.mismatch``.
4. ``tine query`` shows the records, verified per row by pinned roles only.
"""

from __future__ import annotations

import hashlib
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import opentine.cli as cli
from opentine import _interp_custody as ic
from opentine import _organism, _schemas
from opentine._organism_registry import accesses
from opentine._signing_pins import key_fingerprint
from opentine.repository import Repo
from opentine.repository._holds import HoldError, holds_path, read_holds, release
from tests.key_roles_helpers import isolated_trust_config, pin_roles  # noqa: F401

pytestmark = pytest.mark.filterwarnings("ignore::Warning")

AT = "2026-12-05T10:00:00Z"
SEEDS = {"runner": 0x71, "policy": 0x72, "optimizer": 0x73, "approver": 0x74}
CKPT_BYTES = b"checkpoint bytes, never stored\n"
CKPT = "sha256:" + hashlib.sha256(CKPT_BYTES).hexdigest()
GRAPH = json.dumps({"nodes": ["f1", "f2"], "edges": [["f1", "f2", 0.5]]}).encode("utf-8")


def _key(name: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes([SEEDS[name]]) * 32)


def _fpr(name: str) -> str:
    return key_fingerprint(_key(name).public_key().public_bytes_raw())


@pytest.fixture
def room(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    repo = Repo.init(tmp_path / "r")
    roles = {"runner": [_fpr("runner"), _fpr("optimizer")], "policy": [_fpr("policy")],
             "optimizer": [_fpr("optimizer")], "approver": [_fpr("approver")]}  # fmt: skip
    text = "version = 1\n[roles]\n" + "".join(f"{k} = {json.dumps(v)}\n" for k, v in roles.items())
    (repo.path / "key-roles.toml").write_bytes(text.encode("utf-8"))
    pin_roles(repo.path)
    keys = {}
    for name in SEEDS:
        keys[name] = tmp_path / f"{name}.hex"
        keys[name].write_bytes(_key(name).private_bytes_raw().hex().encode("ascii"))
    graph = tmp_path / "graph.json"
    graph.write_bytes(GRAPH)
    return {"repo": repo, "where": repo.path.parent.as_posix(), "keys": keys, "graph": graph,
            "tmp": tmp_path}  # fmt: skip


def _tine(capsys, *argv: str) -> tuple[int, dict]:
    capsys.readouterr()
    code = 0
    try:
        cli.main(list(argv))
    except SystemExit as exc:
        code = exc.code or 0
    body = json.loads(capsys.readouterr().out)
    assert _schemas.validate_output(body) == [] or "error" in body
    return code, body


def _store(capsys, room, *extra: str, key: str = "runner") -> dict:
    code, body = _tine(capsys, "interp", "store", room["graph"].as_posix(), "--kind",
                       "attribution-graph", "--checkpoint", CKPT, "--key",
                       room["keys"][key].as_posix(), "--repo", room["where"], "--json",
                       *extra)  # fmt: skip
    assert code == 0, body
    return body


def test_store_keeps_a_held_blob_and_a_verified_record(room, capsys):
    body = _store(capsys, room)
    assert body["digest"] == "sha256:" + hashlib.sha256(GRAPH).hexdigest()
    assert bytes(room["repo"].get(body["blob"]).body) == GRAPH
    held = {r["oid"]: r["target"] for r in read_holds(holds_path(room["repo"]))}
    assert held[body["blob"]].startswith("custody:interp:") and body["record"] in held
    for oid in (body["blob"], body["record"]):
        with pytest.raises(HoldError, match="interpretability custody record"):
            release(room["repo"], oid)
    code, listed = _tine(capsys, "interp", "list", "--checkpoint", CKPT, "--repo", room["where"],
                         "--json")  # fmt: skip
    assert code == 0
    [row] = listed["artifacts"]
    assert (row["verification"], row["custody"], row["checkpoint"]) == ("verified", [], CKPT)
    out = room["tmp"] / "out.json"
    code, got = _tine(capsys, "interp", "export", body["digest"], "--out", out.as_posix(),
                      "--repo", room["where"], "--json")  # fmt: skip
    assert code == 0 and out.read_bytes() == GRAPH and got["size"] == len(GRAPH)


def test_an_optimizer_signer_is_not_verified_even_with_a_runner_role(room, capsys):
    _store(capsys, room, key="optimizer")
    [row] = ic.artifacts(room["repo"])
    assert row["verification"] == "unverified: the signer is an optimizer key"


def test_store_refuses_a_bad_checkpoint_kind_or_probe_without_layer(room):
    key = _key("runner")
    for kwargs in ({"kind": "attribution-graph", "checkpoint": "abc"},
                   {"kind": "weights", "checkpoint": CKPT},
                   {"kind": "probe-weights", "checkpoint": CKPT}):  # fmt: skip
        with pytest.raises(ValueError):
            ic.store(room["repo"], GRAPH, key=key, **kwargs)


def test_a_record_tag_denies_export_and_logs_the_refusal(room, capsys):
    body = _store(capsys, room, "--tag", "model-organism")
    out = room["tmp"] / "out.json"
    code, err = _tine(capsys, "interp", "export", body["digest"], "--out", out.as_posix(),
                      "--run", "r-1", "--repo", room["where"], "--json")  # fmt: skip
    assert code == 6 and err["reason"] == "custody.denied" and not out.exists()
    [entry] = accesses(room["repo"], body["digest"])
    assert (entry["outcome"], entry["run"]) == ("refused", "r-1")


def test_a_tagged_checkpoint_covers_its_artifacts_until_the_run_is_approved(room, capsys):
    body = _store(capsys, room)
    repo = room["repo"]
    _organism.tag(repo, CKPT, _key("policy"), names=["ckpt.bin"], reason="sleeper", at=AT)
    [row] = ic.artifacts(repo)
    assert ic.tagged(repo, row) == ["checkpoint tagged"]
    with pytest.raises(ic.CustodyDenied, match="custody.denied"):
        ic.export(repo, body["digest"], run="r-2")
    with pytest.raises(ic.CustodyDenied):
        ic.export(repo, body["digest"])  # no run: nothing can approve it
    _organism.approve(repo, CKPT, "r-1", _key("approver"), why="audit", at=AT)
    with pytest.raises(ic.CustodyDenied):
        ic.export(repo, body["digest"], run="r-3")  # the approval names another run
    data, _ = ic.export(repo, body["digest"], run="r-1")
    assert data == GRAPH
    outcomes = sorted(a["outcome"] for a in accesses(repo, body["digest"]))
    assert outcomes == ["allowed", "refused", "refused", "refused"]


def test_an_unreadable_organism_registry_denies_export(room, capsys, monkeypatch):
    from opentine import _organism_registry

    body = _store(capsys, room)

    def unreadable(repo):
        raise _organism_registry.RegistryUnreadable("organism.registry-unreadable: test")

    monkeypatch.setattr(_organism_registry, "registry", unreadable)
    with pytest.raises(ic.CustodyDenied, match="registry unreadable"):
        ic.export(room["repo"], body["digest"], run="r-1")
    holds_path(room["repo"]).write_bytes(b"not json")
    with pytest.raises(HoldError):
        ic.export(room["repo"], body["digest"], run="r-1")


def test_bytes_that_do_not_match_their_digest_fail_with_digest_mismatch(room, capsys):
    body = _store(capsys, room)
    row = {**ic.find(room["repo"], body["digest"]), "digest": CKPT}
    with pytest.raises(ic.DigestMismatch) as caught:
        ic.read_bytes(room["repo"], row)
    assert caught.value.code == "digest.mismatch"


def test_query_shows_artifact_rows_verified_per_row(room, capsys):
    good = _store(capsys, room)["record"]
    room["graph"].write_bytes(GRAPH + b"\n")
    bad = _store(capsys, room, key="optimizer")["record"]
    assert _tine(capsys, "query", "index", "--rebuild", "--repo", room["where"], "--json")[0] == 0
    code, body = _tine(capsys, "query", "SELECT oid, kind, checkpoint FROM interp_artifacts "
                       "ORDER BY oid", "--repo", room["where"], "--verify", "--json")  # fmt: skip
    assert code == 0, body
    assert {r["oid"] for r in body["rows"]} == {good, bad}
    assert all(r["checkpoint"] == CKPT for r in body["rows"])
    assert body["verification"]["counts"]["verified"] == 1
