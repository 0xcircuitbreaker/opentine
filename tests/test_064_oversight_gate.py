"""0.64: the k-of-n oversight gate on promotions, from a pinned ``.tine/oversight.toml``."""

from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine import _oversight, _oversight_gate, _oversight_policy, _oversight_queue, _schemas, cli
from opentine._signing_pins import key_fingerprint
from opentine.repository import Repo
from opentine.repository._holds import HoldError, release
from tests.key_roles_helpers import isolated_trust_config, pin_roles  # noqa: F401

pytestmark = pytest.mark.filterwarnings("ignore::Warning")

RUN = "run:sha256:" + "c" * 64
OTHER = "run:sha256:" + "d" * 64
AT = "2026-12-03T10:00:00Z"
SEEDS = {"optimizer": 1, "a1": 2, "a2": 3, "a3": 4, "alice2": 5, "policy": 6, "monitor": 7}


def _key(seed: int) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)


def _fpr(name: str) -> str:
    return key_fingerprint(_key(SEEDS[name]).public_key().public_bytes_raw())


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


def _toml(rows: dict[str, list[str]]) -> str:
    return "".join(f"{k} = {json.dumps(v)}\n" for k, v in rows.items())


@pytest.fixture
def repo(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    repo = Repo.init(tmp_path / "r")
    approvers = [_fpr("a1"), _fpr("a2"), _fpr("a3"), _fpr("alice2"), _fpr("optimizer")]
    roles = {"optimizer": [_fpr("optimizer")], "monitor": [_fpr("monitor")],
             "policy": [_fpr("policy")], "approver": approvers}  # fmt: skip
    (repo.path / "key-roles.toml").write_bytes(
        ("version = 1\n[roles]\n" + _toml(roles)).encode("utf-8"))  # fmt: skip
    pin_roles(repo.path)
    policy = ("version = 1\n[tiers.high]\nk = 2\n" + _toml({"approvers": approvers})
              + "[humans]\n" + _toml({"alice": [_fpr("a1"), _fpr("alice2")]})
              + '[[route]]\nsource = "promotion"\nlabel = "prod*"\ntier = "high"\n'
              + '[[route]]\nsource = "monitor"\ntier = "high"\n')  # fmt: skip
    (repo.path / "oversight.toml").write_bytes(policy.encode("utf-8"))
    data = (repo.path / "oversight.toml").read_bytes()
    doc = _oversight_policy.sign(_key(SEEDS["policy"]), data, AT)
    (repo.path / "oversight.sig.json").write_bytes(json.dumps(doc).encode("utf-8"))
    return repo


def _approve(repo, name: str, *, decision: str = "approve", candidate: str = RUN,
             sequence: int = 0, label: str = "prod", human: str | None = None) -> str:  # fmt: skip
    bind = {"label": label, "candidate": candidate, "previous": None, "sequence": sequence}
    item = _oversight.promotion_item(label, candidate)
    return _oversight.decide(repo, item, decision, _key(SEEDS[name]), bind=bind, human=human,
                             at=AT)  # fmt: skip


def _codes(repo, label: str = "prod", sequence: int = 0) -> list[str]:
    found = _oversight_gate.promote_refusals(repo.path.parent, RUN, label, previous=None,
                                             sequence=sequence)  # fmt: skip
    return [r["code"] for r in found]


def test_k_minus_one_approvals_are_refused_and_k_pass(repo):
    assert _oversight_policy.load(repo.path)["status"] == "pinned"
    assert _codes(repo) == ["promote.oversight-insufficient"]
    _approve(repo, "a2")
    assert _codes(repo) == ["promote.oversight-insufficient"]  # k-1 = 1 of 2
    _approve(repo, "a3")
    assert _codes(repo) == []


def test_an_unrouted_label_is_not_gated(repo):
    assert _codes(repo, label="staging") == []


def test_the_same_key_or_the_same_human_counts_once(repo):
    _approve(repo, "a1")
    _approve(repo, "a1")
    assert _codes(repo) == ["promote.oversight-insufficient"]
    _approve(repo, "alice2")  # alice's second key ([humans])
    assert _codes(repo) == ["promote.oversight-insufficient"]
    _approve(repo, "a2", human="bob")
    _approve(repo, "a3", human="bob")  # one declared person on two keys
    row = _oversight_queue.queue(repo)["items"][0]
    assert row["tiers"][0]["approvers"] == ["human:alice", "human:bob"]
    assert _codes(repo) == []


def test_an_optimizer_key_approval_is_refused_as_key_separation(repo, tmp_path, capsys):
    _approve(repo, "a2")
    _approve(repo, "optimizer")  # written by hand: never counts, though a listed approver
    assert _codes(repo) == ["promote.oversight-key-separation"]
    path = tmp_path / "opt.key"
    path.write_bytes(_key(SEEDS["optimizer"]).private_bytes_raw().hex().encode("ascii"))
    code, body = _tine(capsys, "oversight", "approve", f"promotion:prod:{RUN}", "--key",
                       path.as_posix(), "--repo", "r", "--json")  # fmt: skip
    assert code != 0 and "oversight.key-separation" in json.dumps(body)


def test_an_approval_for_an_older_sequence_or_candidate_is_stale(repo):
    _approve(repo, "a2")
    _approve(repo, "a3")
    assert _codes(repo, sequence=1) == ["promote.oversight-stale"]
    _approve(repo, "a1", candidate=OTHER)  # another item: not counted here at all
    assert _codes(repo) == []


def test_a_rejection_refuses_and_a_later_approval_by_the_same_key_replaces_it(repo):
    _approve(repo, "a2")
    _approve(repo, "a3")
    _approve(repo, "a1", decision="reject")
    assert _codes(repo) == ["promote.oversight-rejected"]
    _approve(repo, "a1")
    assert _codes(repo) == []


def test_an_unsigned_or_tampered_policy_grants_nothing(repo):
    _approve(repo, "a2")
    _approve(repo, "a3")
    path = repo.path / "oversight.toml"
    path.write_bytes(path.read_bytes().replace(b"k = 2", b"k = 1"))
    state = _oversight_policy.load(repo.path)
    assert state["status"] == "unpinned"
    assert _codes(repo) == ["promote.oversight-insufficient"]


def test_unpinned_roles_grant_no_approver(repo):
    (repo.path / "trust-bundle.note").unlink()
    _approve(repo, "a2")
    _approve(repo, "a3")
    assert _codes(repo) == ["promote.oversight-insufficient"]


def test_decisions_are_held_and_never_released(repo):
    oid = _approve(repo, "a2")
    with pytest.raises(HoldError):
        release(repo, oid)


def test_queue_state_rebuilt_from_objects_equals_the_queue(repo, capsys):
    _approve(repo, "a2")
    _approve(repo, "a1", decision="reject")
    _approve(repo, "a3", candidate=OTHER)
    _approve(repo, "optimizer", candidate=OTHER)
    code, shown = _tine(capsys, "oversight", "queue", "--repo", "r", "--json")
    assert code == 0
    code, rebuilt = _tine(capsys, "oversight", "queue", "--repo", "r", "--from-objects", "--json")
    assert code == 0 and rebuilt == shown
    states = {row["item"]: row["state"] for row in shown["items"]}
    assert states == {f"promotion:prod:{RUN}": "rejected", f"promotion:prod:{OTHER}": "pending"}
    assert _oversight.by_objects(repo) == _oversight.by_holds(repo)


def test_cli_policy_sign_and_decide_round_trip(repo, tmp_path, capsys):
    key = tmp_path / "p.key"
    key.write_bytes(_key(SEEDS["policy"]).private_bytes_raw().hex().encode("ascii"))
    code, body = _tine(capsys, "oversight", "sign-policy", "--key", key.as_posix(), "--repo",
                       "r", "--at", AT, "--json")  # fmt: skip
    assert code == 0 and body["policy"]["status"] == "pinned"
    for name in ("a2", "a3"):
        path = tmp_path / f"{name}.key"
        path.write_bytes(_key(SEEDS[name]).private_bytes_raw().hex().encode("ascii"))
        code, body = _tine(capsys, "oversight", "approve", f"promotion:prod:{RUN}", "--key",
                           path.as_posix(), "--repo", "r", "--at", AT, "--json")  # fmt: skip
        assert code == 0, body
    assert _codes(repo) == []
