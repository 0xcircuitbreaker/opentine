"""0.91: custody export and copy need k-of-n approvals from distinct pinned custodian keys.

Hostile attempts: a copy with too few approvals, one custodian approving twice,
a requester approving itself, an optimizer key listed as a custodian, an
approval of other bytes (a re-encode), another checkpoint, requester or
operation, a revoked approval whose revocation lost its hold row, a copy
event written around ``tine custody record``, and an unreadable bundle.
"""

from __future__ import annotations

import hashlib
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine import _containment_records as records
from opentine import _custody_quorum as quorum
from opentine import _interp_custody as ic
from opentine import _oversight_queue, _trust_bundle
from opentine import _weight_custody as wc
from opentine import _weight_custody_check as check
from opentine._signing_pins import key_fingerprint
from opentine.repository import Repo
from opentine.repository._holds import edit_holds, holds_path
from tests.key_roles_helpers import isolated_trust_config, pin_roles  # noqa: F401
from tests.monitor_ledger_helpers import tine

pytestmark = pytest.mark.filterwarnings("ignore::Warning")
SEEDS = {"runner": 81, "policy": 82, "optimizer": 83, "c1": 84, "c2": 85, "c3": 86,
         "stranger": 87}  # fmt: skip
W1 = "sha256:" + hashlib.sha256(b"weights v1").hexdigest()
W2 = "sha256:" + hashlib.sha256(b"weights v1, re-encoded").hexdigest()
AT = 1_800_000_000.0


def key(name: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes([SEEDS[name]]) * 32)


def fpr(name: str) -> str:
    return key_fingerprint(key(name).public_key().public_bytes_raw())


def _roles(repo, custodians: list[str], extra: dict | None = None) -> None:
    roles = {
        "runner": [fpr("runner")],
        "policy": [fpr("policy")],
        "optimizer": [fpr("optimizer")],
        "custodian": sorted(fpr(c) for c in custodians),
    }
    text = "version = 1\n[roles]\n" + "".join(f"{k} = {json.dumps(v)}\n"
                                              for k, v in roles.items() if v)  # fmt: skip
    (repo.path / "key-roles.toml").write_bytes(text.encode("utf-8"))
    pin_roles(repo.path, extra=extra)


@pytest.fixture
def repo(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    repo = Repo.init(tmp_path / "r")
    for name in SEEDS:
        (tmp_path / f"{name}.key").write_bytes(bytes([SEEDS[name]]).hex().encode() * 32)
    _roles(repo, ["c1", "c2", "c3", "optimizer"])
    wc.record(repo, "m", "created", key("runner"), location="s3://a/m", digest=W1, now=AT)
    return repo


def _approve(repo, name: str, digest: str = W1, **fields) -> str:
    request = {"operation": "copy", "digest": digest, "checkpoint": W1,
               "requester": fpr("runner"), **fields}  # fmt: skip
    return quorum.approve(repo, key(name), now=AT, **request)


def _copy(repo, digest: str = W1, where: str = "s3://b/m") -> dict:
    return wc.record(repo, "m", "copied", key("runner"), location=where, digest=digest,
                     now=AT + 10)  # fmt: skip


def test_a_copy_needs_two_distinct_custodians(repo):
    with pytest.raises(quorum.QuorumError, match="0 of 2"):
        _copy(repo)
    _approve(repo, "c1")
    _approve(repo, "c1")  # the same key twice counts once
    with pytest.raises(quorum.QuorumError, match="1 of 2"):
        _copy(repo)
    refused = [i for i in _oversight_queue._sources(repo) if i["source"] == "custody"]
    assert len(refused) == 2  # each refusal is held for review
    _approve(repo, "c2")
    assert _copy(repo)["seq"] == 1
    assert check.check(repo, "m")["ok"]


def test_self_approval_and_optimizer_keys_never_count(repo):
    with pytest.raises(quorum.QuorumError, match="custody.approver"):
        _approve(repo, "optimizer")  # pinned custodian too, but an optimizer key
    with pytest.raises(quorum.QuorumError, match="custody.self-approval"):
        _approve(repo, "c1", requester=fpr("c1"))
    claim = {"convention": quorum.APPROVAL, "operation": "copy", "digest": W1,
             "checkpoint": W1, "requester": fpr("runner"), "artifact": None,
             "destination": None, "at": "2027-01-15T08:00:00Z"}  # fmt: skip
    for name in ("optimizer", "stranger"):  # written around the command
        records.record(repo, records.anchor(repo, "forge", "x"), claim, key(name),
                       quorum.HOLD + "approval:forged")  # fmt: skip
    _approve(repo, "c1")
    found = quorum.tally(repo, operation="copy", digest=W1, checkpoint=W1,
                         requester=fpr("runner"))  # fmt: skip
    assert found["counted"] == 1 and not found["ok"]
    assert {a["why"] for a in found["approvals"]} == {None, "not a pinned custodian key"}


@pytest.mark.parametrize("other", [
    {"digest": W2}, {"checkpoint": W2}, {"requester": "sha256:" + "1" * 64},
    {"operation": "export"}])  # fmt: skip
def test_an_approval_covers_only_its_exact_request(repo, other):
    _approve(repo, "c1", **other)
    _approve(repo, "c2", **other)
    with pytest.raises(quorum.QuorumError, match="0 of 2"):
        _copy(repo)


def test_re_encoded_bytes_need_approvals_of_their_own(repo):
    _approve(repo, "c1")
    _approve(repo, "c2")
    with pytest.raises(quorum.QuorumError):
        _copy(repo, digest=W2)
    _approve(repo, "c1", digest=W2)
    _approve(repo, "c3", digest=W2)
    assert _copy(repo, digest=W2)["seq"] == 1


def test_a_revocation_holds_even_when_its_hold_row_is_dropped(repo, capsys):
    first = _approve(repo, "c1")
    _approve(repo, "c2")
    with pytest.raises(quorum.QuorumError, match="custody.revoker"):
        quorum.revoke(repo, first, key("stranger"))
    code, body = tine(capsys, "custody", "revoke", first, "--key", "c1.key", "--repo", "r",
                      "--json")  # fmt: skip
    assert code == 0 and body["approval"] == first
    edit_holds(holds_path(repo), lambda rows: [r for r in rows if r["oid"] != body["record"]])
    with pytest.raises(quorum.QuorumError, match="1 of 2"):
        _copy(repo)
    quorum.revoke(repo, _approve(repo, "c3"), key("policy"))  # a policy key revokes too
    with pytest.raises(quorum.QuorumError, match="1 of 2"):
        _copy(repo)


def test_a_copy_written_around_the_command_is_a_check_failure(repo):
    rows = wc.events(repo, "m")
    claim = {"convention": wc.CONVENTION, "artifact": "m", "event": "copied", "seq": 1,
             "prev": rows[0]["oid"], "location": "s3://x/m", "digest": W1, "size": None,
             "run": None, "data": [], "lineage": None, "tags": [],
             "recorded_at": "2027-01-15T08:00:00Z"}  # fmt: skip
    records.record(repo, rows[0]["target"], claim, key("runner"), f"{wc.HOLD}m:{1:08d}")
    body = check.check(repo, "m")
    assert not body["ok"] and check.COPY_UNAPPROVED in {f["code"] for f in body["findings"]}


def test_without_custodians_nothing_changes(repo):
    _roles(repo, [])
    assert not quorum.policy(repo)["required"]
    assert _copy(repo)["seq"] == 1


def test_a_pinned_k_raises_the_quorum_and_a_bundle_that_does_not_verify_fails_closed(repo):
    _roles(repo, ["c1", "c2", "c3"], extra={"custody": {"version": 1, "k": 3}})
    for name in ("c1", "c2"):
        _approve(repo, name)
    with pytest.raises(quorum.QuorumError, match="2 of 3"):
        _copy(repo)
    _approve(repo, "c3")
    (repo.path / "trust-bundle.note").write_bytes(b"tampered\n")
    with pytest.raises(quorum.QuorumError, match="trust bundle"):
        _copy(repo)


@pytest.mark.parametrize(
    "section",
    [
        {"version": 1, "k": 1},
        {"version": 1, "k": 257},
        {"version": 1, "k": True},
        {"version": 1, "n": 2},
    ],
)
def test_a_quorum_below_two_is_refused_by_the_bundle_validator(section):
    payload = {
        "trust_bundle": 1,
        "serial": 1,
        "issued_at": "2027-01-15T08:00:00Z",
        "trust_policy": {"pin": ["sha256:" + "0" * 64]},
        "custody": section,
    }
    with pytest.raises(_trust_bundle.BundleError, match="custody is"):
        _trust_bundle.validate(payload)


def test_interp_export_needs_the_requester_and_its_approvals(repo, tmp_path, capsys):
    data = b'{"nodes": []}\n'
    row = ic.store(repo, data, kind="attribution-graph", checkpoint=W1, key=key("runner"))
    art = row["claim"]["digest"] if "claim" in row else ic.digest(data)
    argv = ("interp", "export", art, "--out", (tmp_path / "out.json").as_posix(), "--repo", "r")
    code, _ = tine(capsys, *argv, "--json")
    assert code != 0 and not (tmp_path / "out.json").exists()
    for name in ("c1", "c2"):
        code, body = tine(capsys, "custody", "approve", "--operation", "export", "--digest", art,
                          "--checkpoint", W1, "--requester", fpr("runner"), "--key",
                          f"{name}.key", "--repo", "r", "--json")  # fmt: skip
        assert code == 0, body
    code, body = tine(
        capsys,
        "custody",
        "approvals",
        "--operation",
        "export",
        "--digest",
        art,
        "--checkpoint",
        W1,
        "--requester",
        fpr("runner"),
        "--repo",
        "r",
        "--json",
    )
    assert code == 0 and body["counted"] == 2 and body["ok"]
    code, _ = tine(capsys, *argv, "--requester-key", "runner.key", "--json")
    assert code == 0 and (tmp_path / "out.json").read_bytes() == data
    code, _ = tine(capsys, *argv, "--requester-key", "c1.key", "--json")
    assert code != 0  # approvals name the requester: another key is not covered
