"""0.71 review: a loop holding only its optimizer key cannot hide a copy or open the gate."""

from __future__ import annotations

import io
import json
import types

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine import _weight_custody as wc
from opentine import _weight_custody_check as wcc
from opentine._cli_custody_weights import gate
from opentine.repository import Repo
from opentine.repository._holds import edit_holds, holds_path
from tests.key_roles_helpers import isolated_trust_config, pin_roles  # noqa: F401

pytestmark = pytest.mark.filterwarnings("ignore::Warning")

RUNNER = Ed25519PrivateKey.from_private_bytes(b"\x61" * 32)
APPROVER = Ed25519PrivateKey.from_private_bytes(b"\x62" * 32)
OPTIMIZER = Ed25519PrivateKey.from_private_bytes(b"\x63" * 32)
DIGEST = "sha256:" + "a" * 64
OTHER = "sha256:" + "b" * 64
CALL = {"tool_name": "Bash", "tool_input": {"command": "python serve.py /models/mo-1"}}


def _hex(key):
    return key.public_key().public_bytes_raw().hex()


@pytest.fixture
def repo(tmp_path):
    repo = Repo.init(tmp_path / "r")
    roles = (
        f'version = 1\n[roles]\nrunner = ["{_hex(RUNNER)}"]\npolicy = ["{_hex(APPROVER)}"]\n'
        f'optimizer = ["{_hex(OPTIMIZER)}"]\n'
    )
    (repo.path / "key-roles.toml").write_bytes(roles.encode())
    pin_roles(repo.path)
    wc.record(
        repo, "mo", "created", RUNNER, location="/models/mo-1", digest=DIGEST,
        tags=["model-organism"],
    )  # fmt: skip
    return repo


def _denied(repo, call=CALL):
    sink = io.BytesIO()
    args = types.SimpleNamespace(repo=str(repo.path.parent), agent="claude-code")
    assert gate(args, io.BytesIO(json.dumps(call).encode()), sink) == 0
    return "deny" in sink.getvalue().decode()


def _drop(repo, keep):
    edit_holds(holds_path(repo), lambda rows: [r for r in rows if keep(r)])


def test_an_optimizer_signed_copy_event_does_not_explain_a_copy(repo):
    wc.record(repo, "mo", "copied", OPTIMIZER, location="/tmp/exfil", digest=DIGEST)
    body = wcc.check(repo, "mo", [("/tmp/exfil", DIGEST)])
    assert "fail:custody-gap" in {f["code"] for f in body["findings"]}


def test_an_optimizer_signed_destroy_does_not_open_the_gate(repo):
    wc.record(repo, "mo", "destroyed", OPTIMIZER, location="/models/mo-1")
    assert _denied(repo)


def test_dropping_the_created_hold_row_does_not_open_the_gate(repo):
    wc.record(repo, "mo", "copied", RUNNER, location="/scratch/mo", digest=DIGEST)
    _drop(repo, lambda r: not r["target"].endswith(":00000000"))
    assert _denied(repo)


def test_deleting_every_custody_hold_does_not_open_the_gate(repo):
    _drop(repo, lambda r: False)
    assert _denied(repo)


def test_a_forged_first_row_does_not_untag_the_artifact(repo):
    oid = wc.record(repo, "decoy", "created", OPTIMIZER, location="/x", digest=OTHER)["record"]
    _drop(repo, lambda r: not r["target"].startswith("custody:weights:"))
    edit_holds(
        holds_path(repo),
        lambda rows: [*rows, {"oid": oid, "target": "custody:weights:mo:00000000"}],
    )
    assert _denied(repo)


def test_renaming_the_artifact_keeps_the_tag_of_its_digest(repo):
    wc.record(repo, "mo-renamed", "created", RUNNER, location="/data/innocent.bin", digest=DIGEST)
    call = {"tool_name": "Bash", "tool_input": {"command": "load /data/innocent.bin"}}
    assert _denied(repo, call)


def test_the_optimizer_cannot_approve_its_own_load(repo):
    wc.record(repo, "mo", "approved", OPTIMIZER, location="self", digest=DIGEST)
    assert _denied(repo)
    wc.record(repo, "mo", "approved", APPROVER, location="review-1", digest=DIGEST)
    assert not _denied(repo)
