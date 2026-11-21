"""The policy input counts an approval only where the oversight queue would.

A decision counts toward ``oversight.approvers`` only when its anchor is the
anchor blob of its own item, only when it is the signer's latest decision on
that item (a later reject cancels an approve), and, when the check binds a
``label`` param, only for a promotion to that label.
"""

from __future__ import annotations

import json

import pytest

from opentine import _oversight, _policy_input
from opentine.attest_signing import sign_attestation
from opentine.repository import Repo
from tests.containment_fixture import costed_run
from tests.key_roles_helpers import isolated_trust_config, pin_roles  # noqa: F401
from tests.promote_helpers import AT, fingerprint, key

pytestmark = pytest.mark.filterwarnings("ignore::Warning")

SEEDS = {"a1": "41" * 32, "a2": "42" * 32}
LATER = "2026-11-02T12:00:00Z"


def _world(tmp_path):
    root = tmp_path / "repo"
    repo = Repo.init(root)
    roles = {"approver": [fingerprint(SEEDS["a1"]), fingerprint(SEEDS["a2"])]}
    text = "version = 1\n[roles]\n" + "".join(f"{k} = {json.dumps(v)}\n" for k, v in roles.items())
    (repo.path / "key-roles.toml").write_bytes(text.encode("utf-8"))
    pin_roles(repo.path)
    return root, repo, repo.put_run(costed_run("subject", 0.5, 100)).run_id


def _approvers(repo, root, run, **kw):
    return _policy_input.build(repo, root, run, **kw)["oversight"]["approvers"]


def _approve(repo, run, name, label="prod", decision="approve", at=AT):
    bind = {"label": label, "candidate": run, "previous": None, "sequence": 0}
    _oversight.decide(repo, _oversight.promotion_item(label, run), decision,
                      key(SEEDS[name]), bind=bind, at=at)  # fmt: skip


def test_a_decision_anchored_on_an_unrelated_blob_does_not_count(tmp_path):
    root, repo, run = _world(tmp_path)
    item = _oversight.promotion_item("prod", run)
    value = {"convention": _oversight.DECISION, "item": item, "decision": "approve",
             "bind": None, "human": None, "note": "", "decided_at": AT}  # fmt: skip
    payload = {"target_id": repo.put("blob", b"unrelated", redact=False), "previous_id": None,
               "value": value, "signer": fingerprint(SEEDS["a1"])}  # fmt: skip
    payload["signature"] = sign_attestation(payload, key(SEEDS["a1"]), algorithm="ed25519",
                                            signed_at=AT)  # fmt: skip
    _oversight.hold(repo, repo.put("annotation", payload, redact=False), item)
    assert _approvers(repo, root, run) == []
    _approve(repo, run, "a2")
    assert _approvers(repo, root, run) == [fingerprint(SEEDS["a2"])]


def test_a_later_reject_cancels_an_approve(tmp_path):
    root, repo, run = _world(tmp_path)
    _approve(repo, run, "a1")
    _approve(repo, run, "a2")
    _approve(repo, run, "a1", decision="reject", at=LATER)
    assert _approvers(repo, root, run) == [fingerprint(SEEDS["a2"])]


def test_a_label_param_counts_only_approvals_for_that_label(tmp_path):
    root, repo, run = _world(tmp_path)
    _approve(repo, run, "a1", label="staging")
    _approve(repo, run, "a2", label="prod")
    assert _approvers(repo, root, run, params={"label": "prod"}) == [fingerprint(SEEDS["a2"])]
    assert _approvers(repo, root, run, params={"label": "staging"}) == [fingerprint(SEEDS["a1"])]
