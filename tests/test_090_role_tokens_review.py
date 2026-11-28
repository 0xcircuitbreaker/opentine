"""0.90 role tokens: holes found in review, each pinned by a test."""

from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine import Run, StepKind, _review
from opentine.kernel import ObjectEnvelope
from opentine.remote import _token_roles as roles
from opentine.remote._token_scope import SCOPE_CLAIM
from opentine.remote._token_store import TokenStore
from opentine.remote.interfaces import Identity
from opentine.repository import Repo
from tests._auth_helpers import call, make_app

T = "/v1/tenants/acme"


def _role(app, role, refs, agent):
    return app.tokens.mint("acme", "write", refs, ttl=3600, role=role, agent=agent)[0]


class _Objects:
    def __init__(self, stored):
        self.stored = stored

    def get(self, tenant, oid):
        if oid not in self.stored:
            raise KeyError(oid)
        return self.stored[oid]


class _Service:
    authors_of = None

    def __init__(self, stored):
        self.objects = _Objects(stored)


@pytest.mark.parametrize("field", ["agent_id", "agent", "author"])
def test_a_run_payload_naming_the_tokens_agent_is_its_own(field):
    envelope = ObjectEnvelope.create("run", {field: "Agent-7", "status": "done"})
    service = _Service({envelope.oid: envelope.encode()})
    scope = {"role": "approve", "agent": "agent-7", "refs": ["*"]}
    identity = Identity("token:x", "acme", ("writer",), {SCOPE_CLAIM: scope})
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes_raw().hex()
    version = _review.sign(
        _review.build("rv", title="t", reviewers=[pub],
                      repos=[{"name": "acme", "project": None}],
                      subjects=[{"repo": "acme", "type": "run", "id": envelope.oid}],
                      gates=["ship"]),
        key,
    )  # fmt: skip
    why = roles.self_authored(service, identity, "acme", version)
    assert why is not None and "own agent id" in why


def _admin_push(app, tmp_path, label, metadata):
    local = Repo.init(tmp_path / f"local-{label}")
    run = Run(id=label, metadata=metadata)
    run.add_step(StepKind.done, {"text": label})
    run_id = local.put_run(run).run_id
    admin = app.service.authenticate({"authorization": "Bearer admin-token"})
    app.service.install_pack(admin, "acme", local.pack())
    return run_id


def _review_and_decide(app, run_id, token):
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes_raw().hex()
    version = _review.sign(
        _review.build("rv", title="t", reviewers=[pub],
                      repos=[{"name": "acme", "project": None}],
                      subjects=[{"repo": "acme", "type": "run", "id": run_id}], gates=["ship"]),
        key,
    )  # fmt: skip
    assert call(app, "PUT", f"{T}/reviews/rv", {"expected_old": None, "version": version})[0] == 200
    record = _review.sign_gate(_review.build_gate(version, "ship", "approve"), key)
    return call(app, "POST", f"{T}/reviews/rv/decisions", {"decision": record}, token)


@pytest.mark.parametrize("claimed", ["Agent-7", "AGENT-7", "\uff41gent-7"])
def test_an_agent_id_spelled_differently_is_still_the_tokens_own(tmp_path, claimed):
    app = make_app(tmp_path / "remote")
    approver = _role(app, "approve", ["*"], "agent-7")
    ingest = _role(app, "ingest", ["heads/in/"], claimed)
    run_id = _admin_push(app, tmp_path, "spelled", {})
    identity = app.service.authenticate({"authorization": f"Bearer {ingest}"})
    assert app.service.update_ref(identity, "acme", "heads/in/x", run_id, None)
    refused = _review_and_decide(app, run_id, approver)
    assert refused[0] == 403 and json.loads(refused[2])["code"] == "token.self-approval"


@pytest.mark.parametrize("agent", [" agent", "agent ", "a​b"])
def test_an_agent_id_with_padding_or_invisible_characters_is_refused_at_mint(tmp_path, agent):
    store = TokenStore(tmp_path / "auth.sqlite3")
    with pytest.raises(ValueError):
        store.mint("acme", "write", ["*"], role="approve", agent=agent)


def test_a_role_token_reaches_no_admin_route(tmp_path):
    app = make_app(tmp_path / "remote", admin={"dev_login": True, "open_signup": False})
    approver = _role(app, "approve", ["*"], "agent-1")
    for path in ("", "/holds", "/members", "/settings", "/retention", "/invitations"):
        status = call(app, "GET", T + path, token=approver)[0]
        assert status in (403, 404), (path, status)
    status, _headers, body = call(app, "GET", "/v1/me", token=approver)
    if status == 200:
        tenants = json.loads(body)["tenants"]
        assert all(row.get("role") is None for row in tenants), tenants
