"""0.52 review: the admin surface's login and tenancy edges (SPEC 8.27)."""

from __future__ import annotations

import hashlib
import struct

import pytest

from opentine.remote import _authn
from opentine.remote._authn import PasskeyAuthenticator, _origin_ok
from opentine.remote._webauthn import b64url
from tests.test_052_admin_api import RP, SoftKey, _register_acme, call
from tests.test_052_admin_api import app as _app_fixture

app = _app_fixture


def _registered(app, kind="es256"):
    key = SoftKey(kind)
    options = call(app, "POST", "/v1/auth/passkey/registration/options", {}, "root-token")[1]
    assert options["authenticatorSelection"]["userVerification"] == "required"
    assert call(app, "POST", "/v1/auth/passkey/registration", key.create(options),
                "root-token")[0] == 201  # fmt: skip
    return key


def _login(app, key, **kw):
    options = call(app, "POST", "/v1/auth/passkey/assertion/options", {})[1]
    return call(app, "POST", "/v1/auth/passkey/assertion", key.get(options, **kw))


def test_a_login_challenge_is_single_use_and_a_counter_cannot_go_back(app):
    key = _registered(app)
    options = call(app, "POST", "/v1/auth/passkey/assertion/options", {})[1]
    response = key.get(options)
    assert call(app, "POST", "/v1/auth/passkey/assertion", response)[0] == 201
    replay = call(app, "POST", "/v1/auth/passkey/assertion", response)
    assert replay[0] == 400 and replay[1]["code"] == "auth.passkey_invalid"
    key.count = 0  # a cloned authenticator restarts its counter
    status, body = _login(app, key)
    assert status == 400 and "counter" in body["error"]


def test_a_passkey_without_user_verification_is_refused(app):
    key = _registered(app)
    options = call(app, "POST", "/v1/auth/passkey/assertion/options", {})[1]
    response = key.get(options)
    auth = hashlib.sha256(RP.encode()).digest() + bytes([0x01]) + struct.pack(">I", 9)
    response["authenticatorData"] = b64url(auth)  # UP only; signature also stops matching
    status, body = call(app, "POST", "/v1/auth/passkey/assertion", response)
    assert status == 400 and "verification" in body["error"]


def test_challenge_flooding_answers_429_not_an_error(app, monkeypatch):
    monkeypatch.setattr(_authn, "MAX_CHALLENGES", 2)
    for _ in range(2):
        assert call(app, "POST", "/v1/auth/passkey/assertion/options", {})[0] == 200
    status, body = call(app, "POST", "/v1/auth/passkey/assertion/options", {})
    assert status == 429 and body["code"] == "auth.challenge.limit"


@pytest.mark.parametrize(
    "origin,ok",
    [
        ("https://tine.example", True),
        ("https://tine.example:8443", True),
        ("http://localhost:8080", True),
        ("http://127.0.0.1:8080", True),
        ("http://localhost.evil.example", False),
        ("http://127.evil.example", False),
        ("http://tine.example", False),
        ("https://tine.example/path", False),
        ("https://user@tine.example", False),
        ("https://tine.example:99999", False),
    ],
)
def test_passkey_origins_are_https_or_loopback_http(origin, ok, tmp_path):
    assert _origin_ok(origin) is ok
    if not ok:
        with pytest.raises(ValueError):
            PasskeyAuthenticator(None, rp_id="tine.example", origin=origin)


def test_open_signup_cannot_claim_a_tenant_a_static_token_names(tmp_path):
    from opentine.remote import Identity, LocalKeyProvider, StaticTokenIdentityProvider, server

    identities = StaticTokenIdentityProvider({"t": Identity("root", "acme", ("admin",))})
    srv = server.reference_app(tmp_path / "r", identities=identities,
                               keys=LocalKeyProvider(b"k" * 32),
                               admin={"dev_login": True, "open_signup": True})  # fmt: skip
    mallory = call(srv, "POST", "/v1/auth/dev/login", {"subject": "mallory"})[1]["token"]
    squat = call(srv, "POST", "/v1/tenants", {"name": "acme"}, mallory)
    assert squat[0] == 409 and squat[1]["code"] == "tenant.exists"
    assert call(srv, "POST", "/v1/tenants", {"name": "mallory-co"}, mallory)[0] == 201
    assert call(srv, "POST", "/v1/tenants", {"name": "acme"}, "t")[0] == 201


def test_an_archived_tenant_keeps_its_holds(app, tmp_path):
    from opentine import Run
    from opentine.graph import StepKind
    from opentine.repository import Repo

    _register_acme(app)
    local = Repo.init(tmp_path / "local")
    run = Run(id="held")
    run.add_step(StepKind.done, {"text": "x"})
    oid = local.put_run(run).run_id
    assert call(app, "POST", "/v1/tenants/acme/packs", token="root-token", raw=local.pack(),
                content_type="application/vnd.opentine.pack")[0] == 201  # fmt: skip
    assert call(app, "POST", "/v1/tenants/acme/holds", {"oid": oid}, "root-token")[0] == 201
    assert call(app, "POST", "/v1/tenants/acme/archive", token="root-token")[0] == 200
    release = call(app, "DELETE", f"/v1/tenants/acme/holds/{oid}", token="root-token")
    assert release[0] == 409 and release[1]["code"] == "tenant.archived"
    assert app.service.objects.held("acme") == {oid}
