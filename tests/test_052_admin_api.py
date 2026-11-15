"""0.52: the admin surface of tine serve -- session, passkey login, tenants (SPEC 8.27).

A software authenticator (an ES256 or Ed25519 key made here) drives the real
WebAuthn ceremonies; the server only ever sees its public key.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import struct

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine import _cbor
from opentine.remote import Identity, LocalKeyProvider, StaticTokenIdentityProvider, server
from opentine.remote._admin_surface import admin_options
from opentine.remote._openapi import build
from opentine.remote._webauthn import b64url

RP, ORIGIN = "tine.example", "https://tine.example"
SPEC = build()


@pytest.fixture
def app(tmp_path):
    identities = StaticTokenIdentityProvider(
        {"root-token": Identity("root", "acme", ("admin",)),
         "eve-token": Identity("eve", "other", ("admin",))}
    )  # fmt: skip
    admin = {"passkey_rp_id": RP, "passkey_origin": ORIGIN, "dev_login": True}
    return server.reference_app(tmp_path / "remote", identities=identities,
                                keys=LocalKeyProvider(b"k" * 32), admin=admin)  # fmt: skip


def call(app, method, path, body=None, token=None, raw=None, content_type="application/json"):
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else b"")
    environ = {
        "CONTENT_LENGTH": str(len(data)),
        "CONTENT_TYPE": content_type,
        "PATH_INFO": path,
        "REQUEST_METHOD": method,
        "wsgi.input": io.BytesIO(data),
        "REMOTE_ADDR": "10.0.0.1",
    }
    if token:
        environ["HTTP_AUTHORIZATION"] = f"Bearer {token}"
    state: dict = {}
    out = b"".join(app(environ, lambda status, headers: state.update(status=status)))
    return int(state["status"].split()[0]), (json.loads(out) if out else None)


def valid(schema: str, value) -> None:
    from opentine import _jsonschema

    ref = {"$ref": f"#/components/schemas/{schema}", "components": SPEC["components"]}
    assert _jsonschema.validate(ref, value) == [], (schema, value)


class SoftKey:
    def __init__(self, kind="es256"):
        self.kind, self.count, self.id = kind, 0, hashlib.sha256(kind.encode()).digest()[:16]
        if kind == "es256":
            self.key = ec.generate_private_key(ec.SECP256R1())
            numbers = self.key.public_key().public_numbers()
            self.cose = {1: 2, 3: -7, -1: 1, -2: numbers.x.to_bytes(32, "big"),
                         -3: numbers.y.to_bytes(32, "big")}  # fmt: skip
        else:
            self.key = Ed25519PrivateKey.generate()
            self.cose = {1: 1, 3: -8, -1: 6, -2: self.key.public_key().public_bytes_raw()}

    def client(self, kind, challenge, origin=ORIGIN):
        return json.dumps({"type": kind, "challenge": challenge, "origin": origin}).encode()

    def create(self, options, **extra):
        auth = hashlib.sha256(RP.encode()).digest() + bytes([0x45]) + struct.pack(">I", 0)
        auth += b"\0" * 16 + struct.pack(">H", len(self.id)) + self.id + _cbor.dumps(self.cose)
        attestation = _cbor.dumps({"fmt": "none", "attStmt": {}, "authData": auth})
        return {"challenge": options["challenge"], "attestationObject": b64url(attestation),
                "clientDataJSON": b64url(self.client("webauthn.create", options["challenge"])),
                **extra}  # fmt: skip

    def get(self, options, *, rp=RP, origin=ORIGIN):
        self.count += 1
        auth = hashlib.sha256(rp.encode()).digest() + bytes([0x05]) + struct.pack(">I", self.count)
        client = self.client("webauthn.get", options["challenge"], origin)
        signed = auth + hashlib.sha256(client).digest()
        if self.kind == "es256":
            signature = self.key.sign(signed, ec.ECDSA(hashes.SHA256()))
        else:
            signature = self.key.sign(signed)
        return {"challenge": options["challenge"], "credential_id": b64url(self.id),
                "clientDataJSON": b64url(client), "authenticatorData": b64url(auth),
                "signature": b64url(signature)}  # fmt: skip


def _register_acme(app):
    status, tenant = call(app, "POST", "/v1/tenants", {"name": "acme", "display_name": "Acme"},
                          "root-token")  # fmt: skip
    assert status == 201 and tenant["role"] == "admin"
    valid("Tenant", tenant)


def _invite(app, role="writer"):
    status, made = call(app, "POST", "/v1/tenants/acme/invitations", {"role": role}, "root-token")
    assert status == 201
    valid("InvitationCreated", made)
    return made["token"]


@pytest.mark.parametrize("kind", ["es256", "ed25519"])
def test_an_invited_passkey_signs_up_logs_in_and_reaches_the_data_routes(app, kind):
    _register_acme(app)
    invitation = _invite(app)
    key = SoftKey(kind)
    status, options = call(app, "POST", "/v1/auth/passkey/registration/options",
                           {"invitation": invitation})  # fmt: skip
    assert status == 200 and options["attestation"] == "none"
    valid("PasskeyCreationOptions", options)
    status, made = call(app, "POST", "/v1/auth/passkey/registration",
                        key.create(options, invitation=invitation))  # fmt: skip
    assert status == 201, made
    valid("PasskeyRegistered", made)
    assert made["tenant"]["role"] == "writer" and made["subject"].startswith("user:")
    stored = (app.state / "admin" / "state.json").read_text()
    assert "private" not in stored and invitation not in stored

    status, options = call(app, "POST", "/v1/auth/passkey/assertion/options", {})
    valid("PasskeyRequestOptions", options)
    assertion = key.get(options)
    status, opened = call(app, "POST", "/v1/auth/passkey/assertion", assertion)
    assert status == 201, opened
    valid("SessionOpened", opened)
    replay = call(app, "POST", "/v1/auth/passkey/assertion", assertion)
    assert replay[0] == 400 and replay[1]["code"] == "auth.passkey_invalid"

    session = opened["token"]
    status, me = call(app, "GET", "/v1/session", token=session)
    assert status == 200 and me["method"] == "session:passkey"
    assert [(t["name"], t["role"]) for t in me["tenants"]] == [("acme", "writer")]
    valid("Session", me)
    assert call(app, "GET", "/v1/tenants/acme/refs", token=session)[0] == 200
    assert call(app, "GET", "/v1/tenants/other/refs", token=session)[0] in (403, 404)
    assert call(app, "GET", "/v1/tenants/acme/members", token=session)[0] == 200
    forbidden = call(app, "PUT", "/v1/tenants/acme/members/bob", {"role": "reader"}, session)
    assert forbidden == (403, {"error": "needs the admin role", "code": "tenant.forbidden"})

    assert call(app, "DELETE", "/v1/session", token=session) == (200, {"ended": True})
    assert call(app, "GET", "/v1/session", token=session)[0] == 401
    assert call(app, "GET", "/v1/tenants/acme/refs", token=session)[0] == 401


def test_a_ceremony_for_another_origin_or_rp_is_refused(app):
    _register_acme(app)
    key = SoftKey()
    status, options = call(app, "POST", "/v1/auth/passkey/registration/options", {}, "root-token")
    assert call(app, "POST", "/v1/auth/passkey/registration", key.create(options),
                "root-token")[0] == 201  # fmt: skip
    for wrong in ({"origin": "https://evil.example"}, {"rp": "evil.example"}):
        options = call(app, "POST", "/v1/auth/passkey/assertion/options", {})[1]
        status, body = call(app, "POST", "/v1/auth/passkey/assertion", key.get(options, **wrong))
        assert status == 400 and body["code"] == "auth.passkey_invalid", wrong
    options = call(app, "POST", "/v1/auth/passkey/assertion/options", {})[1]
    status, opened = call(app, "POST", "/v1/auth/passkey/assertion", key.get(options))
    assert status == 201 and opened["subject"] == "root"
    unregistered = call(app, "POST", "/v1/auth/passkey/registration/options", {})
    assert unregistered[0] == 401 and unregistered[1]["code"] == "auth.required"


def test_members_invitations_settings_retention_and_archive(app):
    _register_acme(app)
    root = "root-token"
    status, members = call(app, "PUT", "/v1/tenants/acme/members/dev%3Abob", {"role": "reader"},
                           root)  # fmt: skip
    assert status == 200 and {"subject": "dev:bob", "role": "reader"} in members["members"]
    valid("MemberList", members)
    last = call(app, "DELETE", "/v1/tenants/acme/members/root", token=root)
    assert last[0] == 409 and last[1]["code"] == "member.last_admin"
    bob = call(app, "POST", "/v1/auth/dev/login", {"subject": "bob"})[1]["token"]
    assert call(app, "GET", "/v1/tenants/acme", token=bob)[1]["role"] == "reader"
    assert call(app, "POST", "/v1/tenants", {"name": "bobco"}, bob)[1]["code"] == (
        "tenant.signup_closed"
    )

    invitation = _invite(app, "admin")
    status, listed = call(app, "GET", "/v1/tenants/acme/invitations", token=root)
    valid("InvitationList", listed)
    assert invitation not in json.dumps(listed)
    status, joined = call(app, "POST", "/v1/invitations/accept", {"token": invitation}, bob)
    assert (status, joined["role"]) == (200, "admin")
    again = call(app, "POST", "/v1/invitations/accept", {"token": invitation}, bob)
    assert again == (404, {"error": "not found"})

    status, settings = call(
        app,
        "PATCH",
        "/v1/tenants/acme/settings",
        {"description": "Agents", "homepage": "https://acme.example"},
        root,
    )
    assert status == 200 and settings["settings"]["description"] == "Agents"
    valid("TenantSettings", settings)
    bad = call(app, "PATCH", "/v1/tenants/acme/settings", {"homepage": "http://x"}, root)
    assert bad[0] == 400 and bad[1]["code"] == "request.invalid"
    status, kept = call(app, "PUT", "/v1/tenants/acme/retention",
                        {"keep_days": 30, "status": {"failed": 7}}, root)  # fmt: skip
    assert status == 200 and kept["server_deletes"] is False
    valid("Retention", kept)
    assert call(app, "PUT", "/v1/tenants/acme/retention", {"keep_days": -1}, root)[0] == 400

    status, renamed = call(app, "PATCH", "/v1/tenants/acme", {"display_name": "Acme Inc"}, root)
    assert (status, renamed["display_name"], renamed["name"]) == (200, "Acme Inc", "acme")
    assert call(app, "POST", "/v1/tenants/acme/archive", token=root)[1]["archived"] is True
    oid = "run:sha256:" + "a" * 64
    assert call(app, "PUT", "/v1/tenants/acme/refs/heads%2Fx", {"new": oid}, root)[0] == 403
    assert call(app, "GET", "/v1/tenants/acme/refs", token=root)[0] == 200
    archived = call(app, "PATCH", "/v1/tenants/acme/settings", {"description": "x"}, root)
    assert archived[0] == 409 and archived[1]["code"] == "tenant.archived"
    assert call(app, "POST", "/v1/tenants/acme/unarchive", token=root)[1]["archived"] is False


def test_holds_reuse_the_tine_holds_file_and_refuse_unknown_objects(app, tmp_path):
    from opentine import Run
    from opentine.graph import StepKind
    from opentine.repository import Repo

    local = Repo.init(tmp_path / "local")
    run = Run(id="held")
    run.add_step(StepKind.done, {"text": "x"})
    oid = local.put_run(run).run_id
    pushed = call(app, "POST", "/v1/tenants/acme/packs", token="root-token", raw=local.pack(),
                  content_type="application/vnd.opentine.pack")  # fmt: skip
    assert pushed[0] == 201
    status, holds = call(app, "POST", "/v1/tenants/acme/holds", {"oid": oid}, "root-token")
    assert status == 201 and holds == {"holds": [{"oid": oid, "target": oid}]}
    assert app.service.objects.held("acme") == {oid}
    missing = "run:sha256:" + "b" * 64
    assert call(app, "POST", "/v1/tenants/acme/holds", {"oid": missing}, "root-token")[0] == 404
    assert call(app, "GET", "/v1/tenants/acme/holds", token="eve-token") == (
        404, {"error": "not found"})  # fmt: skip
    released = call(app, "DELETE", f"/v1/tenants/acme/holds/{oid}", token="root-token")
    assert released == (200, {"holds": []})
    # A tenant someone else's data already lives in cannot be claimed by name.
    claim = call(app, "POST", "/v1/tenants", {"name": "acme"}, "eve-token")
    assert claim[0] in (403, 409)


def test_dev_login_and_passkeys_are_off_unless_configured(tmp_path):
    identities = StaticTokenIdentityProvider({"t": Identity("root", "acme", ("admin",))})
    app = server.reference_app(
        tmp_path / "r", identities=identities, keys=LocalKeyProvider(b"k" * 32)
    )
    assert call(app, "POST", "/v1/auth/dev/login", {"subject": "x"}) == (
        404,
        {"error": "not found"},
    )
    assert call(app, "POST", "/v1/auth/passkey/assertion/options", {})[0] == 404
    caps = call(app, "GET", "/v1/capabilities")[1]
    assert caps["session"]["authenticators"] == {}
    assert caps["session"]["provider_signin"] == "identity-linking-only"
    assert caps["tenancy"]["limits"]["members"] > 0


def test_serve_flags_keep_dev_login_to_insecure_dev():
    args = argparse.Namespace(dev_login=True, insecure_dev=False, passkey_rp_id=None,
                              passkey_origin=None, open_signup=False)  # fmt: skip
    with pytest.raises(SystemExit, match="insecure-dev"):
        admin_options(args)
    args.dev_login, args.passkey_rp_id = False, RP
    with pytest.raises(SystemExit, match="go together"):
        admin_options(args)
