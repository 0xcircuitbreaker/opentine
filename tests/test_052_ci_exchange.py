"""0.52 caps.oidc_exchange: GitHub, GitLab and Forgejo ID tokens for short-lived scoped tokens.

Offline: the issuers' keys are generated here and their JWKS is configured
inline or as a file; nothing is fetched.
"""

from __future__ import annotations

import base64
import json
import time

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils

from opentine.remote._ci_exchange import CIExchange
from opentine.remote._token_store import TokenStore
from tests._auth_helpers import call, make_app, push

GITHUB = "https://token.actions.githubusercontent.com"
GITLAB = "https://gitlab.example"
FORGEJO = "https://code.example"
AUD = "https://tine.example"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class _Key:
    def __init__(self, alg: str, kid: str):
        self.alg, self.kid = alg, kid
        if alg == "RS256":
            self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        else:
            self.key = ec.generate_private_key(ec.SECP256R1())

    def jwks(self) -> dict:
        public = self.key.public_key().public_numbers()
        if self.alg == "RS256":
            n = public.n.to_bytes((public.n.bit_length() + 7) // 8, "big")
            jwk = {"kty": "RSA", "n": _b64(n), "e": _b64(public.e.to_bytes(3, "big"))}
        else:
            jwk = {"kty": "EC", "crv": "P-256", "x": _b64(public.x.to_bytes(32, "big")),
                   "y": _b64(public.y.to_bytes(32, "big"))}  # fmt: skip
        return {"keys": [{**jwk, "kid": self.kid, "alg": self.alg, "use": "sig"}]}

    def token(self, iss: str, **claims) -> str:
        header = {"alg": self.alg, "kid": self.kid, "typ": "JWT"}
        payload = {"iss": iss, "aud": AUD, "sub": "repo:acme/app", "exp": time.time() + 300,
                   "iat": time.time(), **claims}  # fmt: skip
        signing = f"{_b64(json.dumps(header).encode())}.{_b64(json.dumps(payload).encode())}"
        if self.alg == "RS256":
            sig = self.key.sign(signing.encode(), padding.PKCS1v15(), hashes.SHA256())
        else:
            der = self.key.sign(signing.encode(), ec.ECDSA(hashes.SHA256()))
            r, s = utils.decode_dss_signature(der)
            sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        return f"{signing}.{_b64(sig)}"


@pytest.fixture(scope="module")
def keys():
    return {"github": _Key("RS256", "gh1"), "gitlab": _Key("ES256", "gl1"),
            "forgejo": _Key("ES256", "fj1"), "rogue": _Key("RS256", "gh1")}  # fmt: skip


@pytest.fixture
def trust(tmp_path, keys):
    (tmp_path / "gitlab.jwks.json").write_text(json.dumps(keys["gitlab"].jwks()), "utf-8")
    config = {"issuers": [
        {"name": "github", "provider": "github", "audience": AUD, "jwks": keys["github"].jwks(),
         "rules": [{"claims": {"repository": "acme/app", "ref": "refs/heads/*"},
                    "tenant": "acme", "access": "write", "refs": ["heads/ci/"],
                    "ttl_seconds": 600}]},
        {"name": "gitlab", "provider": "gitlab", "issuer": GITLAB, "audience": AUD,
         "jwks_file": "gitlab.jwks.json",
         "rules": [{"claims": {"project_path": "acme/app"}, "tenant": "acme", "access": "read",
                    "refs": ["*"]}]},
        {"name": "forgejo", "provider": "forgejo", "issuer": FORGEJO, "audience": AUD,
         "jwks": keys["forgejo"].jwks(),
         "rules": [{"claims": {"repository": "acme/app"}, "tenant": "acme", "access": "read",
                    "refs": ["heads/main"]}]}]}  # fmt: skip
    path = tmp_path / "ci-trust.json"
    path.write_text(json.dumps(config), "utf-8")
    return path


def test_each_provider_exchanges_for_a_scoped_short_lived_token(tmp_path, keys, trust):
    app = make_app(tmp_path / "remote", ci_trust=trust)
    run_id = push(app, tmp_path, "base", "heads/main")
    assert {p["name"] for p in app.service.capabilities()["oidc_exchange"]["providers"]} == {
        "github", "gitlab", "forgejo"}  # fmt: skip
    gh = keys["github"].token(GITHUB, repository="acme/app", ref="refs/heads/main", jti="j1")
    status, _, body = call(app, "POST", "/v1/auth/oidc-exchange", {"token": gh}, token=None)
    assert status == 201
    issued = json.loads(body)
    assert issued["token"].startswith("tine_ci_") and issued["refs"] == ["heads/ci/"]
    record = app.tokens.get(issued["token_id"])
    assert record["kind"] == "ci" and record["access"] == "write"
    ci = issued["token"]
    assert call(app, "PUT", "/v1/tenants/acme/refs/heads%2Fci%2Fa", {"new": run_id}, ci)[0] == 200
    assert call(app, "PUT", "/v1/tenants/acme/refs/heads%2Fmain", {"new": run_id,
                "expected_old": run_id}, ci)[0] == 403  # fmt: skip
    gl = keys["gitlab"].token(GITLAB, project_path="acme/app")
    gl_reply = json.loads(call(app, "POST", "/v1/auth/oidc-exchange", {"token": gl}, None)[2])
    assert gl_reply["access"] == "read" and gl_reply["refs"] == ["*"]
    fj = keys["forgejo"].token(FORGEJO, repository="acme/app")
    fj_reply = json.loads(call(app, "POST", "/v1/auth/oidc-exchange", {"token": fj}, None)[2])
    refs = json.loads(call(app, "GET", "/v1/tenants/acme/refs", token=fj_reply["token"])[2])
    assert set(refs["refs"]) == {"heads/main"}


def test_untrusted_tokens_are_refused_and_throttled(tmp_path, keys, trust):
    app = make_app(tmp_path / "remote", ci_trust=trust)
    gh = keys["github"]
    refusals = [
        gh.token(GITHUB, repository="acme/other", ref="refs/heads/main"),  # no rule matches
        gh.token(GITHUB, repository="acme/app", ref="refs/tags/v1"),
        gh.token(GITHUB, aud="https://elsewhere", repository="acme/app", ref="refs/heads/x"),
        gh.token("https://evil.example", repository="acme/app", ref="refs/heads/x"),
        keys["rogue"].token(GITHUB, repository="acme/app", ref="refs/heads/x"),  # same kid
        gh.token(GITHUB, repository="acme/app", ref="refs/heads/x", exp=time.time() - 3600),
        "not-a-jwt",
    ]
    for index, token in enumerate(refusals):
        status, _, body = call(app, "POST", "/v1/auth/oidc-exchange", {"token": token}, None,
                               addr=f"10.1.0.{index}")  # fmt: skip
        assert (status, json.loads(body)) == (401, {"error": "authentication failed"}), index
    wrong_tenant = gh.token(GITHUB, repository="acme/app", ref="refs/heads/main")
    body = {"token": wrong_tenant, "tenant": "other"}
    assert call(app, "POST", "/v1/auth/oidc-exchange", body, None, addr="10.2.0.1")[0] == 401
    bad = {"token": refusals[0]}
    codes = [call(app, "POST", "/v1/auth/oidc-exchange", bad, None, addr="10.3.0.1")[0]
             for _ in range(30)]  # fmt: skip
    assert codes[-1] == 429
    assert app.tokens.list() == []


def test_a_jti_is_exchanged_once(tmp_path, keys, trust):
    app = make_app(tmp_path / "remote", ci_trust=trust)
    gh = keys["github"].token(GITHUB, repository="acme/app", ref="refs/heads/main", jti="once")
    assert call(app, "POST", "/v1/auth/oidc-exchange", {"token": gh}, None)[0] == 201
    assert call(app, "POST", "/v1/auth/oidc-exchange", {"token": gh}, None)[0] == 401


def test_without_a_trust_config_the_route_is_the_uniform_404(tmp_path):
    app = make_app(tmp_path / "remote")
    status, _, body = call(app, "POST", "/v1/auth/oidc-exchange", {"token": "a.b.c"}, None)
    assert (status, json.loads(body)) == (404, {"error": "not found"})


@pytest.mark.parametrize(
    "rule",
    [
        {"claims": {"ref": "refs/heads/main"}, "tenant": "acme", "access": "read", "refs": ["*"]},
        {"claims": {"repository": "*"}, "tenant": "acme", "access": "read", "refs": ["*"]},
        {"claims": {}, "tenant": "acme", "access": "read", "refs": ["*"]},
        {"claims": {"repository": "a/b"}, "tenant": "acme", "access": "admin", "refs": ["*"]},
        {
            "claims": {"repository": "a/b"},
            "tenant": "acme",
            "access": "read",
            "refs": ["*"],
            "ttl_seconds": 7200,
        },
        {"claims": {"repository": "a/b"}, "tenant": "Acme Corp", "access": "read", "refs": ["*"]},
    ],
)
def test_a_trust_rule_must_pin_the_repository_and_stay_bounded(tmp_path, keys, rule):
    config = {"issuers": [{"name": "gh", "provider": "github", "audience": AUD,
                           "jwks": keys["github"].jwks(), "rules": [rule]}]}  # fmt: skip
    path = tmp_path / "t.json"
    path.write_text(json.dumps(config), "utf-8")
    with pytest.raises(ValueError):
        CIExchange.load(path, TokenStore(tmp_path / "auth.sqlite3"))


def test_an_issuer_must_be_https_and_name_its_keys(tmp_path, keys):
    rule = {"claims": {"repository": "a/b"}, "tenant": "acme", "access": "read", "refs": ["*"]}
    for issuer in (
        {"name": "fj", "provider": "forgejo", "audience": AUD, "jwks": keys["forgejo"].jwks()},
        {
            "name": "fj",
            "provider": "forgejo",
            "issuer": "http://code.example",
            "audience": AUD,
            "jwks": keys["forgejo"].jwks(),
        },
        {"name": "gh", "provider": "github", "audience": AUD},
        {"name": "gh", "provider": "jenkins", "audience": AUD, "jwks": keys["github"].jwks()},
    ):
        path = tmp_path / "t.json"
        path.write_text(json.dumps({"issuers": [{**issuer, "rules": [rule]}]}), "utf-8")
        with pytest.raises(ValueError):
            CIExchange.load(path, TokenStore(tmp_path / "auth.sqlite3"))
