"""0.36.0 X15: `tine serve` OIDC wiring, strong static tokens, auth backoff, generic 500s."""

from __future__ import annotations

import base64
import io
import json
import logging

import pytest

from opentine.cli import _build_parser
from opentine.remote import _serve_auth, server
from opentine.remote._auth_throttle import AuthThrottle
from opentine.remote.app import RemoteApp
from opentine.remote.interfaces import Identity
from opentine.remote.security import (
    LocalKeyProvider,
    OIDCIdentityProvider,
    StaticTokenIdentityProvider,
)

TOKEN = "s" * 32


def _jwks():
    from cryptography.hazmat.primitives.asymmetric import ec

    numbers = ec.generate_private_key(ec.SECP256R1()).public_key().public_numbers()

    def b64(value):
        return base64.urlsafe_b64encode(value.to_bytes(32, "big")).rstrip(b"=").decode()

    key = {"kty": "EC", "crv": "P-256", "kid": "k1", "x": b64(numbers.x), "y": b64(numbers.y)}
    return json.dumps({"keys": [key]}).encode()


def _args(*extra):
    return _build_parser().parse_args(["serve", "--insecure-dev", *extra])


def _serve(tmp_path, monkeypatch, *extra):
    monkeypatch.setenv("TINE_KMS_KEY", base64.b64encode(b"k" * 32).decode())

    def bound(*args, **kwargs):
        raise RuntimeError("bound")

    monkeypatch.setattr(server, "make_server", bound)
    args = _args("--root", str(tmp_path / "r"), "--port", "0", *extra)
    server.cmd_serve(args, None)


def test_short_static_token_refuses_to_start(tmp_path, monkeypatch):
    monkeypatch.setenv("TINE_REMOTE_TOKEN", "x" * 20)
    with pytest.raises(SystemExit, match="at least 32"):
        _serve(tmp_path, monkeypatch)
    with pytest.raises(RuntimeError, match="bound"):
        _serve(tmp_path, monkeypatch, "--allow-weak-tokens")
    monkeypatch.setenv("TINE_REMOTE_TOKEN", TOKEN)
    with pytest.raises(RuntimeError, match="bound"):
        _serve(tmp_path, monkeypatch)


def test_oidc_urls_must_be_https_and_configured():
    with pytest.raises(SystemExit, match="https"):
        _serve_auth.serve_identities(_args("--oidc-issuer", "http://idp", "--oidc-audience", "a"))
    with pytest.raises(SystemExit, match="--oidc-audience is required"):
        _serve_auth.serve_identities(_args("--oidc-issuer", "https://idp"))
    with pytest.raises(SystemExit, match="https"):
        _serve_auth.serve_identities(
            _args(
                "--oidc-issuer", "https://idp", "--oidc-audience", "a",
                "--oidc-jwks-uri", "http://idp/jwks",
            )
        )  # fmt: skip
    with pytest.raises(SystemExit, match="need --oidc-issuer"):
        _serve_auth.serve_identities(_args("--oidc-audience", "a"))


def test_oidc_fetches_only_the_configured_jwks_url():
    fetched = []

    def fetch(url):
        fetched.append(url)
        return _jwks()

    args = _args(
        "--oidc-issuer", "https://idp.example", "--oidc-audience", "api",
        "--oidc-jwks-uri", "https://idp.example/jwks",
    )  # fmt: skip
    provider = _serve_auth.serve_identities(args, fetch)
    assert isinstance(provider, OIDCIdentityProvider)
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "RS256", "kid": "k", "jku": "https://evil/jwks"}).encode()
    ).rstrip(b"=")
    body = base64.urlsafe_b64encode(json.dumps({"iss": "https://evil"}).encode()).rstrip(b"=")
    with pytest.raises(PermissionError):
        provider.authenticate({"authorization": f"Bearer {header.decode()}.{body.decode()}.c2ln"})
    assert set(fetched) == {"https://idp.example/jwks"}


def test_oidc_discovery_uses_the_configured_issuer():
    fetched = []

    def fetch(url):
        fetched.append(url)
        if url.endswith("openid-configuration"):
            doc = {"issuer": "https://idp.example", "jwks_uri": "https://idp.example/k"}
            return json.dumps(doc).encode()
        return _jwks()

    args = _args("--oidc-issuer", "https://idp.example", "--oidc-audience", "api")
    assert isinstance(_serve_auth.serve_identities(args, fetch), OIDCIdentityProvider)
    assert fetched == [
        "https://idp.example/.well-known/openid-configuration",
        "https://idp.example/k",
    ]


def test_throttle_backs_off_exponentially_and_resets():
    now = [0.0]
    throttle = AuthThrottle(free_failures=2, base_delay=1.0, max_delay=8.0, clock=lambda: now[0])
    throttle.failed("a")
    assert throttle.retry_after("a") == 0
    throttle.failed("a")
    assert throttle.retry_after("a") == 1
    throttle.failed("a")
    assert throttle.retry_after("a") == 2
    for _ in range(10):
        throttle.failed("a")
    assert throttle.retry_after("a") == 8
    assert throttle.retry_after("b") == 0
    throttle.succeeded("a")
    assert throttle.retry_after("a") == 0


class _Service:
    audit = objects = None

    def __init__(self, error=None):
        self.identities = StaticTokenIdentityProvider({TOKEN: Identity("u", "acme", ("reader",))})
        self.error = error

    def authenticate(self, headers):
        return self.identities.authenticate(headers)

    def list_refs(self, identity, tenant):
        raise self.error


def _call(app, token, addr="10.0.0.1"):
    seen = {}
    environ = {
        "REQUEST_METHOD": "GET",
        "PATH_INFO": "/v1/tenants/acme/refs",
        "HTTP_AUTHORIZATION": f"Bearer {token}",
        "REMOTE_ADDR": addr,
        "wsgi.input": io.BytesIO(),
    }
    body = b"".join(app(environ, lambda status, headers: seen.update(s=status, h=headers)))
    return seen["s"], dict(seen["h"]), json.loads(body)


def test_repeated_401s_lock_the_client_out(tmp_path):
    app = RemoteApp(_Service(KeyError("x")), tmp_path, staging_keys=LocalKeyProvider(b"k" * 32))
    for _ in range(app.auth_throttle.free_failures):
        assert _call(app, "wrong")[0].startswith("401")
    status, headers, _ = _call(app, TOKEN)
    assert status.startswith("429") and int(headers["Retry-After"]) >= 1
    assert _call(app, TOKEN, addr="10.0.0.2")[0].startswith("404")


def test_500_is_generic_and_logged(tmp_path, caplog):
    app = RemoteApp(
        _Service(ZeroDivisionError("secret detail")),
        tmp_path,
        staging_keys=LocalKeyProvider(b"k" * 32),
    )
    with caplog.at_level(logging.ERROR, logger="opentine.remote"):
        status, _, body = _call(app, TOKEN)
    assert status.startswith("500")
    assert set(body) == {"error", "request_id"} and body["error"] == "internal"
    assert "ZeroDivision" not in json.dumps(body)
    assert body["request_id"] in caplog.text and "secret detail" in caplog.text
