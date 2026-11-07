"""0.44 X15: QuotaAdmission (429 + Retry-After, bounded memory), VSA emission,
and the client's bounded retry of 429."""

from __future__ import annotations

import base64
import io
import json
from pathlib import Path

import httpx
import pytest

from opentine.remote import (
    FilesystemObjectStore,
    Identity,
    LocalKeyProvider,
    RemoteApp,
    RemoteService,
    RoleAuthorizationPolicy,
    SQLiteBackend,
    StaticTokenIdentityProvider,
)
from opentine.remote._quota import QuotaAdmission, QuotaExceeded
from opentine.remote._serve_admission import serve_admission
from opentine.remote._vsa import VSA_TYPE, TrustPolicyAdmission, directory_sink
from opentine.repository import Repo, _http, _http_retry

WRITER = Identity("writer", "acme", ("writer",))


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def _service(tmp_path: Path, admission):
    objects = FilesystemObjectStore(tmp_path / "objects", LocalKeyProvider(b"k" * 32))
    index = SQLiteBackend(tmp_path / "remote.sqlite3")
    identities = StaticTokenIdentityProvider({"writer-token": WRITER})
    service = RemoteService(
        objects, index, identities, RoleAuthorizationPolicy(), admission=admission
    )
    local = Repo.init(tmp_path / "local")
    oid = local.put("blob", b"payload", redact=False)
    objects.put("acme", oid, local.raw(oid))
    return service, oid


def _put_ref(app, oid: str):
    state: dict = {}

    def start_response(status, headers):
        state.update(status=status, headers=dict(headers))

    body = json.dumps({"new": oid, "expected_old": None}).encode()
    environ = {
        "CONTENT_LENGTH": str(len(body)),
        "HTTP_AUTHORIZATION": "Bearer writer-token",
        "PATH_INFO": "/v1/tenants/acme/refs/tags/one",
        "REQUEST_METHOD": "PUT",
        "wsgi.input": io.BytesIO(body),
    }
    payload = b"".join(app(environ, start_response))
    return state["status"], state["headers"], json.loads(payload)


def test_token_bucket_refills_and_reports_retry_after():
    clock = Clock()
    quota = QuotaAdmission(rate=0.5, burst=2, clock=clock)
    quota.admit(WRITER, "update_ref", {"tenant": "acme"})
    quota.admit(WRITER, "update_ref", {"tenant": "acme"})
    with pytest.raises(QuotaExceeded) as refused:
        quota.admit(WRITER, "update_ref", {"tenant": "acme"})
    assert refused.value.retry_after == 2
    clock.now += 2
    quota.admit(WRITER, "update_ref", {"tenant": "acme"})
    # Another tenant has its own bucket.
    quota.admit(WRITER, "update_ref", {"tenant": "other"})


def test_quota_memory_is_bounded_by_lru_eviction():
    quota = QuotaAdmission(rate=1, burst=1, max_keys=8, clock=Clock())
    for number in range(1000):
        quota.admit(Identity(f"user{number}", "acme", ("writer",)), "upload", {"tenant": "acme"})
    assert quota.tracked == 8


def test_large_uploads_cost_more_tokens():
    quota = QuotaAdmission(rate=1, burst=4, bytes_per_token=100, clock=Clock())
    assert quota.cost("upload", {"bytes": 250}) == 3
    # Capped at the burst, so a big upload is slow but never refused forever.
    quota.admit(WRITER, "upload", {"tenant": "acme", "bytes": 10_000})
    with pytest.raises(QuotaExceeded):
        quota.admit(WRITER, "upload", {"tenant": "acme"})


def test_over_quota_push_gets_429_with_retry_after(tmp_path: Path):
    service, oid = _service(tmp_path, QuotaAdmission(rate=0.1, burst=1, clock=Clock()))
    app = RemoteApp(service, tmp_path / "state")
    assert _put_ref(app, oid)[0] == "200 OK"
    status, headers, body = _put_ref(app, oid)
    assert status == "429 Too Many Requests"
    assert headers["Retry-After"] == "10"
    assert body == {"error": "quota exceeded"}


def test_trust_policy_admission_emits_a_vsa_for_admitted_pushes(tmp_path: Path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    written = tmp_path / "vsa"
    policy = TrustPolicyAdmission(sink=directory_sink(written))
    service, oid = _service(tmp_path, policy)
    assert service.update_ref(WRITER, "acme", "tags/one", oid, None)
    (statement,) = policy.recent
    assert statement["predicateType"] == VSA_TYPE
    assert statement["subject"][0]["digest"]["sha256"] == oid.rsplit(":", 1)[1]
    predicate = statement["predicate"]
    assert predicate["verificationResult"] == "PASSED"
    assert predicate["resourceUri"] == "tine://acme/tags/one"
    (saved,) = (written / "acme").iterdir()
    assert json.loads(saved.read_text()) == statement

    signed = TrustPolicyAdmission(private_key=Ed25519PrivateKey.generate())
    signed.admit(WRITER, "update_ref", {"tenant": "acme", "name": "tags/x", "new": oid})
    envelope = signed.recent[0]
    assert json.loads(base64.b64decode(envelope["payload"]))["predicateType"] == VSA_TYPE


def test_trust_policy_refusal_is_403_and_emits_nothing(tmp_path: Path):
    def refuse(identity, operation, facts):
        raise PermissionError("unsigned run")

    policy = TrustPolicyAdmission(refuse)
    service, oid = _service(tmp_path, policy)
    app = RemoteApp(service, tmp_path / "state")
    assert _put_ref(app, oid)[0] == "403 Forbidden"
    assert not policy.recent


def test_serve_flags_build_the_chain(tmp_path: Path):
    from argparse import Namespace

    none = Namespace(quota_rate=None, vsa_dir=None)
    assert serve_admission(none) is None
    chain = serve_admission(
        Namespace(quota_rate=2.0, quota_burst=5.0, quota_max_keys=10, vsa_dir=str(tmp_path))
    )
    assert isinstance(chain, TrustPolicyAdmission)
    assert isinstance(chain.inner, QuotaAdmission)
    with pytest.raises(SystemExit):
        serve_admission(Namespace(quota_rate=0.0, quota_burst=5.0, quota_max_keys=10))


def _client(responses: list[httpx.Response], seen: list[str]) -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        return responses.pop(0)

    return httpx.Client(base_url="http://remote", transport=httpx.MockTransport(handler))


def test_client_retries_429_honouring_retry_after(monkeypatch):
    slept: list[float] = []
    monkeypatch.setattr(_http.time, "sleep", slept.append)
    seen: list[str] = []
    session = _client(
        [
            httpx.Response(429, headers={"Retry-After": "2"}, json={"error": "quota exceeded"}),
            httpx.Response(200, json={"ok": True}),
        ],
        seen,
    )
    assert _http.request_json(session, "GET", "/v1/x") == (200, {"ok": True})
    assert slept == [2.0] and len(seen) == 2


def test_client_retry_is_bounded_and_degrades_to_a_clean_error(monkeypatch):
    monkeypatch.setattr(_http.time, "sleep", lambda seconds: None)
    seen: list[str] = []
    busy = [httpx.Response(429, headers={"Retry-After": "1"}) for _ in range(10)]
    with pytest.raises(ValueError, match="HTTP 429"):
        _http.request_json(_client(busy, seen), "GET", "/v1/x")
    assert len(seen) == _http_retry.MAX_RETRIES + 1
    # A wait longer than the cap is not slept: the 429 surfaces at once, as it
    # does for a 0.34 client, which has no retry at all.
    seen.clear()
    long = [httpx.Response(429, headers={"Retry-After": "3600"})]
    with pytest.raises(ValueError, match="HTTP 429"):
        _http.request_pack(_client(long, seen), "GET", "/v1/x")
    assert len(seen) == 1


def test_retry_after_parsing():
    assert _http_retry.parse_retry_after("7") == 7.0
    assert _http_retry.parse_retry_after("garbage") is None
    assert _http_retry.parse_retry_after("Thu, 01 Jan 1970 00:00:10 GMT", now=0) == 10.0
