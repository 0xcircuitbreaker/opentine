"""0.46: hosted-beta caps on ``tine serve`` -- object reads, closures, lists, shares, log, admin."""

from __future__ import annotations

import io
import json
from pathlib import Path

from opentine import Run
from opentine.graph import StepKind
from opentine.remote import Identity, LocalKeyProvider, StaticTokenIdentityProvider, server
from opentine.remote._shares import ShareStore
from opentine.repository import Repo
from opentine.repository.pack import inspect_pack

KEY = b"k" * 32


def _app(tmp_path: Path):
    identities = StaticTokenIdentityProvider(
        {
            "writer-token": Identity("alice", "acme", ("writer",)),
            "reader-token": Identity("rita", "acme", ("reader",)),
            "admin-token": Identity("root", "acme", ("admin",)),
            "other-token": Identity("eve", "other", ("admin",)),
        }
    )
    return server.reference_app(
        tmp_path / "remote", identities=identities, keys=LocalKeyProvider(KEY)
    )


def _call(app, method, path, body=b"", token="writer-token", query="", addr="10.0.0.1", **hdr):
    state: dict = {}

    def start_response(status, headers):
        state["status"], state["headers"] = status, dict(headers)

    environ = {
        "CONTENT_LENGTH": str(len(body)),
        "CONTENT_TYPE": "application/json",
        "PATH_INFO": path,
        "QUERY_STRING": query,
        "REMOTE_ADDR": addr,
        "REQUEST_METHOD": method,
        "wsgi.input": io.BytesIO(body),
    }
    if token:
        environ["HTTP_AUTHORIZATION"] = f"Bearer {token}"
    environ.update({f"HTTP_{k.upper().replace('-', '_')}": v for k, v in hdr.items()})
    out = b"".join(app(environ, start_response))
    return state["status"], state["headers"], out


def _push(app, tmp_path: Path, label: str = "one") -> tuple[str, Repo]:
    local = Repo.init(tmp_path / f"local-{label}")
    run = Run(id=label, metadata={"label": label})
    run.add_step(StepKind.done, {"text": label * 50})
    stored = local.put_run(run)
    service = app.service
    writer = service.authenticate({"authorization": "Bearer writer-token"})
    service.install_pack(writer, "acme", local.pack())
    assert service.update_ref(writer, "acme", f"heads/{label}", stored.run_id, None)
    return stored.run_id, local


def test_capabilities_advertise_every_hosted_cap(tmp_path):
    caps = _app(tmp_path).service.capabilities()
    for name in ("object_read_http", "run_closure", "list", "search", "share", "log_http", "admin"):
        assert name in caps, name
    # 0.45 keys are untouched: old clients read the same fields.
    assert caps["protocol"] == "opentine-remote/1" and caps["pack_format"] == "TINEPACK3"


def test_object_reads_are_private_cacheable_and_a_uniform_404(tmp_path):
    app = _app(tmp_path)
    run_id, _ = _push(app, tmp_path)
    status, headers, body = _call(
        app, "GET", f"/v1/tenants/acme/objects/{run_id}", token="reader-token"
    )
    assert status == "200 OK" and body
    assert (
        headers["Cache-Control"].startswith("private") and "public" not in headers["Cache-Control"]
    )
    assert headers["Vary"] == "Authorization" and headers["ETag"] == f'"{run_id}"'
    again = _call(app, "GET", f"/v1/tenants/acme/objects/{run_id}", token="reader-token",
                  **{"If-None-Match": f'"{run_id}"'})  # fmt: skip
    assert again[0] == "304 Not Modified"
    missing = "run:sha256:" + "0" * 64
    absent = _call(app, "GET", f"/v1/tenants/acme/objects/{missing}")
    cross = _call(app, "GET", f"/v1/tenants/acme/objects/{run_id}", token="other-token")
    bogus = _call(app, "GET", "/v1/tenants/acme/objects/nonsense")
    assert absent[0] == cross[0] == bogus[0] == "404 Not Found"
    assert absent[2] == cross[2] == bogus[2]


def test_run_closure_negotiates_one_pack_with_lazy_blobs(tmp_path):
    app = _app(tmp_path)
    run_id, _ = _push(app, tmp_path)
    url = f"/v1/tenants/acme/runs/{run_id}/closure"
    status, headers, full = _call(app, "POST", url, b"{}", token="reader-token")
    assert status == "200 OK"
    _, packed, _ = inspect_pack(full)
    oids = [oid for oid, _ in packed]
    assert run_id in oids and headers["OpenTine-Lazy-Blobs"] == "0"
    _, headers, lazy = _call(app, "POST", url, b'{"lazy_blobs": true}', token="reader-token")
    _, kept, shallow = inspect_pack(lazy)
    blobs = [oid for oid in oids if oid.startswith("blob:")]
    assert blobs and not any(oid.startswith("blob:") for oid, _ in kept)
    assert int(headers["OpenTine-Lazy-Blobs"]) == len(blobs) and set(blobs) <= set(shallow)
    for blob in blobs:  # each lazy blob is read, and authorized, on its own
        assert (
            _call(app, "GET", f"/v1/tenants/acme/objects/{blob}", token="reader-token")[0]
            == "200 OK"
        )
        assert (
            _call(app, "GET", f"/v1/tenants/acme/objects/{blob}", token="other-token")[0]
            == "404 Not Found"
        )
    assert _call(app, "POST", url, b"{}", token="other-token")[0] == "404 Not Found"


def test_lists_are_cursor_paginated(tmp_path):
    app = _app(tmp_path)
    runs = sorted(_push(app, tmp_path, label)[0] for label in ("a", "b", "c"))
    seen, cursor = [], None
    while True:
        query = "limit=2" + (f"&cursor={cursor}" if cursor else "")
        status, _, body = _call(
            app, "GET", "/v1/tenants/acme/list/runs", token="reader-token", query=query
        )
        assert status == "200 OK"
        data = json.loads(body)
        seen += data["items"]
        cursor = data["next_cursor"]
        if not cursor:
            break
    assert seen == runs
    _, _, refs = _call(app, "GET", "/v1/tenants/acme/list/refs", token="reader-token")
    assert [row["name"] for row in json.loads(refs)["items"]] == ["heads/a", "heads/b", "heads/c"]
    assert _call(app, "GET", "/v1/tenants/acme/list/runs", query="limit=0")[0] == "400 Bad Request"


def test_shares_are_scoped_expiring_revocable_and_throttled(tmp_path):
    app = _app(tmp_path)
    run_id, _ = _push(app, tmp_path)
    other, _ = _push(app, tmp_path, "two")
    assert _call(app, "POST", "/v1/tenants/acme/shares", json.dumps({"run": run_id}).encode(),
                 token="reader-token")[0] == "404 Not Found"  # fmt: skip
    status, _, body = _call(app, "POST", "/v1/tenants/acme/shares",
                            json.dumps({"run": run_id, "ttl": 3600}).encode())  # fmt: skip
    assert status == "201 Created"
    created = json.loads(body)
    token = created["token"]
    stored = (tmp_path / "remote" / "shares.json").read_text()
    assert token not in stored  # only its digest is kept
    status, headers, meta = _call(app, "GET", f"/v1/share/{token}", token=None)
    assert status == "200 OK" and json.loads(meta)["run"] == run_id
    assert _call(app, "POST", f"/v1/share/{token}/closure", b"{}", token=None)[0] == "200 OK"
    assert _call(app, "GET", f"/v1/share/{token}/objects/{run_id}", token=None)[0] == "200 OK"
    outside = _call(app, "GET", f"/v1/share/{token}/objects/{other}", token=None)
    unknown = _call(app, "GET", "/v1/share/tine_share_" + "A" * 43, token=None, addr="10.0.0.2")
    assert outside[0] == unknown[0] == "404 Not Found" and outside[2] == unknown[2]
    _, _, listed = _call(app, "GET", "/v1/tenants/acme/shares")
    assert json.loads(listed)["shares"][0]["state"] == "active" and "token" not in listed.decode()
    assert _call(app, "DELETE", f"/v1/tenants/acme/shares/{created['id']}")[0] == "200 OK"
    assert (
        _call(app, "GET", f"/v1/share/{token}", token=None, addr="10.0.0.3")[0] == "404 Not Found"
    )
    for _ in range(6):
        _call(app, "GET", "/v1/share/nope", token=None, addr="10.9.9.9")
    assert (
        _call(app, "GET", "/v1/share/nope", token=None, addr="10.9.9.9")[0]
        == "429 Too Many Requests"
    )


def test_share_expiry(tmp_path):
    clock = [1000.0]
    store = ShareStore(tmp_path / "s.json", clock=lambda: clock[0])
    token, row = store.create("acme", "run:sha256:" + "1" * 64, "alice", ttl=60)
    assert store.resolve(token)["id"] == row["id"]
    clock[0] += 61
    assert store.resolve(token) is None and store.list("acme")[0]["state"] == "expired"


def test_admin_stats_and_log_entries(tmp_path):
    app = _app(tmp_path)
    _push(app, tmp_path)
    assert _call(app, "GET", "/v1/tenants/acme/admin/stats")[0] == "404 Not Found"
    status, _, body = _call(app, "GET", "/v1/tenants/acme/admin/stats", token="admin-token")
    assert status == "200 OK" and json.loads(body)["refs"] == 1
    status, _, body = _call(app, "GET", "/v1/tenants/acme/log/entries", token="reader-token")
    if status == "200 OK":
        items = json.loads(body)["items"]
        assert all(json.loads(item["entry"])["tenant"] == "acme" for item in items)
    else:
        assert status == "404 Not Found"


def test_search_over_http_matches_run_text(tmp_path):
    app = _app(tmp_path)
    alpha, _ = _push(app, tmp_path, "alpha")
    _push(app, tmp_path, "beta")
    body = json.dumps({"text": "ALPHA"}).encode()
    status, _, out = _call(app, "POST", "/v1/tenants/acme/search", body, token="reader-token")
    assert status == "200 OK" and json.loads(out)["objects"] == [alpha]
    bad = json.dumps({"text": "x" * 300}).encode()
    assert _call(app, "POST", "/v1/tenants/acme/search", bad)[0] == "400 Bad Request"


def test_a_live_share_cannot_reset_the_guess_throttle_and_never_leaks(tmp_path):
    app = _app(tmp_path)
    run_id, _ = _push(app, tmp_path)
    other, _ = _push(app, tmp_path, "two")
    _, _, body = _call(app, "POST", "/v1/tenants/acme/shares", json.dumps({"run": run_id}).encode())
    token = json.loads(body)["token"]
    addr = "10.7.7.7"
    for _ in range(6):  # guesses interleaved with valid reads still lock the client out
        _call(app, "GET", f"/v1/share/{token}", token=None, addr=addr)
        _call(app, "GET", f"/v1/share/{token}/objects/{other}", token=None, addr=addr)
    status, headers, _ = _call(app, "GET", f"/v1/share/{token}", token=None, addr=addr)
    assert status == "429 Too Many Requests"
    for path in (f"/v1/share/{token}", f"/v1/share/{token}/objects/{run_id}"):
        status, headers, _ = _call(app, "GET", path, token=None, addr="10.7.7.8")
        assert status == "200 OK" and headers["Referrer-Policy"] == "no-referrer"
    # A share's haves only count inside its run: a tenant oid outside it changes nothing.
    plain = _call(app, "POST", f"/v1/share/{token}/closure", b"{}", token=None, addr="10.7.7.9")
    probe = json.dumps({"haves": [other]}).encode()
    probed = _call(app, "POST", f"/v1/share/{token}/closure", probe, token=None, addr="10.7.7.9")
    assert plain[2] == probed[2]


def test_the_access_log_redacts_share_tokens():
    from opentine.remote._http_server import _SHARE_PATH

    path = _SHARE_PATH.sub("/v1/share/<token>", "/v1/share/tine_share_abc/objects/x")
    assert path == "/v1/share/<token>/objects/x"
