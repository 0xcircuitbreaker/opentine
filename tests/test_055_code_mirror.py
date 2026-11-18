"""0.55 code mirror: a fixture repo served by ``tine serve --mirror`` has the documented shapes."""

from __future__ import annotations

import base64

import pytest

from opentine import _mirror_state
from opentine.remote import _mirror_store
from tests._mirror_fixture import UPSTREAM, call, fixture_repo, make_app, put_project, schema_errors

C = "/v1/tenants/acme/project/code/"


@pytest.fixture
def mirrored(tmp_path):
    commits = fixture_repo(tmp_path / "upstream")
    app = make_app(tmp_path)
    put_project(app)
    linked = call(app, "PUT", "/v1/tenants/acme/project/mirror",
                  {"url": (tmp_path / "upstream").as_uri()})  # fmt: skip
    assert linked.status == 200, linked.body
    return app, commits, tmp_path


def _label_ok(found: dict) -> None:
    mirror = found["mirror"]
    assert mirror["upstream"] == UPSTREAM and mirror["computed_by"] == "host"
    assert mirror["label"] == _mirror_state.LABEL and mirror["synced_at"]
    assert mirror["status"] == "synced"


def test_the_mirror_is_off_unless_turned_on(tmp_path):
    from opentine.remote import LocalKeyProvider, StaticTokenIdentityProvider, server
    from tests._mirror_fixture import TOKENS

    app = server.reference_app(tmp_path / "r", identities=StaticTokenIdentityProvider(TOKENS),
                               keys=LocalKeyProvider(b"k" * 32))  # fmt: skip
    assert "mirror" not in app.service.capabilities()["project"]
    assert call(app, "GET", C + "refs").status == 404
    assert call(app, "GET", "/v1/tenants/acme/project/mirror").status == 404


def test_caps_publish_the_sync_spec(tmp_path):
    caps = make_app(tmp_path).service.capabilities()
    spec = caps["project"]["mirror"]
    assert spec["sync"]["webhook"] == "project/mirror/sync" and spec["sync"]["poll_seconds"] > 0
    assert {"max_repo_bytes", "max_refs", "max_blob_bytes"} <= set(spec["limits"])
    assert {"push", "receive-pack", "archive", "lfs"} <= set(spec["refuses"])
    assert spec["computed_by"] == "host" and "mirror" not in caps


def test_link_records_a_host_statement_mirror_state(mirrored):
    app, commits, _ = mirrored
    status = call(app, "GET", "/v1/tenants/acme/project/mirror", token="acme-reader").json()
    assert schema_errors("MirrorStatus", status) == []
    state = status["state"]
    _mirror_state.consistent(_mirror_state.body(state))
    assert state["refs"]["refs/heads/main"] == commits["second"]
    assert state["refs"]["refs/tags/v1"] == commits["first"]
    assert "signature" not in state  # the host never signs as a user


def test_refs_tree_blob_raw_are_the_documented_shapes(mirrored):
    app, commits, _ = mirrored
    refs = call(app, "GET", C + "refs", token="acme-reader").json()
    assert schema_errors("CodeRefs", refs) == [] and refs["default_branch"] == "main"
    assert refs["refs"]["refs/heads/feature"] == commits["feature"]
    _label_ok(refs)
    tree = call(app, "GET", C + "tree", query="ref=main").json()
    assert schema_errors("CodeTree", tree) == [] and tree["commit"] == commits["second"]
    assert {e["name"]: e["type"] for e in tree["entries"]} == {
        "README.md": "blob", "data.bin": "blob", "src": "tree"}  # fmt: skip
    sub = call(app, "GET", C + "tree", query="ref=feature&path=src").json()
    assert [e["path"] for e in sub["entries"]] == ["src/lexer.py", "src/parser.py"]
    blob = call(app, "GET", C + "blob", query="path=README.md").json()
    assert schema_errors("CodeBlob", blob) == [] and blob["encoding"] == "utf-8"
    assert blob["content"] == "# App\n\nThe fixture app.\n" and not blob["truncated"]
    binary = call(app, "GET", C + "blob", query="path=data.bin").json()
    assert binary["encoding"] == "base64"
    assert base64.b64decode(binary["content"]) == bytes(range(256))
    raw = call(app, "GET", C + "raw", query="ref=v1&path=src/parser.py")
    assert raw.status == 200 and raw.body.startswith(b"def parse_tokens")
    assert raw.headers["Content-Type"] == "application/octet-stream"
    assert raw.headers["X-OpenTine-Upstream"] == UPSTREAM
    assert raw.headers["X-OpenTine-Computed-By"] == "host"
    assert raw.headers["X-OpenTine-Synced-At"]


def test_history_compare_and_search(mirrored):
    app, commits, _ = mirrored
    history = call(app, "GET", C + "history", query="ref=feature").json()
    assert schema_errors("CodeHistory", history) == []
    assert [c["oid"] for c in history["commits"]] == [
        commits["feature"], commits["second"], commits["first"]]  # fmt: skip
    assert history["next_cursor"] is None and history["commits"][0]["subject"] == "Add a lexer"
    only = call(app, "GET", C + "history", query="path=data.bin").json()
    assert [c["oid"] for c in only["commits"]] == [commits["second"]]
    compare = call(app, "GET", C + "compare", query="base=main&head=feature").json()
    assert schema_errors("CodeCompare", compare) == []
    assert (compare["ahead_by"], compare["behind_by"]) == (1, 0)
    assert compare["files"] == [{"status": "A", "path": "src/lexer.py"}]
    found = call(app, "GET", C + "search", query="q=parse_tokens").json()
    assert schema_errors("CodeSearch", found) == [] and found["commit"] == commits["second"]
    assert found["hits"][0]["path"] == "src/parser.py" and found["hits"][0]["line"] == 1
    _label_ok(found)


@pytest.mark.parametrize("query", ["ref=nope", "path=missing.txt", "ref=--upload-pack=x",
                                   "path=../etc/passwd", "ref=main..feature"])  # fmt: skip
def test_unknown_refs_and_paths_are_the_uniform_404(mirrored, query):
    app, _, _ = mirrored
    reply = call(app, "GET", C + "blob", query=query)
    assert (reply.status, reply.json()) == (404, {"error": "not found"})


def test_a_blob_over_the_limit_is_not_served(tmp_path):
    fixture_repo(tmp_path / "upstream")
    app = make_app(tmp_path, max_blob_bytes=16)
    put_project(app)
    call(app, "PUT", "/v1/tenants/acme/project/mirror", {"url": (tmp_path / "upstream").as_uri()})
    blob = call(app, "GET", C + "blob", query="path=data.bin").json()
    assert blob["truncated"] and blob["content"] is None and blob["size"] == 256
    raw = call(app, "GET", C + "raw", query="path=data.bin")
    assert raw.status == 403 and raw.json()["code"] == "mirror.limit-exceeded"


def test_an_upstream_over_the_size_limit_pauses_the_mirror(tmp_path):
    fixture_repo(tmp_path / "upstream")
    app = make_app(tmp_path, max_repo_bytes=1)
    put_project(app)
    linked = call(app, "PUT", "/v1/tenants/acme/project/mirror",
                  {"url": (tmp_path / "upstream").as_uri()}).json()  # fmt: skip
    assert linked["state"]["status"] == "paused"
    assert linked["state"]["reasons"] == ["mirror.limit-exceeded"]
    assert call(app, "GET", C + "refs").status == 404


def test_webhook_sync_honours_the_interval_and_polling_picks_up_new_commits(mirrored):
    app, _, tmp_path = mirrored
    too_soon = call(app, "POST", "/v1/tenants/acme/project/mirror/sync")
    assert too_soon.status == 429 and too_soon.json()["code"] == "mirror.too-soon"
    assert int(too_soon.headers["Retry-After"]) >= 1
    assert call(app, "POST", "/v1/tenants/acme/project/mirror/sync",
                token="acme-reader").status == 403  # fmt: skip
    from tests._mirror_fixture import git

    (tmp_path / "upstream" / "NEW.md").write_text("new\n")
    git(tmp_path / "upstream", "add", ".")
    git(tmp_path / "upstream", "commit", "-q", "-m", "New file", when=3)
    head = git(tmp_path / "upstream", "rev-parse", "HEAD")
    root, cfg = app.service.objects.root, app.service.mirror
    state = _mirror_store.state_of(root, "acme")
    later = _mirror_store._epoch(state["synced_at"]) + cfg["poll_seconds"]
    assert _mirror_store.due(root, cfg, later - 1) == []
    assert _mirror_store.poll(root, cfg, later) == ["acme"]
    assert call(app, "GET", C + "refs").json()["refs"]["refs/heads/main"] == head
