"""0.55 code mirror refusals: push, git smart HTTP, archive, LFS, public-over-private;
unlink deletes; tenants are isolated."""

from __future__ import annotations

import shutil
import subprocess
import threading
from wsgiref.simple_server import make_server

import pytest

from opentine import _project
from opentine.remote import _mirror_store
from opentine.remote._http_server import ThreadingWSGIServer, TimeoutRequestHandler
from tests._mirror_fixture import call, fixture_repo, make_app, put_project

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="needs git on PATH")

T = "/v1/tenants/acme/project/"
PUSHES = [
    ("POST", "code/git-receive-pack", "", "mirror.push-refused"),
    ("GET", "code/info/refs", "service=git-receive-pack", "mirror.git-protocol-refused"),
    ("GET", "code/info/refs", "service=git-upload-pack", "mirror.git-protocol-refused"),
    ("POST", "code/git-upload-pack", "", "mirror.git-protocol-refused"),
    ("GET", "code/archive", "ref=main", "mirror.archive-refused"),
    ("GET", "code/archive/main.tar.gz", "", "mirror.archive-refused"),
    ("POST", "code/info/lfs/objects/batch", "", "mirror.lfs-refused"),
    ("PUT", "code/tree", "", "mirror.push-refused"),
    ("POST", "code/blob", "", "mirror.push-refused"),
    ("DELETE", "code/refs", "", "mirror.push-refused"),
]


@pytest.fixture
def mirrored(tmp_path):
    fixture_repo(tmp_path / "upstream")
    app = make_app(tmp_path)
    put_project(app)
    reply = call(app, "PUT", T + "mirror", {"url": (tmp_path / "upstream").as_uri()})
    assert reply.status == 200, reply.body
    return app, tmp_path


@pytest.mark.parametrize(("method", "path", "query", "code"), PUSHES)
def test_every_push_and_git_endpoint_is_refused(mirrored, method, path, query, code):
    app, _ = mirrored
    reply = call(app, method, T + path, query=query)
    assert reply.status == 403 and reply.json()["code"] == code
    hidden = call(app, method, T + path, query=query, token="other-admin")
    assert (hidden.status, hidden.json()) == (404, {"error": "not found"})


def test_a_real_git_push_and_clone_fail(mirrored):
    app, tmp_path = mirrored
    server = make_server("127.0.0.1", 0, app, server_class=ThreadingWSGIServer,
                         handler_class=TimeoutRequestHandler)  # fmt: skip
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/v1/tenants/acme/project/code"
        auth = ["-c", "http.extraHeader=Authorization: Bearer acme-writer"]
        env = {"GIT_TERMINAL_PROMPT": "0", "PATH": __import__("os").environ["PATH"]}
        push = subprocess.run(["git", "-C", str(tmp_path / "upstream"), *auth, "push", url,
                               "main"], capture_output=True, env=env, timeout=60)  # fmt: skip
        clone = subprocess.run(["git", *auth, "clone", url, str(tmp_path / "clone")],
                               capture_output=True, env=env, timeout=60)  # fmt: skip
    finally:
        server.shutdown()
        server.server_close()
    assert push.returncode != 0 and clone.returncode != 0
    assert not (tmp_path / "clone" / "README.md").exists()


def test_unlink_deletes_the_mirror_and_its_caches(mirrored):
    app, _ = mirrored
    root = app.service.objects.root
    place = _mirror_store.directory(root, "acme")
    assert (place / "git" / "HEAD").is_file() and (place / "search.sqlite3").is_file()
    assert call(app, "DELETE", T + "mirror", token="acme-reader").status == 403
    gone = call(app, "DELETE", T + "mirror")
    assert gone.status == 200 and gone.json() == {"unlinked": True}
    assert not place.exists()
    for path in ("mirror", "code/refs", "code/search"):
        reply = call(app, "GET", T + path, query="q=parse")
        assert (reply.status, reply.json()) == (404, {"error": "not found"})
    assert call(app, "DELETE", T + "mirror").status == 404


def test_tenants_are_isolated_with_a_uniform_404(mirrored):
    app, _ = mirrored
    for path in ("mirror", "code/refs", "code/tree", "code/blob", "code/raw", "code/history",
                 "code/compare", "code/search"):  # fmt: skip
        other = call(app, "GET", T + path, token="other-admin", query="q=parse")
        nowhere = call(app, "GET", f"/v1/tenants/no-such-x/project/{path}", token="other-admin")
        assert (other.status, other.body) == (nowhere.status, nowhere.body) == (
            404, b'{"error":"not found"}')  # fmt: skip
        mine = call(app, "GET", "/v1/tenants/other/project/" + path, token="other-admin")
        assert mine.status == 404  # the other tenant has no mirror of its own
    for method, path in (("PUT", "mirror"), ("POST", "mirror/sync"), ("DELETE", "mirror")):
        reply = call(app, method, T + path, {}, token="other-admin")
        assert (reply.status, reply.json()) == (404, {"error": "not found"})
    assert call(app, "GET", T + "code/refs", token=None).status == 401


def test_a_public_project_over_private_code_is_refused(tmp_path):
    fixture_repo(tmp_path / "upstream")
    app = make_app(tmp_path)
    put_project(app)
    reply = call(app, "PUT", T + "mirror", {"private": True})
    assert reply.status == 403 and reply.json()["code"] == "mirror.private-upstream"
    swap = call(app, "PUT", T + "mirror", {"url": "https://elsewhere.example/x.git"})
    assert swap.status == 403 and swap.json()["code"] == "mirror.locator"
    assert not _mirror_store.directory(app.service.objects.root, "acme").exists()


def test_local_upstreams_need_the_operator_switch(tmp_path):
    fixture_repo(tmp_path / "upstream")
    app = make_app(tmp_path, allow_local=False)
    put_project(app)
    reply = call(app, "PUT", T + "mirror", {"url": (tmp_path / "upstream").as_uri()})
    assert reply.status == 403 and reply.json()["code"] == "mirror.locator"


def test_a_private_project_links_by_commitment_and_never_shows_the_url(tmp_path):
    fixture_repo(tmp_path / "upstream")
    app = make_app(tmp_path)
    url, salt = (tmp_path / "upstream").as_uri(), bytes(range(16))
    locator = {"commitment": _project.commitment(url, salt)}
    put_project(app, visibility="private", locator=locator)
    wrong = call(app, "PUT", T + "mirror", {"url": url, "salt": "00" * 16})
    assert wrong.status == 403 and wrong.json()["code"] == "mirror.locator"
    linked = call(app, "PUT", T + "mirror", {"url": url, "salt": salt.hex()})
    assert linked.status == 200 and linked.json()["mirror"]["upstream"] == locator["commitment"]
    raw = call(app, "GET", T + "code/raw", query="path=README.md")
    assert raw.status == 200 and str(tmp_path) not in str(raw.headers)
    assert str(tmp_path) not in call(app, "GET", T + "mirror").body.decode()


def test_an_upstream_on_a_private_address_is_refused_before_git_runs(tmp_path):
    from opentine import _mirror_git

    for url in ("https://127.0.0.1/x.git", "https://169.254.169.254/x.git",
                "https://[::1]/x.git", "https://localhost/x.git"):  # fmt: skip
        try:
            _mirror_git.fetch(url, tmp_path / "m", allow_local=False, timeout=5, max_bytes=1)
        except _mirror_git.GitError as exc:
            assert exc.code in ("mirror.upstream-unverifiable", "mirror.upstream-unreachable")
        else:
            raise AssertionError(url)
        assert not (tmp_path / "m").exists()


def test_a_public_upstream_is_pinned_to_the_checked_address_without_redirects(monkeypatch):
    from opentine import _mirror_git

    answer = [(2, 1, 6, "", ("93.184.216.34", 443))]
    monkeypatch.setattr(_mirror_git.socket, "getaddrinfo", lambda *a, **k: answer)
    pin = _mirror_git._pinned("https://code.example/x.git", allow_private=False)
    assert pin == ("-c", "http.curloptResolve=code.example:443:93.184.216.34")
