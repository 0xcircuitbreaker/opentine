"""``caps.coord`` (0.47): ``tine task`` over HTTP against ``tine serve``.

The same compare-and-swap and fencing rules as a local repository, on the
server's clock; uniform 404 for a missing task, another tenant and a caller who
may not read; 403 for a reader who writes. The scale test here is the CI-sized
copy of ``scripts/coord_scale.py`` (1,000 tasks x 50 workers in full): zero
lost or duplicated claims, and a crashed holder's late ``done`` is refused.
"""

from __future__ import annotations

import json

import httpx
import pytest

from opentine.cli import main


@pytest.fixture
def remote(tmp_path, monkeypatch):
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
    from opentine.repository import _http

    identities = StaticTokenIdentityProvider({
        "w": Identity("w", "acme", ("writer",)), "r": Identity("r", "acme", ("reader",)),
        "o": Identity("x", "other", ("admin",)),
    })  # fmt: skip
    service = RemoteService(
        FilesystemObjectStore(tmp_path / "objects", LocalKeyProvider(b"k" * 32)),
        SQLiteBackend(tmp_path / "remote.sqlite3"),
        identities,
        RoleAuthorizationPolicy(),
    )
    app = RemoteApp(service, tmp_path / "state")

    def http(token: str | None = "w", **_kw) -> httpx.Client:
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        return httpx.Client(base_url="http://remote", transport=httpx.WSGITransport(app=app),
                            headers=headers)  # fmt: skip

    monkeypatch.setattr(_http, "client", lambda base, token, **kw: http(token))
    return service, http


def _tine(capsys, *argv) -> tuple[int, dict]:
    try:
        code = main(list(argv)) or 0
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else 1
    out = capsys.readouterr().out
    return code, json.loads(out.strip().splitlines()[-1]) if out.strip() else {}


REMOTE = ("--remote", "https://remote", "--tenant", "acme", "--token", "w", "--json")


def test_the_capability_and_the_cli_round_trip(remote, capsys):
    service, _http = remote
    assert service.capabilities()["coord"]["format"] == "opentine-coord/1"
    assert _tine(capsys, "task", "add", "build", "--title", "Build", *REMOTE)[0] == 0
    code, body = _tine(capsys, "task", "claim", "build", "--holder", "a", *REMOTE)
    assert code == 0 and body["task"]["fencing"] == 1 and body["task"]["holder"] == "a"
    code, body = _tine(capsys, "task", "claim", "build", "--holder", "b", *REMOTE)
    assert code == 1 and body["error"]["code"] == "held"
    code, _ = _tine(capsys, "task", "heartbeat", "build", "--holder", "a", "--fencing", "1",
                    *REMOTE)  # fmt: skip
    assert code == 0
    code, body = _tine(capsys, "task", "done", "build", "--holder", "a", "--fencing", "0",
                       *REMOTE)  # fmt: skip
    assert code == 1 and body["error"]["code"] == "stale"
    assert (
        _tine(capsys, "task", "done", "build", "--holder", "a", "--fencing", "1", *REMOTE)[0] == 0
    )
    code, body = _tine(capsys, "task", "list", *REMOTE)
    assert [row["status"] for row in body["tasks"]] == ["done"]
    code, body = _tine(capsys, "task", "add", "build", *REMOTE)
    assert code == 1 and body["error"]["code"] == "exists"


def test_every_move_is_an_audited_annotation_ref(remote):
    service, http = remote
    assert http().post("/v1/tenants/acme/coord/tasks", json={"task": "x"}).status_code == 201
    claimed = http().post("/v1/tenants/acme/coord/tasks/x/claim", json={"holder": "h"})
    assert claimed.status_code == 200
    oid = service.index.read_ref("acme", "coord/tasks/x")
    assert oid and oid.startswith("annotation:")
    from opentine.coord._store import history
    from opentine.remote._coord_http import CoordRepo

    versions = history(CoordRepo(service, None, "acme"), oid)
    assert [v["status"] for v in versions] == ["claimed", "open"]
    assert "coord/tasks/x" in http().get("/v1/tenants/acme/refs").json()["refs"]


def test_reads_and_writes_are_a_uniform_404_or_403(remote):
    _service, http = remote
    http().post("/v1/tenants/acme/coord/tasks", json={"task": "x"})
    missing = http().get("/v1/tenants/acme/coord/tasks/nope")
    other = http("o").get("/v1/tenants/acme/coord/tasks/x")
    nowhere = http("o").get("/v1/tenants/nobody/coord/tasks/x")
    assert missing.status_code == 404 and missing.json() == {"error": "not found"}
    assert (other.status_code, other.content) == (nowhere.status_code, nowhere.content)
    assert other.status_code == 404
    write = http("o").post("/v1/tenants/acme/coord/tasks/x/claim", json={"holder": "h"})
    assert (write.status_code, write.json()) == (404, {"error": "not found"})
    claim_missing = http().post("/v1/tenants/acme/coord/tasks/nope/claim", json={"holder": "h"})
    assert claim_missing.status_code == 404 and claim_missing.content == missing.content
    reader = http("r").post("/v1/tenants/acme/coord/tasks/x/claim", json={"holder": "h"})
    assert reader.status_code == 403
    assert http("r").get("/v1/tenants/acme/coord/tasks/x").status_code == 200
    assert http(None).get("/v1/tenants/acme/coord/tasks").status_code == 401
    bad = http().post("/v1/tenants/acme/coord/tasks/x/claim", json={"holder": "h", "ttl": "x"})
    assert bad.status_code == 400


def test_the_scaled_claim_test_loses_and_duplicates_nothing(remote):
    from opentine._cli_task_remote import RemoteTasks
    from opentine.coord import _scale

    _service, http = remote
    report = _scale.run(lambda: RemoteTasks(http(), "acme"), 100, 10, crash_every=5)
    assert report["lost"] == report["duplicated"] == report["stale_accepted"] == 0, report
    assert report["done"] == 100 and report["crashed"] > 0
    assert report["claims"] >= report["done"] + report["crashed"]
