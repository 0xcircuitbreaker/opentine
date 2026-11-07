"""0.43 ``POST ref-txn``: several ref moves applied all or none, gated on ``caps``.

The server advertises ``"ref_txn": true``; a client sends the transaction only
then, and an older server keeps getting one ``PUT /refs/<name>`` per ref.
Leases work over the remote the same way: a ``coord/tasks/*`` move is a CAS.
"""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from opentine import Run
from opentine.coord._store import swap
from opentine.graph import StepKind
from opentine.remote.app import RemoteApp
from opentine.remote.backend import FilesystemObjectStore, SQLiteBackend
from opentine.remote.interfaces import Identity
from opentine.remote.security import (
    LocalKeyProvider,
    RoleAuthorizationPolicy,
    StaticTokenIdentityProvider,
)
from opentine.remote.service import RemoteService
from opentine.repository import Repo
from opentine.repository import client as repository_client

URL = "https://remote.example/v1/tenants/acme"


def _remote(tmp_path: Path, monkeypatch, *, ref_txn: bool = True):
    identities = StaticTokenIdentityProvider(
        {
            "writer-token": Identity("writer", "acme", ("writer",)),
            "reader-token": Identity("reader", "acme", ("reader",)),
        }
    )
    objects = FilesystemObjectStore(tmp_path / "objects", LocalKeyProvider(b"k" * 32))
    index = SQLiteBackend(tmp_path / "remote.sqlite3")
    service = RemoteService(objects, index, identities, RoleAuthorizationPolicy())
    if not ref_txn:  # a 0.42 server: no ref_txn capability
        caps = {k: v for k, v in service.capabilities().items() if k != "ref_txn"}
        monkeypatch.setattr(service, "capabilities", lambda: caps)
    app = RemoteApp(service, tmp_path / "state")
    seen: list[httpx.Request] = []
    transport = httpx.WSGITransport(app=app)

    def session(*_args, token: str = "writer-token", **_kwargs):
        return httpx.Client(
            transport=transport,
            base_url="https://remote.example",
            headers={"authorization": f"Bearer {token}"},
            event_hooks={"request": [seen.append]},
        )

    monkeypatch.setattr(repository_client, "_client", session)
    return service, session, seen


def _run(name: str) -> Run:
    run = Run(id=name)
    run.add_step(StepKind.think, {"text": name})
    run.add_tag("demo")  # so the run has an annotation ref to push
    return run


def _txn(session, updates, token="writer-token"):
    with session(token=token) as client:
        return client.post("/v1/tenants/acme/ref-txn", json={"updates": updates})


def test_the_capability_is_advertised(tmp_path, monkeypatch):
    service, _, _ = _remote(tmp_path, monkeypatch)
    assert service.capabilities()["ref_txn"] is True


def test_push_uses_one_transaction_for_head_and_annotation(tmp_path, monkeypatch):
    service, _, seen = _remote(tmp_path, monkeypatch)
    origin = Repo.init(tmp_path / "origin")
    result = origin.put_run(_run("a"), ref="heads/main")
    repository_client.push(origin, URL, ref="heads/main")
    paths = [(r.method, r.url.path) for r in seen]
    assert ("POST", "/v1/tenants/acme/ref-txn") in paths
    assert not any(method == "PUT" for method, _ in paths)
    refs = service.index.list_refs("acme")
    assert refs["heads/main"] == result.run_id
    assert refs["annotations/" + result.run_id[11:]] == result.annotation_id


def test_an_old_server_still_gets_one_put_per_ref(tmp_path, monkeypatch):
    service, _, seen = _remote(tmp_path, monkeypatch, ref_txn=False)
    origin = Repo.init(tmp_path / "origin")
    run_id = origin.put_run(_run("a"), ref="heads/main").run_id
    repository_client.push(origin, URL, ref="heads/main")
    methods = [r.method for r in seen if "/refs/" in r.url.path]
    assert methods == ["PUT", "PUT"]  # the head, then its annotation
    assert not any(r.url.path.endswith("/ref-txn") for r in seen)
    assert service.index.list_refs("acme")["heads/main"] == run_id


def test_a_transaction_with_one_stale_ref_changes_nothing(tmp_path, monkeypatch):
    service, session, _ = _remote(tmp_path, monkeypatch)
    origin = Repo.init(tmp_path / "origin")
    one = origin.put_run(_run("a"), ref="heads/main").run_id
    two = origin.put_run(_run("b"), ref="heads/other").run_id
    repository_client.push(origin, URL, ref="heads/main")
    repository_client.push(origin, URL, ref="heads/other")
    before = service.index.list_refs("acme")
    stale = [
        {"name": "heads/main", "new": two, "expected_old": one},
        {"name": "heads/other", "new": one, "expected_old": one},  # really at `two`
        {"name": "tags/new", "new": one, "expected_old": None},
    ]
    response = _txn(session, stale)
    assert response.status_code == 409 and response.json() == {"updated": False}
    assert service.index.list_refs("acme") == before
    stale[1]["expected_old"] = two
    assert _txn(session, stale).status_code == 200
    after = service.index.list_refs("acme")
    assert (after["heads/main"], after["heads/other"], after["tags/new"]) == (two, one, one)


def test_a_transaction_is_checked_like_put(tmp_path, monkeypatch):
    service, session, _ = _remote(tmp_path, monkeypatch)
    origin = Repo.init(tmp_path / "origin")
    run_id = origin.put_run(_run("a"), ref="heads/main").run_id
    repository_client.push(origin, URL, ref="heads/main")
    move = {"name": "tags/x", "new": run_id, "expected_old": None}
    assert _txn(session, [move], token="reader-token").status_code == 403
    missing = {"name": "tags/y", "new": "run:sha256:" + "0" * 64, "expected_old": None}
    assert _txn(session, [move, missing]).status_code == 404
    assert "tags/x" not in service.index.list_refs("acme")  # nothing applied
    assert _txn(session, [move, move]).status_code == 400  # each ref once
    assert _txn(session, []).status_code == 400


def test_a_lease_claim_over_the_remote_is_a_compare_and_swap(tmp_path, monkeypatch):
    """Two claimants race on the remote: the second CAS from the same version loses."""
    service, session, _ = _remote(tmp_path, monkeypatch)
    local = Repo.init(tmp_path / "local")
    base = swap(local, "coord/tasks/t", "task", {"task": "t", "fencing": 0}, None)
    service.install_pack(service.authenticate({"authorization": "Bearer writer-token"}),
                         "acme", local.pack())  # fmt: skip
    assert _txn(session, [{"name": "coord/tasks/t", "new": base, "expected_old": None}]).is_success
    claims = []
    for holder in ("alice", "bob"):
        payload = {"coord": "opentine-coord/1", "kind": "task", "previous_id": base,
                   "value": {"task": "t", "fencing": 1, "holder": holder}}  # fmt: skip
        claims.append(local.put("annotation", payload))
    service.install_pack(service.authenticate({"authorization": "Bearer writer-token"}),
                         "acme", local.pack())  # fmt: skip
    codes = [
        _txn(session, [{"name": "coord/tasks/t", "new": oid, "expected_old": base}]).status_code
        for oid in claims
    ]
    assert codes == [200, 409]
    assert service.index.list_refs("acme")["coord/tasks/t"] == claims[0]


@pytest.mark.parametrize("body", [{"updates": "x"}, {"updates": [{"name": 1}]}, {"other": 1}])
def test_malformed_transactions_are_refused(tmp_path, monkeypatch, body):
    _, session, _ = _remote(tmp_path, monkeypatch)
    with session() as client:
        assert client.post("/v1/tenants/acme/ref-txn", json=body).status_code == 400
