"""0.52: ``tine tenant import --remote`` is all or nothing.

One export (two runs, an attestation, a purged blob's tombstone, a Review with
a gate decision, a project manifest) is imported into a fresh ``tine serve``
once per seed, with one fault injected: a server write that fails, a server
that dies at a write (and recovers on restart, as the next import does), or a
connection that drops at the client's k-th request. Afterwards the target is
either exactly as before or fully imported, never in between, and importing
again completes it. ``OPENTINE_STRESS_IMPORT_SEEDS`` (200 in the nightly job)
sets the number of seeds.
"""

from __future__ import annotations

import os
import random

import httpx
import pytest

from opentine import _tenant_move
from opentine.remote import _project_store, _review_store
from opentine.remote import _tenant_import_apply as apply
from tests.test_050_leave_service import TOKEN, _export, _seed_tenant, _serve
from tests.test_050_leave_service import services as services  # noqa: F401 - the fixture

SEEDS = int(os.environ.get("OPENTINE_STRESS_IMPORT_SEEDS", "24"))


class Crash(BaseException):
    """The server process dies here: nothing after it runs."""


def _state(app) -> dict:
    service = app.service
    root = service.objects.root
    reviews = {rid: (_review_store.versions(root, "acme", rid),
                     _review_store.decisions(root, "acme", rid))
               for rid in _review_store.names(root, "acme")}  # fmt: skip
    project = [_project_store.read(root, "acme", s)
               for s in range(_project_store.count(root, "acme"))]  # fmt: skip
    return {"refs": service.index.list_refs("acme"), "reviews": reviews, "project": project}


def _import(source, url):
    return _tenant_move.import_remote(source, url, "acme", TOKEN, allow_insecure=True,
                                      timeout=30)  # fmt: skip


class _Faults:
    def __init__(self, mode: str, at: int):
        self.mode, self.at, self.seen, self.dead = mode, at, 0, False

    def server(self, step: str) -> None:
        if self.dead:
            raise Crash(step)
        self.seen += 1
        if self.seen == self.at:
            if self.mode == "crash":
                self.dead = True
                raise Crash(step)
            raise OSError(f"injected fault at {step}")


def test_a_faulted_import_leaves_the_target_unchanged_or_fully_imported(
    services, tmp_path, monkeypatch, capsys
):
    _seed_tenant(services, tmp_path, monkeypatch, capsys)
    _export(monkeypatch, capsys, services, "old", tmp_path / "out")
    source = tmp_path / "out"

    # A clean import, counting server writes and client requests.
    counter = _Faults("count", 0)
    monkeypatch.setattr(apply, "FAULT", counter.server)
    sends = []
    real_send = httpx.Client.send
    counted = lambda self, *a, **k: sends.append(1) or real_send(self, *a, **k)  # noqa: E731
    monkeypatch.setattr(httpx.Client, "send", counted)
    _import(source, services["new"])
    full, writes, requests = _state(services["new_app"]), counter.seen, len(sends)
    assert full["refs"] and full["reviews"] and full["project"] and writes > 4

    outcomes = set()
    for seed in range(SEEDS):
        rng = random.Random(seed)
        mode = rng.choice(["error", "crash", "network"])
        httpd, url, app = _serve(tmp_path / f"target-{seed}")
        try:
            empty = _state(app)
            faults = _Faults(mode, rng.randrange(1, writes + 1))
            monkeypatch.setattr(apply, "FAULT", None if mode == "network" else faults.server)
            drop = rng.randrange(1, requests + 1)
            calls = []

            def send(self, *args, _drop=drop, _calls=calls, _mode=mode, **kwargs):
                _calls.append(1)
                if _mode == "network" and len(_calls) == _drop:
                    raise httpx.ConnectError("injected: connection dropped")
                return real_send(self, *args, **kwargs)

            monkeypatch.setattr(httpx.Client, "send", send)
            try:
                _import(source, url)
            except Exception:  # noqa: BLE001 - the fault surfaces as any client error
                pass
            monkeypatch.setattr(apply, "FAULT", None)  # restart: the next import recovers
            monkeypatch.setattr(httpx.Client, "send", real_send)
            apply.recover(app.service.index, app.service.objects.root, "acme")
            after = _state(app)
            assert after in (empty, full), (seed, mode, faults.at, drop)
            outcomes.add("full" if after == full else "unchanged")
            assert not list((app.service.objects.root / apply.IMPORTS).rglob("*.json")), seed
            _import(source, url)  # importing again completes it ...
            assert _state(app) == full, seed
            _import(source, url)  # ... and a repeat changes nothing
            assert _state(app) == full, seed
        finally:
            httpd.shutdown()
    if SEEDS >= 12:
        assert outcomes == {"full", "unchanged"}, outcomes


def test_a_conflicting_ref_refuses_the_whole_import(services, tmp_path, monkeypatch, capsys):
    from opentine.repository import Repo
    from opentine.repository import client as repository_client

    runs, _ = _seed_tenant(services, tmp_path, monkeypatch, capsys)
    _export(monkeypatch, capsys, services, "old", tmp_path / "out")
    app = services["new_app"]
    work = Repo.open(tmp_path / "work")
    repository_client.push(work, services["new"], tenant="acme", token=TOKEN, ref="heads/beta",
                           remote_ref="heads/alpha", allow_insecure=True)  # fmt: skip
    before = _state(app)
    with pytest.raises(ValueError, match="already points elsewhere"):
        _import(tmp_path / "out", services["new"])
    assert _state(app) == before


def test_the_server_refuses_a_conflict_with_nothing_changed(services, tmp_path, monkeypatch,
                                                            capsys):  # fmt: skip
    """A ref created between the client's check and the swap: 409, nothing visible."""
    _seed_tenant(services, tmp_path, monkeypatch, capsys)
    _export(monkeypatch, capsys, services, "old", tmp_path / "out")
    app = services["new_app"]
    real = app.service.index.update_refs

    def raced(tenant, rows):  # another writer takes a name first
        name, new, _ = rows[0]
        assert real(tenant, [(name, new, None)])
        return real(tenant, rows)

    monkeypatch.setattr(app.service.index, "update_refs", raced)
    with pytest.raises(ValueError, match="nothing was imported"):
        _import(tmp_path / "out", services["new"])
    state = _state(app)
    assert len(state["refs"]) == 1 and state["reviews"] == {} and state["project"] == []


def test_an_old_server_without_the_capability_is_refused(services, tmp_path, monkeypatch, capsys):
    from opentine.remote import _tenant_import_http

    _seed_tenant(services, tmp_path, monkeypatch, capsys)
    _export(monkeypatch, capsys, services, "old", tmp_path / "out")
    monkeypatch.setattr(_tenant_import_http, "capabilities", lambda service: {})
    with pytest.raises(ValueError, match="caps.tenant_import"):
        _import(tmp_path / "out", services["new"])
    assert services["new_app"].service.index.list_refs("acme") == {}


@pytest.mark.parametrize(
    "body",
    [
        {"reviews": [{"versions": "x"}]},
        {"reviews": ["x"]},
        {"reviews": [{"versions": [1]}]},
        {"reviews": {"a": 1}},
        {"project": "x"},
        {"project": [1]},
        {"refs": ["x"]},
        {"refs": {"heads/a": 1}},
    ],
)
def test_a_malformed_import_request_is_a_400_with_nothing_changed(services, body):
    app = services["new_app"]
    before = _state(app)
    response = httpx.post(services["new"] + "/v1/tenants/acme/import", json=body,
                          headers={"Authorization": f"Bearer {TOKEN}"})  # fmt: skip
    assert response.status_code == 400, response.text
    assert _state(app) == before


def test_a_malformed_review_decision_list_is_a_400(services, tmp_path, monkeypatch, capsys):
    _seed_tenant(services, tmp_path, monkeypatch, capsys)
    _export(monkeypatch, capsys, services, "old", tmp_path / "out")
    reviews = _tenant_move._files(tmp_path / "out")
    assert reviews
    app = services["new_app"]
    before = _state(app)
    for decisions in ("abc", [1], [{"x": 1}], {"a": 1}):
        bad = [{**reviews[0], "decisions": decisions}]
        response = httpx.post(services["new"] + "/v1/tenants/acme/import",
                              json={"reviews": bad},
                              headers={"Authorization": f"Bearer {TOKEN}"})  # fmt: skip
        assert response.status_code == 400, (decisions, response.text)
    assert _state(app) == before
