"""0.77: ``GET /v1/tenants/<t>/tail``: live tail over SSE with limits, resume and backpressure."""

from __future__ import annotations

import io
import itertools
import json
from pathlib import Path

from opentine import Run, _schemas
from opentine.graph import StepKind
from opentine.remote import Identity, LocalKeyProvider, StaticTokenIdentityProvider, server
from opentine.remote._tail_http import TailLimits, limits
from opentine.repository import Repo


def _app(tmp_path: Path):
    identities = StaticTokenIdentityProvider(
        {
            "writer-token": Identity("alice", "acme", ("writer",)),
            "reader-token": Identity("rita", "acme", ("reader",)),
            "other-token": Identity("eve", "other", ("admin",)),
            "scoped-token": Identity(
                "ci",
                "acme",
                ("reader",),
                {"opentine_scope": {"token": "t1", "access": "read", "refs": ["heads/ci/"]}},
            ),
        }
    )
    app = server.reference_app(
        tmp_path / "remote", identities=identities, keys=LocalKeyProvider(b"k" * 32)
    )
    ticks = itertools.count()
    # An injected clock: each reading is one "second" later, so a stream ends after
    # a few loops and never waits on real time (heartbeat 0: no sleeping).
    app.tail_clock = lambda: float(next(ticks))
    app.stream_seconds, app.heartbeat_seconds, app.tail_send_seconds = 40.0, 0.0, 100.0
    return app


def _push(app, tmp_path: Path, steps: int, ref: str = "heads/main", run: Run | None = None) -> Run:
    local = Repo.init(tmp_path / f"local-{steps}")
    run = run or Run(id="tail0001")
    for index in range(len(run.steps), steps):
        run.add_step(StepKind.model, {"text": str(index)}, {"text": "ok"})
    stored = local.put_run(run)
    service = app.service
    writer = service.authenticate({"authorization": "Bearer writer-token"})
    service.install_pack(writer, "acme", local.pack())
    old = service.index.list_refs("acme").get(ref)
    assert service.update_ref(writer, "acme", ref, stored.run_id, old, force=True)
    return run


def _get(app, query: str = "", token: str = "reader-token", tenant: str = "acme", **headers):
    state: dict = {}
    environ = {
        "CONTENT_LENGTH": "0",
        "HTTP_AUTHORIZATION": f"Bearer {token}",
        "PATH_INFO": f"/v1/tenants/{tenant}/tail",
        "QUERY_STRING": query,
        "REQUEST_METHOD": "GET",
        "wsgi.input": io.BytesIO(b""),
    }
    environ.update({f"HTTP_{k.upper().replace('-', '_')}": v for k, v in headers.items()})
    body = app(environ, lambda status, hs: state.update(status=status, headers=dict(hs)))
    try:
        out = b"".join(body)
    finally:
        getattr(body, "close", lambda: None)()
    return state["status"], state["headers"], out


def _frames(raw: bytes) -> list[dict]:
    from opentine._cli_watch import parse_sse

    return [f for f in parse_sse(iter(raw.decode().split("\n"))) if f.get("event")]


def test_the_tail_streams_verified_rows_and_resumes_from_the_last_id(tmp_path):
    app = _app(tmp_path)
    assert app.service.capabilities()["tail_sse"] == {"format": "tine-tail/1", "path": "tail"}
    run = _push(app, tmp_path, 3)
    status, headers, body = _get(app, "lines=3")
    assert status == "200 OK" and headers["Content-Type"].startswith("text/event-stream")
    frames = _frames(body)
    rows = [json.loads(f["data"]) for f in frames]
    assert [r["index"] for r in rows] == [0, 1, 2]
    assert all(r["status"] == "verified" for r in rows)
    for item in rows:
        assert _schemas.validate(item, "tine-tail-1")[1] == []
    assert b": heartbeat" in body
    assert frames[-1].get("id") and not frames[0].get("id")  # one id per batch, on its last row
    _push(app, tmp_path, 5, run=run)  # the run grew by two events
    _, _, again = _get(app, **{"Last-Event-ID": frames[-1]["id"]})
    assert [json.loads(f["data"])["index"] for f in _frames(again)] == [3, 4]
    assert limits(app.service).open() == 0  # every stream gave its slot back


def test_an_unreadable_resume_point_is_a_reset_then_the_present(tmp_path):
    app = _app(tmp_path)
    _push(app, tmp_path, 2)
    _, _, body = _get(app, "lines=1", **{"Last-Event-ID": "c1.bogus"})
    frames = _frames(body)
    assert frames[0]["event"] == "reset" and frames[0].get("id")
    assert [json.loads(f["data"])["index"] for f in frames[1:]] == [1]
    status, _, _ = _get(app, "lines=5000")
    assert status == "400 Bad Request"


def test_the_tail_is_tenant_scoped_like_every_other_read(tmp_path):
    app = _app(tmp_path)
    _push(app, tmp_path, 2)
    status, _, body = _get(app, "lines=2", token="other-token")
    assert status == "404 Not Found" and json.loads(body) == {"error": "not found"}
    status, _, _ = _get(app, "lines=2", token="scoped-token")
    assert status in ("403 Forbidden", "404 Not Found")  # tenant-wide, as GET events
    _, _, mine = _get(app, "lines=2", token="other-token", tenant="other")
    assert [f["event"] for f in _frames(mine)] == []  # nothing of acme's


def test_streams_are_limited_globally_and_per_caller(tmp_path):
    app = _app(tmp_path)
    app.service.tail_limits = TailLimits(total=2, per_client=1)
    slots = app.service.tail_limits
    assert slots.acquire(("acme", "rita")) is None
    status, headers, _ = _get(app)
    assert status == "429 Too Many Requests" and headers["Retry-After"] == "5"
    assert slots.acquire(("acme", "someone")) is None
    status, _, _ = _get(app, token="writer-token")
    assert status == "503 Service Unavailable"
    slots.release(("acme", "someone"))
    assert _get(app, token="writer-token")[0] == "200 OK"
    assert slots.open() == 1


def test_a_lagging_consumer_is_dropped_and_resumes_without_loss(tmp_path):
    app = _app(tmp_path)
    app.tail_batch, app.tail_max_lag = 2, 3
    _push(app, tmp_path, 9)
    _, _, body = _get(app, "lines=9")
    frames = _frames(body)
    assert frames[-1]["event"] == "dropped"
    assert json.loads(frames[-1]["data"])["detail"] == "consumer lagging"
    got = [json.loads(f["data"])["index"] for f in frames if f["event"] == "event"]
    assert got == [0, 1, 2, 3]  # two full batches, then dropped: nothing queued for it
    cursor = [f["id"] for f in frames if f.get("id")][-1]
    app.tail_max_lag = 100
    _, _, rest = _get(app, **{"Last-Event-ID": cursor})
    assert [json.loads(f["data"])["index"] for f in _frames(rest)] == [4, 5, 6, 7, 8]


def test_a_slow_consumer_is_dropped(tmp_path):
    app = _app(tmp_path)
    app.tail_send_seconds = 0.5  # each clock reading is a second: every send looks slow
    _push(app, tmp_path, 2)
    frames = _frames(_get(app, "lines=2")[2])
    assert [f["event"] for f in frames] == ["event", "event", "dropped"]
    assert json.loads(frames[-1]["data"])["detail"] == "slow consumer"
