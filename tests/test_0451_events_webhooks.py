"""0.45.1: SSE events, signed webhooks and their SSRF guards on the reference remote."""

from __future__ import annotations

import io
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from opentine import Run, _schemas, _webhook_sig
from opentine.graph import StepKind
from opentine.remote import Identity, LocalKeyProvider, StaticTokenIdentityProvider, server
from opentine.remote._events import EventHub
from opentine.remote._webhook_delivery import Dispatcher, post
from opentine.remote._webhooks import check_url, resolve
from opentine.repository import Repo

KEY = b"k" * 32


def _reference(tmp_path: Path, **options):
    identities = StaticTokenIdentityProvider(
        {
            "writer-token": Identity("alice", "acme", ("writer",)),
            "reader-token": Identity("rita", "acme", ("reader",)),
            "admin-token": Identity("root", "acme", ("admin",)),
            "other-token": Identity("eve", "other", ("admin",)),
        }
    )
    app = server.reference_app(
        tmp_path / "remote", identities=identities, keys=LocalKeyProvider(KEY), **options
    )
    app.stream_seconds, app.heartbeat_seconds = 0.3, 0.05
    return app


def _call(app, method: str, path: str, body: bytes = b"", token="writer-token", **headers):
    state: dict = {}

    def start_response(status, response_headers):
        state["status"], state["headers"] = status, dict(response_headers)

    environ = {
        "CONTENT_LENGTH": str(len(body)),
        "CONTENT_TYPE": "application/json",
        "HTTP_AUTHORIZATION": f"Bearer {token}",
        "PATH_INFO": path,
        "REQUEST_METHOD": method,
        "wsgi.input": io.BytesIO(body),
    }
    environ.update({f"HTTP_{k.upper().replace('-', '_')}": v for k, v in headers.items()})
    out = b"".join(app(environ, start_response))
    return state["status"], state["headers"], out


def _frames(text: str) -> list[dict]:
    from opentine._cli_watch import parse_sse

    return list(parse_sse(iter(text.split("\n"))))


def _push(app, tmp_path: Path, label: str, ref: str) -> str:
    local = Repo.init(tmp_path / f"local-{label}")
    run = Run(id=label, metadata={"label": label})
    run.add_step(StepKind.done, {"text": label})
    stored = local.put_run(run)
    service = app.service
    writer = service.authenticate({"authorization": "Bearer writer-token"})
    service.install_pack(writer, "acme", local.pack())
    assert service.update_ref(writer, "acme", ref, stored.run_id, None)
    return stored.run_id


def test_capabilities_advertise_events_and_a_self_consistent_webhook_key(tmp_path):
    app = _reference(tmp_path)
    caps = app.service.capabilities()
    assert caps["events_sse"]["path"] == "events"
    hooks = caps["webhooks"]
    assert hooks["format"] == "tine-webhook/1" and hooks["replay_window"] == 300
    keys = _webhook_sig.public_keys(hooks["keys"])
    assert len(keys) == 1
    key_file = tmp_path / "remote" / "webhook-ed25519.key"
    assert key_file.stat().st_size == 32
    assert _reference(tmp_path).service.capabilities()["webhooks"]["keys"] == hooks["keys"]


def test_the_stream_carries_ref_run_and_checkpoint_events_and_resumes(tmp_path):
    app = _reference(tmp_path)
    head = app.service.events.position(None)[0]
    run_id = _push(app, tmp_path, "one", "heads/main")
    status, headers, body = _call(
        app,
        "GET",
        "/v1/tenants/acme/events",
        token="reader-token",
        **{"Last-Event-ID": f"{app.service.events.epoch}-{head}"},
    )
    assert status == "200 OK" and headers["Content-Type"].startswith("text/event-stream")
    frames = [f for f in _frames(body.decode()) if f.get("id")]
    kinds = [f["event"] for f in frames]
    assert {"run.created", "ref.updated", "log.checkpoint"} <= set(kinds)
    for frame in frames:
        event = json.loads(frame["data"])
        assert frame["id"] == event["id"] and event["tenant"] == "acme"
        assert _schemas.validate(event, "tine-event-1")[1] == []
    moved = next(json.loads(f["data"]) for f in frames if f["event"] == "ref.updated")
    assert moved["data"] == {"forced": False, "name": "heads/main", "new": run_id, "old": None}
    assert b": heartbeat" in body
    # Resume after the ref event: only later events come back.
    after = next(f["id"] for f in frames if f["event"] == "ref.updated")
    _, _, again = _call(app, "GET", "/v1/tenants/acme/events", **{"Last-Event-ID": after})
    later = [f for f in _frames(again.decode()) if f.get("id")]
    assert all(int(f["id"].split("-")[1]) > int(after.split("-")[1]) for f in later)
    # A resume point from another server process is a reset, not a silent gap.
    _, _, reset = _call(app, "GET", "/v1/tenants/acme/events", **{"Last-Event-ID": "beef-1"})
    assert _frames(reset.decode())[0]["event"] == "reset"


def test_events_are_tenant_scoped_and_streams_are_bounded(tmp_path):
    app = _reference(tmp_path)
    status, _, _ = _call(app, "GET", "/v1/tenants/acme/events", token="other-token")
    assert status == "403 Forbidden"
    _push(app, tmp_path, "one", "heads/main")
    _, _, body = _call(
        app,
        "GET",
        "/v1/tenants/other/events",
        token="other-token",
        **{"Last-Event-ID": f"{app.service.events.epoch}-0"},
    )
    seen = [json.loads(f["data"]) for f in _frames(body.decode()) if f.get("id")]
    # Only the checkpoint of other's own (denied) audit row; nothing of acme's.
    assert {(e["tenant"], e["kind"]) for e in seen} <= {("other", "log.checkpoint")}
    hub = app.service.events
    while hub.streams.acquire(blocking=False):
        pass
    status, headers, _ = _call(app, "GET", "/v1/tenants/acme/events")
    assert status == "503 Service Unavailable" and headers["Retry-After"] == "5"


def test_an_evicted_resume_point_gets_a_reset():
    hub = EventHub(buffer=2)
    for i in range(5):
        hub.ref_moved("acme", f"heads/{i}", None, "run:" + "0" * 64, False)
    events, lost, head = hub.after("acme", 1)
    assert lost and head == 5 and [seq for seq, _ in events] == [4, 5]
    assert hub.after("acme", 3)[1] is False


def test_webhook_registration_is_admin_only_and_refuses_private_targets(tmp_path):
    app = _reference(tmp_path)
    url = json.dumps({"url": "https://hooks.example.com/x"}).encode()
    assert _call(app, "POST", "/v1/tenants/acme/webhooks", url)[0] == "403 Forbidden"
    status, _, body = _call(app, "POST", "/v1/tenants/acme/webhooks", url, token="admin-token")
    assert status == "201 Created"
    hook = json.loads(body)
    assert hook["kinds"] == sorted(["ref.updated", "run.created", "log.checkpoint"])
    for bad in (
        "http://hooks.example.com/",
        "https://127.0.0.1/",
        "https://10.1.2.3/",
        "https://169.254.169.254/latest",
        "https://localhost/",
        "https://[::1]/",
        "https://[::ffff:127.0.0.1]/",
        "https://user:pw@hooks.example.com/",
    ):
        status, _, _ = _call(
            app,
            "POST",
            "/v1/tenants/acme/webhooks",
            json.dumps({"url": bad}).encode(),
            token="admin-token",
        )
        assert status == "400 Bad Request", bad
    listed = json.loads(_call(app, "GET", "/v1/tenants/acme/webhooks", token="admin-token")[2])
    assert [h["id"] for h in listed["webhooks"]] == [hook["id"]]
    path = f"/v1/tenants/acme/webhooks/{hook['id']}"
    assert _call(app, "DELETE", path, token="admin-token")[0] == "200 OK"
    assert _call(app, "DELETE", path, token="admin-token")[0] == "404 Not Found"
    check_url("http://10.0.0.5:8080/hook", True)  # self-host opt-in


def test_delivery_resolves_once_and_refuses_a_name_that_points_inside():
    def private(host, port, type=0):
        return [(2, 1, 6, "", ("10.0.0.7", port))]

    def public(host, port, type=0):
        return [(2, 1, 6, "", ("93.184.215.14", port))]

    with pytest.raises(ValueError, match="private"):
        resolve("rebind.example", 443, False, private)
    assert resolve("rebind.example", 443, True, private) == "10.0.0.7"
    assert resolve("ok.example", 443, False, public) == "93.184.215.14"


def test_deliveries_are_signed_retried_with_backoff_and_give_up_on_4xx(tmp_path):
    app = _reference(tmp_path)
    hooks = app.service.webhooks
    hooks.add("acme", "https://hooks.example.com/a", ["ref.updated"])
    sent, statuses = [], [500, 503, 200]

    def sender(url, body, headers, allow_private):
        sent.append((body, headers))
        return statuses.pop(0)

    dispatcher = Dispatcher(hooks, base_delay=0.0, sender=sender)
    jobs: list = []
    dispatcher._push = lambda delay, job: jobs.append((delay, job))  # type: ignore[method-assign]
    dispatcher(app.service.events.publish("acme", "ref.updated", {"name": "heads/x"}))
    dispatcher(app.service.events.publish("acme", "run.created", {"runs": [], "total": 0}))
    assert len(jobs) == 1  # the hook did not subscribe to run.created
    while jobs:
        dispatcher.deliver(jobs.pop(0)[1])
    assert [row["outcome"] for row in dispatcher.log] == ["retrying", "retrying", "delivered"]
    keys = _webhook_sig.public_keys(hooks.capabilities()["keys"])
    deliveries = {headers[_webhook_sig.DELIVERY_HEADER] for _, headers in sent}
    assert len(deliveries) == 1
    for body, headers in sent:
        payload = _webhook_sig.verify(body, headers[_webhook_sig.HEADER], keys)
        assert _schemas.validate(payload, "tine-webhook-1")[1] == []
    statuses[:] = [400]
    dispatcher(app.service.events.publish("acme", "ref.updated", {"name": "heads/y"}))
    dispatcher.deliver(jobs.pop(0)[1])
    assert dispatcher.log[-1]["outcome"] == "failed" and not jobs


def test_a_real_delivery_reaches_a_local_receiver_only_when_private_is_allowed(tmp_path):
    received: list = []

    class Receiver(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            body = self.rfile.read(int(self.headers["Content-Length"]))
            received.append((body, self.headers[_webhook_sig.HEADER]))
            self.send_response(204)
            self.end_headers()

        def log_message(self, *args):
            pass

    httpd = HTTPServer(("127.0.0.1", 0), Receiver)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{httpd.server_address[1]}/hook"
        with pytest.raises(ValueError):
            post(url, b"{}", {}, False)
        app = _reference(tmp_path, webhooks_allow_private=True)
        app.service.webhooks.add("acme", url)
        dispatcher = app.service.webhooks.dispatcher
        _push(app, tmp_path, "one", "heads/main")
        keys = _webhook_sig.public_keys(app.service.capabilities()["webhooks"]["keys"])
        wanted, kinds = {"ref.updated", "run.created"}, set()
        deadline = threading.Event()
        for _ in range(600):  # wait for the kinds themselves; slow runners deliver late
            kinds = {_webhook_sig.verify(b, h, keys)["event"]["kind"] for b, h in list(received)}
            if wanted <= kinds:
                break
            deadline.wait(0.05)
        assert wanted <= kinds, (kinds, list(dispatcher.log))
    finally:
        httpd.shutdown()
