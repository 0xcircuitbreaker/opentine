"""0.49: webhook and OTLP alerts (``tine alert``, ``tine watch --alerts``)."""

from __future__ import annotations

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

import pytest

from opentine import _alerts, _alerts_deliver, _schemas, _webhook_sig, cli

FIXTURES = Path(__file__).parent / "fixtures"


def _tine(monkeypatch, capsys, *argv: str) -> tuple[int, str]:
    monkeypatch.setattr(sys, "argv", ["tine", *argv])
    code = 0
    try:
        cli.main()
    except SystemExit as exc:
        code = int(exc.code or 0) if not isinstance(exc.code, str) else 1
    return code, capsys.readouterr().out


class _Receiver:
    """A loopback HTTP server that records every POST (webhook and OTLP alike)."""

    def __init__(self, status: int = 200):
        self.posts: list[tuple[str, dict[str, str], bytes]] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802 - http.server's spelling
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                outer.posts.append((self.path, dict(self.headers), body))
                self.send_response(status)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def receiver():
    server = _Receiver()
    yield server
    server.close()


@pytest.fixture
def repo(monkeypatch, capsys, tmp_path: Path) -> Path:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    monkeypatch.chdir(tmp_path)
    assert _tine(monkeypatch, capsys, "init", ".")[0] == 0
    source = str(FIXTURES / "jules" / "session.json")
    code, _ = _tine(monkeypatch, capsys, "import", source, "--format", "jules", "--repo", ".")
    assert code == 0
    return tmp_path


def test_rules_are_checked_and_stored(monkeypatch, capsys, repo):
    code, out = _tine(
        monkeypatch,
        capsys,
        "alert",
        "add",
        "cost",
        "--on",
        "cost.threshold",
        "--threshold",
        "1.5",
        "--otlp",
        "http://127.0.0.1:4318",
        "--allow-private",
        "--json",
    )
    assert code == 0
    doc = json.loads(out)
    assert _schemas.validate(doc, "tine-cli-alert-1")[1] == []
    assert doc["rule"]["threshold"] == 1.5
    for bad in (["--on", "cost.threshold", "--otlp", "http://x"],  # no threshold
                ["--on", "policy.denied", "--threshold", "1", "--otlp", "http://x"],
                ["--on", "policy.denied"],  # no sink
                ["--on", "policy.denied", "--webhook", "http://example.com/"]):  # fmt: skip
        assert _tine(monkeypatch, capsys, "alert", "add", "x", *bad)[0] == 1
    assert _tine(monkeypatch, capsys, "alert", "add", "cost", "--on", "verify.failed",
                 "--otlp", "http://x")[0] == 1  # fmt: skip
    code, out = _tine(monkeypatch, capsys, "alert", "list", "--json")
    listed = json.loads(out)
    assert _schemas.validate(listed, "tine-cli-alert-1")[1] == []
    assert [r["name"] for r in listed["rules"]] == ["cost"]
    assert listed["webhook_key"]["kid"].startswith("ed25519:")
    assert _tine(monkeypatch, capsys, "alert", "remove", "cost", "--json")[0] == 0
    assert _tine(monkeypatch, capsys, "alert", "remove", "cost")[0] == 1


def test_test_delivers_a_signed_webhook_and_an_otlp_log_record(monkeypatch, capsys, repo,
                                                               receiver):  # fmt: skip
    assert _tine(monkeypatch, capsys, "alert", "add", "deny", "--on", "policy.denied",
                 "--webhook", receiver.url + "/hook", "--allow-private",
                 "--otlp", receiver.url)[0] == 0  # fmt: skip
    _, out = _tine(monkeypatch, capsys, "alert", "list", "--json")
    keys = _webhook_sig.public_keys([json.loads(out)["webhook_key"]])
    code, out = _tine(monkeypatch, capsys, "alert", "test", "--json")
    assert code == 0 and json.loads(out)["alerts"] == []  # the run has no policy denial
    code, out = _tine(monkeypatch, capsys, "alert", "test", "deny", "--always", "--json")
    doc = json.loads(out)
    assert code == 0 and doc["ok"] is True
    assert _schemas.validate(doc, "tine-cli-alert-1")[1] == []
    outcomes = [(r["sink"], r["outcome"]) for r in doc["alerts"][0]["deliveries"]]
    assert outcomes == [("webhook", "delivered"), ("otlp", "delivered")]
    hook = next(p for p in receiver.posts if p[0] == "/hook")
    otlp = next(p for p in receiver.posts if p[0] == "/v1/logs")
    payload = _webhook_sig.verify(hook[2], hook[1][_webhook_sig.HEADER], keys)
    assert payload["alert"]["rule"] == "deny" and payload["alert"]["test"] is True
    assert payload["webhook"] == "alert:deny" and payload["event"]["kind"] == "op.logged"
    assert _schemas.validate(payload, "tine-webhook-1")[1] == []
    record = json.loads(otlp[2])["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]
    assert record["severityText"] == "WARN"
    assert {"key": "opentine.alert.rule", "value": {"stringValue": "deny"}} in record["attributes"]


def test_a_failed_delivery_exits_1(monkeypatch, capsys, repo):
    failing = _Receiver(status=400)
    try:
        assert _tine(monkeypatch, capsys, "alert", "add", "v", "--on", "verify.failed",
                     "--webhook", failing.url, "--allow-private")[0] == 0  # fmt: skip
        code, out = _tine(monkeypatch, capsys, "alert", "test", "--always", "--json")
    finally:
        failing.close()
    doc = json.loads(out)
    assert code == 1 and doc["ok"] is False
    assert doc["alerts"][0]["deliveries"][0]["attempts"] == 1  # 400 is not retried


class _FakeRepo:
    def __init__(self, steps, cost=0.0, attest_state=None):
        self.path = None
        self.run = SimpleNamespace(steps=steps, total_cost=cost)
        self.attest_state = attest_state

    def attestations_for(self, oid):
        return ("att:1",) if self.attest_state else ()

    def verify_attestation(self, oid, trust_embedded=False):
        return SimpleNamespace(state=self.attest_state, reason="key disagrees")

    def load_run(self, oid):
        return self.run


def _op(oid: str) -> dict:
    return {
        "format": "tine-event/1",
        "id": "1",
        "kind": "op.logged",
        "tenant": None,
        "time": "2026-01-01T00:00:00Z",
        "data": {"refs": [{"new": oid, "old": None}]},
    }


def _rule(name, on, threshold=None):
    return _alerts.make_rule(
        name, on, threshold=threshold, otlp="http://127.0.0.1:1", allow_private=True
    )


def test_engine_triggers_on_announced_runs():
    deny = SimpleNamespace(kind="policy", id="s1", outputs={"decision": "deny", "reason": "rm -rf"})
    allow = SimpleNamespace(kind="policy", id="s2", outputs={"decision": "allow"})
    repo = _FakeRepo([deny, allow], cost=2.5, attest_state="mismatch")
    rules = [_rule("v", "verify.failed"), _rule("p", "policy.denied"),
             _rule("hi", "cost.threshold", 2.0), _rule("lo", "cost.threshold", 3.0)]  # fmt: skip
    hits = _alerts.Engine(rules, repo).evaluate(_op("run:sha256:" + "a" * 64))
    assert sorted(h["rule"]["name"] for h in hits) == ["hi", "p", "v"]
    assert "rm -rf" in next(h for h in hits if h["rule"]["name"] == "p")["finding"]["detail"]
    clean = _FakeRepo([allow], attest_state="unsigned")
    assert _alerts.Engine(rules[:2], clean).evaluate(_op("run:sha256:" + "b" * 64)) == []
    assert _alerts.announced_runs(_op("blob:sha256:" + "c" * 64)) == []


def test_engine_flags_a_checkpoint_fork_or_rollback():
    engine = _alerts.Engine([_rule("w", "witness.disagreement")])

    def checkpoint(size, root):
        return {"kind": "log.checkpoint", "data": {"origin": "o", "size": size, "root": root}}

    assert engine.evaluate(checkpoint(5, "r5")) == []
    assert engine.evaluate(checkpoint(6, "r6")) == []
    assert engine.evaluate(checkpoint(6, "r6")) == []
    fork = engine.evaluate(checkpoint(6, "other"))
    assert fork and fork[0]["finding"]["detail"].startswith("fork")
    rollback = engine.evaluate(checkpoint(4, "r4"))
    assert rollback and rollback[0]["finding"]["detail"].startswith("rollback")


def test_webhook_delivery_retries_then_succeeds(tmp_path):
    key = _alerts_deliver.signing_key(tmp_path)
    statuses = iter([503, 429, 204])
    seen = []

    def sender(url, body, headers, allow_private):
        seen.append(headers[_webhook_sig.HEADER])
        return next(statuses)

    payload = {"delivery": "d", "format": "tine-webhook/1", "webhook": "alert:x", "event": {}}
    row = _alerts_deliver.send_webhook("https://example.com/h", payload, key, False,
                                       sender=sender, base_delay=0)  # fmt: skip
    assert row["outcome"] == "delivered" and row["attempts"] == 3 and len(seen) == 3


def test_watch_alerts_evaluates_each_event(monkeypatch, capsys, repo, receiver):
    assert _tine(monkeypatch, capsys, "alert", "add", "c", "--on", "cost.threshold",
                 "--threshold", "0", "--otlp", receiver.url, "--allow-private")[0] == 0  # fmt: skip
    calls = []
    real = _alerts.Engine.evaluate

    def spy(self, event):
        calls.append(event["kind"])
        return real(self, event)

    monkeypatch.setattr(_alerts.Engine, "evaluate", spy)
    code, _ = _tine(monkeypatch, capsys, "watch", ".", "--from-start", "--once", "--alerts")
    assert code == 0 and calls == ["op.logged"]


def test_otlp_sink_refuses_private_targets_and_credentials(monkeypatch, capsys, repo):
    for endpoint in (
        "http://127.0.0.1:4318",
        "http://localhost:4318",
        "http://10.0.0.1",
        "http://169.254.169.254/latest",
        "https://user:pw@collector.example",
    ):
        with pytest.raises(ValueError):
            _alerts.make_rule("o", "policy.denied", otlp=endpoint)
    _alerts.make_rule("o", "policy.denied", otlp="http://collector.example:4318")
    with pytest.raises(ValueError):
        _alerts.make_rule("o", "policy.denied", otlp="https://u:p@127.0.0.1", allow_private=True)


def test_send_otlp_checks_resolved_addresses(monkeypatch):
    from opentine.remote import _webhooks

    real = _webhooks.resolve

    def private(host, port, allow_private):
        return real(host, port, allow_private, lambda *a, **k: [(0, 0, 0, "", ("10.1.2.3", 0))])

    monkeypatch.setattr(_webhooks, "resolve", private)
    row = _alerts_deliver.send_otlp("https://rebind.example", {"resourceLogs": []})
    assert row["outcome"] == "failed" and row["status"] == "ValueError"


def test_hand_edited_rules_are_rechecked(repo):
    path = _alerts.state_dir(repo) / "rules.json"
    rule = {"name": "x", "on": "policy.denied", "threshold": None, "webhook": None,
            "otlp": "http://169.254.169.254/", "allow_private": False}  # fmt: skip
    path.write_text(json.dumps({"rules": [rule]}), encoding="utf-8")
    with pytest.raises(ValueError, match="rules.json"):
        _alerts.load_rules(repo)
