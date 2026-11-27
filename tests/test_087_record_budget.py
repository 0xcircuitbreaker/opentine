"""0.87: the model allowlist and budget inside the ``tine record`` proxy, with hostile clients."""

from __future__ import annotations

import http.client
import http.server
import json
import threading

import pytest

from opentine import _budget_ledger, _budget_policy, _budget_status, _model_path
from opentine import _record_proxy as rp
from opentine._record_budget import RecordBudget
from opentine.repository import Repo
from opentine.repository._holds import BUDGET_LEDGER
from tests.key_roles_helpers import isolated_trust_config, pin_roles  # noqa: F401
from tests.record_budget_helpers import fpr, key

pytestmark = pytest.mark.filterwarnings("ignore::Warning")

SUBJECT = "agent:bot"
T0 = 1_800_000_000_000


class Upstream(http.server.ThreadingHTTPServer):
    """A fake provider: records what reached it; replies from ``self.reply``."""

    daemon_threads = True

    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), _Upstream)
        self.seen: list[dict] = []
        self.entered = threading.Event()
        self.release = threading.Event()
        self.release.set()
        self.reply = {"usage": {"prompt_tokens": 7, "completion_tokens": 3}, "choices": []}
        self.sse: bytes | None = None


class _Upstream(http.server.BaseHTTPRequestHandler):
    server: Upstream

    def log_message(self, *args) -> None:
        return

    def do_POST(self) -> None:
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        self.server.seen.append({"path": self.path, "body": body, "headers": dict(self.headers)})
        self.server.entered.set()
        self.server.release.wait(30)
        sse = self.server.sse
        data = sse if sse is not None else json.dumps(self.server.reply).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream" if sse else "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


@pytest.fixture
def env(tmp_path):
    repo = Repo.init(tmp_path / "r")
    roles = {"runner": [fpr("runner")], "policy": [fpr("policy")],
             "optimizer": [fpr("optimizer")]}  # fmt: skip
    text = "version = 1\n[roles]\n" + "".join(f"{k} = {json.dumps(v)}\n" for k, v in roles.items())
    (repo.path / "key-roles.toml").write_bytes(text.encode("utf-8"))
    pin_roles(repo.path)
    up = Upstream()
    threading.Thread(target=up.serve_forever, daemon=True).start()
    servers = []

    def proxy(gate=None):
        bases = {name: f"http://127.0.0.1:{up.server_address[1]}" for name in rp.UPSTREAMS}
        server = rp.RecordingServer(bases, lambda r: None, gate)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
        return server

    yield repo, up, proxy
    for server in servers:
        server.shutdown()
        server.server_close()
    up.release.set()
    up.shutdown()
    up.server_close()


def apply(repo, *, signer="policy", serial=1, model_path=None, **limits):
    doc = _budget_policy.build(SUBJECT, limits, serial=serial, on_limit="deny",
                               issued_at="2027-01-15T08:00:00Z", model_path=model_path)  # fmt: skip
    doc = _budget_policy.sign(doc, key(signer))
    return _budget_ledger.append(repo, SUBJECT, "policy", {"policy": doc}, key("runner"), at_ms=T0)


def gate(repo, catalog=None):
    return RecordBudget(repo, SUBJECT, key("runner"), run="record:test", catalog=catalog,
                        now=lambda: T0 + 1000)  # fmt: skip


def send(server, path, body, headers=None, method="POST"):
    raw = body if isinstance(body, bytes) else json.dumps(body).encode()
    conn = http.client.HTTPConnection("127.0.0.1", server.port, timeout=30)
    try:
        conn.request(method, path, body=raw, headers={"Content-Type": "application/json",
                                                      **(headers or {})})  # fmt: skip
        response = conn.getresponse()
        return response.status, response.read()
    finally:
        conn.close()


def rows(repo, entry):
    return [r for r in _budget_ledger.entries(repo, SUBJECT) if r["value"]["entry"] == entry]


def totals(repo):
    return _budget_status.status(repo, SUBJECT, now_ms=T0 + 2000)["totals"]


CHAT = "/openai/v1/chat/completions"


def test_canonical_folds_case_space_prefixes_width_and_aliases():
    for raw in ("gpt-4o-mini", "  GPT-4o-Mini ", "openai/gpt-4o-mini", "OpenAI:GPT-4o-mini",
                "ｇｐｔ-４ｏ-ｍｉｎｉ", "gpt-4o-\tmini"):  # fmt: skip
        assert _model_path.canonical(raw) == "gpt-4o-mini", raw
    assert _model_path.canonical("models/gemini-1.5-pro") == "gemini-1.5-pro"
    assert _model_path.canonical("us.anthropic.claude-x-v1:0") == "claude-x-v1:0"
    assert _model_path.canonical("publishers/google/models/gemini-pro") == "gemini-pro"
    assert _model_path.canonical("fast", {"fast": "gpt-4o-mini"}) == "gpt-4o-mini"
    assert _model_path.canonical("gpt​-4o") == ""  # a zero-width space never matches
    assert _model_path.canonical(["gpt-4o"]) == ""
    assert _model_path.allowed("claude-sonnet-4-5", ["claude-sonnet-4*"])
    assert not _model_path.allowed("", ["*"])


def test_a_policy_without_model_path_keeps_its_body_and_digest():
    doc = _budget_policy.build(SUBJECT, {"tokens": 5}, serial=1, on_limit="deny",
                               issued_at="2027-01-15T08:00:00Z")  # fmt: skip
    assert "model_path" not in doc
    signed = _budget_policy.sign(doc, key("policy"))
    assert _budget_policy.digest(signed) == _budget_policy.digest({**doc})


def test_widening_the_allowlist_needs_a_pinned_policy_key(env):
    repo, _, _ = env
    apply(repo, model_path={"allow": ["gpt-4o-mini"]})
    wider = apply(repo, signer="runner", serial=2, model_path={"allow": ["gpt-4o-mini", "o3"]})
    status = _budget_status.status(repo, SUBJECT, now_ms=T0)
    assert [f["code"] for f in status["findings"] if f["entry"] == wider] == [
        "fail:budget.limit-raise"
    ]
    narrower = apply(repo, signer="runner", serial=3, model_path={"allow": []})
    assert _budget_status.status(repo, SUBJECT, now_ms=T0)["policy"]["entry"] == narrower
    alias = apply(repo, signer="runner", serial=4,
                  model_path={"allow": [], "aliases": {"cheap": "o3"}})  # fmt: skip
    status = _budget_status.status(repo, SUBJECT, now_ms=T0)
    assert status["policy"]["entry"] == narrower and alias != narrower


def test_an_allowed_model_goes_through_and_a_refused_one_never_reaches_upstream(env):
    repo, up, proxy = env
    apply(repo, model_path={"allow": ["gpt-4o-mini"]})
    server = proxy(gate(repo))
    assert send(server, CHAT, {"model": "OpenAI/GPT-4o-Mini", "max_tokens": 5})[0] == 200
    status, body = send(server, CHAT, {"model": "gpt-4o", "max_tokens": 5})
    assert status == 403 and json.loads(body)["error"]["code"] == "budget.model-not-allowed"
    assert len(up.seen) == 1
    (deny,) = rows(repo, "deny")
    assert deny["signed"] and deny["signer"] == fpr("runner")
    assert deny["value"]["model"] == "gpt-4o" and deny["value"]["about"]
    held = _budget_ledger.held_ids(repo, BUDGET_LEDGER, SUBJECT)
    assert deny["id"] in held


@pytest.mark.parametrize("path,body", [
    (CHAT, b'{"model": "gpt-4o-mini", "model": "gpt-4o"}'),  # duplicate key laundering
    (CHAT, b"model=gpt-4o-mini"),  # not JSON
    (CHAT, b'{"messages": []}'),  # names no model
    ("/openai/v1/x/../chat/completions", b'{"model": "gpt-4o-mini"}'),
    ("/openai/v1/%62atches", b'{"input_file_id": "f", "endpoint": "/v1/chat/completions"}'),
    ("/openai/v1/files", b'{"model": "gpt-4o-mini"}'),
    ("/gemini/v1beta/models/gemini-pro:generateContent", b'{"contents": []}'),
    ("/azure/openai/deployments/big/chat/completions", b'{"model": "gpt-4o-mini"}'),
    ("/anthropic/v1/messages/batches", json.dumps({"requests": [
        {"params": {"model": "gpt-4o-mini", "max_tokens": 1}},
        {"params": {"model": "claude-opus", "max_tokens": 1}}]}).encode()),
    (CHAT, b'{"model": "gpt-4o-mini", "n": 100000}'),
    (CHAT, b'{"model": "gpt-4o-mini", "max_tokens": -1}'),
    (CHAT, b"[" * 5000 + b"]" * 5000),
])  # fmt: skip
def test_bypass_attempts_are_refused_and_recorded(env, path, body):
    repo, up, proxy = env
    apply(repo, model_path={"allow": ["gpt-4o-mini"]})
    server = proxy(gate(repo))
    status, _ = send(server, path, body)
    assert status == 403
    assert up.seen == []
    assert len(rows(repo, "deny")) == 1


def test_an_inline_batch_of_allowed_models_is_reserved_per_request(env):
    repo, up, proxy = env
    apply(repo, model_path={"allow": ["claude-haiku*"]})
    server = proxy(gate(repo))
    batch = {"requests": [{"params": {"model": "claude-haiku-4", "max_tokens": 10}}] * 3}
    up.reply = {"id": "b"}
    assert send(server, "/anthropic/v1/messages/batches", batch)[0] == 200
    (reserve,) = [r for r in rows(repo, "spend") if r["value"]["phase"] == "reserve"]
    assert reserve["value"]["cost"]["output_tokens"] == 30


def test_spend_settles_from_reported_usage(env):
    repo, _, proxy = env
    apply(repo, tokens=100_000)
    server = proxy(gate(repo))
    assert send(server, CHAT, {"model": "m", "max_tokens": 50})[0] == 200
    assert totals(repo)["tokens"] == 10  # 7 + 3 reported, not the estimate
    phases = sorted(r["value"]["phase"] for r in rows(repo, "spend"))
    assert phases == ["reserve", "settle"]


def test_missing_usage_settles_at_the_pessimistic_estimate(env):
    repo, up, proxy = env
    apply(repo, tokens=100_000)
    up.reply = {"choices": []}
    server = proxy(gate(repo))
    body = {"model": "m", "max_tokens": 50}
    assert send(server, CHAT, body)[0] == 200
    assert totals(repo)["tokens"] == len(json.dumps(body).encode()) + 50


def test_a_request_without_an_output_limit_assumes_the_policy_maximum(env):
    repo, up, proxy = env
    apply(repo, tokens=100_000, model_path={"max_output_tokens": 1000})
    up.reply = {}
    server = proxy(gate(repo))
    body = {"model": "m"}
    assert send(server, CHAT, body)[0] == 200
    assert totals(repo)["tokens"] == len(json.dumps(body).encode()) + 1000


def test_a_cap_refuses_a_call_whose_estimate_does_not_fit(env):
    repo, up, proxy = env
    apply(repo, tokens=200)
    server = proxy(gate(repo))
    status, body = send(server, CHAT, {"model": "m", "max_tokens": 500})
    assert status == 403 and json.loads(body)["error"]["code"] == "budget.would-exceed"
    assert up.seen == []


def test_a_held_call_reserves_so_a_second_call_cannot_pass(env):
    repo, up, proxy = env
    body = {"model": "m", "max_tokens": 100}
    apply(repo, tokens=len(json.dumps(body).encode()) + 150)
    server = proxy(gate(repo))
    up.release.clear()
    first: list = []
    worker = threading.Thread(target=lambda: first.append(send(server, CHAT, body)))
    worker.start()
    assert up.entered.wait(30)  # the first call is in flight, its estimate reserved
    assert send(server, CHAT, body)[0] == 403
    up.release.set()
    worker.join(30)
    assert first[0][0] == 200 and len(up.seen) == 1


def test_concurrent_calls_never_overrun_the_cap(env):
    repo, up, proxy = env
    body = {"model": "m", "max_tokens": 100}
    one = len(json.dumps(body).encode()) + 100
    apply(repo, tokens=one * 2 + one // 2)  # room for exactly two estimates
    server = proxy(gate(repo))
    up.release.clear()
    start = threading.Barrier(8)
    results: list = []

    def call():
        start.wait(30)
        results.append(send(server, CHAT, body)[0])

    workers = [threading.Thread(target=call) for _ in range(8)]
    for w in workers:
        w.start()
    for _ in range(6000):  # six refusals come back while two calls are held upstream
        if results.count(403) == 6:
            break
        threading.Event().wait(0.01)
    up.release.set()
    for w in workers:
        w.join(30)
    assert sorted(results) == [200, 200] + [403] * 6
    assert len(up.seen) == 2


def test_judge_calls_have_their_own_cap_and_the_tag_is_not_forwarded(env):
    repo, up, proxy = env
    apply(repo, tokens=100_000, model_path={"judge": {"tokens": 100}})
    server = proxy(gate(repo))
    body = {"model": "m", "max_tokens": 80}
    judge = {"X-Opentine-Call-Role": "Judge"}
    status, raw = send(server, CHAT, body, judge)
    assert status == 403 and json.loads(raw)["error"]["code"] == "budget.judge-would-exceed"
    assert send(server, CHAT, {"model": "m", "max_tokens": 1}, judge)[0] == 200
    assert send(server, CHAT, body)[0] == 200  # an untagged call is not judge spend
    assert all("X-Opentine-Call-Role" not in s["headers"] for s in up.seen)
    assert totals(repo)["judge_tokens"] == 10 and totals(repo)["tokens"] == 20


def test_an_unreachable_ledger_fails_closed(env, monkeypatch):
    repo, up, proxy = env
    apply(repo, tokens=100_000)
    server = proxy(gate(repo))

    def broken(*args, **kwargs):
        raise OSError("ledger gone")

    monkeypatch.setattr(_budget_status, "check", broken)
    status, raw = send(server, CHAT, {"model": "m", "max_tokens": 1})
    assert status in (403, 503)
    assert json.loads(raw)["error"]["code"] == "budget.ledger-unreachable"
    assert up.seen == []


def test_no_policy_in_force_refuses(env):
    repo, up, proxy = env
    server = proxy(gate(repo))
    status, raw = send(server, CHAT, {"model": "m", "max_tokens": 1})
    assert status == 403 and json.loads(raw)["error"]["code"] == "budget.no-policy"
    assert up.seen == []


def test_without_a_gate_nothing_changes(env):
    _, up, proxy = env
    server = proxy()
    assert send(server, CHAT, b"not json", {"X-Opentine-Call-Role": "judge"})[0] == 200
    assert up.seen[0]["body"] == b"not json"
    assert up.seen[0]["headers"].get("X-Opentine-Call-Role") == "judge"


def test_reads_are_not_gated(env):
    repo, up, proxy = env
    server = proxy(gate(repo))  # no policy at all: a model call would be refused
    assert send(server, "/openai/v1/models", b"", method="GET")[0] in (200, 501)
    assert rows(repo, "deny") == []


def test_a_finished_stream_settles_from_its_usage_and_a_cut_one_at_the_estimate(env):
    repo, up, proxy = env
    apply(repo, tokens=100_000)
    server = proxy(gate(repo))
    usage = {"usage": {"prompt_tokens": 4, "completion_tokens": 2}, "choices": []}
    up.sse = b"data: " + json.dumps(usage).encode() + b"\n\ndata: [DONE]\n\n"
    body = {"model": "m", "max_tokens": 60, "stream": True}
    assert send(server, CHAT, body)[0] == 200
    assert totals(repo)["tokens"] == 6
    up.sse = b"data: " + json.dumps(usage).encode() + b"\n\n"  # no end-of-stream marker
    assert send(server, CHAT, body)[0] == 200
    assert totals(repo)["tokens"] == 6 + len(json.dumps(body).encode()) + 60


def test_a_money_cap_refuses_a_model_the_catalog_cannot_price(env):
    repo, up, proxy = env
    apply(repo, money_usd=5.0)
    server = proxy(gate(repo))
    status, raw = send(server, CHAT, {"model": "no-such-model-x", "max_tokens": 1})
    assert status == 403 and json.loads(raw)["error"]["code"] == "budget.model-unpriced"
    assert send(server, CHAT, {"model": "gpt-4o", "max_tokens": 10})[0] == 200
    assert 0 < totals(repo)["money_usd"] < 5.0


def test_a_forged_low_settle_cannot_hide_a_reservation(env):
    repo, up, proxy = env
    apply(repo, tokens=100_000)
    up.reply = {}
    server = proxy(gate(repo))
    assert send(server, CHAT, {"model": "m", "max_tokens": 50})[0] == 200
    before = totals(repo)["tokens"]
    (reserve,) = [r for r in rows(repo, "spend") if r["value"]["phase"] == "reserve"]
    forged = {**reserve["value"], "phase": "settle", "cost": {"total_tokens": 0}}
    forged = {k: v for k, v in forged.items() if k not in ("convention", "subject", "entry",
                                                          "at", "at_ms")}  # fmt: skip
    _budget_ledger.append(repo, SUBJECT, "spend", forged, key("stranger"), at_ms=T0 + 5)
    assert totals(repo)["tokens"] == before
