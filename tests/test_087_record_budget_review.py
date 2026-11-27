"""0.87 review: holes in the record-proxy budget a hostile loop could use."""

from __future__ import annotations

import json

from opentine import _model_path
from opentine._record_budget import RecordBudget, _complete


def _probe(body: dict, path: str = "/v1/chat/completions", dialect: str = "openai") -> dict:
    raw = json.dumps(body).encode()
    return _model_path.probe(dialect, "POST", path, raw, body, 100)


def _section(**kw) -> dict:
    return _model_path.section(kw)


def test_a_new_alias_widens_even_without_an_allowlist_because_it_changes_the_price():
    old = _section(allow=None, aliases={})
    new = _section(allow=None, aliases={"claude-opus-4": "gpt-4o-mini"})
    assert "model_path.aliases" in _model_path.widens(old, new)


def test_snake_case_and_extra_fanout_fields_count_toward_the_estimate():
    gem = {"generation_config": {"candidate_count": 8, "max_output_tokens": 1000}}
    assert _probe(gem, "/v1beta/models/gemini-x:generateContent", "gemini")["output"] == 8000
    both = {"n": 1, "generationConfig": {"candidateCount": 4, "maxOutputTokens": 10}}
    assert _probe(both, "/v1beta/models/gemini-x:generateContent", "gemini")["output"] == 40
    legacy = {"model": "m", "best_of": 20, "max_tokens": 5}
    assert _probe(legacy, "/v1/completions")["output"] == 100


def test_a_gateway_fallback_model_list_is_checked():
    seen = _probe({"model": "gpt-4o-mini", "models": ["evil-model"]})
    assert "evil-model" in seen["models"]
    assert _probe({"model": "gpt-4o-mini", "models": "evil"})["problem"]


def test_every_models_segment_of_a_path_is_checked():
    path = "/v1/projects/models/gemini-ok/x/publishers/google/models/gemini-ultra:generateContent"
    seen = _probe({}, path, "gemini")
    assert {"gemini-ok", "gemini-ultra"} <= set(seen["models"])


def test_only_an_exact_count_tokens_endpoint_is_free():
    assert _probe({"model": "m"}, "/v1/messages/count_tokens", "anthropic")["free"]
    assert not _probe({"model": "m"}, "/v1/messages;count_tokens", "anthropic")["free"]
    path = "/v1beta/models/g:generateContent:countTokens"
    assert not _probe({}, path, "gemini")["free"]


def _stream(text: bytes) -> dict:
    return {"content_type": "text/event-stream", "response": text, "status": 200}


def test_model_text_cannot_fake_the_end_of_a_stream():
    fake = b'data: {"choices":[{"delta":{"content":"[DONE] message_stop"}}]}\n\n'
    assert not _complete(_stream(fake))
    assert _complete(_stream(fake + b"data: [DONE]\n\n"))
    assert _complete(_stream(b"event: message_stop\r\ndata: {}\r\n\r\n"))


def _settle(monkeypatch, usage: dict, answered: str = "gpt-4o-mini") -> dict:
    written: list[dict] = []
    monkeypatch.setattr(
        "opentine._budget_ledger.append",
        lambda repo, subject, entry, fields, key, at_ms: written.append(fields),
    )
    gate = RecordBudget(None, "agent:bot", None, run="r", now=lambda: 0)
    prices = {"gpt-4o-mini": 0.001, "gpt-4o": 1.0}
    monkeypatch.setattr(gate, "_price", lambda prov, model, u: prices.get(model))
    reply = {"model": answered, "usage": usage, "choices": []}
    record = {
        "upstream": "openai",
        "path": "/v1/chat/completions",
        "request": b'{"model":"gpt-4o-mini"}',
        "status": 200,
        "content_type": "application/json",
        "response": json.dumps(reply).encode(),
    }
    ticket = {
        "call": 1,
        "role": "agent",
        "model": "gpt-4o-mini",
        "provider": "openai",
        "estimate": {"input": 50, "output": 50},
        "money": 0.5,
        "priced": True,
        "names": ["gpt-4o-mini"],
    }
    gate.settle(ticket, record)
    return written[-1]["cost"]


def test_settle_prices_the_model_that_answered_when_it_is_dearer(monkeypatch):
    cost = _settle(monkeypatch, {"prompt_tokens": 7, "completion_tokens": 3}, answered="gpt-4o")
    assert cost["total_cost"] == 1.0


def test_settle_keeps_the_estimate_for_negative_or_absurd_usage(monkeypatch):
    cost = _settle(monkeypatch, {"prompt_tokens": -(10**9), "completion_tokens": 3})
    assert cost["total_tokens"] >= 0 and cost["total_cost"] >= 0
