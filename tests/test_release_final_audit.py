"""Adversarial release regressions for the final v0.3.0 audit."""

from __future__ import annotations

from decimal import Decimal
from types import SimpleNamespace

import pytest

from opentine.billing import CatalogError, RateCard, Usage, calculate
from opentine.billing._catalog_json import parse_catalog_json
from opentine.graph import Run, StepKind
from opentine.kernel import KernelError
from opentine.models._chat import ChatCompletions
from opentine.models._continuation import anthropic_sdk_blocks, google_sdk_parts
from opentine.models._google_stream import GoogleStreamState
from opentine.models._metered import metered_response
from opentine.models._responses import ResponsesTransport, parse_response, response_input
from opentine.models._stream_content import anthropic_content, chat_content, google_content
from opentine.models._streaming import ollama_result
from opentine.models._terminal import chat_terminal
from opentine.models._usage import (
    anthropic_usage,
    google_usage,
    ollama_usage,
    openai_usage,
)
from opentine.models.compat import (
    MLXLM,
    TGI,
    KoboldCpp,
    LiteLLM,
    LlamaCppPython,
    NvidiaNIM,
    SGLang,
    TensorRTLLM,
)
from opentine.models.google import Google
from opentine.models.ollama import Ollama
from opentine.models.openai import OpenAI
from opentine.repo import Repo
from opentine.trace import Recorder, TraceEvent


def test_catalog_parser_rejects_pathological_numbers():
    with pytest.raises(CatalogError):
        parse_catalog_json(b'{"value":' + b"9" * 5000 + b"}", CatalogError)
    with pytest.raises(CatalogError, match="non-finite"):
        parse_catalog_json(b'{"value":1e999999}', CatalogError)


def test_decimal_extra_usage_remains_exact_in_calculation_provenance():
    exact = Decimal("0.123456789012345678901234567")
    card = RateCard("local:compute", "local", "x", {"compute": Decimal("1000000")})
    result = calculate(Usage(extra={"compute": exact}), card)
    assert result.status == "complete"
    assert result.calculation["usage"]["compute"] == str(exact)
    assert result.known_subtotal_usd == exact


def test_reported_model_controls_pricing_and_invalid_identity_is_ignored():
    usage = Usage(input=1_000, output=1_000)
    terra = metered_response("openai", "gpt-5.6", usage, reported_model="gpt-5.6-terra")
    assert terra["billing"]["rate_card_id"].startswith("openai:gpt-5.6-terra")
    assert Decimal(terra["billing"]["amount_usd"]) == Decimal("0.0175")
    invalid = metered_response("openai", "gpt-5.6", usage, reported_model=["bad"])
    assert invalid["billing"]["status"] == "unknown"
    assert invalid["billing"]["known_subtotal_usd"] == "0"
    assert any("invalid model identifier" in item for item in invalid["billing"]["warnings"])
    mismatch = metered_response(
        "openai",
        "gpt-5.6",
        Usage(input=1_000_000),
        rate_override={"input": "99"},
        reported_model="gpt-4o",
    )
    assert mismatch["billing"]["rate_card_id"].startswith("openai:gpt-4o")
    assert Decimal(mismatch["billing"]["amount_usd"]) == Decimal("2.5")
    assert any("explicit rates were ignored" in item for item in mismatch["billing"]["warnings"])


def test_native_responses_honors_explicit_unmetered_mode():
    adapter = OpenAI("gpt-5.6", unmetered=True)
    response = SimpleNamespace(
        model="gpt-5.6",
        usage=SimpleNamespace(input_tokens=1_000_000, output_tokens=1_000_000),
    )
    result = adapter._responses.meter(response)
    assert result["billing"]["status"] == "unmetered"
    assert result["billing"]["amount_usd"] == "0"
    assert result["cost"] == 0.0


def test_unknown_billing_pins_provider_identity():
    kimi = metered_response("kimi", "future-model", Usage(input=1))
    compat = metered_response("openai-compatible", "future-model", Usage(input=1))
    assert kimi["billing"]["calculation"]["provider"] == "kimi"
    assert compat["billing"]["calculation"]["provider"] == "openai-compatible"
    assert kimi["billing"] != compat["billing"]


def test_derived_usage_totals_never_exceed_canonical_safe_integer():
    maximum = (1 << 53) - 1
    usages = (
        openai_usage({"input_tokens": maximum, "output_tokens": maximum}),
        anthropic_usage({"input_tokens": maximum, "output_tokens": maximum}),
        google_usage({"promptTokenCount": maximum, "candidatesTokenCount": maximum}),
        ollama_usage({"prompt_eval_count": maximum, "eval_count": maximum}),
    )
    assert all(usage.total is None for usage in usages)
    assert all("total" not in usage.to_dict() for usage in usages)


def test_large_ollama_duration_is_lossless_and_storable():
    result = Ollama("x")._meter({"prompt_eval_count": 1, "eval_count": 1, "total_duration": 10**30})
    exact = "1000000000000000000000"
    assert result["usage"]["total_seconds"] == exact
    assert result["billing"]["calculation"]["usage"]["total_seconds"] == exact


def test_oversized_tool_arguments_are_never_executable():
    oversized = {"payload": "x" * (1024 * 1024)}
    results = (
        chat_content({"tool_calls": [{"function": {"name": "unsafe", "arguments": oversized}}]}),
        parse_response(
            {
                "output": [{"type": "function_call", "name": "unsafe", "arguments": oversized}],
                "status": "completed",
            }
        ),
        anthropic_content(
            {"content": [{"type": "tool_use", "name": "unsafe", "input": oversized}]}
        ),
        google_content(
            {
                "candidates": [
                    {
                        "content": {
                            "parts": [{"function_call": {"name": "unsafe", "args": oversized}}]
                        },
                        "finish_reason": "STOP",
                    }
                ]
            }
        ),
        ollama_result(
            {"message": {"tool_calls": [{"function": {"name": "unsafe", "arguments": oversized}}]}},
            [],
        ),
    )
    assert all(result["tool_calls"] == [] for result in results)
    assert all("non-executable" in result["refusal"] for result in results)


def test_ollama_token_compute_and_unmetered_modes_are_distinct():
    token = Ollama("x", input_cost_per_mtok=2, output_cost_per_mtok=4)._meter(
        {
            "prompt_eval_count": 100,
            "eval_count": 200,
            "prompt_eval_duration": 1_000_000_000,
            "eval_duration": 2_000_000_000,
        }
    )
    assert token["billing"]["status"] == "complete"
    assert token["billing"]["known_subtotal_usd"] == "0.0010"

    compute = Ollama("x", compute_cost_per_second=2)._meter(
        {"prompt_eval_duration": 1_000_000_000, "eval_duration": 2_000_000_000}
    )
    assert compute["billing"]["status"] == "complete"
    assert compute["billing"]["known_subtotal_usd"] == "6"
    partial = Ollama("x", compute_cost_per_second=2)._meter({"prompt_eval_duration": 1_000_000_000})
    assert partial["billing"]["status"] == "partial"
    assert partial["billing"]["known_subtotal_usd"] == "2"
    assert Ollama("x")._meter({})["billing"]["status"] == "unmetered"
    with pytest.raises(ValueError, match="mutually exclusive"):
        Ollama("x", input_cost_per_mtok=1, compute_cost_per_second=1)
    with pytest.raises(ValueError, match="finite and non-negative"):
        Ollama("x", input_cost_per_mtok=-1)


@pytest.mark.parametrize(
    ("adapter", "base"),
    [
        (SGLang(), "http://localhost:30000/v1"),
        (TGI(), "http://localhost:8080/v1"),
        (MLXLM(), "http://localhost:8080/v1"),
        (NvidiaNIM(), "http://localhost:8000/v1"),
        (TensorRTLLM(), "http://localhost:8000/v1"),
        (KoboldCpp(), "http://localhost:5001/v1"),
        (LlamaCppPython(), "http://localhost:8000/v1"),
    ],
)
def test_named_local_compatible_presets_are_unmetered(adapter, base):
    assert adapter._base_url == base
    billing = adapter._meter({"prompt_tokens": 1, "completion_tokens": 1})["billing"]
    assert billing["status"] == "unmetered"


def test_litellm_gateway_is_not_silently_mislabeled_unmetered():
    adapter = LiteLLM()
    assert adapter._base_url == "http://localhost:4000/v1"
    assert (
        adapter._meter({"prompt_tokens": 1, "completion_tokens": 1})["billing"]["status"]
        == "unknown"
    )


def test_provider_terminal_states_fail_closed_without_losing_usage():
    chat = {"text": "", "tool_calls": [], "warnings": []}
    chat_terminal(chat, "tool_calls")
    assert "without a valid tool call" in chat["refusal"]
    google = google_content(
        SimpleNamespace(
            candidates=[
                SimpleNamespace(content=SimpleNamespace(parts=[]), finish_reason="MAX_TOKENS")
            ]
        )
    )
    assert google["refusal"] == "MAX_TOKENS"
    ollama = ollama_result(
        {"message": {"content": "partial"}, "done": True, "done_reason": "length"}, []
    )
    assert ollama["refusal"] == "incomplete response: length"


@pytest.mark.asyncio
async def test_chat_empty_choices_and_responses_stream_errors_retain_billing():
    adapter = ChatCompletions("gpt-5.6", provider="openai")
    chat_response = SimpleNamespace(
        choices=[],
        model="gpt-5.6",
        usage=SimpleNamespace(
            prompt_tokens=10,
            completion_tokens=2,
            prompt_tokens_details=SimpleNamespace(cache_write_tokens=0),
        ),
    )
    client = SimpleNamespace(
        chat=SimpleNamespace(
            completions=SimpleNamespace(create=lambda **kwargs: _awaited(chat_response))
        )
    )
    result = await adapter._complete(client, [{"role": "user", "content": "go"}])
    assert result["refusal"] == "provider returned no choices"
    assert result["usage"]["total"] == 12 and result["cost"] > 0

    async def error_events():
        yield SimpleNamespace(type="error", code="server_error", message="boom")

    responses = SimpleNamespace(create=lambda **kwargs: _awaited(error_events()))
    events = [
        event
        async for event in ResponsesTransport(model="gpt-5.6").stream(
            SimpleNamespace(responses=responses),
            [{"role": "user", "content": "go"}],
            None,
            None,
            0.0,
        )
    ]
    assert events[-1]["type"] == "response"
    assert "response failed" in events[-1]["refusal"]
    assert events[-1]["billing"]["status"] == "unknown"


async def _awaited(value):
    return value


@pytest.mark.asyncio
async def test_responses_and_ollama_abrupt_stream_eof_fail_closed(monkeypatch):
    async def no_events():
        if False:
            yield None

    responses = SimpleNamespace(create=lambda **kwargs: _awaited(no_events()))
    events = [
        event
        async for event in ResponsesTransport(model="gpt-5.6").stream(
            SimpleNamespace(responses=responses),
            [{"role": "user", "content": "go"}],
            None,
            None,
            0.0,
        )
    ]
    assert events[-1]["type"] == "response"
    assert "before terminal event" in events[-1]["refusal"]

    class Response:
        def raise_for_status(self): ...

    class Stream:
        async def __aenter__(self):
            return Response()

        async def __aexit__(self, *exc): ...

    class Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc): ...

        def stream(self, *args, **kwargs):
            return Stream()

    async def no_chunks(response):
        if False:
            yield response

    monkeypatch.setattr("opentine.models.ollama.httpx.AsyncClient", lambda **kwargs: Client())
    monkeypatch.setattr("opentine.models.ollama._http.iter_ndjson", no_chunks)
    local = [event async for event in Ollama("qwen3").stream([{"role": "user", "content": "go"}])]
    assert local[-1]["type"] == "response"
    assert "before done marker" in local[-1]["refusal"]
    assert local[-1]["billing"]["status"] == "unmetered"

    async def error_chunks(response):
        del response
        yield {"error": "backend failed"}

    monkeypatch.setattr("opentine.models.ollama._http.iter_ndjson", error_chunks)
    failed = [event async for event in Ollama("qwen3").stream([{"role": "user", "content": "go"}])]
    assert failed[-1]["type"] == "response"
    assert failed[-1]["refusal"] == "Ollama error: backend failed"


def test_complete_google_requires_candidate_and_finish_reason():
    empty = Google("gemini-test")._result(SimpleNamespace(usage_metadata=None))
    assert empty["refusal"] == "provider returned no candidates"
    missing = Google("gemini-test")._result(
        SimpleNamespace(
            candidates=[SimpleNamespace(content=SimpleNamespace(parts=[]), finish_reason=None)],
            usage_metadata=None,
        )
    )
    assert missing["refusal"] == "incomplete response: missing finish reason"

    state = GoogleStreamState()
    state.add(
        SimpleNamespace(
            candidates=[SimpleNamespace(content=SimpleNamespace(parts=[]), finish_reason=None)]
        )
    )
    events = state.finish(lambda usage, model, tier: {"usage": {}, "billing": {}, "cost": 0.0})
    assert events[-1]["refusal"] == "incomplete response: stream ended before STOP"


def test_stored_provider_continuations_have_aggregate_replay_limits():
    huge = "x" * (2 * 1024 * 1024)
    with pytest.raises(ValueError, match="aggregate size"):
        anthropic_sdk_blocks([{"type": "thinking", "thinking": huge, "signature": "sig"}])
    with pytest.raises(ValueError, match="aggregate size"):
        response_input(
            [
                {
                    "role": "assistant",
                    "content": "",
                    "response_items": [{"type": "reasoning", "x": huge}],
                }
            ]
        )

    class Types:
        class FunctionCall:
            def __init__(self, **kwargs):
                self.kwargs = kwargs

        class Part:
            def __init__(self, **kwargs):
                self.kwargs = kwargs

    with pytest.raises(ValueError, match="aggregate size"):
        google_sdk_parts(Types, [{"text": huge}])


def _two_step_run() -> tuple[Run, object, object]:
    run = Run(id="fork-source", model_info="model-b", user_prompt="future")
    first = run.add_step(StepKind.done, {"text": "first"}, model_info="model-a")
    second = run.add_step(StepKind.done, {"text": "second"}, model_info="model-b")
    run.transcript = [
        {"role": "user", "content": "first prompt"},
        {"step_id": first.id, "role": "assistant", "content": "first"},
        {"role": "user", "content": "future prompt"},
        {"step_id": second.id, "role": "assistant", "content": "second"},
    ]
    run.manifest = {
        "model": {"name": "model-b"},
        "pricing": {
            "catalog_id": "future-catalog",
            "catalog_hash": "future-hash",
            "catalog_provenance": [{"future": True}],
            "catalogs": [
                {
                    "catalog_id": "future-catalog",
                    "catalog_hash": "future-hash",
                    "catalog_provenance": [{"future": True}],
                }
            ],
            "complete": True,
            "invocations": [
                {
                    "status": "complete",
                    "step_id": second.id,
                    "catalog_id": "future-catalog",
                    "catalog_hash": "future-hash",
                }
            ],
            "rate_cards": {second.id: "future-card"},
        },
    }
    return run, first, second


def test_repo_fork_applies_overrides_and_removes_future_manifest_state(tmp_path):
    repo = Repo.init(tmp_path)
    source, first, _ = _two_step_run()
    source.policies = {"old": True}
    stored = repo.put_run(source)
    forked = repo.fork(
        stored.run_id,
        stored.event_map[first.id],
        overrides={"model": "model-c", "prompt": "new prompt", "policy": {"strict": True}},
    )
    loaded = repo.load_run(forked)
    assert loaded.model_info == "model-c"
    assert loaded.manifest["model"]["name"] == "model-c"
    assert loaded.user_prompt == "new prompt"
    assert loaded.policies == {"strict": True}
    pricing = loaded.manifest["pricing"]
    assert pricing["invocations"] == [] and pricing["rate_cards"] == {}
    assert "catalog_id" not in pricing and "catalog_provenance" not in pricing


def test_compatibility_fork_is_deep_and_causally_slices_pricing():
    source, first, _ = _two_step_run()
    forked = source.fork(first.id)
    assert len(forked.steps) == 1
    assert forked.manifest["pricing"]["invocations"] == []
    forked.manifest["pricing"]["complete"] = False
    assert source.manifest["pricing"]["complete"] is True


def test_pricing_manifest_rejects_unknown_step_references(tmp_path):
    repo = Repo.init(tmp_path)
    run = Run(id="stale")
    run.add_step(StepKind.done, {"text": "ok"})
    run.manifest["pricing"] = {
        "invocations": [{"step_id": "stale-step", "status": "complete"}],
        "rate_cards": {"stale-step": "card"},
    }
    with pytest.raises(ValueError, match="unknown step"):
        repo.put_run(run)


def test_compatibility_roundtrip_preserves_run_envelope_provenance(tmp_path):
    repo = Repo.init(tmp_path)
    event = repo.put("event", {"causal_ids": [], "kind": "model", "parent_ids": []})
    code = repo.put("blob", b"code", redact=False)
    legacy = repo.put("blob", b"legacy", redact=False)
    mapping = repo.put("blob", b"{}", redact=False)
    run_id = repo.put(
        "run",
        {
            "custom": {"kept": True},
            "events": [event],
            "legacy_blob": legacy,
            "legacy_verification": {"integrity": {"ok": True}},
            "manifests": {"code": code},
            "migration_map_blob": mapping,
            "roots": [event],
            "signature_scope": "legacy_blob_only",
            "tips": [event],
        },
    )
    restored = repo.put_run(repo.load_run(run_id)).run_id
    payload = repo.get(restored).payload()
    assert payload["custom"] == {"kept": True}
    assert payload["manifests"]["code"] == code
    assert payload["legacy_blob"] == legacy
    assert payload["migration_map_blob"] == mapping
    assert payload["legacy_verification"]["integrity"]["ok"] is True


def test_annotation_import_converges_and_cross_target_versions_fail(tmp_path):
    origin = Repo.init(tmp_path / "origin")
    source = Run(id="annotated", metadata={"note": "old"})
    source.add_step(StepKind.done, {"text": "stored"})
    first = origin.put_run(source)
    clone = Repo.init(tmp_path / "clone")
    clone.import_pack(origin.pack())
    clone.put_run(clone.load_run(first.run_id))
    source.metadata = {"note": "new"}
    second = origin.put_run(source)
    clone.import_pack(origin.pack())
    assert clone.load_run(first.run_id).metadata == {"note": "old"}
    annotation_ref = f"annotations/{first.run_id.rsplit(':', 1)[-1]}"
    clone.update_ref(
        annotation_ref,
        second.annotation_id,
        expected_old=clone.read_ref(annotation_ref),
    )
    assert clone.load_run(first.run_id).metadata == {"note": "new"}

    other = origin.put("run", {"events": [], "manifests": {}, "roots": [], "tips": []})
    previous = origin.put(
        "annotation", {"previous_id": None, "target_id": first.run_id, "value": {}}
    )
    with pytest.raises(KernelError, match="same object"):
        origin.put("annotation", {"previous_id": previous, "target_id": other, "value": {}})


def test_compatibility_fork_retains_v3_causal_dependencies(tmp_path):
    repo = Repo.init(tmp_path)
    recorder = Recorder.start(repo, capture=False)
    ids = recorder.import_events(
        [
            TraceEvent("tool", 1, "trace", "cause"),
            TraceEvent("model", 2, "trace", "effect", causal_span_ids=("cause",)),
        ]
    )
    forked = repo.load_run(recorder.run_id).fork(ids[1])
    assert {step.id for step in forked.steps} == set(ids)
    stored = repo.put_run(forked)
    assert set(repo.get(stored.run_id).payload()["events"]) == set(ids)
    assert repo.fsck().ok
