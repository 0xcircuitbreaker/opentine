"""Round-six adversarial regressions for the v0.3.0 release candidate."""

from __future__ import annotations

import base64
import hashlib
import json
import zlib
from contextlib import nullcontext
from decimal import Decimal
from types import SimpleNamespace

import pytest

from opentine import Agent
from opentine.billing import RateCard, Usage, load_catalogs
from opentine.graph import Run, StepKind
from opentine.kernel import KernelError, ObjectEnvelope, canonical_json
from opentine.models._anthropic_request import convert_messages
from opentine.models._chat_request import build_messages
from opentine.models._responses import parse_response
from opentine.models._responses_request import response_input
from opentine.models._stream_content import chat_content
from opentine.models._streaming import ollama_result
from opentine.models._terminal import chat_terminal
from opentine.models._tool_args import stored_tool_calls
from opentine.models._usage import google_usage
from opentine.models.anthropic import Anthropic
from opentine.models.compat import Kimi
from opentine.models.google import Google
from opentine.models.ollama import Ollama
from opentine.repo import Repo
from opentine.repository import client as repository_client
from opentine.repository.pack import MAGIC, create_pack, negotiate, reachable
from opentine.trace import TraceEvent


def _call(arguments=None):
    return {"name": "danger", "arguments": arguments or {}, "id": "call-1"}


def test_decimal_usage_extra_serializes_without_identity_collisions():
    left = Usage(extra={"compute": Decimal("0.1000000000000000001")}).to_dict()
    right = Usage(extra={"compute": Decimal("0.1000000000000000002")}).to_dict()
    assert left == {"compute": "0.1000000000000000001"}
    assert right == {"compute": "0.1000000000000000002"}
    assert canonical_json(left) != canonical_json(right)


def test_signed_billing_records_are_deeply_immutable_and_json_safe():
    rates = {"input": "5"}
    metadata = {"nested": ["original"]}
    direct = RateCard("test:direct", "test", "direct", rates, metadata=metadata)
    rates["input"] = "0"
    metadata["nested"].append("changed")
    assert direct.rates["input"] == Decimal("5")
    assert direct.metadata["nested"] == ("original",)
    with pytest.raises(TypeError):
        direct.rates["input"] = Decimal("0")

    catalog = load_catalogs()
    signed = catalog.lookup("openai", "gpt-5.6")
    assert signed is not None
    with pytest.raises(TypeError):
        signed.rates["input"] = Decimal("0")
    with pytest.raises(TypeError):
        catalog.provenance[0]["catalog_hash"] = "forged"
    json.dumps(catalog.to_dict())


@pytest.mark.parametrize(
    "arguments",
    [
        '{"path":"safe","path":"danger"}',
        '{"value":NaN}',
        '{"value":Infinity}',
        "[]",
        '{"value":9007199254740992}',
    ],
)
def test_noncanonical_tool_json_is_never_executable(arguments):
    chat = chat_content({"tool_calls": [{"function": {"name": "danger", "arguments": arguments}}]})
    response = parse_response(
        {
            "output": [{"type": "function_call", "name": "danger", "arguments": arguments}],
            "status": "completed",
        }
    )
    for result in (chat, response):
        assert result["tool_calls"] == []
        assert "non-executable" in result["refusal"]


def test_unsuccessful_terminal_states_strip_tool_calls():
    chat = chat_content({"tool_calls": [{"function": {"name": "danger", "arguments": "{}"}}]})
    chat_terminal(chat, "length")
    responses = parse_response(
        {
            "output": [{"type": "function_call", "name": "danger", "arguments": "{}"}],
            "status": "incomplete",
        }
    )
    anthropic = Anthropic()._result(
        SimpleNamespace(
            content=[SimpleNamespace(type="tool_use", name="danger", input={}, id="call-1")],
            model="claude-sonnet-5",
            stop_reason="max_tokens",
            usage=SimpleNamespace(input_tokens=1, output_tokens=1),
        )
    )
    google = Google()._result(
        {
            "candidates": [
                {
                    "content": {"parts": [{"function_call": _call()}]},
                    "finish_reason": "MAX_TOKENS",
                }
            ],
            "modelVersion": "gemini-3.5-flash",
            "usage_metadata": {"promptTokenCount": 1, "candidatesTokenCount": 1},
        }
    )
    ollama = ollama_result(
        {"done_reason": "length", "message": {"tool_calls": [{"function": _call()}]}}, []
    )
    for result in (chat, responses, anthropic, google, ollama):
        assert result.get("refusal")
        assert result["tool_calls"] == []


def test_refused_provider_continuations_are_audited_but_not_replayed():
    continuation = [{"type": "tool_use", "id": "call-1", "name": "danger", "input": {}}]
    response = {
        "text": "",
        "refusal": "incomplete response",
        "tool_calls": [],
        "anthropic_content": continuation,
        "google_content": [{"function_call": {"name": "danger", "args": {}}}],
        "response_items": [{"type": "function_call", "name": "danger", "arguments": "{}"}],
    }
    run = Run(id="refused")
    message, calls, refused = Agent(model=SimpleNamespace(name="test"))._record_model(
        run, response, 0
    )
    assert refused and calls == []
    assert run.steps[-1].outputs["response_items"] == response["response_items"]
    assert set(message) == {"content", "refusal", "role"}
    assert not any("response_items" in item for item in run.transcript)


def test_responses_requires_completed_terminal_status():
    for status in (None, "queued", "in_progress", "future_state"):
        response = {"output": [], **({"status": status} if status is not None else {})}
        result = parse_response(response)
        assert result["refusal"].startswith("response ")


def test_fable_refusal_modifier_uses_reported_model():
    response = SimpleNamespace(
        content=[],
        model="claude-opus-4-8",
        stop_reason="refusal",
        usage=SimpleNamespace(input_tokens=1_000_000, output_tokens=0),
    )
    result = Anthropic("claude-fable-5")._result(response)
    assert result["billing"]["rate_card_id"].startswith("anthropic:claude-opus-4.8")
    assert Decimal(result["billing"]["known_subtotal_usd"]) == Decimal("5")


@pytest.mark.parametrize("reported_model", ["not-fable-5-custom", None])
def test_fable_refusal_modifier_requires_exact_priced_model(reported_model):
    response = SimpleNamespace(
        content=[],
        model=reported_model,
        stop_reason="refusal",
        usage=SimpleNamespace(input_tokens=1_000_000, output_tokens=0),
    )
    result = Anthropic("not-fable-5-custom")._result(response)
    assert result["billing"]["rate_card_id"] is None
    assert result["billing"]["status"] == "unknown"
    assert result["billing"]["amount_usd"] is None
    assert result["billing"]["known_subtotal_usd"] == "0"


def test_google_tool_use_usage_and_actual_service_tier():
    usage = google_usage(
        {"promptTokenCount": 10, "toolUsePromptTokenCount": 5, "candidatesTokenCount": 2}
    )
    assert usage.input == 15 and usage.total == 17
    maximum = (1 << 53) - 1
    split = google_usage({"promptTokenCount": maximum, "toolUsePromptTokenCount": maximum})
    assert split.input == maximum and split.extra["input_tool_use"] == maximum

    result = Google(service_tier="priority")._result(
        {
            "candidates": [{"content": {"parts": [{"text": "ok"}]}, "finish_reason": "STOP"}],
            "modelVersion": "gemini-3.5-flash",
            "sdk_http_response": {"headers": {"x-gemini-service-tier": "standard"}},
            "usage_metadata": {"promptTokenCount": 1_000_000, "candidatesTokenCount": 0},
        }
    )
    assert result["billing"]["calculation"]["service_tier"] == "standard"
    assert Decimal(result["billing"]["known_subtotal_usd"]) == Decimal("1.5")

    usage = {"promptTokenCount": 1_000_000, "candidatesTokenCount": 0}
    adapter = Google(service_tier="priority")
    unobserved = adapter._meter(usage)
    assert unobserved["billing"]["status"] == "unknown"
    assert unobserved["billing"]["known_subtotal_usd"] == "0"
    calculation = unobserved["billing"]["calculation"]
    assert calculation["components_usd"] == {}
    assert calculation["candidate_components_usd"] == {"input": "2.70"}
    assert calculation["requested_service_tier"] == "priority"
    assert unobserved["cost"] == 0.0
    observed = adapter._meter(usage, response_tier="priority")
    assert observed["billing"]["status"] == "complete"
    assert Decimal(observed["billing"]["known_subtotal_usd"]) == Decimal("2.70")
    overridden = Google(service_tier="priority", rates={"input": "7", "output": "8"})._meter(usage)
    assert overridden["billing"]["status"] == "complete"
    assert Decimal(overridden["billing"]["known_subtotal_usd"]) == Decimal("7")


def test_kimi_requests_stream_usage_and_all_replay_paths_are_bounded(monkeypatch):
    assert Kimi()._include_usage is True
    huge = [_call({"payload": "x" * (1024 * 1024)})]
    message = {"role": "assistant", "content": "", "tool_calls": huge}
    for convert in (
        lambda: build_messages([message], None),
        lambda: response_input([message]),
        lambda: convert_messages([message]),
        lambda: Ollama._build_messages([message], None),
        lambda: stored_tool_calls(huge),
    ):
        with pytest.raises(ValueError, match="safe aggregate size"):
            convert()

    class Types:
        class GenerateContentConfig:
            def __init__(self, **kwargs):
                self.__dict__.update(kwargs)

        class FunctionCall:
            def __init__(self, **kwargs):
                self.__dict__.update(kwargs)

        class Part:
            def __init__(self, **kwargs):
                self.__dict__.update(kwargs)

        class Content:
            def __init__(self, **kwargs):
                self.__dict__.update(kwargs)

    google = Google(service_tier="flex")
    monkeypatch.setattr(google, "_types", lambda: Types)
    with pytest.raises(ValueError, match="safe aggregate size"):
        google._request([message], None, None, 0)
    _, config = google._request([], None, None, 0)
    assert config.service_tier == "flex"


def test_repo_fork_preserves_start_snapshot_and_drops_future_extensions(tmp_path):
    repo = Repo.init(tmp_path)
    recorder = __import__("opentine.trace", fromlist=["Recorder"]).Recorder.start(
        repo,
        capture=False,
        pricing={"catalog_hash": "h", "catalog_id": "c", "rate_card_id": "r"},
    )
    recorder.append(TraceEvent("model", 1, "trace", "first", model="past"))
    tool = recorder.append(TraceEvent("tool", 2, "trace", "tool", parent_span_id="first"))
    future = repo.put("blob", b"future", redact=False)
    payload = recorder.payload
    payload["future_secret_blob"] = future
    extended = repo.put("run", payload)
    forked = repo.fork(extended, tool)
    stored = repo.get(forked).payload()
    pricing = json.loads(repo.get(stored["manifests"]["pricing"]).body)
    assert pricing == {"catalog_hash": "h", "catalog_id": "c", "rate_card_id": "r"}
    assert stored["model"] == "past"
    assert "future_secret_blob" not in stored


def test_compatibility_fork_slices_dedicated_pricing_manifest(tmp_path):
    repo = Repo.init(tmp_path)
    source = Run(id="priced")
    first = source.add_step(StepKind.done, {"text": "past"}, model_info="past")
    second = source.add_step(StepKind.done, {"text": "future"}, model_info="future")
    stored = repo.put_run(source)
    first_id, second_id = stored.event_map[first.id], stored.event_map[second.id]
    static = {name: repo.put("blob", name.encode(), redact=False) for name in ("budget", "code")}
    pricing = {
        "catalogs": [
            {"catalog_hash": "past-hash", "catalog_id": "past"},
            {"catalog_hash": "future-hash", "catalog_id": "future"},
        ],
        "invocations": [
            {"catalog_hash": "past-hash", "catalog_id": "past", "step_id": first_id},
            {"catalog_hash": "future-hash", "catalog_id": "future", "step_id": second_id},
        ],
        "rate_cards": {first_id: "past-card", second_id: "future-card"},
    }
    payload = repo.get(stored.run_id).payload()
    source_id = repo.put(
        "run",
        {
            **payload,
            "manifests": {
                **payload["manifests"],
                **static,
                "pricing": repo.put("blob", canonical_json(pricing), redact=False),
            },
        },
    )
    fork = repo.load_run(source_id).fork(first_id)
    saved = repo.put_run(fork)
    manifests = repo.get(saved.run_id).payload()["manifests"]
    sliced = json.loads(repo.get(manifests["pricing"]).body)
    assert [item["step_id"] for item in sliced["invocations"]] == [first_id]
    assert sliced["rate_cards"] == {first_id: "past-card"}
    assert sliced["catalogs"] == [{"catalog_hash": "past-hash", "catalog_id": "past"}]
    assert {name: manifests[name] for name in static} == static


def test_incremental_push_uses_exact_old_closure_not_local_associations(tmp_path, monkeypatch):
    repo = Repo.init(tmp_path)
    manifest = repo.put("blob", b"code", redact=False)
    old = repo.put("run", {"events": [], "manifests": {"code": manifest}, "roots": [], "tips": []})
    repo.put("attestation", {"claim": {}, "signer": "test", "target_id": old})
    new = repo.put(
        "run",
        {
            "events": [],
            "manifests": {"code": manifest},
            "roots": [],
            "status": "running",
            "tips": [],
        },
    )
    repo.update_ref("heads/main", new, expected_old=None)
    captured = {}

    def request_json(_client, method, url, **_kwargs):
        if method == "GET":
            return 200, {"refs": {"heads/main": old}}
        return 200, {}

    def capture_negotiate(_repo, wants, haves, **_kwargs):
        captured.update(wants=wants, haves=haves)
        return []

    monkeypatch.setattr(repository_client, "_client", lambda *a, **k: nullcontext(object()))
    monkeypatch.setattr(repository_client, "_request_json", request_json)
    monkeypatch.setattr(repository_client, "negotiate", capture_negotiate)
    synthetic_pack = repository_client.MAGIC + b"\x11" * 32
    monkeypatch.setattr(repository_client, "create_pack", lambda *_a, **_k: synthetic_pack)
    monkeypatch.setattr(
        repository_client,
        "_upload",
        lambda *_a, **_k: {"objects": 0, "pack_id": "sha256:" + "11" * 32},
    )
    repository_client.push(repo, "https://remote.example", tenant="acme")
    assert captured["wants"] == [new]
    assert set(captured["haves"]) == {old, manifest}


def test_exact_haves_allow_shallow_repository_to_deepen_and_clear_boundaries(tmp_path):
    source = Repo.init(tmp_path / "source")
    run = Run(id="deep")
    first = run.add_step(StepKind.done, {"text": "first"})
    second = run.add_step(StepKind.done, {"text": "second"})
    stored = source.put_run(run)
    first_id, second_id = stored.event_map[first.id], stored.event_map[second.id]
    clone = Repo.init(tmp_path / "clone")
    clone.import_pack(create_pack(source, [stored.run_id, second_id]))
    assert first_id in clone.shallow_oids()
    missing = negotiate(source, [stored.run_id], clone.iter_oids())
    assert first_id in missing
    clone.import_pack(create_pack(source, missing))
    assert set(reachable(clone, [stored.run_id])) == set(reachable(source, [stored.run_id]))
    assert clone.shallow_oids() == set()


def test_pack_rejects_unreferenced_shallow_boundaries(tmp_path):
    fake = "blob:sha256:" + "0" * 64
    body = canonical_json({"objects": [], "shallow": [fake], "version": 1})
    pack = MAGIC + hashlib.sha256(body).digest() + zlib.compress(body)
    with pytest.raises(KernelError, match="shallow boundaries"):
        Repo.init(tmp_path).import_pack(pack)


def test_marked_compatibility_annotation_survives_unrelated_root_on_clone(tmp_path):
    origin = Repo.init(tmp_path / "origin")
    run = Run(id="run", metadata={"selected": True})
    run.add_step(StepKind.done, {"text": "ok"})
    stored = origin.put_run(run)
    origin.put(
        "annotation",
        {"previous_id": None, "target_id": stored.run_id, "value": {"other": True}},
    )
    clone = Repo.init(tmp_path / "clone")
    clone.import_pack(origin.pack())
    assert clone.load_run(stored.run_id).metadata == {"selected": True}


def test_shallow_run_still_validates_every_present_event(tmp_path):
    outside = ObjectEnvelope.create(
        "event", {"causal_ids": [], "parent_ids": [], "span_id": "outside"}
    )
    missing = ObjectEnvelope.create(
        "event", {"causal_ids": [], "parent_ids": [], "span_id": "missing"}
    )
    bad = ObjectEnvelope.create("event", {"causal_ids": [], "parent_ids": [outside.oid]})
    run = ObjectEnvelope.create(
        "run",
        {
            "events": [bad.oid, missing.oid],
            "manifests": {},
            "roots": [],
            "tips": [bad.oid],
        },
    )
    entries = [
        {"data": base64.b64encode(item.encode()).decode(), "id": item.oid} for item in (bad, run)
    ]
    body = canonical_json(
        {"objects": entries, "shallow": sorted([outside.oid, missing.oid]), "version": 1}
    )
    pack = MAGIC + hashlib.sha256(body).digest() + zlib.compress(body)
    with pytest.raises(KernelError, match="parent outside"):
        Repo.init(tmp_path / "clone").import_pack(pack)
