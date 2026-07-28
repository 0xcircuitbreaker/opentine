"""End-to-end agent record, fork, evaluate, promote, and clone workflow."""

from __future__ import annotations

import threading
from wsgiref.simple_server import make_server

import pytest

from opentine import Agent, Run
from opentine._jsonsafe import json_safe
from opentine.kernel import KernelError
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
from opentine.repository import Repo
from opentine.repository.client import clone as clone_remote
from opentine.repository.pack import reachable
from opentine.trace import Recorder, TraceEvent


@pytest.mark.parametrize(
    "kwargs,match",
    [
        ({"timestamp": float("nan")}, "timestamp must be finite"),
        ({"usage": {"input": -1}}, "usage.input must be finite and non-negative"),
        ({"usage": {"input": "1"}}, "usage.input must be finite and non-negative"),
        ({"usage": {"input": 1e20}}, "usage.input must be finite and non-negative"),
    ],
)
def test_trace_event_rejects_invalid_metrics_before_recording(kwargs, match):
    values = {"kind": "model", "timestamp": 0, "trace_id": "t", "span_id": "s"}
    values.update(kwargs)
    with pytest.raises(ValueError, match=match):
        TraceEvent(**values)


@pytest.mark.parametrize("field", ["inputs", "outputs", "billing", "attributes"])
def test_trace_event_rejects_non_mapping_payload_fields(field):
    values = {"kind": "model", "timestamp": 0, "trace_id": "t", "span_id": "s"}
    values[field] = ["not", "a", "mapping"]
    with pytest.raises(ValueError, match=rf"trace {field} must be a mapping"):
        TraceEvent(**values)


def test_trace_event_wraps_extreme_usage_integer_as_value_error():
    with pytest.raises(ValueError, match="trace usage.input"):
        TraceEvent("model", 0, "t", "s", usage={"input": 10**4000})


def test_json_safe_bounds_extreme_integer_values_and_keys_without_collision():
    first = 10**5000
    second = first + 1
    converted = json_safe({first: first, "second": second})
    key = next(name for name in converted if name != "second")
    assert key.startswith("[BIGINT:+")
    assert converted[key].startswith("[BIGINT:+")
    assert converted[key] != converted["second"]
    with pytest.raises(ValueError, match="mapping keys collide"):
        json_safe({1: "integer", "1": "string"})


def test_recorder_and_repository_reject_unreadable_run_status_before_mutation(tmp_path):
    repo = Repo.init(tmp_path)
    recorder = Recorder.start(repo, capture=False)
    before = set(repo.iter_oids())
    ref_before = repo.read_ref("heads/main")

    with pytest.raises(ValueError, match="invalid run status"):
        recorder.finalize("garbage")
    assert set(repo.iter_oids()) == before
    assert repo.read_ref("heads/main") == ref_before

    payload = dict(recorder.payload)
    payload["status"] = "garbage"
    with pytest.raises(KernelError, match="run status is invalid"):
        repo.put("run", payload)


def _event(span: str, *, parent: str | None = None, output: str = "ok") -> TraceEvent:
    return TraceEvent(
        "model",
        1.0,
        "trace-1",
        span,
        parent_span_id=parent,
        model="kimi-k2.6",
        inputs={"prompt": "hello", "api_key": "secret"},
        outputs={"text": output},
        usage={"input": 5, "output": 2},
        billing={"status": "complete", "known_subtotal_usd": "0.00001"},
    )


def test_recorder_append_does_not_rewalk_all_prior_events(tmp_path, monkeypatch):
    repo = Repo.init(tmp_path)
    recorder = Recorder.start(repo, capture=False)
    original_get = repo.get
    reads = 0

    def counted(oid):
        nonlocal reads
        reads += 1
        return original_get(oid)

    monkeypatch.setattr(repo, "get", counted)
    for index in range(50):
        recorder.append(_event(f"incremental-{index}"))
    assert reads == 50
    assert len(recorder.payload["events"]) == 50
    assert len(original_get(recorder.run_id).payload()["events"]) == 50


def test_recorder_rejects_a_span_map_pointing_outside_its_run(tmp_path):
    repo = Repo.init(tmp_path)
    first = Recorder.start(repo, ref="heads/main", capture=False)
    other = Recorder.start(repo, ref="experiments/other", capture=False)
    foreign = other.append(_event("foreign"))

    with pytest.raises(ValueError, match="outside the run"):
        Recorder(repo, first.run_id, first.ref, {("trace-1", "foreign"): foreign})


def test_compatibility_load_converts_verified_decimal_string_metrics(tmp_path):
    repo = Repo.init(tmp_path)
    recorder = Recorder.start(repo, capture=False)
    recorder.append(
        TraceEvent(
            "model",
            1.0,
            "trace-decimal",
            "span-decimal",
            cost="0.125",
            duration="0.25",  # type: ignore[arg-type]
        )
    )
    run_id = recorder.finalize()

    step = repo.load_run(run_id).steps[0]
    assert step.cost == 0.125 and step.duration == 0.25


def test_multi_agent_repository_workflow(tmp_path):
    repo = Repo.init(tmp_path / "origin")
    recorder = Recorder.start(repo, capture=False, pricing={"catalog_id": "test"})
    first = recorder.append(_event("span-1"))
    second = recorder.append(_event("span-2", parent="span-1"))
    original = recorder.finalize()

    fork = recorder.fork(first, ref="experiments/alternate", model="glm-5.1")
    fork.append(_event("span-3", output="alternate"))
    alternate = fork.finalize()
    evaluation = fork.evaluate({"quality": 0.9}, evaluator="judge")
    approval = fork.approve(approver="reviewer", note="accepted")
    fork.promote("production")
    repo.update_ref("heads/main", alternate, expected_old=original)

    assert repo.read_ref("promotions/production") == alternate
    assert repo.get(evaluation).payload()["target_id"] == alternate
    assert repo.get(approval).payload()["claim"]["kind"] == "approval"
    assert evaluation in reachable(repo, [alternate])
    assert approval in reachable(repo, [alternate])
    assert [entry.oid for entry in repo.context_slice(second)] == [first, second]
    comparison = repo.diff(original, alternate)
    assert comparison.only_right
    assert comparison.summary["cost"] == {"left": 0.00002, "right": 0.00002}
    assert comparison.summary["evaluations"]["right"][0]["attestation"] == evaluation

    clone = Repo.init(tmp_path / "clone")
    clone.import_pack(repo.pack())
    assert clone.fsck().ok
    assert clone.has(alternate) and clone.has(evaluation) and clone.has(approval)
    inspected = repo.inspect(first, resolve_blobs=True)
    assert inspected["resolved_blobs"]["input_blob"]["api_key"] == "[REDACTED]"

    objects = FilesystemObjectStore(tmp_path / "remote-objects", LocalKeyProvider(b"k" * 32))
    index = SQLiteBackend(tmp_path / "remote.sqlite3")
    identities = StaticTokenIdentityProvider(
        {"writer-token": Identity("writer", "team", ("writer",))}
    )
    app = RemoteApp(
        RemoteService(objects, index, identities, RoleAuthorizationPolicy()),
        tmp_path / "remote-state",
    )
    server = make_server("127.0.0.1", 0, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_port}"
    try:
        pushed = repo.push(url, tenant="team", token="writer-token")
        remote_clone = clone_remote(
            url,
            tmp_path / "remote-clone",
            tenant="team",
            token="writer-token",
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert pushed.ref == "heads/main"
    assert remote_clone.read_ref("heads/main") == alternate
    assert remote_clone.has(evaluation) and remote_clone.has(approval)
    assert remote_clone.fsck().ok

    class ReplayModel:
        name = "replay-only"
        supports_tools = False
        supports_thinking = False

    replayed = Agent(ReplayModel()).replay_sync(Run.load(tmp_path / "remote-clone"))
    assert replayed.status.value == "completed"
    assert replayed.metadata["replay"]["mode"] == "cache"
