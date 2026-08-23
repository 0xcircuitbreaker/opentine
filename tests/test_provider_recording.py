"""Provider is recorded data, not a cost artifact and not an adapter's secret.

Until 0.8.0 the only place a run said *who served the call* was
``billing["calculation"]["provider"]`` -- a field the meter writes, which means
identity existed only where cost did.  An unmetered run, and every run imported
from OTel (the importer read the model keys and walked past ``gen_ai.system``),
carried no provider at all and so could never be priced afterwards: cost was a
function of the adapter that happened to be in memory, not of the record.

These tests hold the other half of the model identity to the same contract
``causal_ids`` got in 0.7.2 -- a plain ``Step`` field, written by both formats
only when non-empty, read back by both loaders, and never touched by verify,
fork, diff or replay.  The "only when non-empty" half is the compatibility gate:
a pre-0.8.0 artifact has no provider, must load as ``""``, and must re-serialize
to exactly the bytes it arrived as.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from opentine import Repo, Run, StepKind
from opentine._step_serde import step_from_dict, step_to_dict
from opentine.billing import Usage
from opentine.models._metered import metered_response
from opentine.runtime import Agent
from opentine.trace import _genai_semconv as semconv
from opentine.trace import otel_genai_events, to_otel_genai
from opentine.trace.recorder import Recorder

COMPAT = Path(__file__).parent / "fixtures" / "compat"
RELEASED = sorted(path.name for path in COMPAT.iterdir() if (path / "artifact.tine").is_file())


def _span(**attributes: object) -> dict:
    """One OTLP/JSON span carrying *attributes* as string values."""
    return {
        "name": "chat",
        "traceId": "t",
        "spanId": "s",
        "attributes": [
            {"key": key, "value": {"stringValue": str(value)}} for key, value in attributes.items()
        ],
    }


# --- WS1: the provider a native run was served by ------------------------------


def test_a_metered_native_run_records_its_provider_on_the_step():
    """The value the meter puts in ``billing.calculation`` lands on the step too.

    Reverted, the provider is reachable only by digging through a cost artifact
    that an unmetered or rate-carded-elsewhere run may not even have.
    """

    class MeteredModel:
        name = "kimi-k2.6"
        supports_tools = True
        supports_thinking = True

        async def complete(self, messages, tools=None, system=None, temperature=0.0):
            return {
                "text": "done",
                "tool_calls": [],
                **metered_response("kimi", self.name, Usage(input=10, output=2)),
            }

    run = Agent(MeteredModel()).run_sync("go")
    step = run.steps[-1]
    assert step.provider == "kimi"
    # The same string, from the two places that must not disagree.
    assert step.billing["calculation"]["provider"] == step.provider
    assert step.model_info == "kimi-k2.6", "provider is the other half, not a replacement"


def test_a_provider_survives_the_tine_round_trip(tmp_path):
    run = Run(id="provider-tine")
    run.add_step(StepKind.model, {"text": "hi"}, {"text": "yo"}, provider="glm-cn")
    path = run.save(tmp_path / "run.tine")

    assert json.loads(path.read_text())["graph"]["steps"].popitem()[1]["provider"] == "glm-cn"
    assert [step.provider for step in Run.load(path).steps] == ["glm-cn"]


def test_a_provider_survives_a_repository_export_and_a_rebuild(tmp_path):
    """The writer/writer leg: repository -> ``.tine`` -> a *fresh* repository."""
    source = Run(id="provider-v3")
    source.add_step(StepKind.model, {"text": "hi"}, {"text": "yo"}, provider="anthropic")
    repo = Repo.init(tmp_path / "repo")
    stored = repo.load_run(repo.put_run(source, ref="heads/main").run_id)
    assert [step.provider for step in stored.steps] == ["anthropic"]

    target = Repo.init(tmp_path / "target")
    exported = Run.load(stored.save(tmp_path / "round.tine"))
    rebuilt = target.load_run(target.put_run(exported, ref="heads/main").run_id)
    assert [step.provider for step in rebuilt.steps] == ["anthropic"]


def test_a_step_without_a_provider_writes_no_provider_key(tmp_path):
    """Absent, not empty: an unconditional key would re-address every v3 event
    and change every stored ``.tine`` byte, for a field that is always ``""``."""
    run = Run(id="no-provider")
    step = run.add_step(StepKind.model, {"text": "hi"})
    assert "provider" not in step_to_dict(step)

    repo = Repo.init(tmp_path / "repo")
    result = repo.put_run(run, ref="heads/main")
    event = repo.get(next(iter(result.event_map.values()))).payload()
    assert "provider" not in event


@pytest.mark.parametrize("version", RELEASED)
def test_a_released_artifact_loads_empty_and_re_serializes_byte_for_byte(version: str):
    """The compatibility gate, at the granularity the new field can break it."""
    raw = json.loads((COMPAT / version / "artifact.tine").read_text())
    run = Run.load(COMPAT / version / "artifact.tine")

    assert {step.provider for step in run.steps} == {""}
    assert {
        step_id: step_to_dict(run.graph.steps[step_id]) for step_id in raw["graph"]["steps"]
    } == raw["graph"]["steps"]


def test_a_foreign_provider_of_the_wrong_shape_loads_as_empty():
    """Nothing validates this field, so a wrong shape must not fail the load."""
    record = {"id": "x", "kind": "model", "inputs": {}, "provider": {"name": "openai"}}
    assert step_from_dict(record).provider == ""
    assert step_from_dict({"id": "x", "kind": "model", "inputs": {}}).provider == ""


# --- WS2: the provider an imported span was served by --------------------------


@pytest.mark.parametrize("key", [semconv.SYSTEM, semconv.PROVIDER_NAME])
def test_a_span_naming_its_provider_imports_with_it(key: str):
    """Both convention spellings: 1.27 ``gen_ai.system``, 1.36 ``gen_ai.provider.name``.

    Reverted, ``otel_genai_events`` drops the attribute on the floor and the
    imported run is unpriceable -- the gap that made every imported trace a
    record of tokens with no rate card they could ever be charged against.
    """
    event = otel_genai_events([_span(**{key: "anthropic"})])[0]
    assert event.provider == "anthropic"


def test_a_span_without_a_provider_imports_cleanly():
    event = otel_genai_events([_span(**{semconv.REQUEST_MODEL: "some-model"})])[0]
    assert event.provider == "" and event.model == "some-model"


def test_an_exported_span_carries_the_provider_and_re_imports_to_it():
    run = Run(id="provider-otel")
    run.add_step(StepKind.model, {"text": "hi"}, {"text": "yo"}, provider="anthropic")
    spans = to_otel_genai(run)

    keys = {item["key"]: item["value"] for item in spans[0]["attributes"]}
    assert keys[semconv.SYSTEM] == {"stringValue": "anthropic"}
    assert otel_genai_events(spans)[0].provider == "anthropic"
    # Export stays a fixed point: the imported span re-exports to itself, with
    # one provider attribute rather than a second copy beside the first.
    assert to_otel_genai(otel_genai_events(spans)) == spans


def test_an_imported_provider_reaches_the_recorded_step(tmp_path):
    """Import writes it into the v3 event, so the loaded step carries it."""
    events = otel_genai_events([_span(**{semconv.SYSTEM: "openai"})])
    recorder = Recorder.start(Repo.init(tmp_path / "imported"), ref="heads/main", capture=False)
    recorder.import_events(events)
    run = recorder.repo.load_run(recorder.finalize())

    assert [step.provider for step in run.steps] == ["openai"]


# --- WS6: the two CLI contracts that surface it --------------------------------


def _one_step_run(run_id: str, *, provider: str = "", model: str = "some-model") -> Run:
    run = Run(id=run_id, model_info=model)
    run.add_step(
        StepKind.model, {"text": "hi"}, {"text": "yo"}, model_info=model, provider=provider
    )
    return run


def test_the_json_step_view_carries_the_provider(tmp_path, capsys):
    """``tine show --json`` is the machine view of a step; identity belongs in it."""
    from opentine import cli

    run = _one_step_run("provider-json", provider="glm-cn")
    run.add_step(StepKind.tool, {"text": "grep"}, tool_info={"name": "grep"})
    path = run.save(tmp_path / "run.tine")

    cli.main(["show", str(path), "--json"])

    steps = json.loads(capsys.readouterr().out)["steps"]
    # Additive: the step that never named a provider reports ``""``, not a
    # missing key, so a reader can rely on the field being there.
    assert [step["provider"] for step in steps] == ["glm-cn", ""]


def test_repo_diff_reports_a_changed_provider(tmp_path, capsys):
    """The same model id served by someone else is a difference worth naming."""
    from opentine import cli

    repo = Repo.init(tmp_path / "repo")
    repo.put_run(_one_step_run("served-here", provider="deepseek"), ref="heads/main")
    repo.put_run(_one_step_run("served-there", provider="openrouter"), ref="heads/other")

    cli.main(["repo-diff", "heads/main", "heads/other", "--repo", str(tmp_path / "repo"), "--json"])

    changed = json.loads(capsys.readouterr().out)["changed"]
    assert [change["fields"] for change in changed] == [["provider"]]


def test_two_runs_with_no_provider_do_not_diff_on_it(tmp_path, capsys):
    """The compatibility half: ``""`` against ``""`` is not a change, and a run
    that differs elsewhere must not grow a spurious ``provider`` field."""
    from opentine import cli

    repo = Repo.init(tmp_path / "repo")
    repo.put_run(_one_step_run("no-provider-left", model="one"), ref="heads/main")
    repo.put_run(_one_step_run("no-provider-right", model="two"), ref="heads/other")

    cli.main(["repo-diff", "heads/main", "heads/other", "--repo", str(tmp_path / "repo"), "--json"])

    changed = json.loads(capsys.readouterr().out)["changed"]
    assert [change["fields"] for change in changed] == [["model"]]
