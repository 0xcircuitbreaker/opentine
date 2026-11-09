"""``tine export RUN --format run-crate``: a Provenance Run Crate (0.48).

The ``ro-crate-metadata.json`` follows RO-Crate 1.1 and the Workflow Run RO-Crate
profiles 0.5 (https://w3id.org/ro/wfrun/): Process Run Crate, Workflow Run
Crate and Provenance Run Crate. The agent loop is the ``ComputationalWorkflow``
(``#workflow``); the recorded run is its ``CreateAction`` (``#run``) whose result
is the ``.tine`` file pinned by its integrity digest. Each step is a
``HowToStep`` of the workflow, executed by a ``CreateAction`` whose
``instrument`` is the model or tool (``SoftwareApplication``) and tied to its
step by a ``ControlAction``; opentine is the engine whose ``OrganizeAction``
orchestrated them. Like ``ro-crate``, the output is a pure function of the run
file and the opentine version (no clock, host or path):
:mod:`opentine._run_crate_check` validates it.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

from opentine._citation_export import OPENTINE_URL, RO_CRATE_CONTEXT, RO_CRATE_SPEC

WFRUN_CONTEXT = "https://w3id.org/ro/terms/workflow-run/context"
WORKFLOW_RO_CRATE = "https://w3id.org/workflowhub/workflow-ro-crate/1.0"
PROFILES = (
    "https://w3id.org/ro/wfrun/process/0.5",
    "https://w3id.org/ro/wfrun/workflow/0.5",
    "https://w3id.org/ro/wfrun/provenance/0.5",
    WORKFLOW_RO_CRATE,
)
WORKFLOW_TYPES = ["File", "SoftwareSourceCode", "ComputationalWorkflow", "HowTo"]
_STATUS = {"completed": "CompletedActionStatus", "failed": "FailedActionStatus"}


def _iso(stamp: Any) -> str:
    value = float(stamp) if isinstance(stamp, int | float) and not isinstance(stamp, bool) else 0
    return datetime.fromtimestamp(value, tz=UTC).isoformat().replace("+00:00", "Z")


def _ref(oid: str) -> dict[str, str]:
    return {"@id": oid}


def _instrument(step: Any) -> tuple[str, str]:
    tool = getattr(step, "tool_info", {}) or {}
    name = tool.get("name") if isinstance(tool, dict) else None
    if isinstance(name, str) and name:
        return f"#tool-{quote(name, safe='')}", name
    model = getattr(step, "model_info", "") or "opentine"
    return f"#model-{quote(str(model), safe='')}", str(model)


def _steps(run: Any) -> tuple[list[dict], list[dict], list[dict], list[dict], list[float]]:
    howto, actions, controls, tools, times = [], [], [], {}, []
    for i, step in enumerate(getattr(run, "steps", []) or []):
        start = float(getattr(step, "timestamp", 0.0) or 0.0)
        end = start + float(getattr(step, "duration", 0.0) or 0.0)
        times += [start, end]
        tool_id, tool_name = _instrument(step)
        tools.setdefault(tool_id, {"@id": tool_id, "@type": "SoftwareApplication",
                                   "name": tool_name})  # fmt: skip
        kind = str(getattr(getattr(step, "kind", ""), "value", getattr(step, "kind", "")))
        howto.append({"@id": f"#step-{i}", "@type": "HowToStep", "position": str(i),
                      "name": f"{kind} step {step.id}", "workExample": _ref(tool_id)})  # fmt: skip
        status = "FailedActionStatus" if kind == "error" else "CompletedActionStatus"
        actions.append({"@id": f"#action-{i}", "@type": "CreateAction", "name": f"{kind} {step.id}",
                        "instrument": _ref(tool_id), "startTime": _iso(start),
                        "endTime": _iso(end), "actionStatus": status})  # fmt: skip
        controls.append({"@id": f"#control-{i}", "@type": "ControlAction",
                         "instrument": _ref(f"#step-{i}"),
                         "object": _ref(f"#action-{i}")})  # fmt: skip
    return howto, actions, controls, list(tools.values()), times


def to_run_crate(f: dict[str, Any], run: Any) -> dict[str, Any]:
    howto, actions, controls, tools, times = _steps(run)
    created = float(run.created_at) if isinstance(run.created_at, int | float) else 0.0
    status = str(getattr(getattr(run, "status", ""), "value", getattr(run, "status", "")))
    end = max([created, *times])
    run_action = {
        "@id": "#run", "@type": "CreateAction", "name": f"opentine run {f['run_id']}",
        "instrument": _ref("#workflow"), "agent": _ref(OPENTINE_URL),
        "startTime": f["created"], "endTime": _iso(end), "result": [_ref(f["file"])],
        "actionStatus": _STATUS.get(status, "ActiveActionStatus"),
    }  # fmt: skip
    graph: list[dict[str, Any]] = [
        {"@id": "ro-crate-metadata.json", "@type": "CreativeWork", "about": _ref("./"),
         "conformsTo": [_ref(RO_CRATE_SPEC), _ref(WORKFLOW_RO_CRATE)]},
        {"@id": "./", "@type": "Dataset", "name": f"opentine run {f['run_id']}",
         "description": f"Provenance of recorded agent run {f['run_id']}.",
         "datePublished": f["date"], "identifier": f["digest"],
         "conformsTo": [_ref(p) for p in PROFILES], "mainEntity": _ref("#workflow"),
         "hasPart": [_ref("#workflow"), _ref(f["file"])], "mentions": [_ref("#run")]},
        {"@id": "#workflow", "@type": WORKFLOW_TYPES, "name": f"agent loop of {f['run_id']}",
         "programmingLanguage": _ref("#opentine-language"),
         "step": [_ref(h["@id"]) for h in howto]},
        {"@id": "#opentine-language", "@type": "ComputerLanguage", "name": "opentine agent run",
         "url": _ref(OPENTINE_URL), "version": f["version"]},
        {"@id": f["file"], "@type": "File", "name": f"opentine-run:{f['run_id']}",
         "encodingFormat": "application/json", "identifier": f["digest"]},
        {"@id": OPENTINE_URL, "@type": "SoftwareApplication", "name": "opentine",
         "version": f["version"]},
        run_action,
        {"@id": "#orchestrate", "@type": "OrganizeAction", "name": "opentine recording",
         "instrument": _ref(OPENTINE_URL), "result": _ref("#run"),
         "object": [_ref(c["@id"]) for c in controls], "startTime": f["created"]},
        *howto, *actions, *controls, *tools,
    ]  # fmt: skip
    return {"@context": [RO_CRATE_CONTEXT, WFRUN_CONTEXT], "@graph": graph}


__all__ = ["PROFILES", "WFRUN_CONTEXT", "WORKFLOW_RO_CRATE", "to_run_crate"]
