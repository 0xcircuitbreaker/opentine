"""MCP v3 tool registration without requiring an MCP runtime."""

from __future__ import annotations

from opentine.mcp_repository import register_repository_tools
from opentine.repository import Repo
from opentine.trace import Recorder, TraceEvent


class FakeMCP:
    def __init__(self):
        self.tools = {}
        self.resources = {}

    def tool(self):
        def register(function):
            self.tools[function.__name__] = function
            return function

        return register

    def resource(self, uri):
        def register(function):
            self.resources[uri] = function
            return function

        return register


def test_repository_mcp_search_context_fork_resume_evaluate_and_promote(tmp_path):
    repo = Repo.init(tmp_path)
    recorder = Recorder.start(repo, capture=False)
    event = recorder.append(TraceEvent("model", 1, "trace", "span", outputs={"text": "ok"}))
    run = recorder.finalize()

    mcp = FakeMCP()
    register_repository_tools(mcp, str(tmp_path))
    expected = {
        "attest_run",
        "context_slice",
        "evaluate_run",
        "fork_run_v3",
        "inspect_object",
        "promote_run",
        "resume_run_v3",
        "search_runs",
        "semantic_diff",
    }
    assert expected <= set(mcp.tools)
    assert mcp.tools["context_slice"](event)[0]["oid"] == event
    forked = mcp.tools["fork_run_v3"](run, event, "experiments/policy", policy={"tools": ["safe"]})
    fork_payload = repo.get(forked["run_id"]).payload()
    policy_blob = fork_payload["manifests"]["policy"]
    assert b'"safe"' in repo.get(policy_blob).body
    evaluation = mcp.tools["evaluate_run"](run, {"quality": 1.0}, "judge")
    assert repo.has(evaluation["attestation_id"])
    resumed = mcp.tools["resume_run_v3"](run, "experiments/resumed")
    assert repo.get(resumed["run_id"]).payload()["status"] == "running"
    promoted = mcp.tools["promote_run"](run, "accepted")
    assert repo.read_ref(promoted["ref"]) == run
    assert "tine-object://{object_id}" in mcp.resources
