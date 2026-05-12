"""Tests for opentine core: Step, Run, fork, serialization, Agent."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

from opentine.core import (
    Agent,
    FilesystemPolicy,
    NetworkPolicy,
    PythonPolicy,
    Run,
    RunStatus,
    ShellPolicy,
    StepKind,
    step_id,
    tool_schema,
)
from opentine.tools import fs, python, shell, web

# --- Step -------------------------------------------------------------------


class TestStep:
    def test_content_addressing_deterministic(self):
        a = step_id(StepKind.think, {"text": "hello"})
        b = step_id(StepKind.think, {"text": "hello"})
        assert a == b

    def test_content_addressing_differs_on_input(self):
        a = step_id(StepKind.think, {"text": "hello"})
        b = step_id(StepKind.think, {"text": "world"})
        assert a != b

    def test_content_addressing_differs_on_kind(self):
        a = step_id(StepKind.think, {"text": "hello"})
        b = step_id(StepKind.tool, {"text": "hello"})
        assert a != b

    def test_content_addressing_differs_on_parent(self):
        a = step_id(StepKind.think, {"text": "hello"}, parent_id="abc")
        b = step_id(StepKind.think, {"text": "hello"}, parent_id="def")
        assert a != b

    def test_step_id_is_full_hash(self):
        sid = step_id(StepKind.think, {"text": "hello"})
        assert len(sid) == 64

    def test_content_addressing_includes_outputs(self):
        a = step_id(StepKind.tool, {"name": "x"}, outputs={"result": "a"})
        b = step_id(StepKind.tool, {"name": "x"}, outputs={"result": "b"})
        assert a != b


# --- Run tree operations ----------------------------------------------------


class TestRun:
    def _make_run(self) -> Run:
        run = Run(id="test_run")
        run.add_step(StepKind.think, {"text": "thinking..."})
        run.add_step(StepKind.tool, {"name": "search", "arguments": {"q": "test"}})
        run.add_step(StepKind.think, {"text": "processing..."})
        run.add_step(StepKind.done, {"text": "done!"})
        return run

    def test_add_step_builds_chain(self):
        run = self._make_run()
        assert len(run.steps) == 4
        for i in range(1, len(run.steps)):
            assert run.steps[i].parent_id == run.steps[i - 1].id

    def test_root_steps(self):
        run = self._make_run()
        roots = run.root_steps()
        assert len(roots) == 1
        assert roots[0].id == run.steps[0].id

    def test_get_step(self):
        run = self._make_run()
        s = run.get_step(run.steps[2].id)
        assert s is not None
        assert s.kind == StepKind.think

    def test_get_step_missing(self):
        run = self._make_run()
        assert run.get_step("nonexistent") is None

    def test_children(self):
        run = self._make_run()
        kids = run.children(run.steps[0].id)
        assert len(kids) == 1
        assert kids[0].id == run.steps[1].id

    def test_ancestors(self):
        run = self._make_run()
        anc = run.ancestors(run.steps[3].id)
        assert len(anc) == 4
        assert anc[0].id == run.steps[0].id
        assert anc[-1].id == run.steps[3].id

    def test_graph_branch_common_ancestor_and_diff(self):
        run = Run(id="branchy")
        root = run.add_step(StepKind.think, {"text": "root"})
        left = run.add_step(StepKind.tool, {"name": "left"}, parent_id=root.id, ref="left")
        right = run.add_step(StepKind.tool, {"name": "right"}, parent_id=root.id, ref="right")
        assert run.common_ancestor(left.id, right.id).id == root.id

        forked = run.fork(root.id, new_run_id="forked")
        forked.add_step(StepKind.done, {"text": "new"})
        diff = run.diff(forked)
        assert diff.common_ancestor == root.id
        assert any(step.inputs.get("name") == "left" for step in diff.only_a)
        assert any(step.inputs.get("text") == "new" for step in diff.only_b)

    def test_total_cost(self):
        run = Run(id="cost_test")
        run.add_step(StepKind.think, {"text": "a"}, cost=0.001)
        run.add_step(StepKind.done, {"text": "b"}, cost=0.002)
        assert abs(run.total_cost - 0.003) < 1e-9

    def test_total_duration(self):
        run = Run(id="dur_test")
        run.add_step(StepKind.think, {"text": "a"}, duration=1.0)
        run.add_step(StepKind.done, {"text": "b"}, duration=2.0)
        assert abs(run.total_duration - 3.0) < 1e-9


# --- Fork -------------------------------------------------------------------


class TestFork:
    def test_fork_preserves_ancestors(self):
        run = Run(id="original")
        run.add_step(StepKind.think, {"text": "step1"})
        run.add_step(StepKind.tool, {"name": "t", "arguments": {}})
        run.add_step(StepKind.think, {"text": "step3"})
        run.add_step(StepKind.done, {"text": "step4"})

        forked = run.fork(run.steps[1].id, new_run_id="forked")
        assert forked.id == "forked"
        assert len(forked.steps) == 2
        assert forked.steps[0].id == run.steps[0].id
        assert forked.steps[1].id == run.steps[1].id
        assert forked.status == RunStatus.running

    def test_fork_metadata(self):
        run = Run(id="orig")
        run.add_step(StepKind.think, {"text": "x"})
        forked = run.fork(run.steps[0].id)
        assert forked.metadata["forked_from"] == "orig"
        assert forked.metadata["fork_point"] == run.steps[0].id

    def test_fork_inherits_prompts(self):
        run = Run(id="orig", system_prompt="sys", user_prompt="user")
        run.add_step(StepKind.think, {"text": "x"})
        forked = run.fork(run.steps[0].id)
        assert forked.system_prompt == "sys"
        assert forked.user_prompt == "user"

    def test_fork_missing_step_ref_fails(self):
        run = Run(id="original")
        run.add_step(StepKind.think, {"text": "step1"})
        try:
            run.fork("missing")
        except KeyError as exc:
            assert "Unknown step ref" in str(exc)
        else:
            raise AssertionError("fork should reject missing refs")


# --- Serialization ----------------------------------------------------------


class TestSerialization:
    def test_save_load_roundtrip(self, tmp_path: Path):
        run = Run(id="serial_test", model_info="test-model")
        run.add_step(StepKind.think, {"text": "hello"}, cost=0.01)
        run.add_step(StepKind.done, {"text": "bye"})

        path = run.save(tmp_path / "test.tine")
        loaded = Run.load(path)
        assert loaded.id == "serial_test"
        assert len(loaded.steps) == 2
        assert loaded.steps[0].cost == 0.01
        assert loaded.model_info == "test-model"

    def test_pause_resume(self, tmp_path: Path):
        run = Run(id="pause_test")
        run.add_step(StepKind.think, {"text": "wip"})

        path = run.pause(tmp_path / "paused.tine")
        assert run.status == RunStatus.paused

        resumed = Run.resume(path)
        assert resumed.status == RunStatus.running
        assert resumed.id == "pause_test"
        assert len(resumed.steps) == 1

    def test_tine_file_is_valid_json(self, tmp_path: Path):
        run = Run(id="json_test")
        run.add_step(StepKind.done, {"text": "ok"})
        path = run.save(tmp_path / "check.tine")
        data = json.loads(path.read_text())
        assert data["format_version"] == 1
        assert data["run_id"] == "json_test"
        expected = {"graph", "refs", "transcript", "manifest", "policies", "cache", "metadata"}
        assert expected.issubset(data)
        assert data["metadata"]["integrity"]["algorithm"] == "sha256"
        assert Run.verify_integrity(path).ok

    def test_old_linear_format_is_rejected(self, tmp_path: Path):
        path = tmp_path / "old.tine"
        path.write_text(json.dumps({"id": "old", "steps": []}), encoding="utf-8")
        try:
            Run.load(path)
        except ValueError as exc:
            assert "Unsupported .tine format_version" in str(exc)
        else:
            raise AssertionError("old linear .tine format should be rejected")

    def test_future_format_is_rejected(self, tmp_path: Path):
        run = Run(id="future_test")
        run.add_step(StepKind.done, {"text": "ok"})
        path = run.save(tmp_path / "future.tine")
        data = json.loads(path.read_text(encoding="utf-8"))
        data["format_version"] = 2
        path.write_text(json.dumps(data), encoding="utf-8")

        result = Run.verify_integrity(path)
        assert not result.ok
        assert "unsupported .tine format_version=2" in result.reason
        try:
            Run.load(path)
        except ValueError as exc:
            assert "Unsupported .tine format_version=2" in str(exc)
        else:
            raise AssertionError("future .tine format should be rejected")

    def test_integrity_verification_detects_mismatch(self, tmp_path: Path):
        run = Run(id="integrity_test")
        run.add_step(StepKind.done, {"text": "ok"})
        path = run.save(tmp_path / "integrity.tine")

        data = json.loads(path.read_text(encoding="utf-8"))
        data["graph"]["steps"][run.steps[0].id]["inputs"]["text"] = "tampered"
        path.write_text(json.dumps(data), encoding="utf-8")

        result = Run.verify_integrity(path)
        assert not result.ok
        assert result.algorithm == "sha256"
        assert result.expected
        assert result.actual
        assert result.expected != result.actual
        assert result.reason == "digest mismatch"

    def test_integrity_verification_rejects_missing_or_malformed_digest(self, tmp_path: Path):
        run = Run(id="integrity_missing")
        run.add_step(StepKind.done, {"text": "ok"})
        path = run.save(tmp_path / "missing.tine")

        data = json.loads(path.read_text(encoding="utf-8"))
        data["metadata"].pop("integrity")
        assert Run.verify_integrity(data).reason == "missing integrity digest"

        data["metadata"]["integrity"] = {"algorithm": "sha256", "digest": "not-a-digest"}
        result = Run.verify_integrity(data)
        assert not result.ok
        assert result.reason == "malformed digest"

        data["metadata"]["integrity"] = {"algorithm": "sha512", "digest": "0" * 64}
        result = Run.verify_integrity(data)
        assert not result.ok
        assert result.reason == "unsupported algorithm"

    def test_save_redacts_common_secret_keys(self, tmp_path: Path):
        run = Run(id="redact_test")
        run.add_step(
            StepKind.tool,
            {
                "name": "call_api",
                "arguments": {"api_key": "shh-value", "nested": {"token": "bearer-value"}},
            },
        )
        path = run.save(tmp_path / "redacted.tine")
        text = path.read_text(encoding="utf-8")
        assert "shh-value" not in text
        assert "bearer-value" not in text
        assert "[REDACTED]" in text


# --- Tool schema ------------------------------------------------------------


class TestToolSchema:
    def test_basic_function(self):
        def greet(name: str, loud: bool = False) -> str:
            """Say hello to someone."""
            return f"Hello, {name}!"

        schema = tool_schema(greet)
        assert schema["name"] == "greet"
        assert schema["description"] == "Say hello to someone."
        assert "name" in schema["input_schema"]["properties"]
        assert schema["input_schema"]["required"] == ["name"]

    def test_no_docstring(self):
        def bare(x: int):
            pass

        schema = tool_schema(bare)
        assert schema["description"] == ""


# --- Agent with mock model --------------------------------------------------


class MockModel:
    def __init__(self, responses: list[dict[str, Any]]):
        self._responses = list(responses)
        self._idx = 0

    @property
    def name(self) -> str:
        return "mock-model"

    @property
    def supports_tools(self) -> bool:
        return True

    @property
    def supports_thinking(self) -> bool:
        return False

    async def complete(self, messages, tools=None, system=None, temperature=0.0):
        resp = self._responses[self._idx]
        self._idx = min(self._idx + 1, len(self._responses) - 1)
        return resp

    async def stream(
        self, messages, tools=None, system=None, temperature=0.0
    ) -> AsyncIterator[dict[str, Any]]:
        yield await self.complete(messages, tools, system, temperature)


class TestAgent:
    def test_simple_completion(self):
        model = MockModel([{"text": "The answer is 42.", "tool_calls": []}])
        agent = Agent(model=model)
        run = agent.run_sync("What is the answer?")
        assert run.status == RunStatus.completed
        assert len(run.steps) == 1
        assert run.steps[0].kind == StepKind.done

    def test_tool_call_flow(self):
        def add(a: int, b: int) -> int:
            """Add two numbers."""
            return a + b

        model = MockModel(
            [
                {
                    "text": "Let me add those.",
                    "tool_calls": [{"name": "add", "arguments": {"a": 2, "b": 3}}],
                },
                {"text": "The sum is 5.", "tool_calls": []},
            ]
        )
        agent = Agent(model=model, tools=[add])
        run = agent.run_sync("Add 2 and 3")
        assert run.status == RunStatus.completed
        assert any(s.kind == StepKind.tool for s in run.steps)
        assert any(s.kind == StepKind.done for s in run.steps)
        assert any(entry["kind"] == "model.complete" for entry in run.cache.values())
        assert any(entry["kind"] == "tool.call" for entry in run.cache.values())

    def test_cached_replay_marks_provenance(self):
        model = MockModel([{"text": "done", "tool_calls": []}])
        agent = Agent(model=model)
        run = agent.run_sync("Do it")
        replayed = agent.replay_sync(run, mode="cache")
        assert replayed.metadata["replay"]["mode"] == "cache"
        assert replayed.metadata["replay"]["reused_steps"] == len(run.steps)

    def test_max_steps_exceeded(self):
        model = MockModel(
            [
                {"text": "loop", "tool_calls": [{"name": "noop", "arguments": {}}]},
            ]
        )

        def noop() -> str:
            """Do nothing."""
            return "ok"

        agent = Agent(model=model, tools=[noop], max_steps=3)
        run = agent.run_sync("Loop forever")
        assert run.status == RunStatus.failed
        assert any(s.kind == StepKind.error for s in run.steps)

    def test_tool_error_handling(self):
        def explode() -> str:
            """Always fails."""
            raise ValueError("boom")

        model = MockModel(
            [
                {"text": "Calling tool.", "tool_calls": [{"name": "explode", "arguments": {}}]},
                {"text": "That failed.", "tool_calls": []},
            ]
        )
        agent = Agent(model=model, tools=[explode])
        run = agent.run_sync("Do the thing")
        assert run.status == RunStatus.completed
        assert any(s.kind == StepKind.error for s in run.steps)


class TestSecurity:
    def test_path_prefix_bypass_rejected(self, tmp_path: Path):
        root = tmp_path / "root"
        root.mkdir()
        outside = tmp_path / "root_evil"
        outside.mkdir()
        (outside / "x.txt").write_text("no", encoding="utf-8")
        try:
            fs.read(str(outside / "x.txt"), policy=FilesystemPolicy(roots=(str(root),)))
        except ValueError:
            pass
        else:
            raise AssertionError("absolute sibling path should not pass prefix check")

    def test_symlink_escape_rejected(self, tmp_path: Path):
        root = tmp_path / "root"
        root.mkdir()
        outside = tmp_path / "secret.txt"
        outside.write_text("secret", encoding="utf-8")
        (root / "link").symlink_to(outside)
        try:
            fs.read("link", policy=FilesystemPolicy(roots=(str(root),), deny_symlinks=True))
        except PermissionError:
            pass
        else:
            raise AssertionError("symlink escape should be denied")

    def test_private_network_hosts_are_blocked(self):
        try:
            web._check_url("https://127.0.0.1/private", NetworkPolicy())
        except PermissionError as exc:
            assert "Private/link-local/loopback host denied" in str(exc)
        else:
            raise AssertionError("private network hosts should be denied by default")

    def test_shell_disabled_by_default(self):
        assert "disabled by policy" in shell.run("python3 -c 'print(1)'")

    def test_shell_allowlist_and_output_cap(self):
        out = shell.run(
            "python3 -c 'print(\"x\" * 100)'",
            policy=ShellPolicy(enabled=True, executables=("python3",), max_output_chars=20),
        )
        assert "truncated" in out

    def test_shell_env_isolated_by_default(self, monkeypatch):
        monkeypatch.setenv("SECRET_TOKEN", "leak")
        out = shell.run(
            'python3 -c \'import os; print(os.environ.get("SECRET_TOKEN", "missing"))\'',
            policy=ShellPolicy(enabled=True, executables=("python3",)),
        )
        assert out == "missing"

    def test_shell_windows_python3_alias_handles_single_quotes(self, monkeypatch):
        monkeypatch.setattr(shell.sys, "platform", "win32")
        out = shell.run(
            "python3 -c 'print(\"ok\")'",
            policy=ShellPolicy(enabled=True, executables=("python3",)),
        )
        assert out == "ok"

    def test_python_disabled_env_scrubbed_and_output_capped(self, monkeypatch):
        monkeypatch.setenv("SECRET_TOKEN", "leak")
        assert "disabled by policy" in python.execute("print('x')")
        out = python.execute(
            "import os; print(os.environ.get('SECRET_TOKEN', 'missing'))",
            policy=PythonPolicy(enabled=True),
        )
        assert out == "missing"
        capped = python.execute(
            "print('x' * 100)",
            policy=PythonPolicy(enabled=True, max_output_chars=20),
        )
        assert "truncated" in capped
