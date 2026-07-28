"""Final repository/API boundary regressions for the v0.3.0 release."""

from __future__ import annotations

import sys

import httpx
import pytest

from opentine import cli
from opentine.kernel import KernelError, ObjectEnvelope
from opentine.mcp_repository import register_repository_tools
from opentine.repository import Repo, _context
from opentine.repository._annotations import validate_annotation_chain


def _empty_run(repo: Repo) -> str:
    return repo.put("run", {"events": [], "manifests": {}, "roots": [], "tips": []})


def _event(repo: Repo, parent: str | None = None, *, note: str = "") -> str:
    return repo.put(
        "event",
        {
            "attributes": {"note": note},
            "causal_ids": [],
            "parent_ids": [parent] if parent else [],
        },
    )


class _MCP:
    def __init__(self) -> None:
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


def test_context_slice_requires_an_event_before_fetching(tmp_path, monkeypatch):
    repo = Repo.init(tmp_path)
    blob = repo.put("blob", b"not an event", redact=False)
    monkeypatch.setattr(repo, "get", lambda _oid: pytest.fail("object was fetched"))
    with pytest.raises(ValueError, match="require an event"):
        repo.context_slice(blob)


def test_context_slice_bounds_aggregate_structured_source_and_output(tmp_path, monkeypatch):
    repo = Repo.init(tmp_path)
    first = _event(repo, note="a" * 256)
    second = _event(repo, first, note="b" * 256)
    combined = repo._object_path(first).stat().st_size + repo._object_path(second).stat().st_size

    monkeypatch.setattr(_context, "MAX_CONTEXT_SOURCE_BYTES", combined - 1)
    with pytest.raises(ValueError, match="structured-source"):
        repo.context_slice(second)

    monkeypatch.setattr(_context, "MAX_CONTEXT_SOURCE_BYTES", combined)
    monkeypatch.setattr(_context, "MAX_CONTEXT_OUTPUT_BYTES", 1)
    with pytest.raises(ValueError, match="output-byte"):
        repo.context_slice(second)


def test_run_only_operations_reject_typed_ids_before_fetching(tmp_path, monkeypatch):
    repo = Repo.init(tmp_path)
    blob = repo.put("blob", b"artifact", redact=False)
    run = _empty_run(repo)
    monkeypatch.setattr(repo, "get", lambda _oid: pytest.fail("object was fetched"))

    with pytest.raises(ValueError, match="run object"):
        repo.diff(blob, run)
    with pytest.raises(ValueError, match="fork point must be an event"):
        repo.fork(run, blob)
    with pytest.raises(ValueError, match="promotions refs require run"):
        repo.promote(blob, "bad")
    with pytest.raises(ValueError, match="heads refs require run"):
        repo.update_ref("heads/main", blob)


def test_mcp_resume_rejects_a_non_run_before_fetching(tmp_path, monkeypatch):
    import opentine.mcp_repository as module

    repo = Repo.init(tmp_path)
    blob = repo.put("blob", b"artifact", redact=False)
    monkeypatch.setattr(module.Repo, "open", classmethod(lambda cls, path=".": repo))
    mcp = _MCP()
    register_repository_tools(mcp, str(tmp_path))
    monkeypatch.setattr(repo, "get", lambda _oid: pytest.fail("object was fetched"))
    with pytest.raises(ValueError, match="resume requires a run"):
        mcp.tools["resume_run_v3"](blob, "heads/main")


def test_repo_log_renders_a_blob_tag_without_treating_bytes_as_a_mapping(
    tmp_path, monkeypatch, capsys
):
    repo = Repo.init(tmp_path)
    blob = repo.put("blob", b"\xffbinary", redact=False)
    repo.update_ref("tags/artifact", blob)
    monkeypatch.setattr(
        sys,
        "argv",
        ["tine", "repo-log", "tags/artifact", "--repo", str(tmp_path)],
    )
    cli.main()
    output = capsys.readouterr().out
    assert blob in output and output.rstrip().endswith("blob")


def test_remote_cli_transport_errors_are_reported_without_tracebacks(monkeypatch, capsys):
    import opentine.repo_cli as module

    def unavailable(*args, **kwargs):
        raise httpx.ConnectError("remote unavailable")

    monkeypatch.setattr(module, "clone", unavailable)
    monkeypatch.setattr(
        sys,
        "argv",
        ["tine", "clone", "https://example.invalid", "target", "--token", "secret"],
    )
    with pytest.raises(SystemExit) as exited:
        cli.main()
    error = capsys.readouterr().err
    assert exited.value.code == 1
    assert "remote unavailable" in error and "Traceback" not in error


@pytest.mark.parametrize(
    "name",
    [
        "heads/Main",
        "heads/main.LOCK",
        "heads/con",
        "tags/aux.txt",
        "heads/trailing.",
        "heads/foo..bar",
        "heads/" + "a" * 241,
    ],
)
def test_ref_names_have_one_portable_cross_platform_spelling(tmp_path, name):
    repo = Repo.init(tmp_path)
    run = _empty_run(repo)
    with pytest.raises(ValueError, match="invalid ref name"):
        repo.update_ref(name, run)


def test_reflog_serialization_failure_cannot_commit_the_ref(tmp_path):
    repo = Repo.init(tmp_path)
    old = repo.put("blob", b"old", redact=False)
    new = repo.put("blob", b"new", redact=False)
    repo.update_ref("tags/main", old)
    with pytest.raises(KernelError, match="Unicode"):
        repo.update_ref("tags/main", new, expected_old=old, actor="\ud800")
    assert repo.read_ref("tags/main") == old
    assert not (repo.path / "refs" / "tags" / "main.lock").exists()
    assert not (repo.path / "refs" / "tags" / "main.new.lock").exists()


def test_malformed_annotation_predecessor_raises_kernel_error():
    prior = ObjectEnvelope.create("annotation", [])
    run_id = "run:sha256:" + "1" * 64
    current = ObjectEnvelope.create(
        "annotation",
        {"previous_id": prior.oid, "target_id": run_id, "value": {}},
    )

    class RepoStub:
        def raw(self, oid):
            assert oid == prior.oid
            return prior.encode()

    with pytest.raises(KernelError, match="same object"):
        validate_annotation_chain(RepoStub(), current)

    class CachedStub:
        def cached_envelope(self, oid):
            assert oid == prior.oid
            return ObjectEnvelope("annotation", 1, b"{", "json")

    with pytest.raises(KernelError, match="previous object is malformed"):
        validate_annotation_chain(CachedStub(), current)


def test_bounded_ref_reader_rejects_noncanonical_and_oversized_files(tmp_path, monkeypatch):
    from opentine.repository import _ref_store

    repo = Repo.init(tmp_path)
    run = _empty_run(repo)
    path = repo.path / "refs" / "heads" / "main"
    path.write_text(" " + run + "\n", encoding="ascii")
    with pytest.raises(KernelError, match="canonically encoded"):
        repo.read_ref("heads/main")

    monkeypatch.setattr(_ref_store, "MAX_REF_BYTES", 8)
    path.write_text(run + "\n", encoding="ascii")
    with pytest.raises(KernelError, match="size limit"):
        repo.read_ref("heads/main")
