"""Release-gate regressions for the fifth v0.3.0 security review."""

from __future__ import annotations

import multiprocessing
import os
import signal
import sqlite3
import sys
import time
from pathlib import Path

import pytest

from opentine import Repo, cli
from opentine._canon import _redact
from opentine.kernel import KernelError
from opentine.redaction import redact_blob
from opentine.remote import _audit_backend
from opentine.remote.backend import SQLiteBackend
from opentine.remote.interfaces import AuditEvent
from opentine.tools._process import run_bounded

_AUDIT_KEY = b"a" * 32


def _event(event_id: str) -> AuditEvent:
    return AuditEvent(event_id, event_id, "acme", "auditor", "read", "ok", {})


def _append_worker(path: str, prefix: str, count: int) -> None:
    backend = SQLiteBackend(path, audit_key=_AUDIT_KEY)
    for index in range(count):
        backend.append(_event(f"{prefix}-{index}"))


def _run(repo: Repo) -> str:
    return repo.put("run", {"events": [], "manifests": {}, "roots": [], "tips": []})


def test_m1_append_refuses_to_anchor_an_unauthenticated_last_row(tmp_path: Path):
    path = tmp_path / "audit.sqlite3"
    backend = SQLiteBackend(path, audit_key=_AUDIT_KEY)
    backend.append(_event("trusted"))
    trusted_head = backend.audit_head()
    with sqlite3.connect(path) as database:
        database.execute(
            "INSERT INTO audit(event_id,timestamp,tenant,actor,action,outcome,details,"
            "prev_hash,row_hash) VALUES(?,?,?,?,?,?,?,?,?)",
            ("forged", "x", "acme", "mallory", "write", "ok", "{}", trusted_head, "f" * 64),
        )
    with pytest.raises(RuntimeError, match="authentication"):
        backend.append(_event("legitimate"))
    assert backend.verify_audit_chain() is False


def test_m1_append_authenticates_the_current_tail_before_extending(tmp_path: Path):
    path = tmp_path / "audit.sqlite3"
    backend = SQLiteBackend(path, audit_key=_AUDIT_KEY)
    backend.append(_event("trusted"))
    with sqlite3.connect(path) as database:
        database.execute("DROP TRIGGER audit_no_update")
        database.execute("UPDATE audit SET details='tampered'")
    with pytest.raises(RuntimeError, match="tail failed authentication"):
        backend.append(_event("next"))


def test_l2_audit_commit_and_anchor_are_serialized_across_processes(tmp_path: Path):
    path = tmp_path / "audit.sqlite3"
    backend = SQLiteBackend(path, audit_key=_AUDIT_KEY)
    context = multiprocessing.get_context("spawn")
    workers = [
        context.Process(target=_append_worker, args=(str(path), prefix, 12))
        for prefix in ("left", "right")
    ]
    for worker in workers:
        worker.start()
    checks = 0
    deadline = time.monotonic() + 30
    while any(worker.is_alive() for worker in workers):
        assert time.monotonic() < deadline
        assert backend.verify_audit_chain()
        checks += 1
    for worker in workers:
        worker.join(30)
        assert worker.exitcode == 0
    recovered = SQLiteBackend(path, audit_key=_AUDIT_KEY)
    assert recovered.verify_audit_chain()
    assert checks
    with sqlite3.connect(path) as database:
        assert database.execute("SELECT count(*) FROM audit").fetchone()[0] == 24


def test_l2_stable_verification_does_not_take_the_exclusive_lock(monkeypatch, tmp_path: Path):
    backend = SQLiteBackend(tmp_path / "audit.sqlite3", audit_key=_AUDIT_KEY)
    backend.append(_event("stable"))

    def forbidden_lock(_path):
        raise AssertionError("stable verification must not take the exclusive audit lock")

    monkeypatch.setattr(_audit_backend, "audit_file_lock", forbidden_lock)
    assert backend.verify_audit_chain()


@pytest.mark.skipif(os.name == "nt", reason="POSIX process-group assertion")
def test_m2_timeout_kills_descendants_and_keeps_bounded_diagnostics():
    script = (
        "import subprocess,sys,time; "
        "p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)']); "
        "print(f'child={p.pid}', flush=True); print('x'*2000, flush=True); "
        "print('critical-error', file=sys.stderr, flush=True); time.sleep(60)"
    )
    result = run_bounded([sys.executable, "-c", script], timeout=0.5, max_chars=180)
    child_pid = int(result.stdout.splitlines()[0].split(b"=", 1)[1])
    try:
        assert result.timed_out
        rendered = result.output(180, prefix="Error: command timed out\n")
        assert len(rendered) <= 180 and "critical-error" in rendered
        for _ in range(40):
            state = Path(f"/proc/{child_pid}/stat")
            if not state.exists() or state.read_text().split()[2] == "Z":
                break
            time.sleep(0.05)
        else:
            pytest.fail("timed-out subprocess descendant is still running")
    finally:
        try:
            os.kill(child_pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def test_l1_run_refs_attestations_and_fsck_enforce_target_types(tmp_path: Path):
    repo = Repo.init(tmp_path)
    blob = repo.put("blob", b"artifact", redact=False)
    run = _run(repo)
    repo.update_ref("tags/artifact", blob)
    repo.update_ref("heads/main", run)
    with pytest.raises(ValueError, match="heads refs require run"):
        repo.update_ref("heads/bad", blob)
    with pytest.raises(ValueError, match="promotions refs require run"):
        repo.promote(blob, "bad")
    with pytest.raises(KernelError, match="target_id must contain a run"):
        repo.attest(blob, {"kind": "approval"}, signer="alice")

    bad_ref = repo.path / "refs" / "heads" / "tampered"
    bad_ref.write_text(blob + "\n", encoding="ascii")
    with pytest.raises(ValueError, match="heads refs require run"):
        repo.read_ref("heads/tampered")
    result = repo.fsck()
    assert not result.ok
    assert any("heads refs require run" in error for error in result.errors)


def test_l3_headers_cannot_use_prose_to_bypass_redaction():
    samples = (
        "authorization: the header field is secret",
        "cookie: the header secret-cookie-value",
    )
    for sample in samples:
        assert redact_blob(sample.encode()).endswith(b"[REDACTED]")
        assert _redact(sample).endswith("[REDACTED]")
    assert redact_blob(b"api_key: how do I rotate it") == b"api_key: how do I rotate it"


def test_l6_truncated_private_key_preserves_separated_trailing_text():
    captured = (
        b"before\n-----BEGIN PRIVATE KEY-----\n"
        b"QUJDREVGR0hJSktMTU5PUA==\n\n"
        b"trailing diagnostics remain\napi_key=still-secret"
    )
    redacted = redact_blob(captured)
    assert b"QUJDREV" not in redacted
    assert b"trailing diagnostics remain" in redacted
    assert b"still-secret" not in redacted


def test_l5_cli_reports_missing_objects_without_a_traceback(monkeypatch, tmp_path, capsys):
    repo = Repo.init(tmp_path)
    missing = "run:sha256:" + "0" * 64
    ref = repo.path / "refs" / "heads" / "missing"
    ref.write_text(missing + "\n", encoding="ascii")
    monkeypatch.setattr(sys, "argv", ["tine", "repo-log", "heads/missing", "--repo", str(tmp_path)])
    with pytest.raises(SystemExit) as exited:
        cli.main()
    captured = capsys.readouterr()
    assert exited.value.code == 1
    assert "repository object is unavailable" in captured.err
    assert "Traceback" not in captured.err


def test_l7_search_rejects_non_string_queries(tmp_path: Path):
    repo = Repo.init(tmp_path)
    with pytest.raises(TypeError, match="query must be a string"):
        repo.search(123)
