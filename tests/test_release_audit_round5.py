"""Release-gate regressions for the fifth v0.3.0 security review."""

from __future__ import annotations

import asyncio
import multiprocessing
import os
import signal
import socket
import sqlite3
import sys
import time
from io import BytesIO
from pathlib import Path

import httpx
import pytest

from opentine import Repo, cli
from opentine._canon import _redact
from opentine.kernel import KernelError
from opentine.policies import NetworkPolicy
from opentine.redaction import redact_blob
from opentine.remote import _audit_backend
from opentine.remote.backend import SQLiteBackend
from opentine.remote.interfaces import AuditEvent
from opentine.tools import _process
from opentine.tools._process import BoundedResult, run_bounded
from opentine.tools.web import _get as web_get

_AUDIT_KEY = b"a" * 32


def _event(event_id: str) -> AuditEvent:
    return AuditEvent(event_id, event_id, "acme", "auditor", "read", "ok", {})


def _append_worker(path: str, prefix: str, count: int) -> None:
    backend = SQLiteBackend(path, audit_key=_AUDIT_KEY)
    for index in range(count):
        backend.append(_event(f"{prefix}-{index}"))


def _run(repo: Repo) -> str:
    return repo.put("run", {"events": [], "manifests": {}, "roots": [], "tips": []})


@pytest.mark.asyncio
async def test_web_fetch_pins_dns_answer_and_preserves_https_identity(monkeypatch):
    resolutions = []
    requests = []

    def resolve(host, port, **kwargs):
        resolutions.append((host, port))
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

    class Body(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b"safe"

    async def handler(request):
        requests.append(request)
        return httpx.Response(200, stream=Body(), request=request)

    transport = httpx.MockTransport(handler)

    class Client(httpx.AsyncClient):
        def __init__(self, **kwargs):
            assert kwargs["trust_env"] is False
            super().__init__(transport=transport, **kwargs)

    monkeypatch.setattr("opentine.tools.web.socket.getaddrinfo", resolve)
    monkeypatch.setattr("opentine.tools.web.httpx.AsyncClient", Client)
    response = await web_get("https://public.example/path", NetworkPolicy())
    assert response.content == b"safe" and resolutions == [("public.example", 443)]
    assert requests[0].url.host == "93.184.216.34"
    assert requests[0].headers["host"] == "public.example"
    assert requests[0].extensions["sni_hostname"] == "public.example"


@pytest.mark.asyncio
async def test_web_fetch_rejects_mixed_public_private_dns_answers(monkeypatch):
    monkeypatch.setattr(
        "opentine.tools.web.socket.getaddrinfo",
        lambda *args, **kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443)),
        ],
    )
    with pytest.raises(PermissionError, match="Private/link-local/loopback"):
        await web_get("https://mixed.example", NetworkPolicy())


@pytest.mark.asyncio
async def test_web_fetch_enforces_whole_response_deadline(monkeypatch):
    class Drip(httpx.AsyncByteStream):
        async def __aiter__(self):
            for _ in range(20):
                await asyncio.sleep(0.01)
                yield b"x"

    transport = httpx.MockTransport(
        lambda request: httpx.Response(200, stream=Drip(), request=request)
    )

    class Client(httpx.AsyncClient):
        def __init__(self, **kwargs):
            super().__init__(transport=transport, **kwargs)

    monkeypatch.setattr(
        "opentine.tools.web.socket.getaddrinfo",
        lambda *args, **kwargs: [(2, 1, 6, "", ("93.184.216.34", 443))],
    )
    monkeypatch.setattr("opentine.tools.web.httpx.AsyncClient", Client)
    with pytest.raises(TimeoutError):
        await web_get(
            "https://drip.example", NetworkPolicy(timeout_seconds=0.04, max_body_bytes=100)
        )


@pytest.mark.asyncio
async def test_web_fetch_dns_timeout_does_not_block_event_loop_shutdown(monkeypatch):
    import threading

    release = threading.Event()

    def stuck(*args, **kwargs):
        release.wait(timeout=1)
        return [(2, 1, 6, "", ("93.184.216.34", 443))]

    monkeypatch.setattr("opentine.tools.web.socket.getaddrinfo", stuck)
    try:
        with pytest.raises(TimeoutError):
            await web_get("https://stuck.example", NetworkPolicy(timeout_seconds=0.03))
    finally:
        release.set()


@pytest.mark.asyncio
async def test_web_fetch_caps_stuck_resolver_threads(monkeypatch):
    import threading

    release = threading.Event()
    calls = 0
    guard = threading.Lock()

    def stuck(*args, **kwargs):
        nonlocal calls
        with guard:
            calls += 1
        release.wait(timeout=1)
        return [(2, 1, 6, "", ("93.184.216.34", 443))]

    monkeypatch.setattr("opentine.tools.web.socket.getaddrinfo", stuck)
    try:
        results = await asyncio.gather(
            *(
                web_get(f"https://stuck-{index}.example", NetworkPolicy(timeout_seconds=0.04))
                for index in range(9)
            ),
            return_exceptions=True,
        )
        assert calls <= 8
        assert any("capacity is exhausted" in str(result) for result in results)
    finally:
        release.set()


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


def test_m1_legacy_flag_cannot_launder_tampered_keyed_rows(tmp_path: Path):
    path = tmp_path / "audit.sqlite3"
    backend = SQLiteBackend(path, audit_key=_AUDIT_KEY)
    backend.append(_event("trusted"))
    Path(str(path) + ".audit-head").unlink()
    with sqlite3.connect(path) as database:
        database.execute("DROP TRIGGER audit_no_update")
        database.execute("UPDATE audit SET details='tampered'")
    with pytest.raises(RuntimeError, match="keyed audit rows cannot be migrated"):
        SQLiteBackend(path, audit_key=_AUDIT_KEY, migrate_legacy_audit=True)


# Cross-process file locking and scheduling are timing-sensitive on Windows;
# retry there only, so a real serialization regression on POSIX fails first-run.
@pytest.mark.flaky(reruns=4, reruns_delay=0.3, condition=sys.platform == "win32")
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


@pytest.mark.skipif(os.name == "nt", reason="POSIX process-group assertion")
def test_m2_normal_parent_exit_cleans_up_descendants_without_blocking():
    script = (
        "import subprocess,sys; "
        "a=subprocess.Popen([sys.executable,'-c','import time; time.sleep(5)']); "
        "b=subprocess.Popen([sys.executable,'-c','import time; time.sleep(5)'],"
        "stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); "
        "print(f'children={a.pid},{b.pid}', flush=True)"
    )
    started = time.monotonic()
    result = run_bounded([sys.executable, "-c", script], timeout=1, max_chars=180)
    child_pids = [int(pid) for pid in result.stdout.split(b"=", 1)[1].split(b",")]
    try:
        assert not result.timed_out and result.returncode == 0
        assert time.monotonic() - started < 2
        for child_pid in child_pids:
            for _ in range(40):
                state = Path(f"/proc/{child_pid}/stat")
                try:
                    stopped = state.read_text().split()[2] == "Z"
                except (FileNotFoundError, ProcessLookupError):
                    stopped = True
                if stopped:
                    break
                time.sleep(0.05)
            else:
                pytest.fail("normal-exit subprocess descendant is still running")
    finally:
        for child_pid in child_pids:
            try:
                os.kill(child_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


def test_bounded_result_empty_fallback_honors_output_limit():
    assert BoundedResult(0, b"", b"").output(1) == "("


# Job-object teardown and interrupt timing are Windows-sensitive; retry there
# only, so a real teardown regression on POSIX still fails on the first run.
@pytest.mark.flaky(reruns=4, reruns_delay=0.3, condition=sys.platform == "win32")
def test_run_bounded_closes_owned_job_when_wait_is_interrupted(monkeypatch):
    class InterruptedProcess:
        pid = 123
        stdout = BytesIO()
        stderr = BytesIO()
        waits = 0

        def wait(self, timeout=None):
            self.waits += 1
            if self.waits == 1:
                raise KeyboardInterrupt
            return -9

    class Job:
        closed = False

        def close(self):
            self.closed = True

    process, job = InterruptedProcess(), Job()
    monkeypatch.setattr(_process.subprocess, "Popen", lambda *args, **kwargs: process)
    monkeypatch.setattr(_process, "_attach_kill_job", lambda _process: job)
    with pytest.raises(KeyboardInterrupt):
        run_bounded(["interrupted"], timeout=1, max_chars=10)
    assert job.closed and process.waits == 2


def test_failed_job_close_falls_back_to_process_tree_kill(monkeypatch):
    class BrokenJob:
        def close(self):
            raise OSError("job close failed")

    killed = []
    monkeypatch.setattr(_process, "_kill_tree", killed.append)
    process = object()
    _process._cleanup_owned(process, BrokenJob())
    assert killed == [process]


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object assertion")
def test_windows_job_cleans_descendant_after_normal_parent_exit(tmp_path: Path):
    marker = tmp_path / "escaped"
    child = f"import time,pathlib;time.sleep(1);pathlib.Path({str(marker)!r}).touch()"
    script = (
        f"import subprocess,sys; subprocess.Popen([sys.executable,'-c',{child!r}],close_fds=True)"
    )
    result = run_bounded([sys.executable, "-c", script], timeout=2, max_chars=100)
    assert result.returncode == 0 and not result.timed_out
    time.sleep(1.5)
    assert not marker.exists()


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
    assert redact_blob(b"api_key: how do I rotate it").endswith(b"[REDACTED]")


def test_header_redaction_covers_equals_and_underscore_spellings():
    samples = (
        "Authorization=Basic dXNlcjpwYXNz",
        "Proxy-Authorization=Basic dXNlcjpwYXNz",
        "proxy_authorization: Basic dXNlcjpwYXNz",
        "set_cookie: session=secret",
    )
    for sample in samples:
        assert redact_blob(sample.encode()).endswith(b"[REDACTED]")
        assert _redact(sample).endswith("[REDACTED]")


def test_quoted_shell_and_dotenv_credentials_are_redacted():
    samples = (
        b"OPENAI_API_KEY='not-a-shaped-secret-value'",
        b'GOOGLE_API_KEY = "AIza-not-shape-dependent"',
        b"export AWS_SECRET_ACCESS_KEY='secret with spaces' # captured environment",
        b'api_key: "plain-generic-value"',
        b"password: 'correct horse battery staple'",
        b'$env:OPENAI_API_KEY = "powershell-secret"',
        b'password: "abc\\"escaped-quote-secret"',
        b"API_KEY = generic secret with spaces",
    )
    for sample in samples:
        redacted = redact_blob(sample)
        assert b"[REDACTED]" in redacted
        assert not any(
            value in redacted
            for value in (
                b"not-a-shaped-secret-value",
                b"AIza-not-shape-dependent",
                b"with spaces",
                b"plain-generic-value",
                b"correct horse battery staple",
                b"powershell-secret",
                b"escaped-quote-secret",
                b"generic secret with spaces",
            )
        )

    raw_json = b'{"password":"abc\\"SUPERSECRET","safe":1}'
    redacted_json = redact_blob(raw_json)
    assert b"SUPERSECRET" not in redacted_json
    assert b'"safe":1' in redacted_json


def test_structured_header_case_collisions_cannot_hide_values():
    value = {
        "name": "Authorization",
        "Name": "ordinary",
        "value": "safe",
        "Value": "Basic dXNlcjpwYXNz",
    }
    redacted = _redact(value)
    assert redacted["value"] == "[REDACTED]"
    assert redacted["Value"] == "[REDACTED]"


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


def test_truncated_private_key_preserves_immediate_non_pem_diagnostics():
    captured = (
        b"-----BEGIN PRIVATE KEY----- note: parser saw a marker\n"
        b"diagnostic output continues\napi_key=still-secret"
    )
    redacted = redact_blob(captured)
    assert redacted.startswith(b"[REDACTED PRIVATE KEY] note: parser saw a marker")
    assert b"diagnostic output continues" in redacted


def test_truncated_private_key_scrubs_same_line_base64():
    redacted = redact_blob(
        b"-----BEGIN PRIVATE KEY----- c2Vuc2l0aXZlLWtleS1tYXRlcmlhbA==\ncertificate lookup failed\n"
    )
    assert b"c2Vuc2l0aXZlLWtleS1tYXRlcmlhbA==" not in redacted
    assert b"certificate lookup failed" in redacted
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
