"""Cross-platform subprocess capture with bounded resident output."""

from __future__ import annotations

import os
import re
import signal
import subprocess
import threading
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from opentine._redact_shapes import TOKEN_SHAPES, URL_USERINFO

#: Environment names a tool subprocess never needs and must never be handed.
_SENSITIVE_PAT = re.compile(r"(KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|AUTH)", re.IGNORECASE)
#: Credential spellings the substring list above missed (audit 0.9.1, D-4):
#: ``MYSQL_PWD``, ``PGPASS``, ``GH_PAT``, ``SENTRY_DSN``, ``*_WEBHOOK_URL``,
#: ``*_CONNECTION_STRING``, ``SIGNING_PRIVATE``, ``*_COOKIE``. ``PWD``/``OLDPWD``
#: themselves are directories, and ``PATH`` is not ``PAT``.
_SENSITIVE_SUFFIX = re.compile(r"(?:PASS|PASSWD|_PWD|_PAT|_DSN)$", re.IGNORECASE)
_SENSITIVE_PART = re.compile(
    r"(?:^|_)(?:PRIVATE|WEBHOOK|COOKIE|CREDS|CONNECTION_STRING|CONN_STR)(?:_|$)", re.IGNORECASE
)


def _sensitive(name: str, value: str) -> bool:
    if _SENSITIVE_PAT.search(name) or _SENSITIVE_SUFFIX.search(name):
        return True
    if _SENSITIVE_PART.search(name):
        return True
    # By value, whatever the name: ``DATABASE_URL=postgres://u:pw@db``, a proxy
    # with credentials, a vendor token or a private key under an innocent name.
    raw = value.encode("utf-8", "replace")
    return bool(TOKEN_SHAPES.search(raw) or URL_USERINFO.search(raw) or b"PRIVATE KEY-----" in raw)


def clean_env(inherit_env: bool, env_allowlist: Iterable[str]) -> dict[str, str]:
    """The environment a bounded subprocess may see, scrubbed on inheritance.

    One spelling for every tool that spawns a process. The shell tool used to
    hand ``dict(os.environ)`` over verbatim on ``inherit_env``, so an
    ANTHROPIC_API_KEY left the host and came straight back into model context
    through the command's own output, while the python tool scrubbed the same
    names — a divergence that only exists while the helper is written twice.
    """
    if inherit_env:
        return {key: value for key, value in os.environ.items() if not _sensitive(key, value)}
    return {name: os.environ[name] for name in env_allowlist if name in os.environ}


@dataclass(frozen=True)
class BoundedResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    timed_out: bool = False
    stdout_truncated: bool = False
    stderr_truncated: bool = False

    def output(self, max_chars: int, *, prefix: str = "") -> str:
        if max_chars < 1:
            raise ValueError("output limit must be positive")
        text = self.stdout.decode(errors="replace")
        errors = self.stderr.decode(errors="replace")
        prefix = _clip(prefix, max_chars)
        available = max_chars - len(prefix)
        if errors:
            label = "\nSTDERR:\n"
            body_budget = max(0, available - len(label))
            error_budget = body_budget if not text else max(1, body_budget // 2)
            text_budget = max(0, body_budget - error_budget)
            rendered = prefix + _clip(text, text_budget) + label + _clip(errors, error_budget)
        else:
            rendered = prefix + _clip(text, available)
        return rendered[:max_chars].strip() or "(no output)"[:max_chars]


def _clip(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    marker = "... (truncated)"
    return marker[:limit] if limit <= len(marker) else text[: limit - len(marker)] + marker


def _kill_process_group(pid: int) -> None:
    if os.name == "nt":
        system_root = os.environ.get("SystemRoot", r"C:\Windows")
        if not os.path.isabs(system_root):
            system_root = r"C:\Windows"
        taskkill = os.path.join(system_root, "System32", "taskkill.exe")
        try:
            subprocess.run(
                [taskkill, "/PID", str(pid), "/T", "/F"],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
            )
        except (OSError, subprocess.TimeoutExpired):
            pass
    else:
        try:
            os.killpg(pid, signal.SIGKILL)
        except OSError:
            pass


def _kill_tree(process: subprocess.Popen[bytes]) -> None:
    _kill_process_group(process.pid)
    try:
        process.kill()
    except OSError:
        pass


def _group_flags() -> dict[str, Any]:
    """Popen arguments that make a child's whole tree killable as one.

    On Windows the child also starts suspended: :func:`_attach_kill_job` puts it
    in a kill-on-close job and only then resumes it, so nothing it spawns can be
    born outside the job. Every launcher must pair this with that call.
    """
    if os.name != "nt":
        return {"start_new_session": True}
    from opentine.tools._winjob import CREATE_SUSPENDED

    return {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP | CREATE_SUSPENDED}


def _attach_kill_job(process: subprocess.Popen[bytes]) -> Any:
    if os.name != "nt":
        return None
    from opentine.tools._winjob import contain_suspended

    return contain_suspended(process)


def _cleanup_owned(process: subprocess.Popen[bytes], job: Any) -> None:
    if job is not None:
        try:
            job.close()
            return
        except OSError:
            pass
    _kill_tree(process)


def run_bounded(
    argv: list[str],
    *,
    timeout: float,
    max_chars: int,
    max_bytes: int | None = None,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
) -> BoundedResult:
    """Run an argv command while draining and discarding output beyond the cap."""
    if timeout <= 0 or max_chars < 1 or (max_bytes is not None and max_bytes < 1):
        raise ValueError("subprocess timeout and output limit must be positive")
    process = subprocess.Popen(
        argv,
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        **_group_flags(),
    )
    job = _attach_kill_job(process)
    byte_limit = max_bytes if max_bytes is not None else max(1024, max_chars * 4)
    buffers = (bytearray(), bytearray())
    truncated = [False, False]

    def drain(stream: Any, buffer: bytearray, index: int) -> None:
        try:
            while chunk := stream.read(64 * 1024):
                remaining = byte_limit - len(buffer)
                if remaining > 0:
                    buffer.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    truncated[index] = True
        except (OSError, ValueError):
            pass
        finally:
            try:
                stream.close()
            except (OSError, ValueError):
                pass

    streams = (process.stdout, process.stderr)
    threads = [
        threading.Thread(target=drain, args=(stream, buffer, index), daemon=True)
        for index, (stream, buffer) in enumerate(zip(streams, buffers))
    ]
    timed_out = False
    returncode = None
    interrupted = False
    try:
        for thread in threads:
            thread.start()
        try:
            returncode = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
    except BaseException:
        interrupted = True
        raise
    finally:
        # The execution boundary owns the fresh process group/job. Cleanup after
        # success too: a top-level process may leave background descendants behind.
        _cleanup_owned(process, job)
        if interrupted:
            try:
                process.wait(timeout=1)
            except BaseException:
                pass
    if returncode is None:
        returncode = process.wait()
    for thread in threads:
        thread.join(timeout=1)
    return BoundedResult(
        returncode,
        bytes(buffers[0]),
        bytes(buffers[1]),
        timed_out,
        truncated[0],
        truncated[1],
    )
