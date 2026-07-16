"""Cross-platform subprocess capture with bounded resident output."""

from __future__ import annotations

import os
import signal
import subprocess
import threading
from dataclasses import dataclass
from typing import Any


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


def _attach_kill_job(process: subprocess.Popen[bytes]) -> Any:
    if os.name != "nt":
        return None
    from opentine.tools._winjob import try_attach_kill_job

    return try_attach_kill_job(process)


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
    group = (
        {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
        if os.name == "nt"
        else {"start_new_session": True}
    )
    process = subprocess.Popen(
        argv,
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        **group,
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
