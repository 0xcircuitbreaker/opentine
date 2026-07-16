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
        return rendered[:max_chars].strip() or "(no output)"


def _clip(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    marker = "... (truncated)"
    return marker[:limit] if limit <= len(marker) else text[: limit - len(marker)] + marker


def _kill_tree(process: subprocess.Popen[bytes]) -> None:
    if os.name == "nt":
        system_root = os.environ.get("SystemRoot", r"C:\Windows")
        if not os.path.isabs(system_root):
            system_root = r"C:\Windows"
        taskkill = os.path.join(system_root, "System32", "taskkill.exe")
        try:
            subprocess.run(
                [taskkill, "/PID", str(process.pid), "/T", "/F"],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
            )
        except (OSError, subprocess.TimeoutExpired):
            pass
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    try:
        process.kill()
    except OSError:
        pass


def run_bounded(
    argv: list[str],
    *,
    timeout: float,
    max_chars: int,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
) -> BoundedResult:
    """Run an argv command while draining and discarding output beyond the cap."""
    if timeout <= 0 or max_chars < 1:
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
    byte_limit = max(1024, max_chars * 4)
    buffers = (bytearray(), bytearray())

    def drain(stream: Any, buffer: bytearray) -> None:
        try:
            while chunk := stream.read(64 * 1024):
                remaining = byte_limit - len(buffer)
                if remaining > 0:
                    buffer.extend(chunk[:remaining])
        except (OSError, ValueError):
            pass

    streams = (process.stdout, process.stderr)
    threads = [
        threading.Thread(target=drain, args=(stream, buffer), daemon=True)
        for stream, buffer in zip(streams, buffers)
    ]
    for thread in threads:
        thread.start()
    timed_out = False
    try:
        returncode = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill_tree(process)
        returncode = process.wait()
    for thread in threads:
        thread.join(timeout=1)
    for stream in streams:
        stream.close()
    return BoundedResult(returncode, bytes(buffers[0]), bytes(buffers[1]), timed_out)
