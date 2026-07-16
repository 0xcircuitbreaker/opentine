"""Cross-platform subprocess capture with bounded resident output."""

from __future__ import annotations

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

    def output(self, max_chars: int) -> str:
        text = self.stdout.decode(errors="replace")
        errors = self.stderr.decode(errors="replace")
        if errors:
            text += f"\nSTDERR:\n{errors}"
        if len(text) > max_chars:
            marker = "... (truncated)"
            text = (
                marker[:max_chars]
                if max_chars <= len(marker)
                else text[: max_chars - len(marker)] + marker
            )
        return text.strip() or "(no output)"


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
    process = subprocess.Popen(
        argv,
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
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
        process.kill()
        returncode = process.wait()
    for thread in threads:
        thread.join(timeout=1)
    for stream in streams:
        stream.close()
    return BoundedResult(returncode, bytes(buffers[0]), bytes(buffers[1]), timed_out)
