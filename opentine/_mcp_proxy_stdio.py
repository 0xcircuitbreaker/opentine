"""The stdio transport of ``tine mcp-proxy``: spawn the server, relay both ways.

MCP over stdio is newline-delimited JSON-RPC. Each direction is copied in
chunks of at most 64 KiB and written on at once, in order, before the recorder
sees anything, so recording can neither block nor reorder the stream. Only the
first :data:`MAX_MESSAGE` bytes of a line are kept for the recorder. The
server's stderr is inherited and passes straight through.
"""

from __future__ import annotations

import subprocess
import sys
import threading
from typing import IO

from opentine._mcp_proxy_record import CLIENT, MAX_MESSAGE, SERVER, McpRecorder

CHUNK = 65536


def pump(source: IO[bytes], sink: IO[bytes], sender: str, recorder: McpRecorder) -> None:
    """Copy *source* to *sink* line by line until EOF, feeding each line to *recorder*."""
    kept, oversize = bytearray(), False
    try:
        while chunk := source.readline(CHUNK):
            try:
                sink.write(chunk)
                sink.flush()
            except (BrokenPipeError, OSError, ValueError):
                return
            if len(kept) + len(chunk) > MAX_MESSAGE:
                oversize, kept = True, bytearray()
            elif not oversize:
                kept += chunk
            if chunk.endswith(b"\n"):
                if oversize or kept.strip():
                    recorder.feed(sender, bytes(kept), oversize)
                kept, oversize = bytearray(), False
    finally:
        if kept.strip():
            recorder.feed(sender, bytes(kept), oversize)


def relay(command: list[str], recorder: McpRecorder) -> int:
    """Run *command* as the MCP server and relay this process's stdio to it."""
    child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    assert child.stdin is not None and child.stdout is not None

    def upstream() -> None:
        try:
            pump(sys.stdin.buffer, child.stdin, CLIENT, recorder)  # type: ignore[arg-type]
        finally:
            try:
                child.stdin.close()  # type: ignore[union-attr]
            except OSError:
                pass

    threading.Thread(target=upstream, daemon=True).start()
    pump(child.stdout, sys.stdout.buffer, SERVER, recorder)
    return child.wait()


__all__ = ["pump", "relay"]
