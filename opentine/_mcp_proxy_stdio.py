"""The stdio transport of ``tine mcp-proxy``: spawn the server, relay both ways.

MCP over stdio is newline-delimited JSON-RPC. Each direction is copied in
chunks of at most 64 KiB and written on at once, in order, before the recorder
sees anything, so recording can neither block nor reorder the stream. Only the
first :data:`MAX_MESSAGE` bytes of a line are kept for the recorder. The
server's stderr is inherited and passes straight through.

0.63: with a monitor (:mod:`opentine._monitor_mcp`) in gate mode, the client
direction is relayed a whole line at a time so a ``tools/call`` is decided
before a byte of it reaches the server; a blocked call is answered on the
client's stdout under the same lock the server direction writes with. A line
longer than :data:`MAX_MESSAGE` cannot be decided and is dropped (fail closed).
In advisory mode the bytes are relayed as before and the call is scored after.
"""

from __future__ import annotations

import subprocess
import sys
import threading
from contextlib import nullcontext
from typing import IO, Any

from opentine._mcp_proxy_record import CLIENT, MAX_MESSAGE, SERVER, McpRecorder

CHUNK = 65536


def pump(
    source: IO[bytes], sink: IO[bytes], sender: str, recorder: McpRecorder,
    lock: Any = None, guard: Any = None,
) -> None:  # fmt: skip
    """Copy *source* to *sink* line by line until EOF, feeding each line to *recorder*."""
    kept, oversize = bytearray(), False
    try:
        while chunk := source.readline(CHUNK):
            try:
                with lock or nullcontext():
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
                    if guard is not None and not oversize:
                        guard.check(bytes(kept))  # advisory: scored after relaying
                kept, oversize = bytearray(), False
    finally:
        if kept.strip():
            recorder.feed(sender, bytes(kept), oversize)


def _deliver(raw, sink, client, lock, recorder: McpRecorder, guard: Any) -> None:
    forward, back, blocked = guard.check(raw)
    if blocked:
        recorder.feed(CLIENT, blocked)
    if forward:
        sink.write(forward)
        sink.flush()
        recorder.feed(CLIENT, forward)
    if back:
        with lock:
            client.write(back)
            client.flush()
        recorder.feed(SERVER, back)


def gated_pump(
    source: IO[bytes], sink: IO[bytes], client: IO[bytes], lock: Any,
    recorder: McpRecorder, guard: Any,
) -> None:  # fmt: skip
    """The client direction in gate mode: decide each whole line, then relay it."""
    line, oversize = bytearray(), False
    try:
        while chunk := source.readline(CHUNK):
            if not oversize:
                line += chunk
                if len(line) > MAX_MESSAGE:
                    oversize, line = True, bytearray()
            if not chunk.endswith(b"\n"):
                continue
            if oversize:
                recorder.feed(CLIENT, b"", True)
                recorder._report("mcp-proxy: an oversize client message was dropped (gate)")
            elif line.strip():
                _deliver(bytes(line), sink, client, lock, recorder, guard)
            line, oversize = bytearray(), False
        if line.strip() and not oversize:
            _deliver(bytes(line), sink, client, lock, recorder, guard)
    except (BrokenPipeError, OSError, ValueError):
        return


def relay(command: list[str], recorder: McpRecorder, guard: Any = None) -> int:
    """Run *command* as the MCP server and relay this process's stdio to it."""
    child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    assert child.stdin is not None and child.stdout is not None
    lock = threading.Lock()

    def upstream() -> None:
        try:
            if guard is not None and not guard.advisory:
                gated_pump(sys.stdin.buffer, child.stdin, sys.stdout.buffer, lock, recorder,
                           guard)  # type: ignore[arg-type]  # fmt: skip
            else:
                pump(sys.stdin.buffer, child.stdin, CLIENT, recorder,  # type: ignore[arg-type]
                     guard=guard)  # fmt: skip
        finally:
            try:
                child.stdin.close()  # type: ignore[union-attr]
            except OSError:
                pass

    threading.Thread(target=upstream, daemon=True).start()
    pump(child.stdout, sys.stdout.buffer, SERVER, recorder, lock)
    return child.wait()


__all__ = ["gated_pump", "pump", "relay"]
