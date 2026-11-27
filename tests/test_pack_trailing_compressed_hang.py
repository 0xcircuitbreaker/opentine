"""0.86.1: a TINEPACK3 body with bytes after its zlib stream is refused, not a hang.

``_bounded_decompress`` looped on ``unconsumed_tail``, which zlib leaves stale
once the stream ends while output was capped, so the fuzzer's input spun forever.
"""

from __future__ import annotations

import hashlib
import threading
import zlib

from opentine.kernel import KernelError
from opentine.repository.pack import MAGIC, _bounded_decompress, inspect_pack


def _refuses_in_time(call) -> BaseException | None:
    outcome: list[BaseException | None] = []

    def run() -> None:
        try:
            call()
            outcome.append(None)
        except BaseException as exc:  # noqa: BLE001 - reported to the test
            outcome.append(exc)

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    worker.join(10)
    assert outcome, "decompressing a stream with trailing bytes did not finish"
    return outcome[0]


def test_trailing_bytes_after_a_capped_stream_are_refused_promptly():
    data = zlib.compress(b"\0" * (2 * 65536)) + b"xy"
    error = _refuses_in_time(lambda: _bounded_decompress(data, 1 << 20))
    assert isinstance(error, KernelError) and "trailing" in str(error)


def test_the_wire_pack_with_trailing_compressed_bytes_is_refused():
    body = b"\0" * (2 * 65536)
    pack = MAGIC + hashlib.sha256(body).digest() + zlib.compress(body) + b"xy"
    error = _refuses_in_time(lambda: inspect_pack(pack))
    assert isinstance(error, KernelError) and "trailing" in str(error)
