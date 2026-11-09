"""0.49 bench: FastCDC stored form in the WORM object store (in-memory client).

Usage: ``uv run python scripts/bench/fastcdc_store.py [--mib 8 32] [--seed 49]``

Prints, per payload size: chunking throughput, chunk count and mean size, the
bytes a 1% append adds (dedup across versions), and how many chunks a 4 KiB
range read fetches compared with a whole ``get``. Uses the default parameters
(min 256 KiB, avg 1 MiB, max 4 MiB, threshold 8 MiB).
"""

from __future__ import annotations

import argparse
import random
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), str(ROOT / "tests")]

from _worm_fakes import FakeBlobClient  # noqa: E402

from opentine.kernel import ObjectEnvelope  # noqa: E402
from opentine.remote._fastcdc import boundaries  # noqa: E402
from opentine.remote._worm_store import WormObjectStore  # noqa: E402
from opentine.remote.security import LocalKeyProvider  # noqa: E402


def _chunk_keys(client: FakeBlobClient) -> set[str]:
    return {key for key in client.blobs if "/chunks/" in key}


def run(mib: int, seed: int) -> dict[str, float]:
    rng = random.Random(seed)
    # Transcript-like: repetitive JSON lines with random ids and text.
    lines, size = [], 0
    while size < mib * 1024 * 1024:
        line = b'{"role":"assistant","id":"%032x","text":"%s"}\n' % (
            rng.getrandbits(128),
            rng.randbytes(rng.randint(40, 400)).hex().encode(),
        )
        lines.append(line)
        size += len(line)
    body = b"".join(lines)
    started = time.process_time()
    cuts = list(boundaries(body))
    chunk_s = time.process_time() - started
    client = FakeBlobClient()
    store = WormObjectStore(client, LocalKeyProvider(b"k" * 32))
    first = ObjectEnvelope.create("blob", body)
    started = time.process_time()
    store.put("bench", first.oid, first.encode())
    put_s = time.process_time() - started
    before = _chunk_keys(client)
    stored_before = sum(len(client.blobs[k]) for k in before)
    grown = ObjectEnvelope.create("blob", body + body[: len(body) // 100])
    store.put("bench", grown.oid, grown.encode())
    added = _chunk_keys(client) - before
    added_bytes = sum(len(client.blobs[k]) for k in added)
    client.gets.clear()
    started = time.perf_counter()
    store.read_range("bench", first.oid, len(body) // 2, 4096)
    range_ms = (time.perf_counter() - started) * 1000
    range_chunks = sum(1 for k in client.gets if "/chunks/" in k)
    started = time.perf_counter()
    store.get("bench", first.oid)
    get_ms = (time.perf_counter() - started) * 1000
    return {
        "MiB": mib,
        "chunks": len(cuts),
        "mean_KiB": len(body) / len(cuts) / 1024,
        "chunk_MiB_s": mib / chunk_s if chunk_s else float("inf"),
        "put_s": put_s,
        "append_1pct_new_chunks": len(added),
        "append_1pct_new_stored_pct": 100 * added_bytes / stored_before,
        "range_4k_chunks": range_chunks,
        "range_4k_ms": range_ms,
        "get_ms": get_ms,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mib", type=int, nargs="+", default=[8, 32])
    parser.add_argument("--seed", type=int, default=49)
    args = parser.parse_args()
    rows = [run(mib, args.seed) for mib in args.mib]
    keys = list(rows[0])
    print("| " + " | ".join(keys) + " |")
    print("|" + "---|" * len(keys))
    for row in rows:
        print(
            "| "
            + " | ".join(
                f"{row[k]:.2f}" if isinstance(row[k], float) else str(row[k]) for k in keys
            )
            + " |"
        )


if __name__ == "__main__":
    main()
