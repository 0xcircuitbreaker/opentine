"""Benchmark batched streaming ingest (0.77): sustained events/s and batch commit latency.

Usage::

    uv run python scripts/bench/ingest_stream.py --events 100000000 --batch 10000
    uv run python scripts/bench/ingest_stream.py --seconds 3600 --batch 10000   # 1 h soak
    uv run python scripts/bench/ingest_stream.py --events 1000000 --json docs/bench/0.77-ingest.json

Each batch is ``--batch`` synthetic RL step events (about 120 bytes of JSON
each) appended through :func:`opentine._ingest_batch.append`: sampling under a
signed policy (``--rate``), one signed annotation per batch, one durability
point per batch, the held head moved after it. ``--http`` posts the batches to
``tine ingest serve``'s loopback endpoint instead. The run stops after
``--events`` events or ``--seconds`` seconds, whichever comes first; then
``tine ingest verify`` re-checks the whole chain and is timed too.

Prints (and with ``--json`` writes) events/s, batch commit latency p50/p99/max
and the hardware. The acceptance target (10k events/s sustained for 1 h, every
batch signed) is a reference-machine number: the bench records it, tests never
assert it.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import statistics
import sys
import tempfile
import time
from pathlib import Path


def _events(start: int, n: int) -> bytes:
    rows = (
        b'{"kind":"step","episode":%d,"t":%d,"reward":0.%03d,"action":"move-%d"}\n'
        % (i // 200, i % 200, i % 997, i % 7)
        for i in range(start, start + n)
    )
    return b"".join(rows)


def _hardware() -> dict:
    return {"machine": platform.machine(), "processor": platform.processor() or None,
            "cpus": os.cpu_count(), "python": platform.python_version(),
            "system": f"{platform.system()} {platform.release()}"}  # fmt: skip


def _pin_policy_key(repo, key, root: Path) -> None:
    """Pin *key* as the policy role through a throwaway owner (bench only)."""
    from datetime import UTC, datetime

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from opentine import _trust_bundle
    from opentine._signing_pins import key_fingerprint
    from opentine.repository._tlog_note import vkey_for

    owner = Ed25519PrivateKey.from_private_bytes(b"\x42" * 32)
    fpr = key_fingerprint(key.public_key().public_bytes_raw())
    (repo.path / "key-roles.toml").write_bytes(
        f'version = 1\n[roles]\npolicy = ["{fpr}"]\nrunner = ["{fpr}"]\n'.encode()
    )
    payload = {"trust_bundle": 1, "serial": 1,
               "issued_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
               "trust_policy": {"pin": ["sha256:" + "0" * 64]},
               "key_roles": {"version": 1,
                             "roles": {"policy": [fpr], "runner": [fpr]}}}  # fmt: skip
    signed = _trust_bundle.sign(payload, owner, "bench.example/trust")
    (repo.path / "trust-bundle.note").write_bytes(signed)
    config = root / "xdg" / "opentine"
    config.mkdir(parents=True)
    vkey = vkey_for("bench.example/trust", owner.public_key().public_bytes_raw())
    (config / "trust-owner").write_bytes((vkey + "\n").encode())
    os.environ["XDG_CONFIG_HOME"] = (root / "xdg").as_posix()


def run(args: argparse.Namespace, root: Path) -> dict:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from opentine import _ingest_batch, _ingest_policy, _ingest_verify
    from opentine.repository import Repo

    repo = Repo.init(root / "repo")
    key = Ed25519PrivateKey.from_private_bytes(b"\x07" * 32)
    doc = _ingest_policy.build("bench", capture=[], drop=[], rate=args.rate, seed="0" * 64,
                               issued_at="2027-01-01T00:00:00Z",
                               redact=not args.no_redact)  # fmt: skip
    _ingest_policy.record(repo, doc, key)
    _pin_policy_key(repo, key, root)
    server = None
    if args.http:
        import http.client

        from opentine import _ingest_http

        server = _ingest_http.start(repo, "bench", key)
        conn = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=600)
    latencies: list[float] = []
    sent = 0
    began = time.perf_counter()
    while sent < args.events and time.perf_counter() - began < args.seconds:
        n = min(args.batch, args.events - sent)
        body = _events(sent, n)
        start = time.perf_counter()
        if server is not None:
            conn.request("POST", "/v1/ingest", body)
            response = conn.getresponse()
            response.read()
            if response.status != 200:
                raise SystemExit(f"endpoint answered {response.status}")
        else:
            _ingest_batch.append(repo, "bench", body, key, at_ms=1_800_000_000_000)
        latencies.append(time.perf_counter() - start)
        sent += n
    elapsed = time.perf_counter() - began
    if server is not None:
        conn.close()
        server.stop()
    start = time.perf_counter()
    report = _ingest_verify.verify(repo, "bench")
    verify_s = time.perf_counter() - start
    latencies.sort()
    return {
        "events": sent, "batches": len(latencies), "batch": args.batch, "rate": args.rate,
        "redact": not args.no_redact,
        "path": "http" if args.http else "direct", "seconds": round(elapsed, 3),
        "events_per_s": round(sent / elapsed, 1),
        "batch_ms": {"p50": round(statistics.median(latencies) * 1000, 2),
                     "p99": round(latencies[int(len(latencies) * 0.99) - 1] * 1000, 2),
                     "max": round(latencies[-1] * 1000, 2)},
        "verify_s": round(verify_s, 3), "verify_ok": report["ok"],
        "captured": report["captured"], "dropped": report["dropped"], "hardware": _hardware(),
    }  # fmt: skip


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--events", type=int, default=100_000_000)
    parser.add_argument("--seconds", type=float, default=float("inf"))
    parser.add_argument("--batch", type=int, default=10_000)
    parser.add_argument("--rate", type=float, default=1.0)
    parser.add_argument("--http", action="store_true", help="Post to tine ingest serve")
    parser.add_argument("--no-redact", action="store_true", help='Policy "redact": false')
    parser.add_argument("--json", metavar="PATH", help="Also write the result here")
    parser.add_argument("--dir", metavar="PATH", help="Scratch directory (default: a temp dir)")
    args = parser.parse_args(argv)
    with tempfile.TemporaryDirectory(dir=args.dir) as tmp:
        result = run(args, Path(tmp))
    text = json.dumps(result, indent=2, sort_keys=True) + "\n"
    sys.stdout.write(text)
    if args.json:
        Path(args.json).write_bytes(text.encode("utf-8"))
    return 0 if result["verify_ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
