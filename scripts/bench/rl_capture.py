"""Benchmark RL-scale capture (0.84): episodes/hour through ingest, seal and audit.

Usage::

    uv run python scripts/bench/rl_capture.py --episodes 1000000 --segment 100000
    uv run python scripts/bench/rl_capture.py --json docs/bench/0.84-rl-capture.json

Synthetic RL episodes (one JSON line each, about 200 bytes: id, return, length
and a short action summary) are appended through
:func:`opentine._ingest_batch.append` in batches of ``--batch`` under a
``rate = 1`` signed policy with ``redact: false`` (numeric episodes). Every
``--segment`` episodes the batches are sealed into one Merkle-rooted segment
(:func:`opentine._rl_segment.seal`), the op log moves on, and the segment is
audited for "99% confidence that at most 0.5% are tampered or missing"
(:func:`opentine._rl_audit.run`). The end-to-end rate (ingest + seal + audit)
is extrapolated to episodes/hour.

The acceptance target (1M synthetic episodes/hour on the reference machine) is
recorded here with the hardware; tests never assert a time.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ingest_stream import _hardware  # noqa: E402


def _episodes(start: int, n: int) -> bytes:
    rows = (
        b'{"kind":"episode","episode":%d,"return":%d.%03d,"length":%d,'
        b'"actions":"m%d,m%d,m%d,m%d","env":"grid-%d","policy_step":%d}\n'
        % (i, i % 50, i % 997, 100 + i % 900, i % 7, i % 5, i % 3, i % 11, i % 4, i // 1000)
        for i in range(start, start + n)
    )
    return b"".join(rows)


def _pin(repo, roles: dict, root: Path) -> None:
    """Pin the bench keys' roles through a throwaway owner (bench only)."""
    from datetime import UTC, datetime

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from opentine import _trust_bundle
    from opentine.repository._tlog_note import vkey_for

    owner = Ed25519PrivateKey.from_private_bytes(b"\x42" * 32)
    lines = "".join(f'{r} = ["{f}"]\n' for r, f in roles.items())
    (repo.path / "key-roles.toml").write_bytes(f"version = 1\n[roles]\n{lines}".encode())
    payload = {"trust_bundle": 1, "serial": 1,
               "issued_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
               "trust_policy": {"pin": ["sha256:" + "0" * 64]},
               "key_roles": {"version": 1,
                             "roles": {r: [f] for r, f in roles.items()}}}  # fmt: skip
    (repo.path / "trust-bundle.note").write_bytes(
        _trust_bundle.sign(payload, owner, "bench.example/trust")
    )
    config = root / "xdg" / "opentine"
    config.mkdir(parents=True)
    vkey = vkey_for("bench.example/trust", owner.public_key().public_bytes_raw())
    (config / "trust-owner").write_bytes((vkey + "\n").encode())
    os.environ["XDG_CONFIG_HOME"] = (root / "xdg").as_posix()


def run(args: argparse.Namespace, root: Path) -> dict:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from opentine import _ingest_batch, _ingest_policy, _rl_audit, _rl_segment, _rl_verify
    from opentine._signing_pins import key_fingerprint
    from opentine.repository import Repo, _oplog

    repo = Repo.init(root / "repo")
    keys = {r: Ed25519PrivateKey.from_private_bytes(bytes([n]) * 32)
            for n, r in enumerate(("policy", "runner", "auditor"), 7)}  # fmt: skip
    _pin(repo, {r: key_fingerprint(k.public_key().public_bytes_raw()) for r, k in keys.items()},
         root)  # fmt: skip
    doc = _ingest_policy.build("bench", capture=[], drop=[], rate=1.0, seed="0" * 64,
                               issued_at="2027-01-01T00:00:00Z", redact=False)  # fmt: skip
    _ingest_policy.record(repo, doc, keys["policy"])
    phase = {"ingest": 0.0, "seal": 0.0, "audit": 0.0}
    audits, sent = [], 0
    while sent < args.episodes:
        target = min(args.episodes, sent + args.segment)
        start = time.perf_counter()
        while sent < target:
            n = min(args.batch, target - sent)
            _ingest_batch.append(repo, "bench", _episodes(sent, n), keys["runner"],
                                 at_ms=1_800_000_000_000)  # fmt: skip
            sent += n
        phase["ingest"] += time.perf_counter() - start
        start = time.perf_counter()
        segment = _rl_segment.seal(repo, "bench", keys["runner"], at_ms=1_800_000_000_000)
        later = _oplog._Op("bench", None)
        later.note = "after seal"
        _oplog.record(repo.path, later, [])
        phase["seal"] += time.perf_counter() - start
        start = time.perf_counter()
        row = _rl_audit.run(repo, segment["id"], keys["auditor"], confidence="0.99",
                            max_bad="0.005", at_ms=1_800_000_000_000)  # fmt: skip
        phase["audit"] += time.perf_counter() - start
        audits.append({"episodes": row["episodes"], "sample": row["checked"],
                       "verdict": row["verdict"]})  # fmt: skip
    total = sum(phase.values())
    start = time.perf_counter()
    report = _rl_verify.verify(repo, "bench")
    verify_s = time.perf_counter() - start
    return {
        "episodes": sent, "batch": args.batch, "segment": args.segment,
        "segments": len(audits), "audits": audits,
        "seconds": {k: round(v, 3) for k, v in phase.items()},
        "episodes_per_hour": round(sent / total * 3600),
        "ingest_only_per_hour": round(sent / phase["ingest"] * 3600),
        "verify_s": round(verify_s, 3), "verify_ok": report["ok"],
        "verify_fails": sorted({f["code"] for f in report["findings"] if f["level"] == "fail"}),
        "hardware": _hardware(), "python_impl": platform.python_implementation(),
    }  # fmt: skip


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--episodes", type=int, default=1_000_000)
    parser.add_argument("--batch", type=int, default=10_000)
    parser.add_argument("--segment", type=int, default=100_000)
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
