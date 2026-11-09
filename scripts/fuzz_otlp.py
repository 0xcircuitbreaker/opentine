"""Fuzz the OTLP protobuf ingest path (HTTP protobuf and gRPC share it).

    python scripts/fuzz_otlp.py --iterations 50000 --seed 1     # the scaled CI run
    python scripts/fuzz_otlp.py --hours 72 --crashes fuzz-out   # the 0.48 acceptance run
    python scripts/fuzz_otlp.py --atheris --hours 72            # coverage-guided, if installed

The harness is ``opentine._otlp_fuzz``: mutated traces and logs export
requests through the bounded decoders and the GenAI importers; anything but a
clean import or a ``ValueError``/413 refusal is a crash. Each crash input is
written to ``--crashes`` as ``<route>-<sha256>.bin`` with its traceback, and the
exit status is 1. Progress is printed every ``--report-every`` seconds, so a
72-hour run leaves a log line per interval.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from opentine import _otlp_fuzz  # noqa: E402


def _atheris(hours: float | None) -> int:  # pragma: no cover - needs atheris
    import atheris

    def target(data: bytes) -> None:
        route = _otlp_fuzz.ROUTES[data[0] & 1] if data else "add_spans"
        _otlp_fuzz.run_one(route, data[1:])

    argv = [sys.argv[0], *([f"-max_total_time={int(hours * 3600)}"] if hours else [])]
    atheris.Setup(argv, target)
    atheris.Fuzz()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--iterations", type=int, help="Stop after this many mutated inputs")
    parser.add_argument("--hours", type=float, help="Stop after this many hours (72 for 0.48)")
    parser.add_argument("--seed", type=int, default=int(time.time()), help="PRNG seed")
    parser.add_argument("--crashes", default="fuzz-crashes", help="Directory for crash inputs")
    parser.add_argument("--report-every", type=float, default=600.0, help="Seconds a line")
    parser.add_argument("--atheris", action="store_true", help="Use atheris (coverage-guided)")
    args = parser.parse_args(argv)
    if args.atheris:
        return _atheris(args.hours)
    if args.iterations is None and args.hours is None:
        parser.error("give --iterations or --hours")
    out = Path(args.crashes)

    def keep(route: str, data: bytes, trace: str) -> None:
        out.mkdir(parents=True, exist_ok=True)
        name = f"{route}-{hashlib.sha256(data).hexdigest()[:16]}"
        (out / f"{name}.bin").write_bytes(data)
        (out / f"{name}.txt").write_text(trace, encoding="utf-8")

    print(f"fuzz_otlp: seed {args.seed}", flush=True)
    total, crashes, slowest = 0, 0, 0.0
    deadline = time.monotonic() + args.hours * 3600 if args.hours is not None else None
    while True:
        budget = args.report_every
        if deadline is not None:
            budget = min(budget, deadline - time.monotonic())
        left = None if args.iterations is None else args.iterations - total
        if (left is not None and left <= 0) or budget <= 0:
            break
        report = _otlp_fuzz.fuzz(seed=args.seed + total, iterations=left, seconds=budget,
                                 on_crash=keep)  # fmt: skip
        total += report.iterations
        crashes += len(report.crashes)
        for found in report.slow:  # the long run fails on slow inputs too; keep them
            keep(found["route"], bytes.fromhex(found["input"]), "slow")
        crashes += len(report.slow)
        slowest = max(slowest, report.slowest)
        print(f"fuzz_otlp: {total} inputs, {crashes} crashes, slowest {slowest:.3f}s", flush=True)
    return 1 if crashes else 0


if __name__ == "__main__":
    raise SystemExit(main())
