"""Fuzz the format readers: OTLP ingest, .tine v4/v5, packs, local packs, DSSE (0.53).

    python scripts/fuzz.py --iterations 20000 --seed 1          # the scaled CI run
    OPENTINE_FUZZ_HOURS=72 python scripts/fuzz.py --seed 1      # the 72 h human run
    python scripts/fuzz.py --target pack --hours 1              # one target
    python scripts/fuzz.py --reproduce fuzz-crashes/pack/<name>.bin

Targets and their oracle are ``opentine._fuzz_targets``; seeds come from the
conformance vectors (``opentine._fuzz_corpus``). ``--iterations`` is per target.
``--hours`` (or ``OPENTINE_FUZZ_HOURS`` when neither is given) is shared: the
targets take turns, ``--report-every`` seconds each, so every target gets an
equal share of a 72-hour run and a log line per turn.

Crash-triage convention: each crash is written to
``<crashes>/<target>/<sha256[:16]>.bin`` (the input; a multi-part input is
framed, see ``opentine._fuzz.frame``) with ``.txt`` beside it (the traceback,
``slow``, or ``hang``: an input still running after ``HANG_SECONDS`` is
saved by a watchdog and the run exits 1, since a hung reader cannot be
interrupted). Triage: ``--reproduce`` it, fix the reader so it refuses with its
documented error, then move the ``.bin`` to ``tests/fuzz_regressions/<target>/``,
where the suite replays it and the fuzzer seeds from it. The exit status is 1
on any crash or slow input.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from opentine import _fuzz, _fuzz_corpus  # noqa: E402
from opentine._fuzz_targets import TARGETS  # noqa: E402

HOURS_ENV = "OPENTINE_FUZZ_HOURS"
HANG_SECONDS = 120.0  # an input still running after this is saved as "hang" and the run exits 1


def watchdog(watch: list[object], keep, name_of, limit: float = HANG_SECONDS) -> None:
    """Save the input a hung reader is stuck on, then end the run (exit 1)."""

    def loop() -> None:
        while True:
            time.sleep(min(limit / 4, 5.0))
            started, parts = watch[0], watch[1]
            if started is not None and time.monotonic() - started > limit:
                keep(name_of(), parts, f"hang: still running after {limit:.0f}s")
                print(f"fuzz: {name_of()}: an input hung; saved, exiting 1", flush=True)
                os._exit(1)

    threading.Thread(target=loop, daemon=True).start()


def reproduce(path: Path, target: str | None) -> int:
    name = target or path.parent.name
    if name not in TARGETS:
        print(f"fuzz: name the target with --target (one of {sorted(TARGETS)})")
        return 2
    spec = TARGETS[name]
    trace = _fuzz.check(spec.run, spec.refusals, _fuzz.unframe(path.read_bytes()))
    print(trace or f"fuzz: {path.as_posix()} reads or is refused cleanly ({name})")
    return 1 if trace else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--target", action="append", choices=sorted(TARGETS),
                        help="Fuzz only this target (repeatable; default: all)")  # fmt: skip
    parser.add_argument("--iterations", type=int, help="Stop after this many inputs per target")
    parser.add_argument("--hours", type=float, help=f"Total hours (default ${HOURS_ENV})")
    parser.add_argument("--seed", type=int, default=int(time.time()), help="PRNG seed")
    parser.add_argument("--crashes", default="fuzz-crashes", help="Crash-triage directory")
    parser.add_argument("--report-every", type=float, default=600.0, help="Seconds a turn")
    parser.add_argument("--reproduce", type=Path, help="Re-run one saved crash input")
    args = parser.parse_args(argv)
    if args.reproduce:
        return reproduce(args.reproduce, (args.target or [None])[0])
    if args.iterations is None and args.hours is None and os.environ.get(HOURS_ENV):
        args.hours = float(os.environ[HOURS_ENV])
    if args.iterations is None and args.hours is None:
        parser.error(f"give --iterations, --hours or {HOURS_ENV}")
    targets = args.target or sorted(TARGETS)
    seeds = {name: _fuzz_corpus.seeds(name, ROOT) for name in targets}
    out = Path(args.crashes)

    def keep(target: str, parts: tuple[bytes, ...], trace: str) -> None:
        data = _fuzz.frame(parts)
        folder = out / target
        folder.mkdir(parents=True, exist_ok=True)
        name = hashlib.sha256(data).hexdigest()[:16]
        (folder / f"{name}.bin").write_bytes(data)
        (folder / f"{name}.txt").write_text(trace, encoding="utf-8")

    print(f"fuzz: seed {args.seed}, targets {', '.join(targets)}", flush=True)
    done = dict.fromkeys(targets, 0)
    failed = dict.fromkeys(targets, 0)
    deadline = time.monotonic() + args.hours * 3600 if args.hours is not None else None
    turn = 0
    watch: list[object] = [None, None]
    current = [targets[0]]
    watchdog(watch, keep, lambda: current[0])
    while True:
        live = [t for t in targets if args.iterations is None or done[t] < args.iterations]
        if not live or (deadline is not None and time.monotonic() >= deadline):
            break
        name = live[turn % len(live)]
        current[0] = name
        turn += 1
        budget = args.report_every
        if deadline is not None:
            budget = min(budget, max(0.0, deadline - time.monotonic()))
        left = None if args.iterations is None else args.iterations - done[name]
        seed = args.seed + turn * 1_000_003 + done[name]
        report = _fuzz.fuzz(name, seeds[name], seed=seed, iterations=left, seconds=budget,
                            on_crash=keep, watch=watch)  # fmt: skip
        for found in report.slow:
            keep(name, _fuzz.unframe(bytes.fromhex(found["input"])), "slow")
        done[name] += report.iterations
        failed[name] += len(report.crashes) + len(report.slow)
        print(f"fuzz: {name}: {done[name]} inputs, {failed[name]} crashes, "
              f"slowest {report.slowest:.3f}s", flush=True)  # fmt: skip
    return 1 if any(failed.values()) else 0


if __name__ == "__main__":
    raise SystemExit(main())
