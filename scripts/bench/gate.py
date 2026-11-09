"""1.0 criterion 6: the compression bench has regressed by no more than 5% since 0.40.

Usage::

    python scripts/bench/gate.py --base bench-040.json --current bench.json [--max 0.05]

Both reports come from ``run_bench.py`` on the same runner in the same job, with
the same interpreter and dependencies (``--library`` points the baseline at the
0.40.0 tag's ``opentine/``), so the gate is relative and hardware-pinned: no
absolute size or speed is compared against a number measured elsewhere.

Gated: the stored bytes of every form both reports have (``GATED``), at most
``1 + max`` times the 0.40 bytes for the same seeded runs (the object bytes
themselves may differ: format v5 became the default writer in 0.42), so this
is what a user stores for the same recording. Sizes are deterministic.
Reported, not gated: throughput. Wall-clock speed on a shared CI runner varies
by more than 5% between two runs of the same code, so a 5% speed gate would
fail at random; the ratios are printed so a reader can judge them.

Prints a Markdown table and exits 1 when a gated form regressed.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

#: Storage forms the library writes (the zstd reference rows measure zstd itself).
GATED = ("gc", "gc_v3", "wire", "bundle")


def evaluate(base: dict, current: dict, limit: float) -> tuple[list[dict], bool]:
    rows, ok = [], True
    for name in sorted(set(base["results"]) | set(current["results"])):
        old, new = base["results"].get(name), current["results"].get(name)
        row = {"form": name, "base_bytes": old and old["bytes"], "bytes": new and new["bytes"]}
        if old and new and old["bytes"]:
            row["bytes_vs_base"] = round(new["bytes"] / old["bytes"], 4)
        if old and new and old.get("mb_per_s") and new.get("mb_per_s"):
            row["speed_vs_base"] = round(new["mb_per_s"] / old["mb_per_s"], 3)
        row["gated"] = name in GATED and "bytes_vs_base" in row
        row["pass"] = not row["gated"] or row["bytes_vs_base"] <= 1 + limit
        ok = ok and row["pass"]
        rows.append(row)
    missing = [name for name in GATED if name not in current["results"]]
    if missing:
        rows.append({"form": ",".join(missing), "gated": True, "pass": False, "missing": True})
        ok = False
    return rows, ok


def table(base: dict, current: dict, rows: list[dict], limit: float) -> str:
    lines = [
        f"### Bench vs {base['opentine']} (criterion 6: bytes within {limit:.0%})\n",
        f"Runner: {current.get('platform')}, Python {current.get('python')}; "
        f"{current['corpus']['runs']} runs, seed {current['corpus']['seed']}.\n",
        "| form | 0.40 bytes | bytes | bytes vs 0.40 | speed vs 0.40 | gate |",
        "|---|---:|---:|---:|---:|---|",
    ]
    for row in rows:
        gate = ("pass" if row["pass"] else "FAIL") if row["gated"] else "reported"
        lines.append(
            f"| {row['form']} | {row.get('base_bytes') or ''} | {row.get('bytes') or ''} "
            f"| {row.get('bytes_vs_base', '')} | {row.get('speed_vs_base', '')} | {gate} |"
        )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--base", type=Path, required=True)
    parser.add_argument("--current", type=Path, required=True)
    parser.add_argument("--max", type=float, default=0.05, help="largest allowed regression")
    args = parser.parse_args(argv)
    base = json.loads(args.base.read_text("utf-8"))
    current = json.loads(args.current.read_text("utf-8"))
    same = ("seed", "runs", "steps")  # the input; object bytes may differ by format version
    if any(base["corpus"][key] != current["corpus"][key] for key in same):
        print("the two reports recorded different runs; rerun with the same arguments")
        return 2
    rows, ok = evaluate(base, current, args.max)
    print(table(base, current, rows, args.max))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
