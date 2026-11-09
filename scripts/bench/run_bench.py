"""Compression bench: sizes and MB/s for every storage form, as JSON.

Usage::

    uv run python scripts/bench/run_bench.py [--runs 40] [--steps 24] [--seed 37] [--out bench.json]

Builds the synthetic corpus from ``scripts/bench/corpus.py`` through the public
``Repo.put_run`` API, then measures

* ``loose``: the object store before any packing;
* ``gc``: ``tine gc`` packs (whatever pack format and codec the code writes);
* ``gc_v3`` and ``gc_dicts``: ``tine gc --upgrade`` packs, then the same with
  ``--dictionaries`` (0.50; the row is absent for a library without them);
* ``wire``: ``Repo.pack()``, the transfer pack push/fetch send;
* ``bundle``: ``tine bundle create`` output;
* ``zstd19_per_object``: every object compressed alone at zstd level 19;
* ``zstd9_long27_stream``: all objects in run order, one zstd-9 frame with
  ``--long=27`` (window_log 27 plus long-distance matching).

Because it only uses the public writers it measures whatever format the
current checkout produces; compare two checkouts' JSON to see a change.
Throughput is logical (uncompressed object) MB per wall-clock second, single
threaded. ``--compare base.json`` adds the size and speed ratios against an
earlier report.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
if "--library" in sys.argv:  # bench another checkout's opentine with this interpreter
    import importlib.machinery

    sys.path.insert(0, str(Path(sys.argv[sys.argv.index("--library") + 1]).resolve()))
    sys.meta_path.insert(0, importlib.machinery.PathFinder)  # ahead of an editable install

from corpus import generate  # noqa: E402

from opentine import __version__, _bundle  # noqa: E402
from opentine.kernel import parse_oid  # noqa: E402
from opentine.repository import Repo  # noqa: E402
from opentine.repository._gc import gc  # noqa: E402

MB = 1_000_000


def _zstd():
    try:
        from compression import zstd  # Python 3.14+
    except ImportError:
        from backports import zstd  # type: ignore[import-not-found,no-redef]
    return zstd


def _tree_bytes(path: Path) -> int:
    return sum(p.stat().st_size for p in path.rglob("*") if p.is_file())


def _links(value, out: list[str]) -> None:
    if isinstance(value, str):
        try:
            parse_oid(value)
        except Exception:
            return
        out.append(value)
    elif isinstance(value, dict):
        for item in value.values():
            _links(item, out)
    elif isinstance(value, list):
        for item in value:
            _links(item, out)


def run_order(repo: Repo, run_ids: list[str]) -> list[str]:
    """Every reachable object once, in recording order (run by run, depth first)."""
    seen: set[str] = set()
    order: list[str] = []
    for run_id in run_ids:
        stack = [run_id]
        while stack:
            oid = stack.pop()
            if oid in seen or not repo.has(oid):
                continue
            seen.add(oid)
            order.append(oid)
            found: list[str] = []
            _links(repo.get(oid).payload(), found)
            stack.extend(reversed(found))
    return order


def _row(size: int, seconds: float, logical: int, **extra) -> dict:
    return {
        "bytes": size,
        "ratio": round(size / logical, 5) if logical else None,
        "seconds": round(seconds, 4),
        "mb_per_s": round(logical / MB / seconds, 2) if seconds > 0 else None,
        **extra,
    }


def _dict_rows(repo: Repo, logical: int) -> dict:
    """``gc_v3`` (storage v3 packs) and ``gc_dicts`` (v3 with per-kind dictionaries,
    0.50, P3: packs plus the ``dicts/`` they need). Absent before the code had them."""
    rows: dict = {}
    started = time.perf_counter()
    gc(repo, upgrade=True, repack=True)
    seconds = time.perf_counter() - started
    rows["gc_v3"] = _row(_tree_bytes(repo.path / "packs"), seconds, logical)
    try:
        from opentine.repository import _gc_dicts
    except ImportError:
        return rows
    _gc_dicts.enable(repo)
    started = time.perf_counter()
    gc(repo, repack=True)
    seconds = time.perf_counter() - started
    dicts = repo.path / "dicts"
    stored = _tree_bytes(repo.path / "packs") + (_tree_bytes(dicts) if dicts.is_dir() else 0)
    used = len(list(dicts.glob("*.zdict"))) if dicts.is_dir() else 0
    rows["gc_dicts"] = _row(stored, seconds, logical, dictionaries=used)
    return rows


def bench(seed: int, runs: int, steps: int, work: Path) -> dict:
    os.environ["OPENTINE_AUTO_PACK"] = "off"  # measure loose, then gc, explicitly
    repo = Repo.init(work / "repo")
    started = time.perf_counter()
    run_ids = [
        repo.put_run(run, ref=f"heads/bench/{n:04d}").run_id
        for n, run in enumerate(generate(seed=seed, runs=runs, steps=steps))
    ]
    ingest = time.perf_counter() - started
    order = run_order(repo, run_ids)
    raws = [repo.raw(oid) for oid in order]
    logical = sum(len(raw) for raw in raws)
    loose = _tree_bytes(repo.path / "objects")
    results: dict = {"loose": _row(loose, ingest, logical, note="seconds = put_run ingest")}

    zstd = _zstd()
    started = time.perf_counter()
    per_object = sum(len(zstd.compress(raw, level=19)) for raw in raws)
    results["zstd19_per_object"] = _row(per_object, time.perf_counter() - started, logical)

    stream = b"".join(raws)
    param = zstd.CompressionParameter
    options = {
        param.compression_level: 9,
        param.window_log: 27,
        param.enable_long_distance_matching: 1,
    }
    started = time.perf_counter()
    framed = zstd.ZstdCompressor(options=options).compress(stream, zstd.ZstdCompressor.FLUSH_FRAME)
    results["zstd9_long27_stream"] = _row(len(framed), time.perf_counter() - started, logical)

    started = time.perf_counter()
    outcome = gc(repo)
    gc_seconds = time.perf_counter() - started
    packs = _tree_bytes(repo.path / "packs")
    results["gc"] = _row(packs, gc_seconds, logical, codec=getattr(outcome, "codec", None))

    results.update(_dict_rows(repo, logical))
    reopened = Repo.open(repo.path)
    started = time.perf_counter()
    wire = reopened.pack(order)
    results["wire"] = _row(len(wire), time.perf_counter() - started, logical)
    target = Repo.init(work / "fetched")
    started = time.perf_counter()
    target.import_pack(wire)
    results["wire"]["read_mb_per_s"] = round(logical / MB / (time.perf_counter() - started), 2)

    started = time.perf_counter()
    bundle = _bundle.create(reopened)
    results["bundle"] = _row(len(bundle), time.perf_counter() - started, logical)
    started = time.perf_counter()
    _bundle.verify(bundle)
    results["bundle"]["read_mb_per_s"] = round(logical / MB / (time.perf_counter() - started), 2)

    return {
        "schema": "opentine-bench/1",
        "opentine": __version__,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "corpus": {
            "seed": seed,
            "runs": runs,
            "steps": steps,
            "objects": len(order),
            "logical_bytes": logical,
        },
        "results": results,
    }


def compare(report: dict, base: dict) -> dict:
    out = {}
    for name, row in report["results"].items():
        old = base.get("results", {}).get(name)
        if not old:
            continue
        out[name] = {
            "bytes_vs_base": round(row["bytes"] / old["bytes"], 4) if old["bytes"] else None,
            "speed_vs_base": (
                round(row["mb_per_s"] / old["mb_per_s"], 3)
                if row.get("mb_per_s") and old.get("mb_per_s")
                else None
            ),
        }
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--seed", type=int, default=37)
    parser.add_argument("--runs", type=int, default=40)
    parser.add_argument("--steps", type=int, default=24)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--compare", type=Path, help="an earlier report to compare against")
    parser.add_argument("--library", type=Path, help="a checkout whose opentine/ to bench")
    args = parser.parse_args(argv)
    work = Path(tempfile.mkdtemp(prefix="tine-bench-"))
    try:
        report = bench(args.seed, args.runs, args.steps, work)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    if args.compare and args.compare.is_file():
        report["compare"] = compare(report, json.loads(args.compare.read_text("utf-8")))
    text = json.dumps(report, indent=2, sort_keys=True)
    if args.out:
        args.out.write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
