"""The 0.40 CDC bake-off: BLOB_PREFIX_DELTA against FastCDC against both (ROADMAP §4).

Usage::

    uv run python scripts/bench/cdc_bakeoff.py [--runs 40] [--steps 24] [--out report.json]

Corpora:

* ``synthetic``: ``corpus.generate`` stored through ``Repo.put_run``, every
  object in v3 pack order (``_pack_v3.stored_forms``);
* ``fixtures``: every real agent session transcript in the repository
  (``tests/fixtures/harness/**/*.jsonl``), replayed as a transcript blob that
  grows by one line per save, the way ``put_transcript`` stores a run;
* ``growth``: the synthetic runs' transcripts saved after every step (the
  ``put_transcript`` growth pattern at scale).

Every option lays objects out as a v3 local pack does (one kind per block,
blocks up to ``--block-mib``, zstd ``--level``) and reports stored bytes, encode
CPU seconds, and cold random-access latency (p50/p95 over ``--samples`` blobs,
every block a read touches inflated afresh):

* ``full``: v3 as shipped in 0.37-0.39 (every blob whole);
* ``bpd-middle``: BLOB_PREFIX_DELTA, base chosen middle-out among the 16 blobs
  before it, stored as the differing middle (``_blob_delta``);
* ``bpd-patchfrom``: the same bases, the blob zstd-compressed with its base as
  a raw prefix dictionary (``--patch-from``), stored outside the blocks;
* ``cdc-2k`` / ``cdc-8k`` / ``cdc-64k``: FastCDC (gear hash, normalized),
  unique chunks in the blocks, 36 bytes of recipe per chunk reference;
* ``bpd+cdc-8k``: the ``bpd-middle`` stored forms, then chunked and deduplicated.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from opentine._codec import _zstd  # noqa: E402
from opentine.kernel import canonical_json  # noqa: E402
from opentine.repository import Repo  # noqa: E402
from opentine.repository import _blob_delta as bd  # noqa: E402
from opentine.repository._pack_v3 import stored_forms  # noqa: E402
from opentine.repository._run_delta import split  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
REF_BYTES = 36  # sha256 + u32 length per chunk reference in a recipe
_GEAR = [random.Random(40).getrandbits(64) for _ in range(256)]
_M64 = (1 << 64) - 1


# --- FastCDC ----------------------------------------------------------------


def fastcdc(data: bytes, avg: int) -> list[bytes]:
    """FastCDC chunks of *data* (normalized chunking, level 1)."""
    low, high, bits = avg // 4, avg * 8, avg.bit_length() - 1
    hard = ((1 << (bits + 1)) - 1) << (64 - bits - 1)  # below avg: harder to cut
    easy = ((1 << (bits - 1)) - 1) << (64 - bits + 1)  # past avg: easier
    out, start, size = [], 0, len(data)
    gear = _GEAR
    while start < size:
        end = min(size, start + high)
        if end - start <= low:
            out.append(data[start:end])
            break
        h, i, cut = 0, start + low, end
        middle = min(end, start + avg)
        while i < middle:
            h = ((h << 1) + gear[data[i]]) & _M64
            i += 1
            if not h & hard:
                cut = i
                break
        else:
            while i < end:
                h = ((h << 1) + gear[data[i]]) & _M64
                i += 1
                if not h & easy:
                    cut = i
                    break
        out.append(data[start:cut])
        start = cut
    return out


# --- a v3-like block store ----------------------------------------------------


class Store:
    """Items laid out like a v3 pack: one kind per block, blocks zstd-compressed."""

    def __init__(self, block_bytes: int, level: int) -> None:
        self.block_bytes, self.level = block_bytes, level
        self.blocks: list[bytes] = []
        self.where: dict[str, tuple[int, int, int]] = {}
        self.extra = 0  # bytes stored outside the blocks (recipes, patch frames)
        self._pending: list[tuple[str, bytes]] = []
        self._kind, self._size = "", 0

    def add(self, key: str, data: bytes, kind: str) -> None:
        if key in self.where or any(k == key for k, _ in self._pending):
            return
        if self._pending and (kind != self._kind or self._size + len(data) > self.block_bytes):
            self.flush()
        self._pending.append((key, data))
        self._kind, self._size = kind, self._size + len(data)

    def flush(self) -> None:
        if not self._pending:
            return
        offset, number = 0, len(self.blocks)
        for key, data in self._pending:
            self.where[key] = (number, offset, len(data))
            offset += len(data)
        raw = b"".join(data for _, data in self._pending)
        self.blocks.append(_zstd().compress(raw, level=self.level))
        self._pending, self._size = [], 0

    def size(self) -> int:
        return sum(map(len, self.blocks)) + self.extra

    def get(self, key: str, cache: dict[int, bytes]) -> bytes:
        number, offset, length = self.where[key]
        if number not in cache:
            cache[number] = _zstd().decompress(self.blocks[number])
        return cache[number][offset : offset + length]


# --- options ----------------------------------------------------------------


def _layout(objects, block_bytes, level, blob_items):
    """A Store holding every non-blob object whole and the blobs as *blob_items*."""
    store = Store(block_bytes, level)
    for oid, raw in objects:
        if not oid.startswith("blob:"):
            store.add(oid, raw, oid.split(":")[0])
    for key, data in blob_items:
        store.add(key, data, "blob")
    store.flush()
    return store


def opt_full(objects, args):
    store = _layout(objects, args.block, args.level, [(o, r) for o, r in objects if _blob(o)])

    def read(oid, cache):
        return store.get(oid, cache)

    return store, read


def _blob(oid: str) -> bool:
    return oid.startswith("blob:")


def opt_bpd_middle(objects, args, deltas=None):
    deltas = bd.choose(objects) if deltas is None else deltas
    items = [(o, deltas[o][1] if o in deltas else r) for o, r in objects if _blob(o)]
    store = _layout(objects, args.block, args.level, items)

    def read(oid, cache):
        chain = []
        while oid in deltas:
            chain.append(oid)
            oid = deltas[oid][0]
        raw = store.get(oid, cache)
        for key in reversed(chain):
            raw = bd.apply(bd.parse(store.get(key, cache)), raw)
        return raw

    return store, read


def opt_bpd_patchfrom(objects, args):
    zstd = _zstd()
    raws = dict(objects)
    bases = {oid: base for oid, (base, _) in bd.choose(objects).items()}
    frames: dict[str, bytes] = {}
    for oid, base in bases.items():
        prefix = zstd.ZstdDict(split(raws[base])[1], is_raw=True).as_prefix
        frames[oid] = zstd.compress(raws[oid], level=args.level, zstd_dict=prefix)
    full = [(o, r) for o, r in objects if _blob(o) and o not in bases]
    store = _layout(objects, args.block, args.level, full)
    store.extra = sum(len(f) + 32 for f in frames.values())

    def read(oid, cache):
        chain = []
        while oid in bases:
            chain.append(oid)
            oid = bases[oid]
        raw = store.get(oid, cache)
        for key in reversed(chain):
            prefix = zstd.ZstdDict(split(raw)[1], is_raw=True).as_prefix
            raw = zstd.decompress(frames[key], zstd_dict=prefix)
        return raw

    return store, read


def _chunked(objects, args, avg, items):
    recipes: dict[str, list[str]] = {}
    chunks: list[tuple[str, bytes]] = []
    for oid, data in items:
        keys = []
        for chunk in fastcdc(data, avg):
            key = hashlib.sha256(chunk).hexdigest()
            keys.append(key)
            chunks.append((key, chunk))
        recipes[oid] = keys
    store = _layout(objects, args.block, args.level, chunks)
    store.extra = sum(REF_BYTES * len(keys) + 8 for keys in recipes.values())
    return store, recipes


def opt_cdc(avg):
    def build(objects, args):
        items = [(o, r) for o, r in objects if _blob(o)]
        store, recipes = _chunked(objects, args, avg, items)

        def read(oid, cache):
            return b"".join(store.get(key, cache) for key in recipes[oid])

        return store, read

    return build


def opt_bpd_cdc(objects, args):
    deltas = bd.choose(objects)
    items = [(o, deltas[o][1] if o in deltas else r) for o, r in objects if _blob(o)]
    store, recipes = _chunked(objects, args, 8 * 1024, items)

    def stored(oid, cache):
        return b"".join(store.get(key, cache) for key in recipes[oid])

    def read(oid, cache):
        chain = []
        while oid in deltas:
            chain.append(oid)
            oid = deltas[oid][0]
        raw = stored(oid, cache)
        for key in reversed(chain):
            raw = bd.apply(bd.parse(stored(key, cache)), raw)
        return raw

    return store, read


OPTIONS = {
    "full": opt_full,
    "bpd-middle": opt_bpd_middle,
    "bpd-patchfrom": opt_bpd_patchfrom,
    "cdc-2k": opt_cdc(2 * 1024),
    "cdc-8k": opt_cdc(8 * 1024),
    "cdc-64k": opt_cdc(64 * 1024),
    "bpd+cdc-8k": opt_bpd_cdc,
}


def measure(name: str, objects: list[tuple[str, bytes]], args) -> dict:
    logical = sum(len(raw) for _, raw in objects)
    started = time.process_time()
    store, read = OPTIONS[name](objects, args)
    cpu = time.process_time() - started
    blobs = [oid for oid, _ in objects if _blob(oid)]
    sample = random.Random(args.seed).sample(blobs, min(args.samples, len(blobs)))
    raws = dict(objects)
    times = []
    for oid in sample:
        began = time.perf_counter()
        got = read(oid, {})
        times.append(time.perf_counter() - began)
        if got != raws[oid]:
            raise SystemExit(f"{name}: {oid} did not round-trip")
    times.sort()
    pick = lambda q: round(1000 * times[min(len(times) - 1, int(q * len(times)))], 3)  # noqa: E731
    size = store.size()
    return {
        "bytes": size,
        "ratio": round(logical / size, 2),
        "encode_cpu_s": round(cpu, 3),
        "access_p50_ms": pick(0.5),
        "access_p95_ms": pick(0.95),
    }


# --- corpora ----------------------------------------------------------------


def synthetic(work: Path, args) -> tuple[list[tuple[str, bytes]], list[tuple[str, bytes]]]:
    """(pack-ordered objects, per-step transcript growth blobs) of the corpus."""
    from corpus import generate

    repo = Repo.init(work / "synthetic")
    growth: list[tuple[str, bytes]] = []
    for n, run in enumerate(generate(seed=args.seed, runs=args.runs, steps=args.steps)):
        repo.put_run(run, ref=f"heads/bench/{n:04d}")
        history: list = []
        for step in run.steps:  # put_transcript growth: one save per step
            history.append({"id": step.id, "kind": str(step.kind), "outputs": step.outputs})
            oid = repo.put("blob", canonical_json({"messages": history}), redact=False)
            growth.append((oid, repo.raw(oid)))
    objects = [(oid, repo.raw(oid)) for oid in sorted(_all_oids(repo))]
    ordered = [(oid, raw) for oid, _, _, raw in stored_forms(objects, slim=False)]
    return ordered, growth


def _all_oids(repo: Repo) -> list[str]:
    from opentine.repository._gc import _loose_oids

    return _loose_oids(repo)


def fixtures(work: Path) -> list[tuple[str, bytes]]:
    repo = Repo.init(work / "fixtures")
    out = []
    for path in sorted((ROOT / "tests" / "fixtures").rglob("*.jsonl")):
        history: list = []
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            history.append(json.loads(line))
            oid = repo.put("blob", canonical_json({"messages": history}), redact=False)
            out.append((oid, repo.raw(oid)))
    return out


def _tree(path: Path) -> int:
    return sum(p.stat().st_size for p in path.rglob("*") if p.is_file())


def gc_compare(work: Path) -> dict:
    """gc end to end (pack, read back, drop loose) on copies of one ingested repo."""
    import shutil

    from opentine.repository import _gc_deltas
    from opentine.repository._gc import gc

    source = work / "synthetic"
    logical = sum(len(raw) for raw in _raws(Repo.open(source)))
    out = {}
    for mode in ("v1 (0.37 default)", "v3 (gc --upgrade)", "v3 + blob deltas"):
        target = work / f"gc-{len(out)}"
        shutil.copytree(source, target)
        repo = Repo.open(target)
        if "deltas" in mode:
            _gc_deltas.enable(repo)
        started = time.perf_counter()
        gc(repo, upgrade="v3" in mode)
        seconds = time.perf_counter() - started
        size = _tree(repo.path / "packs")
        out[mode] = {"bytes": size, "ratio": round(logical / size, 2), "seconds": round(seconds, 2)}
    return out


def _raws(repo: Repo) -> list[bytes]:
    return [repo.raw(oid) for oid in _all_oids(repo)]


def autopack_gate(work: Path, args) -> dict:
    """Autopack-sized packs (every 4 runs, about the 256-object threshold) timed per call.

    Gate (ROADMAP §4): autopack may write blob deltas only if its p95 latency
    stays within 1.5x of the same autopack without them.
    """
    from corpus import generate

    from opentine.repository import _gc_deltas
    from opentine.repository._autopack import _pack_sizes, merge_candidates
    from opentine.repository._gc import gc

    result = {}
    for mode in ("without", "with"):
        repo = Repo.init(work / f"autopack-{mode}")
        gc(repo, upgrade=True)
        if mode == "with":
            _gc_deltas.enable(repo)
        times = []
        for n, run in enumerate(generate(seed=args.seed, runs=args.runs, steps=args.steps)):
            repo.put_run(run, ref=f"heads/bench/{n:04d}")
            if n % 4 == 3:
                started = time.perf_counter()
                merge = merge_candidates(_pack_sizes(repo.path))
                gc(repo, min_age=0, merge_packs=merge, keep_transfer_packs=True)
                times.append(time.perf_counter() - started)
        times.sort()
        result[mode] = {
            "calls": len(times),
            "p50_s": round(times[len(times) // 2], 3),
            "p95_s": round(times[min(len(times) - 1, int(0.95 * len(times)))], 3),
            "pack_bytes": _tree(repo.path / "packs"),
        }
    ratio = result["with"]["p95_s"] / result["without"]["p95_s"]
    result["p95_ratio"], result["passes"] = round(ratio, 2), ratio <= 1.5
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--seed", type=int, default=37)
    parser.add_argument("--runs", type=int, default=40)
    parser.add_argument("--steps", type=int, default=24)
    parser.add_argument("--level", type=int, default=19)
    parser.add_argument("--block-mib", type=int, default=16)
    parser.add_argument("--samples", type=int, default=200)
    parser.add_argument("--only", nargs="*", choices=sorted(OPTIONS))
    parser.add_argument("--out", type=Path)
    args = parser.parse_args(argv)
    args.block = args.block_mib << 20
    os.environ["OPENTINE_AUTO_PACK"] = "off"
    with tempfile.TemporaryDirectory() as tmp:
        ordered, growth = synthetic(Path(tmp), args)
        corpora = {"synthetic": ordered, "growth": growth, "fixtures": fixtures(Path(tmp))}
        gc_rows = gc_compare(Path(tmp))
        print("gc", json.dumps(gc_rows), file=sys.stderr, flush=True)
        gate = autopack_gate(Path(tmp), args)
        print("autopack", json.dumps(gate), file=sys.stderr, flush=True)
    report: dict = {"schema": "opentine-cdc-bakeoff/1", "level": args.level,
                    "block_mib": args.block_mib, "corpora": {}, "gc": gc_rows,
                    "autopack_gate": gate}  # fmt: skip
    for label, objects in corpora.items():
        logical = sum(len(raw) for _, raw in objects)
        rows = {name: measure(name, objects, args) for name in args.only or OPTIONS}
        report["corpora"][label] = {"objects": len(objects), "logical_bytes": logical, **rows}
        print(label, json.dumps(rows), file=sys.stderr, flush=True)
    text = json.dumps(report, indent=2, sort_keys=True)
    if args.out:
        args.out.write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
