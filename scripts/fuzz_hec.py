"""Coverage-guided fuzzing of the HEC1 decoder with atheris (0.81, optional).

    python scripts/fuzz_hec.py --hours 1            # needs `pip install atheris`

The target is ``opentine._fuzz_hec.run_one``: a refusal must be a ``HecError``
with a published reason code, and an accepted table must decode identically
under its exact want-set and after re-encoding. The corpus starts from the
shipped decode vectors (``tests/vectors/tinepack6/packs``). Without atheris,
use the deterministic mutation fuzzer, which CI runs on every push::

    python scripts/fuzz.py --target hec --target pack --iterations 200000 --seed 1
"""

from __future__ import annotations

import argparse
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

SEEDS = ROOT / "tests" / "vectors" / "tinepack6" / "packs"


def main(argv: list[str] | None = None) -> int:  # pragma: no cover - needs atheris
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--hours", type=float, help="Stop after this many hours")
    args = parser.parse_args(argv)
    try:
        import atheris
    except ImportError:
        print("atheris is not installed; run scripts/fuzz.py --target hec instead")
        return 2
    with atheris.instrument_imports():
        from opentine import _fuzz_hec
    limit = [f"-max_total_time={int(args.hours * 3600)}"] if args.hours else []
    with tempfile.TemporaryDirectory(prefix="hec-corpus-") as corpus:
        for seed in sorted(SEEDS.glob("*.hec")):
            shutil.copy(seed, Path(corpus) / seed.name)
        atheris.Setup([sys.argv[0], *limit, corpus], _fuzz_hec.run_one)
        atheris.Fuzz()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
