"""Regenerate the 0.73 synthetic uplift dataset (deterministic).

    python scripts/gen_uplift_synthetic.py [tests/data/uplift_synthetic.json] [--seed N]

Writes attempts drawn from a known logistic (planted 50%-success horizon 60
minutes, slope -0.8 per doubling) as canonical JSON plus a newline. Same seed,
same bytes (see opentine/_uplift_synth.py).
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from opentine._uplift_synth import generate  # noqa: E402
from opentine.kernel import canonical_json  # noqa: E402

DEFAULT = ROOT / "tests" / "data" / "uplift_synthetic.json"


def render(seed: int = 0) -> bytes:
    return canonical_json(generate(seed)) + b"\n"


def main(argv: list[str]) -> int:
    seed = 0
    if "--seed" in argv:
        at = argv.index("--seed")
        seed = int(argv[at + 1])
        argv = argv[:at] + argv[at + 2 :]
    out = Path(argv[0]) if argv else DEFAULT
    out.write_bytes(render(seed))
    print(f"wrote {out} (seed {seed})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
