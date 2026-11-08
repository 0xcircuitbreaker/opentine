"""Write the published JSON Schemas (0.45) to ``docs/schemas``.

The schemas are spelled once, in ``opentine/_schema_defs*.py``, which is what
``tine schema show`` prints; ``docs/schemas`` is the rendered copy the web and
other languages read, and ``tests/test_045_schemas.py`` fails when it is stale.
Run this after editing a definition::

    uv run python scripts/gen_schemas.py
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from opentine._schemas import SCHEMAS, render  # noqa: E402

TARGETS = (ROOT / "docs" / "schemas",)


def main(check: bool = False) -> int:
    stale = []
    for target in TARGETS:
        target.mkdir(parents=True, exist_ok=True)
        for name, schema in SCHEMAS.items():
            path = target / f"{name}.schema.json"
            text = render(schema)
            if check:
                if not path.is_file() or path.read_text(encoding="utf-8") != text:
                    stale.append(path.relative_to(ROOT).as_posix())
            else:
                path.write_text(text, encoding="utf-8", newline="\n")
    for path in stale:
        print(f"stale: {path}", file=sys.stderr)
    return 1 if stale else 0


if __name__ == "__main__":
    raise SystemExit(main(check="--check" in sys.argv))
