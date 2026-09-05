"""Regenerate ``docs/conformance/`` from the authored conformance cases.

``--check`` diffs instead of writing, which is what the drift gate runs.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tests.conformance.generate import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
