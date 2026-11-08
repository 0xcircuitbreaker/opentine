"""Print the PII detector recall/precision table that docs/PII.md publishes.

    python scripts/pii_eval.py [CORPUS]

The default corpus is ``tests/fixtures/pii/corpus.jsonl``, scored with the
default classifier layer (``rules/1``).
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from opentine._pii_classify import RuleClassifier  # noqa: E402
from opentine._pii_eval import load, table  # noqa: E402

DEFAULT = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "pii" / "corpus.jsonl"

if __name__ == "__main__":
    corpus = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT
    print(table(load(corpus), RuleClassifier()))
