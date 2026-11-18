"""``tine dataset canary-check`` (0.61): a model that codes a canary too cheaply saw it.

A registered canary declares its entropy: the bits a model that never saw the
string needs, at least, to code it. A scoring run reports, per canary, the code
length the model under test assigns it (``-log2 P(canary)`` summed over its
tokens, in bits). A code length *below* the declared entropy is evidence the
model was trained on the holdout the canary sits in, and is refused:
``dataset.canary-below-entropy``. ``--margin-bits M`` refuses only below
``entropy_bits - M`` (slack for a declared entropy that is an estimate).

Only counted registrations (dataset role, pinned; :mod:`opentine._canary`)
judge. Everything else is advisory under owner decision D12 and never blocks
unless ``--strict``: a counted canary the run did not score
(``dataset.canary-unscored``), a scored digest nobody registered
(``dataset.canary-unregistered``), a registration that does not count
(``dataset.canary-not-counted``).

Review hardening: a lengths file that scores *none* of the counted canaries
proves nothing and is refused (``dataset.canary-none-scored``), so a run cannot
pass by leaving every canary out; ``--margin-bits`` must leave each judged
canary a positive floor.

The lengths file is JSON: ``{"lengths": [{"canary_sha256": HEX, "code_bits":
N}, ...]}`` (``model`` optional), or a plain ``{HEX: N}`` object.
"""

from __future__ import annotations

import json
import math
import re
from pathlib import Path
from typing import Any

from opentine._canary import CanaryError

BELOW = "dataset.canary-below-entropy"
UNSCORED = "dataset.canary-unscored"
UNREGISTERED = "dataset.canary-unregistered"
NOT_COUNTED = "dataset.canary-not-counted"
NONE_SCORED = "dataset.canary-none-scored"
CODES = (BELOW, UNSCORED, UNREGISTERED, NOT_COUNTED, NONE_SCORED)
_HEX = re.compile(r"[0-9a-f]{64}")


def read_lengths(data: bytes) -> tuple[dict[str, float], str | None]:
    """``({canary_sha256: code_bits}, model)`` from a scoring run's lengths file."""
    document = json.loads(data)
    model = None
    if isinstance(document, dict) and isinstance(document.get("lengths"), list):
        model = document.get("model") if isinstance(document.get("model"), str) else None
        rows = [r if isinstance(r, dict) else {} for r in document["lengths"]]
        pairs = [(r.get("canary_sha256"), r.get("code_bits"))
                 for r in rows]  # fmt: skip
    elif isinstance(document, dict):
        pairs = list(document.items())
    else:
        raise CanaryError("a lengths file is a JSON object")
    out: dict[str, float] = {}
    for hexdigest, bits in pairs:
        if not (isinstance(hexdigest, str) and _HEX.fullmatch(hexdigest)):
            raise CanaryError(f"{hexdigest!r} is not a canary sha256")
        if isinstance(bits, bool) or not isinstance(bits, (int, float)) or not math.isfinite(bits) \
                or bits < 0:  # fmt: skip
            raise CanaryError(f"code_bits for {hexdigest} is a finite number >= 0")
        if hexdigest in out:
            raise CanaryError(f"{hexdigest} is scored twice")
        out[hexdigest] = float(bits)
    return out, model


def _finding(level: str, code: str, sha: str, detail: str) -> dict[str, str]:
    return {"level": level, "code": code, "canary_sha256": sha, "detail": detail}


def check(root: Path, lengths_path: Path, *, margin_bits: int = 0,
          strict: bool = False) -> dict[str, Any]:  # fmt: skip
    from opentine._canary import load

    if type(margin_bits) is not int or margin_bits < 0:
        raise CanaryError("--margin-bits is an integer >= 0")
    lengths, model = read_lengths(Path(lengths_path).read_bytes())
    rows = load(Path(root))
    counted = {r["canary_sha256"]: r for r in rows if r["counted"]}
    others = {r["canary_sha256"] for r in rows} - set(counted)
    findings: list[dict[str, str]] = []
    judged = []
    for sha, row in sorted(counted.items()):
        bits = lengths.get(sha)
        if bits is None:
            findings.append(_finding("advisory", UNSCORED, sha, "the scoring run has no length"))
            continue
        if margin_bits >= row["entropy_bits"]:
            raise CanaryError(f"--margin-bits {margin_bits} would leave {sha} no floor")
        floor = row["entropy_bits"] - margin_bits
        below = bits < floor
        judged.append({"canary_sha256": sha, "holdout": row["holdout"], "code_bits": bits,
                       "entropy_bits": row["entropy_bits"], "below": below})  # fmt: skip
        if below:
            findings.append(
                _finding(
                    "fail",
                    BELOW,
                    sha,
                    f"coded in {bits:g} bits, below the "
                    f"declared {row['entropy_bits']} (margin {margin_bits})",
                )
            )
    for sha in sorted(set(lengths) - set(counted)):
        code = NOT_COUNTED if sha in others else UNREGISTERED
        why = ("its registration is not signed by a pinned dataset-role key" if sha in others
               else "no registration names this digest")  # fmt: skip
        findings.append(_finding("advisory", code, sha, why))
    if counted and not judged:
        findings.append(_finding("fail", NONE_SCORED, min(counted),
                                 "the run scored no counted canary"))  # fmt: skip
    hard = [f for f in findings if f["level"] == "fail" or strict]
    return {"ok": not hard, "model": model, "margin_bits": margin_bits, "judged": judged,
            "findings": findings, "blocking": len(hard)}  # fmt: skip


__all__ = [
    "BELOW",
    "CODES",
    "NONE_SCORED",
    "NOT_COUNTED",
    "UNREGISTERED",
    "UNSCORED",
    "check",
    "read_lengths",
]
