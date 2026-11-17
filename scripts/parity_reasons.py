"""Reason-code parity for ``scripts/check_parity.py --reasons`` (0.53).

Verdict parity lets a refusal that names no code pass. With ``--reasons`` every
refusal of a pinned ``reject`` case must name a reason code, in each of the
python reference, the built pyz and the TS verifier, and that code must be the
pinned one (or a member of its alias group). An unnamed refusal and a
mismatched code are both problems.
"""

from __future__ import annotations

from collections import Counter


def allowed(record: dict, groups) -> set[str]:
    codes = set(record.get("reason_any") or [record["reason"]])
    for group in groups:
        if group & codes:
            codes |= group
    return codes


class ReasonTally:
    """Counts unnamed refusals and reason mismatches per implementation."""

    def __init__(self) -> None:
        self.unnamed: Counter = Counter()
        self.mismatch: Counter = Counter()
        self.checked: Counter = Counter()
        self.problems: list[str] = []

    def see(self, impl: str, record: dict, groups, refused: bool, code: str | None) -> None:
        if record["expect"] != "reject" or not refused:
            return
        self.checked[impl] += 1
        if not code:
            self.unnamed[impl] += 1
            self.problems.append(f"{impl} unnamed refusal: {record['id']}")
        elif code not in allowed(record, groups):
            self.mismatch[impl] += 1
            want = record.get("reason") or record.get("reason_any")
            self.problems.append(f"{impl} reason mismatch: {record['id']}: {code} != {want}")

    def summary(self) -> str:
        parts = [
            f"{impl} {self.checked[impl]} refusals, {self.unnamed[impl]} unnamed, "
            f"{self.mismatch[impl]} mismatched"
            for impl in ("python", "pyz", "ts")
        ]
        return "reasons: " + "; ".join(parts)
