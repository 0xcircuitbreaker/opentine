"""Evidence-based advisory detectors and the ``advise`` entry point (0.60).

Advisory findings never block by default (D12): ``advise`` returns them with
``blocking: false`` and ``exit_code`` stays 0 unless a caller opts in with
``block_on_advisory``.
"""

from __future__ import annotations

import hashlib
import json

from opentine import _integrity_advisory as _d

DEFAULT_POLICY = {"holdout_gap": 0.15, "judge_disagree": 0.25, "block_on_advisory": False}


def _num(value) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def detect_visible_holdout_gap(run: dict, policy: dict) -> list[_d.Finding]:
    scores = run.get("scores") or {}
    vis, hold = _num(scores.get("visible")), _num(scores.get("holdout"))
    if vis is None or hold is None:
        return []
    gap = vis - hold
    if gap > float(policy["holdout_gap"]):
        detail = f"visible {vis:g} vs holdout {hold:g} gap {gap:.3f} > {policy['holdout_gap']}"
        return [_d._finding("advisory:visible-holdout-gap", "", detail)]
    return []


def detect_judge_ground_truth_disagree(run: dict, policy: dict) -> list[_d.Finding]:
    out = []
    for i, row in enumerate(run.get("judgements", [])):
        judge, truth = _num(row.get("judge")), _num(row.get("ground_truth"))
        if judge is None or truth is None:
            continue
        if abs(judge - truth) > float(policy["judge_disagree"]):
            item = str(row.get("item", i))
            detail = f"item {item}: judge {judge:g} vs ground truth {truth:g}"
            out.append(_d._finding("advisory:judge-ground-truth-disagree", "", detail))
    return out


def _digest(value) -> str:
    if isinstance(value, str) and value.startswith("sha256:"):
        return value
    body = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(body.encode("utf-8")).hexdigest()


def _key(row: dict, field: str) -> tuple[str, str, str]:
    out = row.get(f"output_{field}", row.get("output"))
    return (
        str(row.get("tool", "")),
        _digest(row.get(f"input_{field}", row.get("input"))),
        _digest(out) if out is not None else "",
    )


def detect_fabricated_tool_evidence(run: dict) -> list[_d.Finding]:
    """A claimed tool call (and result) with no matching captured event."""
    events = [e for e in run.get("events", []) if isinstance(e, dict) and e.get("tool")]
    seen = {_key(e, "sha256") for e in events}
    seen_in = {k[:2] for k in seen}
    out = []
    for claim in run.get("claimed_tool_calls", []):
        tool, inp, res = _key(claim, "sha256")
        if (tool, inp) not in seen_in:
            detail = f"claimed {tool} call has no captured event"
        elif res and (tool, inp, res) not in seen:
            detail = f"claimed {tool} result differs from the captured event"
        else:
            continue
        out.append(_d._finding("advisory:fabricated-tool-evidence", "", detail))
    return out


def advise(run: dict, policy: dict | None = None) -> dict:
    """Every advisory finding for one run record, sorted, never blocking by default."""
    pol = {**DEFAULT_POLICY, **(policy or {})}
    findings = []
    for detect in (
        _d.detect_test_deleted,
        _d.detect_test_skipped_added,
        _d.detect_special_casing,
        _d.detect_conftest_tampered,
        _d.detect_timing_fake,
        _d.detect_env_answer_leak,
        detect_fabricated_tool_evidence,
    ):
        findings += detect(run)
    findings += detect_visible_holdout_gap(run, pol)
    findings += detect_judge_ground_truth_disagree(run, pol)
    findings = _d.sort_findings(findings)
    blocking = bool(pol["block_on_advisory"]) and bool(findings)
    return {
        "run": str(run.get("id", "")),
        "findings": findings,
        "codes": sorted({f["code"] for f in findings}),
        "blocking": blocking,
        "exit_code": 1 if blocking else 0,
    }


def render(report: dict) -> str:
    """One output line per finding: ``advisory:<code> <path>: <detail>``."""
    lines = []
    for f in report["findings"]:
        where = f" {f['path']}:" if f["path"] else ""
        lines.append(f"{f['code']}{where} {f['detail']}")
    return "\n".join(lines) + ("\n" if lines else "")
