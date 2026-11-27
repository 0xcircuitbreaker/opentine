"""Scorer isolation at promotion (0.85).

A ``python:`` or ``plugin:`` scorer that ran inside the signing process (no
``--isolate``, so its ``scorer_version`` is not an ``sc1+`` closure pin) is an
in-process scorer. By default ``tine promote`` reports it as the advisory
``scorer.in-process`` and does not block (owner decision D12). It refuses
(``promote.scorer-in-process``) only when the signed promotion policy says so:
``scorer_isolation = "required"``, or ``profile = "rsi"``, which requires it and
cannot be combined with ``scorer_isolation = "advisory"``. From 0.86 the rsi
profile also turns on ``require_plan`` (a pre-registered plan, refusable only
there) and requires every eval signer to hold a pinned ``scorer`` role.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

IN_PROCESS = ("python", "plugin")
MODES = ("advisory", "required")
PROFILES = ("rsi",)


def check_policy(policy: dict[str, Any]) -> None:
    """Validate and settle ``scorer_isolation`` / ``profile`` in a loaded ``[promote]`` table."""
    profile = policy.get("profile")
    if profile is not None and profile not in PROFILES:
        raise ValueError(f"profile is one of {', '.join(PROFILES)}")
    mode = policy.get("scorer_isolation", "required" if profile == "rsi" else "advisory")
    if mode not in MODES:
        raise ValueError(f"scorer_isolation is one of {', '.join(MODES)}")
    if profile == "rsi" and mode != "required":
        raise ValueError('the rsi profile requires scorer_isolation = "required"')
    policy["scorer_isolation"] = mode
    plan = policy.get("require_plan", profile == "rsi")  # 0.86: advisory unless rsi (D12)
    if not isinstance(plan, bool) or (profile == "rsi" and not plan):
        raise ValueError("require_plan is a boolean; the rsi profile requires it")
    policy["require_plan"] = plan
    policy["require_signer_roles"] = profile == "rsi"  # 0.86: pinned scorer keys only
    policy["require_lineage"] = profile == "rsi"  # 0.86: hidden candidates fail closed


def in_process(folder: Path) -> bool:
    from opentine._eval_run import read_verdicts
    from opentine._scorer_closure import PREFIX

    try:
        rows = read_verdicts(Path(folder))
    except (OSError, ValueError):
        return False  # an unreadable eval is refused as promote.eval-invalid
    return any(isinstance(r, dict) and r.get("scorer") in IN_PROCESS
               and not str(r.get("scorer_version", "")).startswith(PREFIX)
               for r in rows)  # fmt: skip


def isolation(policy: dict[str, Any], folders: dict[str, Path]) -> tuple[list, list]:
    """``(refusals, advisories)`` for the eval folders the gate read, by side."""
    from opentine._promote_checks import refusal

    sides = [side for side, folder in folders.items() if in_process(folder)]
    if not sides:
        return [], []
    detail = f"{', '.join(sides)} eval(s) ran an in-process scorer (no --isolate)"
    if policy.get("scorer_isolation", "advisory") == "required":
        return [refusal("promote.scorer-in-process", detail)], []
    return [], [{"code": "advisory:scorer.in-process", "detail": detail}]


__all__ = ["check_policy", "in_process", "isolation"]
