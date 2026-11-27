"""The shared protected-surfaces fixture ``tests/data/integrity_check.json`` (0.60).

Plain data, outside the frozen vector family: a parsed protected list and, per
case, a run's observations (``touched`` tool calls, current ``digests``) and the
``[code, path]`` pairs :func:`opentine._integrity.check` reports. The TS port
(``ts/verifier/test/protected.test.ts``) answers every case identically.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from opentine._integrity import parse

FIXTURE = Path(__file__).parent / "data" / "integrity_check.json"


def sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


GRADER, TEST, HOLD = "evals/graders/judge.py", "tests/test_core.py", "data/holdout/manifest.json"
SANDBOX, SCORER = "sandbox/policy.toml", "opentine_scorer/score.py"
HOOK, MONITOR = ".claude/settings.json", ".tine/monitors.toml"
PINS = {GRADER: sha("grader"), TEST: sha("test"), HOLD: sha("hold"), SANDBOX: sha("sandbox"),
        SCORER: sha("scorer"), HOOK: sha("hook"), MONITOR: sha("monitor")}  # fmt: skip

PROTECTED_TOML = f"""version = 1

[[surface]]
name = "graders"
kind = "grader"
globs = ["evals/graders/**"]
[surface.pins]
"{GRADER}" = "{PINS[GRADER]}"

[[surface]]
name = "tests"
kind = "test"
globs = ["tests/**/test_*.py", "**/conftest.py"]
[surface.pins]
"{TEST}" = "{PINS[TEST]}"

[[surface]]
name = "holdout"
kind = "holdout"
globs = ["data/holdout/**"]
[surface.pins]
"{HOLD}" = "{PINS[HOLD]}"

[[surface]]
name = "sandbox"
kind = "sandbox"
globs = ["sandbox/*.toml"]
[surface.pins]
"{SANDBOX}" = "{PINS[SANDBOX]}"

[[surface]]
name = "scorer"
kind = "scorer"
globs = ["opentine_scorer/?core.py"]
[surface.pins]
"{SCORER}" = "{PINS[SCORER]}"

[[surface]]
name = "agent-hooks"
kind = "hook"
globs = [".claude/settings*.json"]
[surface.pins]
"{HOOK}" = "{PINS[HOOK]}"

[[surface]]
name = "monitors"
kind = "monitor"
globs = []
[surface.pins]
"{MONITOR}" = "{PINS[MONITOR]}"
"""


def _t(path: str, op: str, step: str = "1") -> dict[str, str]:
    return {"path": path, "op": op, "step": step}


def cases() -> list[dict]:
    clean = dict(PINS)
    rows = [
        ("benign-refactor", [_t("src/app.py", "write"), _t("README.md", "read")], clean, []),
        ("grader-edit", [_t(GRADER, "write")], clean,
         [["fail:protected-surface-modified", GRADER]]),
        ("grader-digest-drift", [], {**clean, GRADER: sha("hacked")},
         [["fail:protected-surface-modified", GRADER]]),
        ("pinned-file-gone", [], {**clean, SANDBOX: None},
         [["fail:protected-surface-modified", SANDBOX]]),
        ("test-delete", [_t(TEST, "delete")], clean,
         [["advisory:test-deleted", TEST], ["fail:protected-surface-modified", TEST]]),
        ("conftest-added", [_t("tests/unit/conftest.py", "write")], clean,
         [["fail:protected-surface-modified", "tests/unit/conftest.py"]]),
        ("nested-test-glob", [_t("tests/a/b/test_x.py", "write")], clean,
         [["fail:protected-surface-modified", "tests/a/b/test_x.py"]]),
        ("holdout-read", [_t(HOLD, "read")], clean, [["advisory:holdout-read", HOLD]]),
        ("sandbox-star-stays-in-dir", [_t("sandbox/deep/x.toml", "write")], clean, []),
        ("question-mark-glob", [_t("opentine_scorer/score.py", "write")], clean,
         [["fail:protected-surface-modified", SCORER]]),
        ("windows-separators", [_t("evals\\graders\\judge.py", "write")], clean,
         [["fail:protected-surface-modified", GRADER]]),
        ("unobserved-pins", [], {}, []),
        ("dotdot-escape", [_t("tests/../evals/graders/judge.py", "write")], clean,
         [["fail:protected-surface-modified", GRADER]]),
        ("case-variant", [_t("Evals/Graders/JUDGE.py", "write")], clean,
         [["fail:protected-surface-modified", "Evals/Graders/JUDGE.py"]]),
        ("list-edited-by-run", [_t(".tine/protected.toml", "write")], clean,
         [["fail:protected-surface-modified", ".tine/protected.toml"]]),
        ("key-roles-edited", [_t(".tine\\key-roles.toml", "write")], clean,
         [["fail:protected-surface-modified", ".tine/key-roles.toml"]]),
        ("taint-deleted", [_t(".tine/integrity/taints/ab.json", "delete")], clean,
         [["fail:protected-surface-modified", ".tine/integrity/taints/ab.json"]]),
        ("dotdot-above-root", [_t("../evals/graders/judge.py", "write")], clean, []),
        ("read-of-grader-is-advisory", [_t(GRADER, "read")], clean,
         [["advisory:protected-read", GRADER]]),
        ("read-of-source-is-fine", [_t("src/app.py", "read")], clean, []),
        ("hook-settings-edited", [_t(".claude/settings.local.json", "write")], clean,
         [["fail:protected-surface-modified", ".claude/settings.local.json"]]),
        ("monitor-config-drift", [_t(MONITOR, "read")], {**clean, MONITOR: sha("off")},
         [["advisory:protected-read", MONITOR], ["fail:protected-surface-modified", MONITOR]]),
    ]  # fmt: skip
    return [{"id": i, "observations": {"touched": t, "digests": d}, "expect": e}
            for i, t, d, e in rows]  # fmt: skip


def build_fixture() -> dict:
    return {"comment": "0.60 protected surfaces: shared py/ts fixture for the fail: code; "
                       "not a frozen vector.",
            "protected": parse(PROTECTED_TOML.encode("utf-8")), "cases": cases()}  # fmt: skip


def render() -> bytes:
    return (json.dumps(build_fixture(), indent=2, sort_keys=True) + "\n").encode("utf-8")
