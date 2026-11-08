"""The JSON documents ``tine ui`` serves: runs, steps, verification, workspace.

Every string leaves through :func:`scrub`, which re-runs redaction at render
time (an artifact written by an older or foreign tool may hold secrets), so the
browser never receives a value the redactor has not seen. Verification states
are spelled honestly: ``verified`` and ``failed`` only for checks that ran here;
``unchecked`` when nothing was checked; ``unpinned`` when a signature exists but
no trusted key was given; ``partial`` when only some checks could run.
"""

from __future__ import annotations

import difflib
from pathlib import Path
from typing import Any

from opentine.redaction import redact_text

#: Longest string sent for one field; longer text is cut with a visible marker.
FIELD_CAP = 64 * 1024
WITHHELD = "[withheld: text could not be redacted]"


def scrub(value: Any, depth: int = 0) -> Any:
    """*value* with every string (keys included) re-redacted and capped."""
    if depth > 64:
        return "[withheld: nested too deeply]"
    if isinstance(value, str):
        try:
            text = redact_text(value)
        except ValueError:
            return WITHHELD
        if len(text) > FIELD_CAP:
            return text[:FIELD_CAP] + f"\n… [truncated {len(text) - FIELD_CAP} characters]"
        return text
    if isinstance(value, dict):
        return {str(scrub(str(k), depth + 1)): scrub(v, depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [scrub(item, depth + 1) for item in value]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return scrub(str(value), depth + 1)


def _tool(step: Any) -> str:
    for source in (step.tool_info, step.inputs):
        name = source.get("name") if isinstance(source, dict) else None
        if isinstance(name, str) and name:
            return name
    return ""


def step_doc(index: int, step: Any) -> dict[str, Any]:
    inputs = step.inputs if isinstance(step.inputs, dict) else {}
    return scrub(
        {
            "index": index,
            "id": step.id,
            "kind": step.kind.value,
            "parent_ids": list(step.parent_ids or []),
            "model": step.model_info,
            "provider": step.provider,
            "tool": _tool(step),
            "input_parts": inputs.get("input_parts") or inputs.get("messages") or [],
            "inputs": step.inputs,
            "outputs": step.outputs,
            "error": step.error,
            "usage": step.usage,
            "duration": step.duration,
            "timestamp": step.timestamp,
        }
    )


def verification(path: Path | None, run: Any) -> dict[str, Any]:
    """Integrity, signature and assurance states for one run, as checked here."""
    out: dict[str, Any] = {
        "integrity": "unchecked",
        "signature": "unchecked",
        "assurance": None,
        "computed_by": "local tine (not the browser)",
        "reasons": [],
    }
    if path is None:
        out["reasons"].append("no artifact file: nothing to check")
        out["overall"] = "unchecked"
        return out
    try:
        from opentine._assurance import assess
        from opentine.core import Run

        integrity = Run.verify_integrity(path)
        out["integrity"] = "verified" if integrity.ok else "failed"
        out["reasons"].append(integrity.reason)
        out["assurance"] = assess(path)
    except Exception as exc:  # a broken artifact is shown as failed, never a 500
        out["integrity"] = "failed"
        out["reasons"].append(f"check refused: {type(exc).__name__}")
    metadata = run.metadata if isinstance(run.metadata, dict) else {}
    if metadata.get("signature") or metadata.get("signatures"):
        out["signature"] = "unpinned"
        out["reasons"].append("signed, but tine ui pins no key: run tine verify --pubkey")
    if out["integrity"] == "verified" and out["signature"] == "unpinned":
        out["overall"] = "partial"
    else:
        out["overall"] = out["integrity"]
    return scrub(out)


def run_summary(run: Any) -> dict[str, Any]:
    metadata = run.metadata if isinstance(run.metadata, dict) else {}
    parents = metadata.get("parents") or getattr(run, "parents", None) or []
    forked = metadata.get("forked_from") or ""
    return scrub(
        {
            "id": run.id,
            "status": run.status.value,
            "model": run.model_info,
            "created_at": run.created_at,
            "steps": len(run.steps),
            "parents": [p for p in parents if isinstance(p, str)],
            "forked_from": forked if isinstance(forked, str) else "",
            "fleet": metadata.get("fleet") if isinstance(metadata.get("fleet"), dict) else None,
        }
    )


def step_row(index: int, step: Any) -> dict[str, Any]:
    """The timeline row: what a step is, not what it carried (that is ``step_doc``)."""
    return {
        "index": index,
        "kind": step.kind.value,
        "model": scrub(step.model_info),
        "tool": scrub(_tool(step)),
        "parents": len(step.parent_ids or []),
        "error": bool(step.error),
    }


def run_doc(run: Any) -> dict[str, Any]:
    """The run and its timeline rows; step bodies, verification and files load lazily."""
    doc = run_summary(run)
    doc["system_prompt"] = scrub(run.system_prompt or "")
    doc["user_prompt"] = scrub(run.user_prompt or "")
    doc["timeline"] = [step_row(i, step) for i, step in enumerate(run.steps)]
    return doc


def _histories(run: Any) -> dict[str, list[Any]]:
    from opentine._rewind import histories

    try:
        return histories(run, Path("."))
    except Exception:  # an unreadable action list shows as an empty workspace
        return {}


def tree_at(run: Any, step: int) -> dict[str, str | None]:
    """Each recorded file's content after *step*; ``None`` where it cannot be rebuilt."""
    from opentine._rewind import forward

    tree: dict[str, str | None] = {}
    for key, events in sorted(_histories(run).items()):
        state: str | None = None
        seen = False
        for event in events:
            if event.seq > step:
                break
            seen = True
            state = forward(state, event)
        if seen:
            tree[Path(key).as_posix()] = state
    return scrub(tree)


def diff_between(run: Any, a: int, b: int) -> dict[str, str]:
    before, after = tree_at(run, a), tree_at(run, b)
    out: dict[str, str] = {}
    for key in sorted(set(before) | set(after)):
        old, new = before.get(key), after.get(key)
        if old == new:
            continue
        if old is None and key in before or new is None and key in after:
            out[key] = "[content not recorded: cannot diff]"
            continue
        lines = difflib.unified_diff(
            (old or "").splitlines(keepends=True),
            (new or "").splitlines(keepends=True),
            f"a/{key}@{a}",
            f"b/{key}@{b}",
        )
        out[key] = "".join(lines)
    return out


def attribution(run: Any) -> list[dict[str, Any]]:
    """Which step (and model) last wrote each recorded file."""
    rows = []
    for key, events in sorted(_histories(run).items()):
        last = events[-1].seq
        model = run.steps[last].model_info if 0 <= last < len(run.steps) else None
        rows.append({"path": Path(key).as_posix(), "step": last, "model": model})
    return scrub(rows)


__all__ = ["attribution", "diff_between", "run_doc", "run_summary", "scrub", "tree_at"]
