"""Optional MCP server exposing opentine run history and fork tools."""

from __future__ import annotations

import math
from itertools import islice
from pathlib import Path
from typing import Any

from opentine.core import Run

MAX_MCP_RUN_BYTES = 256 * 1024 * 1024
MAX_MCP_SCAN_RUNS = 5_000
MAX_MCP_LIST_RUNS = 200
MAX_MCP_SUMMARY_BYTES = 64 * 1024 * 1024
MAX_MCP_RENDER_STEPS = 1_000
MAX_MCP_TEXT_CHARS = 256_000


def _scan_runs(root: Path) -> tuple[list[Path], bool]:
    paths = list(islice(root.glob("*.tine"), MAX_MCP_SCAN_RUNS + 1))
    return paths[:MAX_MCP_SCAN_RUNS], len(paths) > MAX_MCP_SCAN_RUNS


def _bounded_text(lines: list[str]) -> str:
    rendered = "\n".join(lines)
    marker = "\n... (truncated)"
    return (
        rendered
        if len(rendered) <= MAX_MCP_TEXT_CHARS
        else rendered[: MAX_MCP_TEXT_CHARS - len(marker)] + marker
    )


def _clip(value: Any, limit: int = 240) -> str:
    text = str(value).replace("\r", "\\r").replace("\n", "\\n")
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _confined_run(root: Path, candidate: Path) -> Path | None:
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
        if not resolved.is_file() or resolved.suffix != ".tine":
            return None
        if resolved.stat().st_size > MAX_MCP_RUN_BYTES:
            raise ValueError("run artifact exceeds the MCP size limit")
        return resolved
    except (OSError, ValueError):
        return None


def find_run(run_id: str, runs_dir: str | Path = ".tine_runs") -> Path:
    """Find a run inside ``runs_dir`` by relative path, exact id, or id prefix."""
    root = Path(runs_dir).resolve()
    direct = Path(run_id)
    direct = direct if direct.is_absolute() else root / direct
    for candidate in (direct, root / f"{run_id}.tine"):
        if found := _confined_run(root, candidate):
            return found
    paths, truncated = _scan_runs(root)
    if truncated:
        raise ValueError("too many saved runs for prefix lookup; use an exact run id")
    matches = [
        found
        for path in sorted(paths)
        if path.stem.startswith(run_id) and (found := _confined_run(root, path))
    ]
    if len(matches) > 1:
        raise ValueError(f"Ambiguous run id prefix: {_clip(run_id, 80)}")
    if matches:
        return matches[0]
    raise FileNotFoundError(f"Run not found: {run_id}")


def list_run_summaries(runs_dir: str | Path = ".tine_runs") -> list[dict[str, Any]]:
    """Return compact metadata for MCP clients that need a run picker."""
    root = Path(runs_dir).resolve()
    if not root.exists():
        return []

    summaries: list[dict[str, Any]] = []
    paths, truncated = _scan_runs(root)
    candidates = [found for path in paths if (found := _confined_run(root, path))]
    candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    truncated |= len(candidates) > MAX_MCP_LIST_RUNS
    total_bytes = 0
    for path in candidates[:MAX_MCP_LIST_RUNS]:
        size = path.stat().st_size
        if total_bytes + size > MAX_MCP_SUMMARY_BYTES:
            truncated = True
            break
        total_bytes += size
        try:
            run = Run.load(path)
            cost = float(run.total_cost)
            if not math.isfinite(cost):
                raise ValueError("non-finite run cost")
            summaries.append(
                {
                    "id": _clip(run.id),
                    "status": run.status.value,
                    "model": _clip(run.model_info),
                    "steps": len(run.steps),
                    "cost": cost,
                    "path": str(path),
                    "forked_from": _clip(run.metadata.get("forked_from"), 120)
                    if run.metadata.get("forked_from")
                    else None,
                }
            )
        except Exception:
            summaries.append({"id": path.stem, "status": "corrupt", "path": str(path)})
    if truncated:
        summaries.append({"id": None, "status": "truncated", "limit": MAX_MCP_LIST_RUNS})
    return summaries


def format_run_for_llm(run: Run) -> str:
    """Render a run as concise text that an IDE agent can use as context."""
    steps = run.steps
    lines = [
        f"Run: {_clip(run.id)}",
        f"Status: {run.status.value}",
        f"Model: {_clip(run.model_info)}",
        f"Steps: {len(steps)}",
        f"Cost: ${run.total_cost:.4f}",
    ]
    if run.metadata.get("forked_from"):
        lines.append(
            f"Forked from: {_clip(run.metadata['forked_from'], 100)} "
            f"at {_clip(run.metadata.get('fork_point'), 100)}"
        )
    lines.append("")
    for idx, step in enumerate(steps[:MAX_MCP_RENDER_STEPS]):
        text = step.inputs.get("text") or step.inputs.get("name") or step.inputs
        lines.append(f"{idx}. {step.kind.value} {_clip(step.id, 80)}: {_clip(text)}")
    if len(steps) > MAX_MCP_RENDER_STEPS:
        lines.append(f"... ({len(steps) - MAX_MCP_RENDER_STEPS} steps omitted)")
    return _bounded_text(lines)


def fork_run_file(
    run_id: str,
    from_step: int,
    *,
    runs_dir: str | Path = ".tine_runs",
    save: str | Path | None = None,
    reason: str | None = None,
) -> dict[str, Any]:
    """Fork a saved run and return metadata for MCP clients."""
    if type(from_step) is not int:
        raise TypeError("from_step must be an integer")
    if reason is not None and (not isinstance(reason, str) or len(reason) > 4_096):
        raise ValueError("fork reason must be at most 4096 characters")
    path = find_run(run_id, runs_dir)
    run = Run.load(path)
    if from_step < 0 or from_step >= len(run.steps):
        raise IndexError(f"Step index {from_step} out of range")

    fork_step = run.steps[from_step]
    forked = run.fork(fork_step.id)
    if reason:
        forked.metadata["fork_reason"] = reason

    out = Path(save) if save else Path(runs_dir) / f"{forked.id}.tine"
    out.parent.mkdir(parents=True, exist_ok=True)
    if out.exists():
        raise FileExistsError(f"refusing to overwrite existing run artifact: {out}")
    forked.save(out)
    return {
        "new_run_id": forked.id,
        "forked_from": run.id,
        "fork_point": fork_step.id,
        "path": str(out),
    }


def diff_runs_text(run_a: str, run_b: str, runs_dir: str | Path = ".tine_runs") -> str:
    """Return a side-by-side text diff of two saved runs."""
    a = Run.load(find_run(run_a, runs_dir))
    b = Run.load(find_run(run_b, runs_dir))
    left_steps, right_steps = a.steps, b.steps
    lines = [f"Diff: {_clip(a.id)} vs {_clip(b.id)}"]
    max_steps = min(max(len(left_steps), len(right_steps)), MAX_MCP_RENDER_STEPS)
    for idx in range(max_steps):
        sa = left_steps[idx] if idx < len(left_steps) else None
        sb = right_steps[idx] if idx < len(right_steps) else None
        left = f"{sa.kind.value}:{_clip(sa.id, 80)}" if sa else "---"
        right = f"{sb.kind.value}:{_clip(sb.id, 80)}" if sb else "---"
        marker = "=" if sa and sb and sa.id == sb.id else "!"
        lines.append(f"{idx:03d} {marker} {left:<22} {right}")
    omitted = max(len(left_steps), len(right_steps)) - max_steps
    if omitted:
        lines.append(f"... ({omitted} step pairs omitted)")
    return _bounded_text(lines)


def create_server(runs_dir: str | Path = ".tine_runs", repo_path: str | Path = "."):
    """Create a FastMCP server. Requires the optional ``mcp`` package."""
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as exc:  # pragma: no cover - optional integration
        raise RuntimeError("Install the mcp package to run opentine's MCP server.") from exc

    mcp = FastMCP("opentine")

    @mcp.tool()
    def list_runs() -> list[dict[str, Any]]:
        """List saved opentine runs."""
        return list_run_summaries(runs_dir)

    @mcp.tool()
    def show_run(run_id: str) -> str:
        """Show a saved run as LLM-readable text."""
        return format_run_for_llm(Run.load(find_run(run_id, runs_dir)))

    @mcp.tool()
    def fork_run(run_id: str, from_step: int, reason: str | None = None) -> dict[str, Any]:
        """Fork a run from a step index."""
        return fork_run_file(run_id, from_step, runs_dir=runs_dir, reason=reason)

    @mcp.tool()
    def diff_runs(run_a: str, run_b: str) -> str:
        """Diff two saved opentine runs."""
        return diff_runs_text(run_a, run_b, runs_dir)

    @mcp.resource("run://{run_id}")
    def run_resource(run_id: str) -> str:
        """Expose a run as an MCP resource."""
        return format_run_for_llm(Run.load(find_run(run_id, runs_dir)))

    try:
        from opentine.mcp_repository import register_repository_tools

        register_repository_tools(mcp, str(repo_path))
    except FileNotFoundError:
        pass

    return mcp


def main() -> None:  # pragma: no cover - exercised manually with MCP clients
    create_server().run()


if __name__ == "__main__":  # pragma: no cover
    main()
