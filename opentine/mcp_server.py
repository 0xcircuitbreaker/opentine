"""Optional MCP server exposing opentine run history and fork tools."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from opentine.core import Run


def find_run(run_id: str, runs_dir: str | Path = ".tine_runs") -> Path:
    """Find a run file by path, exact id, or id prefix."""
    direct = Path(run_id)
    if direct.exists():
        return direct

    root = Path(runs_dir)
    for path in sorted(root.glob("*.tine")):
        if path.stem == run_id or path.stem.startswith(run_id):
            return path
    raise FileNotFoundError(f"Run not found: {run_id}")


def list_run_summaries(runs_dir: str | Path = ".tine_runs") -> list[dict[str, Any]]:
    """Return compact metadata for MCP clients that need a run picker."""
    root = Path(runs_dir)
    if not root.exists():
        return []

    summaries: list[dict[str, Any]] = []
    for path in sorted(root.glob("*.tine"), key=lambda p: p.stat().st_mtime, reverse=True):
        try:
            run = Run.load(path)
        except Exception:
            summaries.append({"id": path.stem, "status": "corrupt", "path": str(path)})
            continue
        summaries.append(
            {
                "id": run.id,
                "status": run.status.value,
                "model": run.model_info,
                "steps": len(run.steps),
                "cost": run.total_cost,
                "path": str(path),
                "forked_from": run.metadata.get("forked_from"),
            }
        )
    return summaries


def format_run_for_llm(run: Run) -> str:
    """Render a run as concise text that an IDE agent can use as context."""
    lines = [
        f"Run: {run.id}",
        f"Status: {run.status.value}",
        f"Model: {run.model_info}",
        f"Steps: {len(run.steps)}",
        f"Cost: ${run.total_cost:.4f}",
    ]
    if run.metadata.get("forked_from"):
        lines.append(
            f"Forked from: {run.metadata['forked_from']} at {run.metadata.get('fork_point')}"
        )
    lines.append("")
    for idx, step in enumerate(run.steps):
        text = step.inputs.get("text") or step.inputs.get("name") or step.inputs
        preview = str(text).replace("\n", " ")[:240]
        lines.append(f"{idx}. {step.kind.value} {step.id}: {preview}")
    return "\n".join(lines)


def fork_run_file(
    run_id: str,
    from_step: int,
    *,
    runs_dir: str | Path = ".tine_runs",
    save: str | Path | None = None,
    reason: str | None = None,
) -> dict[str, Any]:
    """Fork a saved run and return metadata for MCP clients."""
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
    lines = [f"Diff: {a.id} vs {b.id}"]
    max_steps = max(len(a.steps), len(b.steps))
    for idx in range(max_steps):
        sa = a.steps[idx] if idx < len(a.steps) else None
        sb = b.steps[idx] if idx < len(b.steps) else None
        left = f"{sa.kind.value}:{sa.id}" if sa else "---"
        right = f"{sb.kind.value}:{sb.id}" if sb else "---"
        marker = "=" if sa and sb and sa.id == sb.id else "!"
        lines.append(f"{idx:03d} {marker} {left:<22} {right}")
    return "\n".join(lines)


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
