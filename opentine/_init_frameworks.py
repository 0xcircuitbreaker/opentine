"""Agent frameworks a project depends on, and the OTLP recipe for each.

`tine init --auto` reads the project's dependency manifests (never imports
anything) and prints, per framework found, how to point its telemetry at
`tine serve --otlp`. The recipes are the ones in docs/CAPTURE.md.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

MANIFESTS = ("pyproject.toml", "requirements.txt", "uv.lock", "poetry.lock", "package.json")

# (name, distribution names as they appear in a manifest, recipe)
RECIPES: tuple[tuple[str, tuple[str, ...], str], ...] = (
    ("claude-agent-sdk", ("claude-agent-sdk", "claude_agent_sdk", "@anthropic-ai/claude-agent-sdk"),
     "CLAUDE_CODE_ENABLE_TELEMETRY=1 OTEL_TRACES_EXPORTER=otlp"),
    ("openai-agents", ("openai-agents", "openai_agents", "@openai/agents"),
     "install openinference-instrumentation-openai-agents"),
    ("langgraph", ("langgraph", "@langchain/langgraph"),
     "install openinference-instrumentation-langchain"),
    ("pydantic-ai", ("pydantic-ai", "pydantic_ai", "pydantic-ai-slim"),
     "Agent(..., instrument=True)"),
)  # fmt: skip


def _manifest_text(root: Path) -> str:
    parts = []
    for name in MANIFESTS:
        try:
            parts.append((root / name).read_bytes()[:2_000_000].decode("utf-8", "replace"))
        except OSError:
            continue
    return "\n".join(parts).lower()


def detected(root: Path) -> list[str]:
    """Framework names whose distribution appears in a manifest under ``root``."""
    text = _manifest_text(root)
    found = []
    for name, dists, _ in RECIPES:
        for dist in dists:
            if re.search(r"(?<![\w.-])" + re.escape(dist) + r"(?![\w-])", text):
                found.append(name)
                break
    return found


def rows(root: Path, endpoint: str) -> list[dict[str, Any]]:
    """One printed row per detected framework (none when nothing is found)."""
    recipes = {name: recipe for name, _, recipe in RECIPES}
    return [
        {"step": f"framework:{name}", "status": "printed",
         "detail": f"{recipes[name]}; OTEL_EXPORTER_OTLP_ENDPOINT={endpoint} "
                   "(docs/CAPTURE.md, framework recipes)"}
        for name in detected(root)
    ]  # fmt: skip


__all__ = ["RECIPES", "detected", "rows"]
