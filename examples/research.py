"""Research agent — search the web, read pages, synthesize an answer.

Usage:
    tine run examples/research.py

Requires ANTHROPIC_API_KEY (or swap the model).
"""

from opentine import Agent
from opentine.models.anthropic import Anthropic
from opentine.tools.search import search
from opentine.tools.web import fetch

agent = Agent(
    model=Anthropic("claude-sonnet-4-20250514"),
    tools=[search, fetch],
    system=(
        "You are a research assistant. Search the web and read"
        " pages to answer questions thoroughly."
    ),
)

run = agent.run_sync("What are the key differences between RISC-V and ARM architectures?")
run.save("research_run.tine")
print(f"Run completed: {run.id} ({len(run.steps)} steps, {run.total_cost:.4f})")
