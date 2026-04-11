"""Test opentine with Kimi (Moonshot AI).

Set KIMI_API_KEY env var before running:
  PowerShell: $env:KIMI_API_KEY="sk-kimi-..."
  Bash:       export KIMI_API_KEY="sk-kimi-..."
"""

from opentine import Agent
from opentine.models.compat import Kimi

agent = Agent(
    model=Kimi("moonshot-v1-8k"),
    system="Answer concisely in one sentence.",
)
run = agent.run_sync("What is a tine on a fork?")
run.save("kimi_test.tine")

for step in run.steps:
    text = step.inputs.get("text", step.inputs.get("name", ""))[:80]
    print(f"  [{step.kind}] {text}")
print(f"\nDone: {len(run.steps)} steps, cost=${run.total_cost:.4f}")
