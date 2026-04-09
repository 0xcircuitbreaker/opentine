"""Coding agent — reads, writes, and executes code in a sandbox.

Usage:
    tine run examples/coder.py

Requires OPENAI_API_KEY (or swap the model).
"""
from opentine import Agent
from opentine.models.openai import OpenAI
from opentine.tools.fs import read, write, ls
from opentine.tools.python import execute

agent = Agent(
    model=OpenAI("gpt-4o"),
    tools=[read, write, ls, execute],
    system=(
        "You are a coding assistant. Write clean, tested Python code. "
        "Use the filesystem tools to create files and the execute tool to run them."
    ),
)

run = agent.run_sync(
    "Create a Python file called fizzbuzz.py that implements FizzBuzz for 1-20, "
    "then run it and show me the output."
)
run.save("coder_run.tine")
print(f"Run completed: {run.id} ({len(run.steps)} steps)")
