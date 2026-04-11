"""The killer demo — fork a failed run and fix it.

This script demonstrates opentine's core value proposition:
1. An agent run fails at step 4
2. We fork from step 3 (before the failure)
3. The forked run succeeds

Usage:
    python examples/forked_debug.py

Then inspect with:
    tine show failed_run.tine
    tine show fixed_run.tine
    tine diff failed_run.tine fixed_run.tine
"""

from opentine import Run, RunStatus, StepKind

print("=== The Killer Demo: Fork a Failed Run ===\n")

# --- Step 1: Create a run that fails ---

print("1. Creating a run that fails at step 4...\n")

failed = Run(id="failed_run", model_info="demo-model", user_prompt="Analyze dataset.csv")

failed.add_step(StepKind.think, {"text": "I need to read the dataset first."})
failed.add_step(StepKind.tool, {"name": "read", "arguments": {"path": "dataset.csv"}})
failed.add_step(StepKind.think, {"text": "The dataset has 1000 rows. Let me analyze column types."})
failed.add_step(
    StepKind.tool,
    {
        "name": "execute",
        "arguments": {
            "code": "import pandas; df = pandas.read_csv('dataset.csv'); print(df.dtypes)"
        },
    },
)
failed.add_step(
    StepKind.error, {"tool": "execute", "error": "ModuleNotFoundError: No module named 'pandas'"}
)

failed.status = RunStatus.failed
failed.save("failed_run.tine")

print("   Failed run saved. The agent tried to use pandas but it wasn't installed.")
print(f"   Steps: {len(failed.steps)}")
print(f"   Status: {failed.status.value}\n")

# --- Step 2: Fork from step 3 (before the bad tool call) ---

print("2. Forking from step 3 (before the pandas call)...\n")

fixed = failed.fork(failed.steps[2].id, new_run_id="fixed_run")

print(f"   Forked run has {len(fixed.steps)} steps (kept steps 0-2)")
print(f"   Forked from: {fixed.metadata['forked_from']}")
print(f"   Fork point: {fixed.metadata['fork_point']}\n")

# --- Step 3: Continue with a fix ---

print("3. Continuing with stdlib instead of pandas...\n")

fixed.add_step(
    StepKind.tool,
    {
        "name": "execute",
        "arguments": {
            "code": (
                "import csv\nwith open('dataset.csv') as f:\n"
                "    reader = csv.reader(f)\n    header = next(reader)\n"
                "    print(header)"
            )
        },
    },
)
fixed.add_step(
    StepKind.think, {"text": "Successfully read the CSV with stdlib. Columns: name, age, score."}
)
fixed.add_step(
    StepKind.done,
    {"text": "Analysis complete. The dataset has 3 columns: name (str), age (int), score (float)."},
)

fixed.status = RunStatus.completed
fixed.save("fixed_run.tine")

print(f"   Fixed run completed with {len(fixed.steps)} total steps")
print(f"   Status: {fixed.status.value}\n")

# --- Summary ---

print("=== Results ===\n")
print("  tine show failed_run.tine   # See where it went wrong")
print("  tine show fixed_run.tine    # See the fix")
print("  tine diff failed_run.tine fixed_run.tine  # Compare side-by-side")
print()
print("The key insight: we didn't re-run steps 0-2. We forked from step 3")
print("and only changed the approach from step 3 onward. In a real agent run,")
print("those first steps might have cost $0.50 in API calls and 30 seconds.")
print("opentine saved both.")

# --- Step 4: Pause and resume ---

print("\n\n=== Bonus: Pause & Resume ===\n")

paused = Run(id="pausable_run", model_info="demo-model", user_prompt="Count to 10")
for i in range(1, 6):
    paused.add_step(StepKind.think, {"text": f"Step {i}: counting..."})

paused.pause("paused_run.tine")
print("4. Paused at step 5 -> paused_run.tine")

resumed = Run.resume("paused_run.tine")
for i in range(6, 11):
    resumed.add_step(StepKind.think, {"text": f"Step {i}: counting..."})
resumed.status = RunStatus.completed
resumed.add_step(StepKind.done, {"text": "Counted to 10!"})
resumed.save("resumed_run.tine")
print(f"5. Resumed and completed with {len(resumed.steps)} steps -> resumed_run.tine")
print("\n  tine show resumed_run.tine  # See the full run")
