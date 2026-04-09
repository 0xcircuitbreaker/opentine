"""Pause and resume demo — serialize state, resume from another process.

Usage:
    python examples/resume.py          # Creates and pauses a run
    python examples/resume.py resume   # Resumes the paused run

This demonstrates the core opentine primitive: pause anywhere, resume anywhere.
"""

import sys

from opentine import Run, RunStatus, StepKind

PAUSE_FILE = "paused_run.tine"


def create_and_pause():
    """Simulate an agent that pauses mid-execution."""
    run = Run(id="resume_demo", model_info="demo", user_prompt="Count to 10")

    # Simulate some steps
    for i in range(1, 6):
        run.add_step(StepKind.think, {"text": f"Step {i}: counting..."})
        print(f"  Completed step {i}")

    # Pause at step 5
    run.pause(PAUSE_FILE)
    print(f"\nPaused at step 5. State saved to {PAUSE_FILE}")
    print("Resume with: python examples/resume.py resume")


def resume_run():
    """Resume the paused run and continue."""
    run = Run.resume(PAUSE_FILE)
    print(f"Resumed run {run.id} with {len(run.steps)} steps\n")

    # Continue from where we left off
    for i in range(6, 11):
        run.add_step(StepKind.think, {"text": f"Step {i}: counting..."})
        print(f"  Completed step {i}")

    run.status = RunStatus.completed
    run.add_step(StepKind.done, {"text": "Counted to 10!"})
    run.save("resumed_run.tine")
    print(f"\nRun completed with {len(run.steps)} total steps")
    print("Saved to resumed_run.tine")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "resume":
        resume_run()
    else:
        create_and_pause()
