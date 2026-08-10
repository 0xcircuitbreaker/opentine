"""The v3 `.tine/` repository, end to end, with no network and no API keys.

Records a run into a repository, forks an experiment from the middle of it,
diffs the two semantically, scores and attests the winner, and promotes it
behind a release gate — the same object store `tine init` creates and the same
verbs the CLI exposes.

Every model/tool step here is a hand-written `TraceEvent`, which is exactly what
a live capture (`opentine.integrations.langchain`) or an import
(`tine import --format otel-json`) appends for you. Nothing calls a provider, so
this runs from a plain `pip install opentine`.

Usage:
    python examples/v3_repository.py [directory]

Without a directory it works in a fresh temporary one and prints the path.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

from opentine import Recorder, Repo, TraceEvent, cli

MODEL = "demo-model"


def banner(text: str) -> None:
    print(f"\n=== {text} ===\n")


def record_baseline(repo: Repo) -> tuple[str, str]:
    """Append three events to `heads/main` and finalize the run.

    Returns the run oid and the oid of the tool event we will fork from.
    """
    # capture=False keeps the demo hermetic. The default (True) records code,
    # dirty patch, and environment manifests alongside the events.
    recording = Recorder.start(
        repo,
        ref="heads/main",
        prompt="Summarize what changed in the changelog",
        capture=False,
    )
    recording.append(
        TraceEvent(
            kind="model",
            timestamp=1.0,
            trace_id="trace-1",
            span_id="plan",
            model=MODEL,
            inputs={"prompt": "Summarize what changed in the changelog"},
            outputs={"text": "I should read CHANGELOG.md first."},
            usage={"input": 12, "output": 9},
        )
    )
    tool_event = recording.append(
        TraceEvent(
            kind="tool",
            timestamp=2.0,
            trace_id="trace-1",
            span_id="read",
            actor="read_file",
            inputs={"path": "CHANGELOG.md"},
            outputs={"text": "0.7.0 — Interop & Adoption"},
        )
    )
    recording.append(
        TraceEvent(
            kind="model",
            timestamp=3.0,
            trace_id="trace-1",
            span_id="answer",
            model=MODEL,
            outputs={"text": "0.7.0 is the interop and adoption release, with export and import."},
            usage={"input": 40, "output": 14},
        )
    )
    return recording.finalize(), tool_event


def retry_the_answer(repo: Repo, ref: str) -> str:
    """Continue the forked run with a different final answer."""
    recording = Recorder.resume(repo, ref)
    recording.append(
        TraceEvent(
            kind="model",
            timestamp=4.0,
            trace_id="trace-1",
            span_id="answer-terse",
            model=MODEL,
            outputs={"text": "0.7.0 is the interop release."},
            usage={"input": 40, "output": 6},
        )
    )
    return recording.finalize()


def main(argv: list[str]) -> int:
    root = Path(argv[1]) if len(argv) > 1 else Path(tempfile.mkdtemp()) / "opentine-demo"
    repo_arg = ["--repo", str(root)]

    banner("1. tine init — create the repository")
    cli.main(["init", str(root)])
    repo = Repo.open(root)

    banner("2. record a run onto heads/main")
    run_id, tool_event = record_baseline(repo)
    print(f"recorded {run_id}")
    cli.main(["repo-log", "heads/main", *repo_arg])
    cli.main(["repo-show", "heads/main", *repo_arg])

    banner("3. tine context — only what caused the tool call")
    cli.main(["context", tool_event, *repo_arg])

    banner("4. tine repo-fork — branch from the tool call and retry")
    cli.main(
        [
            "repo-fork",
            "heads/main",
            "--from-event",
            tool_event,
            "--ref",
            "experiments/terse",
            "--prompt",
            "Summarize the changelog in one line",
            *repo_arg,
        ]
    )
    print(f"continued {retry_the_answer(repo, 'experiments/terse')}")

    banner("5. tine repo-diff — what actually diverged")
    cli.main(["repo-diff", "heads/main", "experiments/terse", *repo_arg])

    banner("6. evaluate, attest, promote")
    cli.main(
        [
            "evaluate",
            "experiments/terse",
            "--evaluator",
            "brevity-judge",
            "--score",
            "brevity=0.95",
            *repo_arg,
        ]
    )
    cli.main(
        [
            "attest",
            "experiments/terse",
            "--signer",
            "release-manager",
            "--claim",
            json.dumps({"kind": "approval", "note": "shorter answer, same facts"}),
            *repo_arg,
        ]
    )
    cli.main(["promote", "experiments/terse", "--name", "production", *repo_arg])

    banner("7. tine repo-search and tine fsck")
    cli.main(["repo-search", "changelog", *repo_arg])
    cli.main(["fsck", *repo_arg])

    print(f"\nRepository: {root}")
    print(f"Explore it with: tine repo-log promotions/production --repo {root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
