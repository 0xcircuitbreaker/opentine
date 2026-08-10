"""Capture an existing agent through OpenTelemetry GenAI, then export it back.

This is the universal on-ramp: anything already emitting OTel GenAI spans —
OpenLLMetry, OpenInference, an OTLP collector export — becomes an OpenTine run
with `tine import --format otel-json`, and `tine export` sends the verified run
back out to whatever backend you already run.

The "foreign" document below is produced with `to_otel_genai_document` so the
example is self-contained; in real use it is the file your stack already writes.
No network, no API keys, no provider SDK.

Usage:
    python examples/otel_interop.py [directory]
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

from opentine import Run, StepKind, cli, to_otel_genai_document
from opentine.trace import otel_genai_events


def banner(text: str) -> None:
    print(f"\n=== {text} ===\n")


def foreign_agent_run() -> Run:
    """Stand-in for whatever framework produced the trace you already have."""
    run = Run(id="foreign-run", model_info="demo-model", user_prompt="Check the build")
    run.add_step(
        StepKind.think,
        {"text": "Look at the CI workflow first."},
        outputs={"text": "Reading ci.yml."},
    )
    run.add_step(
        StepKind.tool,
        {"name": "read", "arguments": {"path": ".github/workflows/ci.yml"}},
        outputs={"text": "lint, format, architecture, pytest, build"},
    )
    run.add_step(
        StepKind.done,
        {},
        outputs={"text": "CI runs lint, format, the architecture gate, pytest, and build."},
    )
    return run


def comparable(events) -> list[tuple]:
    """The parts of an event a round trip must preserve exactly.

    Span and trace ids are deliberately excluded: importing renames them to the
    content-addressed object ids the repository assigns.
    """
    return [(e.kind, e.model, e.inputs, e.outputs, e.usage) for e in events]


def main(argv: list[str]) -> int:
    work = Path(argv[1]) if len(argv) > 1 else Path(tempfile.mkdtemp())
    work.mkdir(parents=True, exist_ok=True)
    spans = work / "foreign-spans.json"
    artifact = work / "imported.tine"
    roundtrip = work / "roundtrip.json"
    repo = work / "repo"

    banner("1. the trace your existing stack already emits")
    document = to_otel_genai_document(foreign_agent_run(), service_name="legacy-agent")
    spans.write_text(json.dumps(document, indent=2), encoding="utf-8")
    print(f"wrote an OTLP/JSON GenAI export to {spans}")

    banner("2. tine import — one command, any OTel GenAI producer")
    cli.main(["init", str(repo)])
    cli.main(
        [
            "import",
            str(spans),
            "--format",
            "otel-json",
            "--save",
            str(artifact),
            "--repo",
            str(repo),
            "--ref",
            "heads/main",
        ]
    )
    cli.main(["repo-show", "heads/main", "--repo", str(repo)])
    cli.main(["show", str(artifact)])

    banner("3. tine export — back out to your observability backend")
    cli.main(["export", str(artifact), "--output", str(roundtrip), "--service-name", "opentine"])
    print(f"\nPush it to a collector instead with:\n  tine export {artifact} \\")
    print("      --endpoint http://127.0.0.1:4318 --service-name opentine")

    banner("4. import and export are inverses")
    before = comparable(otel_genai_events(json.loads(spans.read_text(encoding="utf-8"))))
    after = comparable(otel_genai_events(json.loads(roundtrip.read_text(encoding="utf-8"))))
    assert before == after, "round trip lost content"
    print(f"{len(before)} span(s) survived import -> export unchanged:")
    print("  kind, model, inputs, outputs, and usage are identical")

    print(f"\nWorking directory: {work}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
