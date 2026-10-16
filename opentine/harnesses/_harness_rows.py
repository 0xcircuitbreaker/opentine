"""Every agent CLI OpenTine can drive, as data: command, event dialect, fidelity.

One row per CLI. A row with a dialect reads the CLI's documented headless JSON
mode into model / tool / usage steps; a row without one records text (or, for a
JSON mode whose schema is undocumented, generic JSON events). Only documented
invocations get a row -- a guessed command fails at spawn time with a confusing
error, while ``--harness generic --harness-command`` already runs anything.

Checked against each CLI's reference docs or source on 2026-10-15; the fixture
for each dialect under ``tests/fixtures/harness/`` names its source. Not listed,
because no documented headless invocation could be confirmed: Kilo Code (binary
and JSON flag differ between versions), iFlow CLI, Z.ai ZCode (desktop only).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from opentine.core import StepKind
from opentine.harnesses import _dialects_claude_family as family
from opentine.harnesses import _dialects_envelopes as envelopes
from opentine.harnesses import _dialects_events as events
from opentine.harnesses import _dialects_more as more
from opentine.harnesses import _dialects_openai as openai
from opentine.harnesses import _dialects_streams as streams
from opentine.harnesses._dialect_harness import Dialect

#: Capture fidelity columns: ``yes``, ``no``, ``flag`` (the model only when the
#: command names it with ``-m``/``--model``), ``unverified`` (JSON mode documented,
#: its schema not; read with the closest dialect plus the generic fallback).
FIDELITY = ("model", "usage", "cost", "tools")


@dataclass(frozen=True)
class Row:
    name: str
    command: tuple[str, ...]
    doc: str
    dialect: type[Dialect] | None = None
    fidelity: tuple[str, str, str, str] = ("no", "no", "no", "no")
    prompt_flag: str | None = None
    login_env_keys: tuple[str, ...] = ()
    json_options: tuple[str, ...] | None = None
    json_values: tuple[str, ...] | None = None
    multiline_json: bool = False
    extra: Mapping[str, Any] = field(default_factory=dict)


ROWS = (
    Row(
        "gemini",
        ("gemini", "--output-format", "stream-json", "-p"),
        "Google's Gemini CLI, headless ``stream-json``.",
        streams.Gemini,
        ("yes", "yes", "no", "yes"),
        "-p",
        ("GEMINI_API_KEY", "GOOGLE_API_KEY", "GOOGLE_CLOUD_PROJECT", "GOOGLE_GENAI_USE_VERTEXAI"),
    ),
    Row(
        "qwen-code",
        ("qwen", "--output-format", "stream-json", "-p"),
        "Alibaba's Qwen Code, headless ``stream-json``.",
        family.QwenCode,
        ("yes", "yes", "no", "yes"),
        "-p",
        ("OPENAI_API_KEY", "OPENAI_BASE_URL", "OPENAI_MODEL", "DASHSCOPE_API_KEY"),
    ),
    Row(
        "cursor",
        ("agent", "--print", "--output-format", "stream-json"),
        "Cursor Agent CLI (``agent``), print mode ``stream-json``; reports no usage.",
        family.Cursor,
        ("yes", "no", "no", "yes"),
        login_env_keys=("CURSOR_API_KEY",),
        extra={"invocation_kind": StepKind.model},
    ),
    Row(
        "opencode",
        ("opencode", "run", "--format", "json"),
        "OpenCode, ``run --format json``; the model is ``--model provider/model``.",
        events.OpenCode,
        ("flag", "yes", "yes", "yes"),
        login_env_keys=("OPENCODE_CONFIG",),
    ),
    Row(
        "pi",
        ("pi", "--mode", "json"),
        "Pi coding agent, ``--mode json`` event stream.",
        events.Pi,
        ("yes", "yes", "yes", "yes"),
        json_options=("--mode",),
        json_values=("json",),
    ),
    Row(
        "hermes",
        ("hermes", "chat", "--oneshot", "--format", "stream-json", "-q"),
        "Nous Research Hermes Agent, one-shot ``--format stream-json``.",
        streams.Hermes,
        ("yes", "yes", "no", "yes"),
        "-q",
        ("HERMES_HOME",),
    ),
    Row(
        "openclaw",
        ("openclaw", "agent", "exec", "--json"),
        "OpenClaw headless ``agent exec --json`` envelope.",
        envelopes.OpenClaw,
        ("yes", "yes", "yes", "no"),
        login_env_keys=("OPENCLAW_HOME",),
        multiline_json=True,
    ),
    Row(
        "kimi-code",
        ("kimi", "--print", "--output-format", "stream-json", "-p"),
        "Moonshot's Kimi Code CLI, print mode ``stream-json`` messages.",
        openai.KimiCode,
        ("flag", "no", "no", "yes"),
        "-p",
        ("KIMI_HOME",),
        extra={"invocation_kind": StepKind.model},
    ),
    Row(
        "grok",
        ("grok", "--no-auto-update", "--output-format", "streaming-json", "-p"),
        "xAI's Grok Build, headless ``-p`` with ``streaming-json``.",
        family.GrokBuild,
        ("unverified", "unverified", "unverified", "unverified"),
        "-p",
        ("XAI_API_KEY", "GROK_CODE_XAI_API_KEY"),
        json_values=("json", "streaming-json"),
    ),
    Row(
        "goose",
        ("goose", "run", "--output-format", "stream-json", "-t"),
        "Goose, ``run --output-format stream-json``; model from ``--model`` or ``GOOSE_MODEL``.",
        more.Goose,
        ("flag", "yes", "yes", "yes"),
        "-t",
        ("GOOSE_PROVIDER", "GOOSE_MODEL"),
    ),
    Row(
        "amp",
        ("amp", "--stream-json", "-x"),
        "Sourcegraph Amp, execute mode ``--stream-json``.",
        family.Amp,
        ("no", "yes", "no", "yes"),
        "-x",
        ("AMP_API_KEY",),
        extra={"json_switches": ("--stream-json",)},
    ),
    Row(
        "droid",
        ("droid", "exec", "--output-format", "json"),
        "Factory Droid, ``droid exec --output-format json`` result.",
        family.Droid,
        ("no", "no", "no", "no"),
        login_env_keys=("FACTORY_API_KEY",),
        multiline_json=True,
        extra={"invocation_kind": StepKind.model},
    ),
    Row(
        "copilot",
        ("copilot", "--output-format", "json", "-p"),
        "GitHub Copilot CLI, ``-p`` with ``--output-format json`` session events.",
        more.Copilot,
        ("yes", "yes", "no", "yes"),
        "-p",
        ("GH_TOKEN", "GITHUB_TOKEN", "COPILOT_GITHUB_TOKEN"),
    ),
    Row(
        "auggie",
        ("auggie", "--print", "--output-format", "json"),
        "Augment's Auggie CLI, print mode JSON result.",
        family.Auggie,
        ("no", "no", "no", "no"),
        multiline_json=True,
        extra={"invocation_kind": StepKind.model},
    ),
    Row(
        "cline",
        ("cline", "--json"),
        "Cline CLI, ``--json`` agent events.",
        envelopes.Cline,
        ("yes", "yes", "yes", "no"),
        json_options=("--json",),
        json_values=(),
    ),
    Row(
        "qoder",
        ("qodercli", "--output-format", "stream-json", "-p"),
        "Qoder CLI, headless ``stream-json``.",
        family.Qoder,
        ("unverified", "unverified", "unverified", "unverified"),
        "-p",
    ),
    Row(
        "continue",
        ("cn", "--format", "json", "-p"),
        "Continue CLI (``cn``), headless ``--format json`` (schema undocumented).",
        fidelity=("no", "no", "no", "unverified"),
        prompt_flag="-p",
    ),
    Row(
        "openhands",
        ("openhands", "--headless", "--json", "-t"),
        "OpenHands CLI, ``--headless --json`` event stream.",
        envelopes.OpenHands,
        ("no", "no", "no", "yes"),
        "-t",
        ("LLM_API_KEY", "LLM_MODEL", "LLM_BASE_URL"),
        json_options=("--json",),
        json_values=(),
        extra={"invocation_kind": StepKind.model},
    ),
    Row(
        "vibe",
        ("vibe", "--output", "streaming", "--prompt"),
        "Mistral Vibe, programmatic ``--output streaming`` messages.",
        openai.MistralVibe,
        ("flag", "unverified", "no", "yes"),
        "--prompt",
        ("MISTRAL_API_KEY",),
        json_options=("--output",),
        json_values=("streaming",),
    ),
    Row(
        "aider",
        ("aider", "--yes-always", "--no-pretty", "--message"),
        "Aider, one message and exit (text only).",
        prompt_flag="--message",
    ),
    Row("crush", ("crush", "run", "-q"), "Charm's Crush, ``crush run`` (text only)."),
    Row(
        "kiro",
        ("kiro-cli", "chat", "--no-interactive"),
        "Kiro CLI, ``chat --no-interactive`` (text only).",
        login_env_keys=("KIRO_API_KEY",),
    ),
)

__all__ = ["FIDELITY", "ROWS", "Row"]
