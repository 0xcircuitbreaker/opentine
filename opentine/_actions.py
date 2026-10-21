"""Normalized action records: what each tool call in a run *did*.

An action is one tool step reduced to the facts a "which agent did X" query
asks about: the tool (and MCP server), a verb from a fixed taxonomy, the
command line and its program, the paths and hosts it named, and who did it --
the agent (harness, transcript source or framework), session, subagent, model
and provider.

Records are built only from **redacted** step content: each step goes through
the same ``_redact``/``redact_value`` pass (under the run's own
``extra_secret_keys`` policy) that a saved run gets, so an index built from
them cannot hold a secret the run file does not. A command that still carries
a ``[REDACTED...]`` label is marked ``redacted`` so a query can say its match
coverage was partial instead of reporting a false "no match".
"""

from __future__ import annotations

import math
import re
from dataclasses import asdict, dataclass, field
from typing import Any

from opentine._actions_parse import MAX_COMMAND_CHARS, command_text, mcp_parts, programs, verbs
from opentine._actions_targets import arg_paths, command_paths, hosts
from opentine._actions_writes import written_paths
from opentine._canon import _redact
from opentine._index_types import run_agent
from opentine.graph import Run, StepKind
from opentine.policies import run_redaction
from opentine.redaction import redact_text, redact_value

#: Bump when extraction changes: a stored index built by another version rebuilds.
ACTIONS_SCHEMA = 3
MAX_ACTIONS_PER_RUN = 20_000
_SESSION_KEYS = ("session_id", "sessionId", "thread_id", "conversation_id")
_SUBAGENT_KEYS = ("agent_id", "subagent", "subagent_type", "parent_tool_use_id")
_WRITE_VERBS = frozenset({"file.write", "file.delete"})
#: A program name kept from the *unredacted* command line: a bare executable
#: name, never an argument, and only when redaction would leave it unchanged.
_PROGRAM = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}")


@dataclass
class Action:
    run_id: str
    step_id: str
    seq: int
    tool: str
    verbs: list[str]
    agent: str = ""
    session: str = ""
    subagent: str = ""
    model: str = ""
    provider: str = ""
    ts: float = 0.0
    mcp_server: str = ""
    mcp_tool: str = ""
    argv0: str = ""
    programs: list[str] = field(default_factory=list)
    command: str = ""
    paths: list[str] = field(default_factory=list)
    #: The subset of *paths* the call wrote or deleted (never a file it only read).
    written: list[str] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)
    error: bool = False
    cost: float = 0.0
    redacted: bool = False
    clipped: bool = False

    @property
    def writes(self) -> list[str]:
        return self.written

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _label(value: Any, limit: int = 256) -> str:
    return value[:limit] if isinstance(value, str) else ""


def _first(mapping: dict[str, Any], keys: tuple[str, ...]) -> str:
    for key in keys:
        if text := _label(mapping.get(key)):
            return text
    return ""


def _number(value: Any) -> float:
    return float(value) if type(value) in (int, float) and math.isfinite(value) else 0.0


def _is_error(step: Any) -> bool:
    outputs = step.outputs if isinstance(step.outputs, dict) else {}
    return bool(step.error) or outputs.get("is_error") is True or step.kind == StepKind.error


def _raw_programs(step: Any) -> list[str]:
    """Program names a command ran before redaction could swallow them.

    ``export TOKEN=abc; rm -rf /`` redacts to ``export TOKEN= [REDACTED]``,
    hiding ``rm`` from every rule. Only names that look like an executable and
    that redaction leaves untouched are kept -- never an argument or a path.
    """
    raw = step.inputs if isinstance(step.inputs, dict) else {}
    try:
        command = command_text(raw.get("arguments", raw.get("input", {}))) or ""
    except (TypeError, ValueError):
        return []
    names = programs(command[:MAX_COMMAND_CHARS]) if command else []
    return [name for name in names if _PROGRAM.fullmatch(name) and redact_text(name) == name]


def _action(run: Run, step: Any, seq: int, agent: str, session: str) -> Action | None:
    inputs = redact_value(_redact(step.inputs if isinstance(step.inputs, dict) else {}))
    tool_info = redact_value(_redact(step.tool_info if isinstance(step.tool_info, dict) else {}))
    if not isinstance(inputs, dict):
        return None
    name = _label(inputs.get("name")) or _label(tool_info.get("name"))
    if step.kind != StepKind.tool or not name:
        return None
    arguments = inputs.get("arguments", inputs.get("input", {}))
    command = command_text(arguments) or ""
    clipped = len(command) > MAX_COMMAND_CHARS
    command = command[:MAX_COMMAND_CHARS]
    run_programs = list(
        dict.fromkeys([*(programs(command) if command else []), *_raw_programs(step)])
    )
    server, mcp_tool = mcp_parts(name, arguments)
    action_verbs = verbs(name, command or None, run_programs)
    if server:
        action_verbs = ["mcp", *[verb for verb in action_verbs if verb != "other"]]
    named = arg_paths(arguments)
    paths = named or (command_paths(command) if command else [])
    # A write tool (Write/Edit/...) writes the paths it names; a shell command
    # writes only its redirect/copy/delete targets, never the files it reads.
    written = named if _WRITE_VERBS.intersection(action_verbs) and not command else []
    if command and (targets := written_paths(command)):
        if "file.write" not in action_verbs:
            action_verbs = [*[verb for verb in action_verbs if verb != "other"], "file.write"]
        written = [*written, *targets]
    if command and "file.delete" in action_verbs:
        written = [*written, *written_paths(command, deletes=True)]
    written = list(dict.fromkeys(written))
    paths = list(dict.fromkeys([*paths, *written]))
    return Action(
        run_id=run.id,
        step_id=step.id,
        seq=seq,
        tool=name,
        verbs=action_verbs,
        agent=agent,
        session=_first(inputs, _SESSION_KEYS) or session,
        subagent=_first(inputs, _SUBAGENT_KEYS),
        model=_label(step.model_info) or _label(run.model_info),
        provider=_label(step.provider),
        ts=_number(step.timestamp),
        mcp_server=server,
        mcp_tool=mcp_tool,
        argv0=run_programs[0] if run_programs else "",
        programs=run_programs,
        command=command,
        paths=paths,
        written=written,
        hosts=hosts(command, arguments=arguments),
        error=_is_error(step),
        cost=_number(step.cost),
        redacted="[REDACTED" in command or "[REDACTED" in " ".join(paths),
        clipped=clipped,
    )


def extract_actions(run: Run) -> tuple[list[Action], bool]:
    """Every tool call in *run* as an :class:`Action`, and whether the cap cut them."""
    agent = run_agent(run)
    metadata = run.metadata if isinstance(run.metadata, dict) else {}
    session = _first(metadata, _SESSION_KEYS)
    actions: list[Action] = []
    with run_redaction(run.policies):
        for seq, step in enumerate(run.steps):
            if len(actions) >= MAX_ACTIONS_PER_RUN:
                return actions, True
            try:
                action = _action(run, step, seq, agent, session)
            except (TypeError, ValueError, RecursionError):
                continue  # one malformed recorded step never hides the rest
            if action is not None:
                actions.append(action)
    return actions, False


__all__ = ["ACTIONS_SCHEMA", "Action", "MAX_ACTIONS_PER_RUN", "extract_actions"]
