"""The one MCP tool registry: every tool the server may expose, and whether it writes.

0.36 (A4). The server registers a tool only if it is listed here, and a tool
annotated ``writes=True`` only when writes are opted into (``--allow-writes`` or
``OPENTINE_MCP_ALLOW_WRITES=1``, see :mod:`opentine._mcp_readonly`). So the
read-only default exposes no write tool, and the write mode exposes exactly the
annotated set: a tool added without an entry is never exposed in either mode.

``CLI_TOOLS`` are generated (:mod:`opentine._mcp_cli_tools`): each one runs its
``tine ... --json`` counterpart in process and returns that payload, so the tool
and the command cannot drift apart. ``HANDWRITTEN`` lists the tools written
before 0.36, whose names and schemas stay as they were.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Param:
    """One tool argument: a CLI positional (``flag=None``) or ``flag VALUE``."""

    name: str
    flag: str | None = None
    kind: type = str
    required: bool = False
    default: Any = None


@dataclass(frozen=True)
class ToolSpec:
    name: str
    writes: bool
    #: ``True``: never exposed by the shipped server, even with writes allowed.
    operator_only: bool = False
    doc: str = ""
    #: The ``tine`` words a generated tool runs (empty for a hand-written tool).
    argv: tuple[str, ...] = ()
    params: tuple[Param, ...] = ()
    #: Fixed flags after the parameters (``--json`` is always added).
    extra: tuple[str, ...] = ()
    #: Pass ``--repo <the server's repository>``.
    repo: bool = False


def _hand(name: str, writes: bool = False, operator_only: bool = False) -> ToolSpec:
    return ToolSpec(name, writes, operator_only)


HANDWRITTEN: tuple[ToolSpec, ...] = (
    _hand("list_runs"),
    _hand("show_run"),
    _hand("diff_runs"),
    _hand("find_actions"),
    _hand("search_runs"),
    _hand("inspect_object"),
    _hand("context_slice"),
    _hand("semantic_diff"),
    _hand("recall"),  # 0.44: the derived FTS5 index, read-only (_mcp_recall)
    _hand("fork_run", writes=True),
    _hand("fork_run_v3", writes=True),
    _hand("resume_run_v3", writes=True),
    _hand("evaluate_run", writes=True),
    _hand("attest_run", writes=True),
    # A promotion ref is a release gate: an operator decision, not a model's.
    _hand("promote_run", writes=True, operator_only=True),
)

_RUN = Param("run_id", required=True)
_LIMIT = Param("limit", "--limit", int, default=20)

CLI_TOOLS: tuple[ToolSpec, ...] = (
    ToolSpec(
        "verify_run",
        False,
        doc="Verify a saved run offline (`tine verify RUN --offline --json`).",
        argv=("verify",),
        params=(_RUN,),
        extra=("--offline",),
    ),
    ToolSpec(
        "log",
        False,
        doc="Run history of the repository (`tine log --json`).",
        argv=("log",),
        params=(Param("ref"), _LIMIT),
        repo=True,
    ),
    ToolSpec(
        "fleet_status",
        False,
        doc="Members of declared fleets (`tine fleet status --json`).",
        argv=("fleet", "status"),
        params=(Param("fleet_id"),),
    ),
    ToolSpec(
        "fanout_status",
        False,
        doc="Members of the repository's fan-outs (`tine fleet status --repo --json`).",
        argv=("fleet", "status"),
        params=(Param("fanout_id"),),
        repo=True,
    ),
    ToolSpec(
        "cost",
        False,
        doc="Cost breakdown of a saved run (`tine cost RUN --json`).",
        argv=("cost",),
        params=(_RUN,),
    ),
    ToolSpec(
        "agent_show",
        False,
        doc="An agent's identity, keys and lineage (`tine agent show TARGET --json`).",
        argv=("agent", "show"),
        params=(Param("target", required=True),),
        repo=True,
    ),
    ToolSpec(
        "stats",
        False,
        doc="Aggregate statistics over saved runs (`tine stats --json`).",
        argv=("stats",),
        params=(Param("group_by", "--group-by"), _LIMIT),
    ),
    ToolSpec(
        "code_graph",
        False,
        doc="Code map of the work tree: symbols, imports, edges (`tine code-graph --json`, 0.48).",
        argv=("code-graph",),
        params=(Param("path"), Param("symbol", "--symbol")),
        repo=True,
    ),
)

TOOLS: dict[str, ToolSpec] = {spec.name: spec for spec in (*HANDWRITTEN, *CLI_TOOLS)}


def exposed(*, allow_writes: bool) -> frozenset[str]:
    """The tool names the shipped server may register in this mode."""
    return frozenset(
        name
        for name, spec in TOOLS.items()
        if not spec.operator_only and (allow_writes or not spec.writes)
    )


__all__ = ["CLI_TOOLS", "HANDWRITTEN", "TOOLS", "Param", "ToolSpec", "exposed"]
