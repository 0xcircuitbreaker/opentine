"""``fleet.toml``: a declared fleet of agent processes, and its trust.

::

    [fleet]
    name = "review"          # lowercase letters, digits, dashes
    layout = "fan-out"       # or "supervisor"
    jobs = 4                 # members at once (default: all)
    budget = 2.5             # shared USD cap (optional)
    timeout = 600            # seconds per member (optional)
    env = ["ANTHROPIC_API_KEY"]   # variable NAMES every member may see

    [[agents]]
    name = "coder"
    argv = ["tine", "run", "--harness", "claude-code", "--prompt", "fix it"]
    count = 3                # copies (default 1)
    role = "worker"          # supervisor layout: exactly one "supervisor"
    env = []                 # extra variable names for this agent
    cwd = "sub/dir"          # relative to the manifest, inside its directory
    agent_ref = "agt_..."    # supervisor only: the parent ref workers claim

Commands are argument lists, never shell strings. A manifest can arrive in a
cloned repository and it chooses what runs, so it is **inert until trusted**:
trust is the SHA-256 of its exact bytes, recorded per path in
``$XDG_CONFIG_HOME/opentine/trusted-fleets.json`` by ``tine fleet up --trust``;
any edit revokes it. The bytes that were checked are the bytes that are parsed.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from opentine._agent_identity import REF_RE
from opentine._canon import atomic_write_text
from opentine.parallel._matrix import MAX_MEMBERS, env_names

MAX_BYTES = 64 * 1024
MAX_AGENTS = 64
MAX_COUNT = 100
MAX_ARGV = 256
MAX_TOKEN = 64 * 1024
NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,47}")
LAYOUTS = ("fan-out", "supervisor")
_FLEET_KEYS = {"name", "layout", "jobs", "budget", "timeout", "env"}
_AGENT_KEYS = {"name", "argv", "count", "role", "env", "cwd", "agent_ref"}


@dataclass(frozen=True)
class Agent:
    name: str
    argv: tuple[str, ...]
    count: int = 1
    role: str = "worker"
    env: tuple[str, ...] = ()
    cwd: str | None = None
    agent_ref: str = ""


@dataclass(frozen=True)
class Fleet:
    name: str
    layout: str
    agents: tuple[Agent, ...]
    digest: str
    root: Path
    jobs: int | None = None
    budget: float | None = None
    timeout: float | None = None
    env: tuple[str, ...] = field(default=())


def _number(value: object, what: str, *, integer: bool = False) -> float | int | None:
    if value is None:
        return None
    kinds = (int,) if integer else (int, float)
    if isinstance(value, bool) or not isinstance(value, kinds) or not value > 0:
        raise ValueError(f"fleet {what} must be a positive number")
    return value


def _names(value: object, what: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"{what} env must be a list of variable names")
    return tuple(env_names(list(value)))


def _cwd(root: Path, value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value or "\x00" in value or Path(value).is_absolute():
        raise ValueError("agent cwd must be a relative path inside the manifest's directory")
    target = (root / value).resolve()
    if target != root and root not in target.parents:
        raise ValueError("agent cwd escapes the manifest's directory")
    return str(target)


def _agent(root: Path, item: object) -> Agent:
    if not isinstance(item, dict) or set(item) - _AGENT_KEYS:
        raise ValueError(f"each [[agents]] entry takes only {sorted(_AGENT_KEYS)}")
    name, argv = item.get("name"), item.get("argv")
    if not isinstance(name, str) or not NAME.fullmatch(name):
        raise ValueError(f"agent name {name!r} must be lowercase letters, digits, dashes")
    if (
        not isinstance(argv, list)
        or not 0 < len(argv) <= MAX_ARGV
        or not all(isinstance(t, str) and len(t) <= MAX_TOKEN and "\x00" not in t for t in argv)
        or not argv[0]
        or argv[0].startswith("-")
    ):
        raise ValueError(f"agent {name}: argv must be a list of strings naming a program")
    count = _number(item.get("count", 1), f"agent {name} count", integer=True)
    role = item.get("role", "worker")
    if role not in ("worker", "supervisor") or not count or count > MAX_COUNT:
        raise ValueError(f"agent {name}: role is worker|supervisor, count 1..{MAX_COUNT}")
    ref = item.get("agent_ref", "")
    if ref and (not isinstance(ref, str) or not REF_RE.fullmatch(ref)):
        raise ValueError(f"agent {name}: agent_ref must be a full agt_ ref")
    return Agent(name, tuple(argv), int(count), role, _names(item.get("env"), name),
                 _cwd(root, item.get("cwd")), ref)  # fmt: skip


def parse(raw: bytes, path: Path) -> Fleet:
    """A validated :class:`Fleet` from the manifest's exact bytes."""
    if len(raw) > MAX_BYTES:
        raise ValueError(f"fleet manifest exceeds {MAX_BYTES} bytes")
    try:
        data = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ValueError(f"fleet manifest is not valid TOML: {exc}") from exc
    head, agents = data.get("fleet"), data.get("agents")
    if set(data) - {"fleet", "agents"} or not isinstance(head, dict) or set(head) - _FLEET_KEYS:
        raise ValueError(f"a fleet manifest has [fleet] ({sorted(_FLEET_KEYS)}) and [[agents]]")
    if not isinstance(agents, list) or not 0 < len(agents) <= MAX_AGENTS:
        raise ValueError(f"a fleet declares 1..{MAX_AGENTS} [[agents]]")
    name, layout = head.get("name"), head.get("layout", "fan-out")
    if not isinstance(name, str) or not NAME.fullmatch(name) or layout not in LAYOUTS:
        raise ValueError(f"[fleet] needs a lowercase name and a layout in {LAYOUTS}")
    root = path.resolve().parent
    parsed = tuple(_agent(root, item) for item in agents)
    if len({agent.name for agent in parsed}) != len(parsed):
        raise ValueError("agent names must be unique")
    supervisors = [agent for agent in parsed if agent.role == "supervisor"]
    if layout == "supervisor" and (len(supervisors) != 1 or supervisors[0].count != 1):
        raise ValueError("the supervisor layout has exactly one supervisor (count 1)")
    if layout == "fan-out" and supervisors:
        raise ValueError("the fan-out layout has workers only")
    if sum(agent.count for agent in parsed) > MAX_MEMBERS:
        raise ValueError(f"a fleet runs at most {MAX_MEMBERS} members")
    return Fleet(name, layout, parsed, hashlib.sha256(raw).hexdigest(), root,
                 _number(head.get("jobs"), "jobs", integer=True),  # type: ignore[arg-type]
                 _number(head.get("budget"), "budget"), _number(head.get("timeout"), "timeout"),
                 _names(head.get("env"), "[fleet]"))  # fmt: skip


def _trust_file() -> Path:
    home = os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config"
    return Path(home, "opentine", "trusted-fleets.json")


def _table() -> dict[str, str]:
    try:
        table = json.loads(_trust_file().read_bytes()[: 1 << 20])
    except (OSError, ValueError, RecursionError):
        return {}
    return {str(k): str(v) for k, v in table.items()} if isinstance(table, dict) else {}


def trusted(path: Path, digest: str) -> bool:
    return _table().get(str(path.resolve())) == digest


def trust(path: Path, digest: str) -> None:
    table = _table()
    table[str(path.resolve())] = digest
    target = _trust_file()
    target.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(target, json.dumps(table, indent=2, sort_keys=True) + "\n")


def load(path: Path, *, trust_now: bool = False) -> Fleet:
    """Read *path* once; refuse it unless its exact bytes are (or are now) trusted."""
    if path.is_symlink():
        raise ValueError(f"{path} is a symlink; give the real manifest")
    with open(path, "rb") as handle:
        raw = handle.read(MAX_BYTES + 1)
    fleet = parse(raw, path)  # validated before it can be trusted
    if trust_now:
        trust(path, fleet.digest)
    elif not trusted(path, fleet.digest):
        raise ValueError(
            f"{path} is not trusted here (new or edited since trusted): review the commands it "
            "runs, then pass --trust"
        )
    return fleet


__all__ = ["LAYOUTS", "Agent", "Fleet", "load", "parse", "trust", "trusted"]
