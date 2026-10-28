"""``--vary``/``--repeat`` expansion, argv templating and the member environment.

Members are argv lists only, never a shell string. A value is substituted into a
token with one non-recursive pass over ``{name}`` placeholders (never
``str.format``, whose ``{0.__class__}`` fields reach attributes), so a value can
neither introduce a new argv element nor expand another placeholder. A value
that would stand alone as a token and starts with ``-`` is refused: it would be
read as an option by the member's own argument parser.
"""

from __future__ import annotations

import hashlib
import itertools
import json
import re

from opentine.tools._env_scrub import clean_env

VARY_KEY = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_PLACEHOLDER = re.compile(r"\{([a-z][a-z0-9_]{0,31})\}")
MAX_MEMBERS = 1000
MAX_VALUE_CHARS = 64 * 1024

#: What a member inherits without ``--env``: enough to start a program on every
#: platform, and no credential. A key (``ANTHROPIC_API_KEY``...) must be named.
DEFAULT_ENV = (
    "PATH",
    "HOME",
    "USERPROFILE",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TERM",
    "TZ",
    "TMPDIR",
    "TEMP",
    "TMP",
    "SYSTEMROOT",
    "WINDIR",
    "COMSPEC",
    "PATHEXT",
    "APPDATA",
    "LOCALAPPDATA",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_CACHE_HOME",
)


def _value(key: str, value: str) -> str:
    if not value or len(value) > MAX_VALUE_CHARS or "\x00" in value:
        raise ValueError(f"--vary {key}: values must be non-empty text without NUL")
    return value


def parse_vary(specs: list[str]) -> dict[str, list[str]]:
    """``["model=a,b", "seed=1,2"]`` -> ``{"model": ["a", "b"], "seed": ["1", "2"]}``."""
    vary: dict[str, list[str]] = {}
    for spec in specs:
        key, sep, raw = spec.partition("=")
        if not sep or not VARY_KEY.fullmatch(key):
            raise ValueError(f"--vary takes NAME=V1,V2,... with a lowercase name, got {spec!r}")
        if key in vary:
            raise ValueError(f"--vary {key} is given twice")
        vary[key] = [_value(key, item) for item in raw.split(",")]
    return vary


def expand(vary: dict[str, list[str]], repeat: int = 1) -> list[dict[str, str]]:
    """Every combination, ``repeat`` times each, in a stable order."""
    if type(repeat) is not int or repeat < 1:
        raise ValueError("--repeat must be a positive integer")
    keys = list(vary)
    combos = [dict(zip(keys, values)) for values in itertools.product(*vary.values())]
    total = len(combos) * repeat
    if total > MAX_MEMBERS:
        raise ValueError(f"{total} members exceed the limit of {MAX_MEMBERS}")
    return [dict(combo) for combo in combos for _ in range(repeat)]


def render(template: list[str], values: dict[str, str]) -> list[str]:
    """*template* with ``{name}`` replaced from *values*; unknown names stay as written."""
    argv = []
    for token in template:
        whole = _PLACEHOLDER.fullmatch(token)
        if whole and whole.group(1) in values and values[whole.group(1)].startswith("-"):
            raise ValueError(f"value for {token} starts with '-' and would be read as an option")
        argv.append(_PLACEHOLDER.sub(lambda m: values.get(m.group(1), m.group(0)), token))
    return argv


def env_names(names: list[str]) -> list[str]:
    for name in names:
        if not ENV_NAME.fullmatch(name):
            raise ValueError(f"--env takes an environment variable name, got {name!r}")
    return names


def member_env(allow: list[str], extra: dict[str, str]) -> dict[str, str]:
    """The allowlisted environment (nothing else of ours leaks in) plus *extra*."""
    env = clean_env(False, [*DEFAULT_ENV, *env_names(allow)])
    env.update(extra)
    return env


def vary_env(values: dict[str, str]) -> dict[str, str]:
    return {f"OPENTINE_VARY_{key.upper()}": value for key, value in values.items()}


def command_digest(template: list[str]) -> str:
    return hashlib.sha256(json.dumps(template, ensure_ascii=False).encode()).hexdigest()


__all__ = [
    "DEFAULT_ENV",
    "command_digest",
    "env_names",
    "expand",
    "member_env",
    "parse_vary",
    "render",
    "vary_env",
]
