"""User-scoped ``tine`` settings: ``output.format`` (``text`` | ``json``).

They live in ``$XDG_CONFIG_HOME/opentine/settings.json`` (written 0600), beside the
0.16 trust policies and never in a repository: a cloned project must not change
what a script parsing ``tine`` output receives. ``OPENTINE_OUTPUT`` overrides the
file; an explicit ``--json`` or ``--text`` on the command line overrides both.

``output.format = json`` turns ``--json`` on for every command whose parser has
it; commands without JSON output ignore it. ``--text`` (added next to every
``--json``) forces the human output for one invocation. With no setting the CLI
is exactly what it was: nothing is read unless the command has ``--json``.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

FILE_NAME = "settings.json"
MAX_BYTES = 64 * 1024
ENV = "OPENTINE_OUTPUT"
KEYS = {"output.format": ("text", "json")}
SUBVERBS = ("set", "get", "unset")


class SettingsError(ValueError):
    """A settings file, key or value that must not be used."""


def settings_file() -> Path:
    home = os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config"
    return Path(home, "opentine", FILE_NAME)


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    if len({key for key, _ in pairs}) != len(pairs):
        raise ValueError("duplicate key")
    return dict(pairs)


def check(key: str, value: Any = None) -> str:
    if key not in KEYS:
        raise SettingsError(f"unknown setting {key!r} (known: {', '.join(sorted(KEYS))})")
    if value is not None and value not in KEYS[key]:
        allowed = " or ".join(repr(choice) for choice in KEYS[key])
        raise SettingsError(f"{key} must be {allowed}, got {value!r}")
    return key


def load() -> dict[str, str]:
    """The stored settings; empty when there is no file. Anything odd fails closed."""
    path = settings_file()
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_BYTES + 1)
    except FileNotFoundError:
        return {}
    except OSError as exc:
        raise SettingsError(f"cannot read {path}: {exc.strerror or exc}") from exc
    try:
        if len(raw) > MAX_BYTES:
            raise ValueError(f"exceeds {MAX_BYTES} bytes")
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique)
        if not isinstance(value, dict) or value.get("version") != 1:
            raise ValueError('expected {"version": 1, "settings": {...}}')
        if set(value) - {"version", "settings"} or not isinstance(value.get("settings"), dict):
            raise ValueError('expected {"version": 1, "settings": {...}}')
        for key, item in value["settings"].items():
            check(key, item)
        return dict(value["settings"])
    except (ValueError, RecursionError, UnicodeDecodeError) as exc:
        raise SettingsError(f"{path} is malformed: {exc}; fix or delete it") from exc


def save(settings: dict[str, str]) -> None:
    from opentine._export_write import write_private

    text = json.dumps({"version": 1, "settings": settings}, indent=2, sort_keys=True) + "\n"
    write_private(settings_file(), text.encode("utf-8"))


def output_format() -> str | None:
    """``OPENTINE_OUTPUT`` if set, else the file's ``output.format``, else None."""
    env = os.environ.get(ENV)
    if env is not None and env != "":
        if env not in KEYS["output.format"]:
            raise SettingsError(f"{ENV} must be 'text' or 'json', got {env!r}")
        return env
    return load().get("output.format")


def _fail(message: str) -> None:
    print(f"tine: {message}", file=sys.stderr)
    raise SystemExit(1)


def apply_output_format(args: argparse.Namespace, argv: list[str]) -> None:
    """Turn ``--json`` on when the user default is json and the call said neither."""
    if not hasattr(args, "json") or is_user_config(args):
        return
    head = argv[: argv.index("--")] if "--" in argv else argv
    if "--text" in head and "--json" in head:
        _fail("--json cannot be combined with --text")
    if args.json or "--text" in head:
        return
    try:
        args.json = output_format() == "json"
    except SettingsError as exc:
        _fail(str(exc))


def add_text_flags(parser: argparse.ArgumentParser, seen: set[int] | None = None) -> None:
    """``--text`` beside every ``--json``: force human output for one call."""
    seen = set() if seen is None else seen
    if id(parser) in seen:
        return
    seen.add(id(parser))
    flags = parser._option_string_actions
    if "--json" in flags and "--text" not in flags:
        parser.add_argument(
            "--text", action="store_true", help="Human-readable output even if output.format=json"
        )
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            for child in action.choices.values():
                add_text_flags(child, seen)


def is_user_config(args: argparse.Namespace) -> bool:
    return getattr(args, "command", None) == "config" and getattr(args, "key", None) in SUBVERBS


def cmd_user_config(args: argparse.Namespace) -> None:
    """``tine config set|get|unset KEY [VALUE]`` on the user settings file."""
    verb, key, value = args.key, args.value, args.setting_value
    if args.list or args.unset or args.trust:
        _fail(f"config {verb}: --list, --unset and --trust are for repository keys")
    if key is None or (verb == "set") != (value is not None):
        _fail(f"usage: tine config {verb} KEY" + (" VALUE" if verb == "set" else ""))
    try:
        check(key, value)
        settings = load()
        if verb == "get":
            if key not in settings:
                raise SystemExit(1)
            if args.json:
                from opentine._cli_json import emit

                emit({"command": "config", "key": key, "value": settings[key]})
            else:
                print(settings[key])
            return
        if verb == "set":
            settings[key] = value
        else:
            settings.pop(key, None)
        save(settings)
    except (ValueError, OSError) as exc:
        _fail(str(exc))


__all__ = [
    "ENV",
    "SettingsError",
    "add_text_flags",
    "apply_output_format",
    "cmd_user_config",
    "is_user_config",
    "load",
    "output_format",
    "save",
    "settings_file",
]
