"""Per-repository porcelain settings: named remotes, ``config`` keys and aliases.

They live in ``.tine/porcelain.json``, beside -- never inside -- the format
descriptor ``config.json`` (SPEC §2.2); they change only what the ``tine``
porcelain does on this machine. Aliases, hooks, a remote's ``token_file`` and
named remotes can act or send credentials, and ``.tine`` can arrive in a clone, so
the file is **inert until trusted**: a hash of its bytes and ``.tine/hooks/`` files,
recorded in ``$XDG_CONFIG_HOME/opentine/trusted-repos.json`` (like direnv).
Writes through ``tine config``/``tine remote`` keep trust; other edits revoke it.
``trust.*``/``policy.*`` keys are refused: trust policies are user-scoped only.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from opentine._canon import atomic_write_text
from opentine.kernel import validate_json_shape
from opentine.repository._paths import internal_path

FILE_NAME = "porcelain.json"
MAX_BYTES = 64 * 1024
MAX_VALUE = 4096
REMOTE_NAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
CONFIG_KEY = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}(\.[a-z0-9][a-z0-9_.-]{0,127})+")
TRUSTED_KEYS = ("alias.", "hooks.")  # only from a trusted file: they act on their own
RESERVED_KEYS = ("trust.", "policy.")  # verify trust roots: never from a repository


def _path(repo_path: Path) -> Path:
    return internal_path(Path(repo_path), FILE_NAME)


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    keys = [key for key, _ in pairs]
    if len(set(keys)) != len(keys):
        raise ValueError("duplicate key")
    return dict(pairs)


def _raw(repo_path: Path) -> bytes:
    path = _path(repo_path)
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_BYTES + 1)
    except FileNotFoundError:
        return b""
    if len(raw) > MAX_BYTES:
        raise ValueError(f"{FILE_NAME} exceeds {MAX_BYTES} bytes")
    return raw


def load(repo_path: Path) -> dict[str, Any]:
    """The validated settings (empty when the file is absent)."""
    raw = _raw(repo_path)
    if not raw:
        return {"remotes": {}, "config": {}}
    try:
        validate_json_shape(raw, max_tokens=20_000)
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique)
    except (ValueError, RecursionError, UnicodeDecodeError) as exc:
        raise ValueError(f"{FILE_NAME} is malformed") from exc
    return _validated(value)


def _validated(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) - {"remotes", "config"}:
        raise ValueError(f"{FILE_NAME} has an unexpected shape")
    remotes = value.get("remotes") or {}
    config = value.get("config") or {}
    if not isinstance(remotes, dict) or not isinstance(config, dict):
        raise ValueError(f"{FILE_NAME} has an unexpected shape")
    for name, remote in remotes.items():
        check_remote_name(name)
        if not isinstance(remote, dict) or set(remote) - {"url", "tenant", "token_file"}:
            raise ValueError(f"remote {name!r} has an unexpected shape")
        check_url(remote.get("url"))
        for field in ("tenant", "token_file"):
            if remote.get(field) is not None and not _short_text(remote[field]):
                raise ValueError(f"remote {name!r} has an invalid {field}")
    for key, item in config.items():
        check_key(key)
        if not _short_text(item):
            raise ValueError(f"config value for {key!r} must be a short string")
    return {"remotes": dict(remotes), "config": dict(config)}


def _short_text(value: Any) -> bool:
    return isinstance(value, str) and 0 < len(value) <= MAX_VALUE and "\0" not in value


def check_remote_name(name: Any) -> str:
    if not isinstance(name, str) or not REMOTE_NAME.fullmatch(name):
        raise ValueError(f"invalid remote name {name!r}: use [a-z0-9][a-z0-9._-]*")
    return name


def check_key(key: Any) -> str:
    if not isinstance(key, str) or not CONFIG_KEY.fullmatch(key):
        raise ValueError(f"invalid config key {key!r}: use section.name in lower case")
    return key


def check_url(url: Any) -> str:
    parts = urlsplit(url) if isinstance(url, str) else None
    if parts is None or parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError(f"remote URL must be http(s)://host[/path], got {url!r}")
    if parts.username or parts.password or parts.query or parts.fragment:
        # The same refusal the transport makes: a credential in a URL leaks into
        # error text, logs and this file. Use --token-file instead.
        raise ValueError("remote URL must not carry credentials, a query or a fragment")
    return url


def save(repo_path: Path, settings: dict[str, Any]) -> None:
    """Write *settings*; keep trust only if trusted before, or new with no hooks.

    A harmless write (``remote add``, ``config set``) must not trust what a clone
    shipped -- ``alias.*``/``hooks.*``/``token_file`` or ``.tine/hooks/`` files --
    without the review ``tine config --trust`` stands for.
    """
    path = _path(repo_path)
    keep_trust = trusted(repo_path) or (not path.exists() and not _hooks_shipped(repo_path))
    value = _validated(settings)
    if reserved := sorted(key for key in value["config"] if key.startswith(RESERVED_KEYS)):
        raise ValueError(f"{reserved[0]!r} is user-scoped: use `tine trust policy`")
    text = json.dumps(value, indent=2, sort_keys=True) + "\n"
    if len(text.encode()) > MAX_BYTES:
        raise ValueError(f"{FILE_NAME} would exceed {MAX_BYTES} bytes")
    atomic_write_text(path, text)
    if keep_trust:
        trust(repo_path)
    elif _hooks_shipped(repo_path):
        print("tine: .tine/hooks/ is unreviewed; run `tine config --trust`", file=sys.stderr)


def _hooks_shipped(repo_path: Path) -> bool:
    try:
        hooks = internal_path(Path(repo_path), "hooks")
        return hooks.is_dir() and any(hooks.iterdir())
    except (OSError, ValueError):
        return True  # unreadable: assume something is there, never auto-trust


# -- trust ---------------------------------------------------------------------


def _trust_file() -> Path:
    home = os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config"
    return Path(home, "opentine", "trusted-repos.json")


def _trust_table() -> dict[str, str]:
    try:
        raw = _trust_file().read_bytes()[: 1 << 20]
        table = json.loads(raw)
    except (OSError, ValueError):
        return {}
    if not isinstance(table, dict):
        return {}
    return {str(key): str(value) for key, value in table.items() if isinstance(value, str)}


def _key(repo_path: Path) -> str:
    return str(Path(repo_path).resolve())


MAX_HOOK_FILES = 256
MAX_HOOK_BYTES = 1 << 20


def _digest(repo_path: Path) -> str:
    """One hash over the porcelain file and every file under ``.tine/hooks/``:
    a hook edited, added or removed after trust revokes it like a file edit."""
    digest = hashlib.sha256(b"porcelain\0" + _raw(repo_path))
    try:
        hooks = internal_path(Path(repo_path), "hooks")
    except (OSError, ValueError):
        return digest.hexdigest() + ":unreadable-hooks"
    if hooks.is_dir():
        entries = sorted(hooks.rglob("*"), key=lambda item: item.as_posix())
        if len(entries) > MAX_HOOK_FILES:
            raise ValueError(f".tine/hooks holds more than {MAX_HOOK_FILES} entries")
        for entry in entries:
            name = entry.relative_to(hooks).as_posix().encode("utf-8", "surrogateescape")
            if entry.is_symlink() or not (entry.is_file() or entry.is_dir()):
                body = b"link-or-special"
            elif entry.is_dir():
                body = b"dir"
            else:
                with entry.open("rb") as handle:
                    content = handle.read(MAX_HOOK_BYTES + 1)
                if len(content) > MAX_HOOK_BYTES:
                    raise ValueError(f"hook {entry.name} exceeds {MAX_HOOK_BYTES} bytes")
                mode = b"x" if os.access(entry, os.X_OK) else b"-"
                body = mode + hashlib.sha256(content).digest()
            digest.update(b"\0" + name + b"\0" + body)
    return digest.hexdigest()


def trust(repo_path: Path) -> str:
    """Record the current file's (and hooks') digest as trusted; returns it."""
    digest = _digest(repo_path)
    table = _trust_table()
    table[_key(repo_path)] = digest
    path = _trust_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(path, json.dumps(table, indent=2, sort_keys=True) + "\n")
    return digest


def trusted(repo_path: Path) -> bool:
    """True only if the file's exact bytes, and its hooks, were trusted here."""
    raw = _raw(repo_path)
    if not raw:
        return False
    recorded = _trust_table().get(_key(repo_path))
    try:
        return recorded == _digest(repo_path)
    except (OSError, ValueError):
        return False


def effective(repo_path: Path) -> dict[str, str]:
    """Config values in force: alias.* and hooks.* only from a trusted file."""
    config = load(repo_path)["config"]
    if trusted(repo_path):
        return dict(config)
    return {key: value for key, value in config.items() if not key.startswith(TRUSTED_KEYS)}


def remote(repo_path: Path, name: str) -> dict[str, Any] | None:
    """A configured remote, only from a trusted file: a cloned file's URL would
    receive the operator's token (a literal URL still works)."""
    found = load(repo_path)["remotes"].get(name)
    if found is None:
        return None
    if not trusted(repo_path):
        raise ValueError(
            f"remote {name!r} comes from a {FILE_NAME} that is not trusted on this "
            "machine; review it and run `tine config --trust`, or give the URL"
        )
    return dict(found)
