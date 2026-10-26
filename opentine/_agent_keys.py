"""Per-agent signing keys, and the ``.tine/agents.toml`` registry of trusted keys.

* ``tine keygen --agent NAME`` writes an Ed25519 key to
  ``$XDG_CONFIG_HOME/opentine/agent-keys/NAME.key`` (0600) and ``NAME.pub`` --
  outside every repository and worktree, and never under the release-catalog
  key directory.
* ``.tine/agents.toml`` maps agent names to allowed key fingerprints::

      [agents.reviewer]
      keys = ["sha256:<64 hex>"]

  It can arrive inside a cloned project, so, like ``porcelain.json``, it is
  **inert until trusted**: ``tine agent trust`` records a hash of its exact
  bytes in ``$XDG_CONFIG_HOME/opentine/trusted-agents.json``, and any edit
  revokes that trust until it is run again.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tomllib
from pathlib import Path
from typing import Any

from opentine._canon import atomic_write_text
from opentine._signing_pins import key_fingerprint, normalize_pin

NAME_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
PINS_FILE = "agents.toml"
MAX_PINS_BYTES = 64 * 1024


def _config_home() -> Path:
    return Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config", "opentine")


def check_name(name: Any) -> str:
    if not isinstance(name, str) or not NAME_RE.fullmatch(name) or name.endswith("."):
        raise ValueError(f"agent name {name!r} must match {NAME_RE.pattern}")
    return name


def key_dir() -> Path:
    return _config_home() / "agent-keys"  # a sibling of, never inside, release/


def key_paths(name: str) -> tuple[Path, Path]:
    base = key_dir() / check_name(name)
    return base.with_suffix(".key"), base.with_suffix(".pub")


def local_fingerprints() -> frozenset[str]:
    """Fingerprints of this user's own agent public keys."""
    found: set[str] = set()
    try:
        files = sorted(key_dir().glob("*.pub"))[:256]
    except OSError:
        return frozenset()
    for path in files:
        try:
            raw = path.read_text(encoding="ascii").strip()
            found.add(key_fingerprint(bytes.fromhex(raw)))
        except (OSError, ValueError):
            continue
    return frozenset(found)


def _pins_path(base: Path | None) -> Path | None:
    if base is None:
        return None
    path = Path(base) / PINS_FILE
    return None if path.is_symlink() or not path.is_file() else path


def _raw(base: Path | None) -> bytes:
    path = _pins_path(base)
    if path is None:
        return b""
    with path.open("rb") as handle:
        raw = handle.read(MAX_PINS_BYTES + 1)
    if len(raw) > MAX_PINS_BYTES:
        raise ValueError(f"{PINS_FILE} exceeds {MAX_PINS_BYTES} bytes")
    return raw


def load_pins(base: Path | None) -> dict[str, frozenset[str]]:
    """``{agent name: fingerprints}`` from *base*/agents.toml (trusted or not)."""
    raw = _raw(base)
    if not raw:
        return {}
    try:
        data = tomllib.loads(raw.decode("utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise ValueError(f"{PINS_FILE} is malformed") from exc
    agents = data.get("agents", {})
    if not isinstance(agents, dict):
        raise ValueError(f"{PINS_FILE}: [agents] must be a table")
    pins: dict[str, frozenset[str]] = {}
    for name, entry in agents.items():
        keys = entry.get("keys", []) if isinstance(entry, dict) else None
        if not isinstance(keys, list) or not all(isinstance(key, str) for key in keys):
            raise ValueError(f"{PINS_FILE}: agents.{name}.keys must be a list of fingerprints")
        pins[check_name(name)] = frozenset(normalize_pin(key) for key in keys)
    return pins


def _trust_file() -> Path:
    return _config_home() / "trusted-agents.json"


def _table() -> dict[str, str]:
    try:
        table = json.loads(_trust_file().read_bytes()[: 1 << 20])
    except (OSError, ValueError):
        return {}
    return (
        {str(k): v for k, v in table.items() if isinstance(v, str)}
        if isinstance(table, dict)
        else {}
    )


def _digest(base: Path) -> str:
    return hashlib.sha256(b"agents\0" + _raw(base)).hexdigest()


def trust(base: Path) -> str:
    """Trust *base*/agents.toml as it is now; returns the recorded digest."""
    if _pins_path(base) is None:
        raise ValueError(f"no {PINS_FILE} to trust in {base}")
    load_pins(base)  # refuse to trust a file that does not parse
    table = _table()
    table[str(Path(base).resolve())] = digest = _digest(base)
    _trust_file().parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(_trust_file(), json.dumps(table, indent=2, sort_keys=True) + "\n")
    return digest


def trusted(base: Path | None) -> bool:
    if base is None or _pins_path(base) is None:
        return False
    try:
        return _table().get(str(Path(base).resolve())) == _digest(base)
    except (OSError, ValueError):
        return False


def trusted_fingerprints(base: Path | None) -> frozenset[str]:
    """Pinned fingerprints in force: the file's only when trusted, plus local keys."""
    pinned: set[str] = set(local_fingerprints())
    if trusted(base):
        for keys in load_pins(base).values():
            pinned |= keys
    return frozenset(pinned)


__all__ = [
    "check_name",
    "key_dir",
    "key_paths",
    "load_pins",
    "local_fingerprints",
    "trust",
    "trusted",
    "trusted_fingerprints",
]
