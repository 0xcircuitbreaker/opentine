"""Named trust policies for ``tine verify``: user-scoped, never repository-scoped.

A policy names the trust roots ``tine verify`` would otherwise take from flags
(``--pubkey``, ``--pin``, ``--rekor-key``, ``--require-receipt``,
``--cert-identity``, ``--cert-oidc-issuer``, ``--fulcio-root``, and 0.18's
``--ct-key``/``--require-sct`` and ``--trusted-root``). They live only in
``$XDG_CONFIG_HOME/opentine/trust-policies.json``: written 0600, and refused when
the file is a symlink, not a regular file, group/world-writable or not owned by
the current user. A repository's ``.tine/porcelain.json`` can neither define nor
select one -- a cloned project must never choose which keys its runs verify
under. ``--trust-embedded-key`` (TOFU) is never a policy field: it stays an
explicit per-call choice.

Explicit flags override policy fields; key material (``--pubkey``/``--pin``/
``--key-env``/``--key-file``/``--trust-embedded-key``) replaces the policy's key
as a unit. ``trust.default`` applies only when no key/receipt/keyless flag and no
``--policy`` is given; ``--no-policy`` turns it off. Paths are stored absolute
and checked again on every use.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
from pathlib import Path
from typing import Any

FILE_NAME = "trust-policies.json"
MAX_BYTES = 256 * 1024
NAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
PATH_FIELDS = ("pubkey", "rekor_key", "fulcio_root", "trusted_root")
TEXT_FIELDS = ("cert_identity", "cert_oidc_issuer")
SCT_FIELDS = ("ct_key", "require_sct")
FIELDS = (
    "pubkey",
    "pin",
    "rekor_key",
    "require_receipt",
    *TEXT_FIELDS,
    "fulcio_root",
    *SCT_FIELDS,
    "trusted_root",
)
KEY_DESTS = ("key_env", "key_file", "pubkey", "pin", "trust_embedded_key")
#: Any of these given on the command line means the caller chose trust explicitly.
EXPLICIT_DESTS = (
    *KEY_DESTS,
    "require_receipt",
    "rekor_key",
    *TEXT_FIELDS,
    "fulcio_root",
    *SCT_FIELDS,
    "trusted_root",
)


class PolicyError(ValueError):
    """A policy file or policy that must not be used."""


def policy_file() -> Path:
    home = os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config"
    return Path(home, "opentine", FILE_NAME)


def check_name(name: Any) -> str:
    if not isinstance(name, str) or not NAME.fullmatch(name):
        raise PolicyError(f"invalid policy name {name!r}: use [a-z0-9][a-z0-9._-]*")
    return name


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    if len({key for key, _ in pairs}) != len(pairs):
        raise ValueError("duplicate key")
    return dict(pairs)


def _refuse_unsafe(path: Path, info: os.stat_result) -> None:
    if stat.S_ISLNK(info.st_mode):
        raise PolicyError(f"{path} is a symlink; trust policies must be a regular file")
    if not stat.S_ISREG(info.st_mode):
        raise PolicyError(f"{path} is not a regular file")
    if os.name == "posix":
        if info.st_mode & 0o022:
            raise PolicyError(f"{path} is group- or world-writable; chmod 600 it")
        if info.st_uid != os.geteuid():
            raise PolicyError(f"{path} is not owned by the current user")


def _read(path: Path) -> bytes:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return b""
    _refuse_unsafe(path, info)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as handle:
        opened = os.fstat(handle.fileno())
        if (opened.st_ino, opened.st_dev) != (info.st_ino, info.st_dev):
            raise PolicyError(f"{path} changed while it was read")
        raw = handle.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise PolicyError(f"{path} exceeds {MAX_BYTES} bytes")
    return raw


def load() -> dict[str, Any]:
    """``{"default": name|None, "policies": {...}}``; empty when there is no file."""
    path = policy_file()
    raw = _read(path)
    if not raw:
        return {"default": None, "policies": {}}
    from opentine.kernel import validate_json_shape

    try:
        validate_json_shape(raw, max_tokens=20_000)
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique)
        return validated(value)
    except PolicyError:
        raise
    except (ValueError, RecursionError, UnicodeDecodeError) as exc:
        raise PolicyError(f"{path} is malformed: {exc}") from exc


def validated(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) - {"version", "default", "policies"}:
        raise PolicyError("trust policies have an unexpected shape")
    policies, default = value.get("policies") or {}, value.get("default")
    if not isinstance(policies, dict):
        raise PolicyError("trust policies have an unexpected shape")
    for name, policy in policies.items():
        check_policy(check_name(name), policy)
    if default is not None and default not in policies:
        raise PolicyError(f"default trust policy {default!r} is not defined")
    return {"default": default, "policies": dict(policies)}


def check_policy(name: str, policy: Any) -> dict[str, Any]:
    if not isinstance(policy, dict) or not policy or set(policy) - set(FIELDS):
        raise PolicyError(f"policy {name!r}: unexpected fields (allowed: {', '.join(FIELDS)})")
    for field in PATH_FIELDS:
        if field in policy and not (
            isinstance(policy[field], str) and os.path.isabs(policy[field])
        ):
            raise PolicyError(f"policy {name!r}: {field} must be an absolute path")
    for field in TEXT_FIELDS:
        if field in policy and not (isinstance(policy[field], str) and 0 < len(policy[field])):
            raise PolicyError(f"policy {name!r}: {field} must be a non-empty string")
    for field in ("require_receipt", "require_sct"):
        if field in policy and not isinstance(policy[field], bool):
            raise PolicyError(f"policy {name!r}: {field} must be true or false")
    if "trusted_root" in policy and {"rekor_key", "fulcio_root", "ct_key"} & set(policy):
        raise PolicyError(f"policy {name!r}: trusted_root replaces rekor_key/fulcio_root/ct_key")
    cts = policy.get("ct_key", [])
    if not isinstance(cts, list) or not all(isinstance(p, str) and os.path.isabs(p) for p in cts):
        raise PolicyError(f"policy {name!r}: ct_key must be a list of absolute paths")
    pins = policy.get("pin", [])
    if not isinstance(pins, list) or not all(isinstance(pin, str) for pin in pins):
        raise PolicyError(f"policy {name!r}: pin must be a list of sha256:HEX strings")
    from opentine._signing_pins import normalize_pins

    normalize_pins(pins)
    return policy


def save(table: dict[str, Any]) -> None:
    from opentine._export_write import write_private

    value = validated(table)
    text = json.dumps({"version": 1, **value}, indent=2, sort_keys=True) + "\n"
    path = policy_file()
    _read(path)  # refuse to replace a symlinked or foreign file
    write_private(path, text.encode("utf-8"))


def _fail(message: str) -> None:
    from opentine._cli_common import _terminal, console

    console.print(f"[red]trust policy: {_terminal(message)}[/]")
    raise SystemExit(1)


def apply(args: argparse.Namespace) -> None:
    """Fill unset verify flags from ``--policy NAME`` or ``trust.default``."""
    from opentine._cli_flags import given

    name, off = getattr(args, "trust_policy", None), getattr(args, "no_policy", False)
    if name and off:
        _fail("--policy and --no-policy cannot be combined")
    if off or (not name and given(args, EXPLICIT_DESTS)):
        return
    try:
        table = load()
    except (OSError, PolicyError) as exc:  # fail closed: never verify under a guess
        _fail(str(exc))
        return
    name = name or table["default"]
    if not name:
        return
    if name not in table["policies"]:
        _fail(f"unknown policy {name!r}; see `tine trust policy list`")
    policy, applied = table["policies"][name], []
    paths = [(f, policy[f]) for f in PATH_FIELDS if f in policy]
    for field, path in paths + [("ct_key", p) for p in policy.get("ct_key", [])]:
        if not os.path.isfile(path):
            _fail(f"policy {name!r}: {field} {path} is not a readable file")
    keyed = bool(given(args, KEY_DESTS))
    for field, value in policy.items():
        if (field in ("pubkey", "pin") and keyed) or given(args, (field,)):
            continue
        setattr(args, field, list(value) if field in ("pin", "ct_key") else value)
        applied.append(field)
    args.policy_fields = tuple(applied)
    args.policy_used = name


def emit_for(args: argparse.Namespace):
    """``emit`` that adds ``"policy"`` only when one was used (pinned JSON stays)."""
    from opentine._cli_json import emit

    name = getattr(args, "policy_used", None)
    return lambda payload: emit({**payload, "policy": name} if name else payload)


__all__ = [
    "FIELDS",
    "PolicyError",
    "apply",
    "check_name",
    "check_policy",
    "emit_for",
    "load",
    "policy_file",
    "save",
    "validated",
]
