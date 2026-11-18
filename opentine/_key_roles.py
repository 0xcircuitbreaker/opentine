"""Key separation for self-improving agent loops (0.58): ``tine keys lint``.

The repository's key-role policy, ``.tine/key-roles.toml``, names which keys
play which part in a loop::

    version = 1
    [roles]
    optimizer = ["sha256:<fingerprint>"]   # signs candidates
    scorer    = ["sha256:<fingerprint>"]   # signs eval verdicts
    dataset   = ["sha256:<fingerprint>"]   # seals and signs datasets
    verdict   = ["sha256:<fingerprint>"]   # signs promotion verdicts
    approver  = ["sha256:<fingerprint>"]   # approves promotions (optional)
    policy    = ["sha256:<fingerprint>"]   # signs promotion policies (optional)
    stopper   = ["sha256:<fingerprint>"]   # may stop a loop (optional)
    eval      = ["sha256:<fingerprint>"]   # unseals sealed holdouts (0.60, optional)

With a ``policy`` role, ``promote`` needs a signed policy
(:mod:`opentine._promote_pins`); with a ``stopper`` role, a loop stop signed by
any other key still fences but reports ``unverified``.

A key is its ``sha256:`` fingerprint (what ``tine verify`` prints) or its raw
Ed25519 public key as 64 hex digits. The policy is a local config file, read
by this command and by ``promote``'s check; it is not an object kind.

0.59: an unsigned file only ever *refuses* (key separation). Powers --
``policy``, ``scorer``, ``stopper`` -- come only from roles an owner-signed
trust bundle carries (:mod:`opentine._key_roles_pin`); a file alone is
``roles: unpinned``.

Findings follow owner decision D12: a ``fail:`` finding is a fact about keys
and policy (the optimizer key also holds a scorer, dataset, verdict or
approver key; a malformed policy) and blocks; an ``advisory:`` finding (a role
nobody holds yet) is reported and never blocks unless ``--strict`` asks.
"""

from __future__ import annotations

import hashlib
import re
import tomllib
from pathlib import Path
from typing import Any

FILE_NAME = "key-roles.toml"
OPTIMIZER = "optimizer"
GUARDED = ("scorer", "dataset", "verdict", "approver", "policy", "eval")
STOPPER = "stopper"
ROLES = (OPTIMIZER, *GUARDED, STOPPER)
REQUIRED = ("scorer", "dataset", "verdict")
MAX_KEYS = 256
_FPR = re.compile(r"sha256:[0-9a-f]{64}")
_RAW = re.compile(r"[0-9a-f]{64}")


class KeyRoleError(ValueError):
    """A key-role policy that cannot be used (a ``fail:`` fact)."""


def normalize_key(value: Any) -> str:
    """A key's ``sha256:`` fingerprint, from a fingerprint or raw public key hex."""
    text = value.strip().lower() if isinstance(value, str) else ""
    if _FPR.fullmatch(text):
        return text
    if _RAW.fullmatch(text):
        return "sha256:" + hashlib.sha256(bytes.fromhex(text)).hexdigest()
    raise KeyRoleError(f"{value!r} is not a key: give sha256:<64 hex> or a 64-hex public key")


def policy_path(repo_path: Path) -> Path:
    return Path(repo_path) / FILE_NAME


def parse(data: bytes) -> dict[str, list[str]]:
    """``{role: [fingerprints]}`` for every known role (empty when unnamed)."""
    try:
        document = tomllib.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise KeyRoleError(f"key-role policy is not TOML: {exc}") from exc
    return parse_doc(document)


def parse_doc(document: Any) -> dict[str, list[str]]:
    """``{role: [fingerprints]}`` from a parsed ``{version: 1, roles: {...}}`` document."""
    if (
        not isinstance(document, dict)
        or set(document) - {"version", "roles"}
        or document.get("version") != 1
    ):
        raise KeyRoleError("key-role policy needs version = 1 and only a [roles] table")
    roles = document.get("roles", {})
    if not isinstance(roles, dict) or set(roles) - set(ROLES):
        unknown = sorted(set(roles) - set(ROLES)) if isinstance(roles, dict) else roles
        raise KeyRoleError(f"unknown key roles {unknown}: use {', '.join(ROLES)}")
    out: dict[str, list[str]] = {}
    for role in ROLES:
        keys = roles.get(role, [])
        if not isinstance(keys, list) or len(keys) > MAX_KEYS:
            raise KeyRoleError(f"role {role} is a list of at most {MAX_KEYS} keys")
        out[role] = sorted({normalize_key(key) for key in keys})
    return out


def load(path: Path) -> dict[str, list[str]] | None:
    """The policy at *path*, or ``None`` when there is none."""
    try:
        data = Path(path).read_bytes()
    except FileNotFoundError:
        return None
    return parse(data)


def _finding(level: str, code: str, message: str, role: str | None = None,
             key: str | None = None) -> dict[str, Any]:  # fmt: skip
    return {"level": level, "code": f"{level}:{code}", "role": role, "key": key,
            "message": message}  # fmt: skip


def lint(roles: dict[str, list[str]], extra_optimizer: list[str] | tuple = ()) -> list[dict]:
    """Findings for *roles*; *extra_optimizer* adds candidate signing keys to check."""
    findings: list[dict[str, Any]] = []
    optimizer = sorted({*roles.get(OPTIMIZER, []), *(normalize_key(k) for k in extra_optimizer)})
    for key in optimizer:
        for role in GUARDED:
            if key in roles.get(role, []):
                findings.append(_finding(
                    "fail", "key-separation.shared",
                    f"the optimizer key {key} also holds a {role} key: an optimizer "
                    f"could sign its own {role} evidence", role, key))  # fmt: skip
    if not optimizer:
        findings.append(_finding("advisory", "key-roles.no-optimizer",
                                 "no optimizer key is named, so separation is unchecked",
                                 OPTIMIZER))  # fmt: skip
    for role in REQUIRED:
        if not roles.get(role):
            findings.append(_finding("advisory", "key-roles.empty-role",
                                     f"no {role} key is named", role))  # fmt: skip
    return findings


def blocking(findings: list[dict[str, Any]], *, strict: bool = False) -> list[dict[str, Any]]:
    """The findings that refuse: every ``fail:``, and ``advisory:`` only when *strict*."""
    return [f for f in findings if f["level"] == "fail" or (strict and f["level"] == "advisory")]


def check_separation(repo_path: Path, signer: str, *, policy: Path | None = None) -> None:
    """Refuse (:class:`KeyRoleError`) when *signer* may not sign a candidate.

    The check ``promote`` runs on the candidate's signing key: it fails when
    that key also holds a scorer, dataset, verdict or approver key, or when it
    is named in a guarded role at all. With no policy file nothing is refused
    (an advisory, by D12).
    """
    if policy is not None:
        roles = load(policy)
    else:
        from opentine._key_roles_pin import resolve

        roles = resolve(repo_path)["roles"]
    if roles is None:
        return
    shared = blocking(lint(roles, [signer]))
    if shared:
        raise KeyRoleError(shared[0]["message"])


__all__ = ["FILE_NAME", "KeyRoleError", "ROLES", "blocking", "check_separation", "lint", "load",
           "normalize_key", "parse", "parse_doc", "policy_path"]  # fmt: skip
