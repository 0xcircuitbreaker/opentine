"""``tine witness doctor`` (0.49): an operator's pre-flight and on-call check.

``witness doctor --key KEY... --name N --log-vkey V... [--state DIR]
[--registry FILE] [--url URL] [--json]`` runs every check and reports each one;
it exits 4 when any fails, so it can gate a deploy or page someone:

* ``keys``      every key loads (file, encrypted file or signer URI);
* ``key-files`` key files are not readable by group or others (POSIX only);
* ``state``     the state directory can be created and written;
* ``logs``      each pinned log key parses and the stored checkpoint opens;
* ``registry``  the registry meets the network policy, lists this witness under
  its name with every key it cosigns with, and witnesses one of the logs here;
* ``health``    ``GET URL/health`` answers ``200`` with ``status: ok``;
* ``keys-served`` ``GET URL/keys`` serves exactly these vkeys, current first;
* ``url``       the registry lists this witness at ``URL``.

Checks that need an input not given are skipped, not passed. It reads and
writes nothing beyond probing ``--state``; its output never names a key path.
"""

from __future__ import annotations

import json
import os
import stat
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

MAX_REPLY = 1 << 16
TIMEOUT = 10.0


def _get(url: str) -> tuple[int, bytes]:
    try:
        with urllib.request.urlopen(url, timeout=TIMEOUT) as reply:  # noqa: S310
            return reply.status, reply.read(MAX_REPLY)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(MAX_REPLY)


def _private(path: str) -> str | None:
    """Why a key file is too open, or None (signer URIs and Windows are not checked)."""
    if os.name == "nt" or "://" in path or not Path(path).is_file():
        return None
    mode = stat.S_IMODE(Path(path).stat().st_mode)
    return f"mode {mode:o} lets group or others read it" if mode & 0o077 else None


def _keys(paths: list[str], name: str, out: list[dict[str, Any]]) -> list[str]:
    from opentine._signing_keys import SignatureError, ed25519_private_from_file
    from opentine.repository._tlog_cosign import witness_vkey

    vkeys, errors, open_ = [], [], []
    for index, path in enumerate(paths):
        try:
            key = ed25519_private_from_file(path, legacy_warn=False)
            vkeys.append(witness_vkey(name, key.public_key().public_bytes_raw()))
        except (OSError, SignatureError, ValueError) as exc:
            errors.append(f"key {index + 1}: {exc.__class__.__name__}")
        if (why := _private(path)) is not None:
            open_.append(f"key {index + 1}: {why}")
    out.append({"check": "keys", "ok": not errors, "detail": "; ".join(errors) or
                f"{len(vkeys)} key(s), current first"})  # fmt: skip
    out.append({"check": "key-files", "ok": not open_, "detail": "; ".join(open_) or "private"})
    return vkeys


def _logs(args: Any, state: Path, out: list[dict[str, Any]]) -> dict[str, str]:
    from opentine._witness_http import stored_size
    from opentine.repository._tlog_note import parse_vkey

    logs, problems, sizes = {}, [], []
    for vkey in args.log_vkey:
        try:
            origin = parse_vkey(vkey)[0]
            logs[origin] = vkey
            sizes.append(f"{origin} at {stored_size(state, origin, vkey)}")
        except (OSError, ValueError) as exc:
            problems.append(str(exc))
    out.append({"check": "logs", "ok": not problems, "detail": "; ".join(problems or sizes)})
    return logs


def _registry(path: str, name: str, vkeys: list[str], logs: dict[str, str], out: list) -> Any:
    from opentine import _witness_network

    try:
        doc = _witness_network.load(Path(path))
    except (OSError, ValueError) as exc:
        out.append({"check": "registry", "ok": False, "detail": str(exc)})
        return None
    entry = next((e for e in doc["witnesses"] if e["name"] == name), None)
    problems = []
    if entry is None:
        problems.append(f"the registry does not list {name}")
    elif missing := [v for v in vkeys if v not in entry["vkeys"]]:
        problems.append(f"{len(missing)} of this witness's vkeys are not in the registry")
    if logs.get(doc["log"]["origin"]) != doc["log"]["vkey"]:
        problems.append(f"this witness does not pin the registry's log {doc['log']['origin']}")
    detail = "; ".join(problems) or f"listed; policy {doc['policy']['quorum']}"
    out.append({"check": "registry", "ok": not problems, "detail": detail})
    return entry


def _served(url: str, vkeys: list[str], entry: Any, out: list[dict[str, Any]]) -> None:
    base = url.rstrip("/")
    try:
        status, body = _get(base + "/health")
        health = json.loads(body) if status == 200 else {}
        ok = status == 200 and health.get("status") == "ok"
        out.append({"check": "health", "ok": ok, "detail": f"HTTP {status}"})
        status, body = _get(base + "/keys")
        served = body.decode("utf-8", "replace").splitlines() if status == 200 else []
        detail = "match" if served == vkeys else f"HTTP {status}, {len(served)} vkey(s) differ"
        out.append({"check": "keys-served", "ok": served == vkeys, "detail": detail})
    except (OSError, ValueError) as exc:
        out.append({"check": "health", "ok": False, "detail": f"unreachable: {exc}"})
    if entry is not None:
        ok = entry["url"].rstrip("/") == base
        out.append({"check": "url", "ok": ok, "detail": "listed" if ok else "registry differs"})


def _writable(state: Path) -> bool:
    try:
        state.mkdir(parents=True, exist_ok=True)
    except OSError:
        return False
    return os.access(state, os.W_OK)


def diagnose(args: Any) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    vkeys = _keys(list(args.key), args.name, checks)
    state = Path(args.state) if args.state else Path(_state_default())
    probe = _writable(state)
    checks.append(
        {"check": "state", "ok": probe, "detail": "writable" if probe else "not writable"}
    )
    logs = _logs(args, state, checks)
    entry = _registry(args.registry, args.name, vkeys, logs, checks) if args.registry else None
    if args.url:
        _served(args.url, vkeys, entry, checks)
    ok = all(check["ok"] for check in checks)
    return {"command": "witness doctor", "schema": "tine-cli-witness-doctor/1", "ok": ok,
            "witness": args.name, "vkeys": vkeys, "checks": checks}  # fmt: skip


def _state_default() -> str:
    from opentine._cli_witness import _state_default as default

    return default()


def cmd_doctor(args: Any) -> None:
    from opentine._cli_common import _terminal
    from opentine._cli_errors import VERIFICATION_FAILED

    result = diagnose(args)
    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        for check in result["checks"]:
            mark = "ok  " if check["ok"] else "FAIL"
            print(f"{mark} {check['check']}: {_terminal(check['detail'])}")
    if not result["ok"]:
        print("tine witness doctor: a check failed", file=sys.stderr)
        raise SystemExit(VERIFICATION_FAILED)


__all__ = ["cmd_doctor", "diagnose"]
