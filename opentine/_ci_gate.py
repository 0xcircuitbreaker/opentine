"""The CI gate behind ``actions/gate`` and the GitLab component (0.46).

``python -m opentine._ci_gate`` reads what the CI job already produced --
``tine verify --json`` and ``tine eval verify --json`` outputs, and a remote's
signed admission VSA (SPEC 8.14) -- and decides one gate::

    python -m opentine._ci_gate --verify v.json --eval e.json \\
        --vsa vsa.json --vsa-key server.pub --subject run:<hex> \\
        [--vsa-policy opentine:trust-policy/prod] [--vsa-level L ...] \\
        --summary gate.json --comment comment.md

It writes ``tine-ci-gate/1`` (``--summary``) and a Markdown PR/MR comment
(``--comment``), and exits 0 when every check passed, 4 when one failed and 2
when an input is unusable. The comment is built from verdicts only: booleans,
fixed reason classes and bounded, sanitized names. It never contains raw tool
output, environment variables or tokens, so nothing secret can reach a PR.
"""

from __future__ import annotations

import argparse
import base64
import json
import re
import sys
from pathlib import Path
from typing import Any

SCHEMA = "tine-ci-gate/1"
MARKER = "<!-- opentine-ci-gate -->"
PASSED, FAILED, USAGE = 0, 4, 2
MAX_INPUT = 4 << 20
_UNSAFE = re.compile(r"[^A-Za-z0-9 ._:/@+=,-]")


def clean(text: Any, limit: int = 120) -> str:
    """*text* as inert Markdown: allowed characters only, bounded length."""
    value = _UNSAFE.sub("?", str(text))
    return value if len(value) <= limit else value[: limit - 1] + "~"


def _json(path: str) -> Any:
    raw = Path(path).read_bytes()
    if len(raw) > MAX_INPUT:
        raise ValueError(f"{path} exceeds {MAX_INPUT} bytes")
    return json.loads(raw.decode("utf-8"))


def _tool_check(kind: str, path: str) -> dict[str, Any]:
    """One ``tine verify``/``tine eval verify`` ``--json`` output as a check row."""
    try:
        value = _json(path)
    except (OSError, ValueError, RecursionError) as exc:
        return {"check": kind, "name": clean(path), "ok": False, "class": "unreadable",
                "detail": clean(type(exc).__name__)}  # fmt: skip
    if not isinstance(value, dict):
        return {"check": kind, "name": clean(path), "ok": False, "class": "malformed"}
    ok = value.get("ok") is True and "error" not in value and "unpinned" not in value
    row = {"check": kind, "name": clean(value.get("path") or path), "ok": ok}
    row["class"] = (
        "passed" if ok else "unpinned" if "unpinned" in value
        else "error" if "error" in value else "failed"
    )  # fmt: skip
    return row


def public_key_bytes(path: str) -> bytes:
    """A raw 32-byte Ed25519 key, base64url text, or a PEM public key file."""
    raw = Path(path).read_bytes()
    if b"-----BEGIN" in raw:
        from cryptography.hazmat.primitives.serialization import load_pem_public_key

        return load_pem_public_key(raw).public_bytes_raw()  # type: ignore[union-attr]
    if len(raw) == 32:
        return raw
    text = raw.decode("ascii").strip()
    return base64.urlsafe_b64decode(
        text.replace("+", "-").replace("/", "_") + "=" * (-len(text) % 4)
    )


def _vsa_check(args: argparse.Namespace) -> dict[str, Any]:
    from opentine._vsa_verify import classify

    row: dict[str, Any] = {"check": "vsa", "name": clean(args.subject)}
    try:
        envelope = _json(args.vsa)
        key = public_key_bytes(args.vsa_key)
    except (OSError, ValueError, RecursionError) as exc:
        return {**row, "ok": False, "class": "unreadable", "detail": clean(type(exc).__name__)}
    kind = classify(envelope, key, args.subject, levels=args.vsa_level, policy=args.vsa_policy,
                    resource=args.vsa_resource)  # fmt: skip
    return {**row, "ok": kind == "valid", "class": kind}


def decide(args: argparse.Namespace) -> dict[str, Any]:
    checks = [_tool_check("verify", path) for path in args.verify]
    checks += [_tool_check("eval", path) for path in args.eval]
    if args.vsa:
        checks.append(_vsa_check(args))
    return {"schema": SCHEMA, "ok": bool(checks) and all(c["ok"] for c in checks),
            "checks": checks}  # fmt: skip


def comment(summary: dict[str, Any]) -> str:
    head = "passed" if summary["ok"] else "FAILED"
    lines = [MARKER, f"### OpenTine gate: {head}", "", "| check | subject | result |",
             "|---|---|---|"]  # fmt: skip
    for row in summary["checks"]:
        mark = "ok" if row["ok"] else "**fail**"
        lines.append(f"| {row['check']} | `{row['name']}` | {mark} ({row['class']}) |")
    if not summary["checks"]:
        lines.append("| - | - | **fail** (no checks were given) |")
    return "\n".join(lines) + "\n"


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m opentine._ci_gate")
    p.add_argument("--verify", action="append", default=[], metavar="FILE")
    p.add_argument("--eval", action="append", default=[], metavar="FILE")
    p.add_argument("--vsa", metavar="ENVELOPE.json")
    p.add_argument("--vsa-key", metavar="PUBKEY")
    p.add_argument("--subject", default="", metavar="OID")
    p.add_argument("--vsa-policy", default="", metavar="URI")
    p.add_argument("--vsa-resource", default="", metavar="tine://TENANT/REF")
    p.add_argument("--vsa-level", action="append", default=[], metavar="LEVEL")
    p.add_argument("--summary", metavar="FILE")
    p.add_argument("--comment", metavar="FILE")
    return p


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.vsa and (not args.vsa_key or not args.subject):
        print("--vsa needs --vsa-key and --subject", file=sys.stderr)
        return USAGE
    summary = decide(args)
    if args.summary:
        Path(args.summary).write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    if args.comment:
        Path(args.comment).write_text(comment(summary), encoding="utf-8")
    print(comment(summary), end="")
    return PASSED if summary["ok"] else FAILED


if __name__ == "__main__":  # pragma: no cover - exercised through main()
    raise SystemExit(main())
