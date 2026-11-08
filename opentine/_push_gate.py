"""The 0.45 pre-push redaction gate and the per-run redaction report.

Objects are redacted when they are written, but a repository can still hold
credential-shaped bytes: an object written with ``redact=False``, one imported
or fetched from a writer with an older ruleset, or a secret shape the current
ruleset learned after the object was stored. Before ``tine push`` sends a pack,
every outgoing object is re-scanned with the *current* ruleset
(:data:`REDACTION_RULESET`): an object the redactor would change is a hit. A hit
refuses the push unless ``--allow-unredacted REASON`` is given, and the reason
is recorded in the op log entry of that push.

Findings name the object and its kind only, never the matched bytes, so a
report (or the refusal message) cannot itself leak the secret it found.

A redaction report is canonical JSON. A key signs it in the ``tine-sig/3``
style over ``opentine.redaction-report.v1:`` + JCS of ``{body, header}``, so a
report cannot pass for an artifact or a push-manifest signature.
"""

from __future__ import annotations

from typing import Any

from opentine._push_preview import tracking_ref
from opentine._redact_obfuscated import REDACTION_RULESET
from opentine._signing_v4 import SCHEME_V3
from opentine._signing_verify import HEADER_KEYS, SignatureResult, sign_block, verify_block
from opentine.kernel import canonical_json
from opentine.redaction import redact_blob
from opentine.repository._pack_fit import fitted_pack
from opentine.repository.pack import reachable

REPORT_KIND = "opentine.redaction-report"
REPORT_VERSION = 1
DOMAIN_PREFIX = b"opentine.redaction-report.v1:"


def _body(repo: Any, oid: str) -> bytes:
    """The stored payload bytes of *oid* (decoded, so a compressed store scans the same)."""
    try:
        return repo.get(oid).body
    except Exception:  # noqa: BLE001 - an unreadable object is scanned as stored
        return repo.raw(oid)


def scan(repo: Any, oids: list[str] | set[str]) -> list[dict[str, str]]:
    """``{oid, kind}`` for every object the current ruleset would still redact."""
    hits = []
    for oid in sorted(oids):
        body = _body(repo, oid)
        if redact_blob(body) != body:
            hits.append({"oid": oid, "kind": oid.split(":", 1)[0]})
    return hits


def outgoing_oids(repo: Any, tracking: str, refs: list[str]) -> set[str]:
    """The objects a push of *refs* would send (as ``tine push --dry-run`` counts them)."""
    sent: set[str] = set()
    for ref in refs:
        new = repo.read_ref(ref)
        if not new:
            continue  # the push itself reports a missing local ref
        old = repo.read_ref(tracking_ref(tracking, ref))
        known = reachable(repo, [old], include_associated=False) if old and repo.has(old) else []
        sent.update(fitted_pack(repo, [new], known)[1])
    return sent


def enforce(repo: Any, tracking: str, refs: list[str], allow_reason: str | None) -> list[dict]:
    """Refuse (``ValueError``) when outgoing objects fail the scan, unless overridden."""
    hits = scan(repo, outgoing_oids(repo, tracking, refs))
    if not hits:
        return hits
    if allow_reason is None:
        listed = ", ".join(hit["oid"] for hit in hits[:5]) + (" …" if len(hits) > 5 else "")
        raise ValueError(
            f"push refused: {len(hits)} outgoing object(s) fail the {REDACTION_RULESET} "
            f"scan ({listed}); run `tine redact check`, or pass "
            "--allow-unredacted REASON to push anyway"
        )
    if not allow_reason.strip():
        raise ValueError("--allow-unredacted needs a non-empty REASON")
    from opentine.repository._oplog import note

    note(f"allow-unredacted: {allow_reason.strip()} ({len(hits)} object(s))")
    return hits


def run_report(repo: Any, run: str) -> dict[str, Any]:
    """The redaction report of one run: every object reachable from it, re-scanned."""
    oids = set(reachable(repo, [run], include_associated=True))
    hits = scan(repo, oids)
    return {
        "kind": REPORT_KIND,
        "report_version": REPORT_VERSION,
        "ruleset": REDACTION_RULESET,
        "run": run,
        "objects": len(oids),
        "findings": hits,
        "clean": not hits,
    }


def _message(body: dict[str, Any], header: dict[str, Any]) -> bytes:
    view = {"body": body, "header": {key: header.get(key) for key in HEADER_KEYS}}
    return DOMAIN_PREFIX + canonical_json(view)


def sign(body: dict[str, Any], key: Any, *, algorithm: str, **header: Any) -> dict[str, Any]:
    block = sign_block(
        lambda h: _message(body, h),
        key,
        algorithm=algorithm,
        scheme=SCHEME_V3,
        subject="redaction report",
        **header,
    )
    return {**body, "signature": block}


def verify(report: dict[str, Any], **keys: Any) -> SignatureResult:
    body = {key: value for key, value in report.items() if key != "signature"}
    return verify_block(
        report.get("signature"),
        lambda h: _message(body, h),
        schemes=(SCHEME_V3,),
        subject="redaction report",
        **keys,
    )


__all__ = [
    "DOMAIN_PREFIX",
    "REPORT_KIND",
    "enforce",
    "outgoing_oids",
    "run_report",
    "scan",
    "sign",
    "verify",
]
