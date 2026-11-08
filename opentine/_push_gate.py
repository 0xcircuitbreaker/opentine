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


def _body(repo: Any, oid: str) -> bytes | None:
    """The decoded payload bytes of *oid*, or ``None`` when it cannot be read."""
    try:
        return repo.get(oid).body
    except Exception:  # noqa: BLE001 - unreadable: scanning stored (maybe compressed) bytes
        return None  # would miss what they hide, so the caller fails closed


def scan(repo: Any, oids: list[str] | set[str]) -> list[dict[str, str]]:
    """``{oid, kind}`` for every object the current ruleset would still redact.

    An object that cannot be decoded is a finding too (fail closed): its stored
    bytes may be compressed, and a scan of them would see nothing.
    """
    hits = []
    for oid in sorted(oids):
        body = _body(repo, oid)
        if body is None or redact_blob(body) != body:
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


class Gate:
    """The gate of one ``tine push``: called with each set of objects about to be sent.

    ``tine push`` calls it once, offline, on the objects its tracking refs say
    are missing (so a refusal comes before any connection), and the transport
    calls it again on the exact pack it negotiated with the server, which can
    hold more (a remote that was reset, a different ``--remote-ref``). An
    override is recorded once per newly found object set.
    """

    def __init__(self, repo: Any, allow_reason: str | None) -> None:
        if allow_reason is not None and not allow_reason.strip():
            raise ValueError("--allow-unredacted needs a non-empty REASON")
        self.repo, self.allow_reason, self.seen = repo, allow_reason, set()

    def __call__(self, oids: Any) -> list[dict]:
        new = set(oids) - self.seen
        hits = check(self.repo, new, self.allow_reason)
        self.seen |= new
        return hits


def enforce(repo: Any, tracking: str, refs: list[str], allow_reason: str | None) -> list[dict]:
    """Refuse (``ValueError``) when outgoing objects fail the scan, unless overridden."""
    return check(repo, outgoing_oids(repo, tracking, refs), allow_reason)


def check(repo: Any, oids: Any, allow_reason: str | None) -> list[dict]:
    """Scan *oids*; refuse on hits, or record the override in the op log first."""
    hits = scan(repo, oids)
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

    # The reason is free text typed on a command line: redact it like any stored
    # string, so the override cannot itself put a secret in the op log. It is
    # written now, before anything is sent, and a failed write refuses the push.
    reason = redact_blob(allow_reason.strip().encode("utf-8")).decode("utf-8", "replace")
    note(f"allow-unredacted: {reason} ({len(hits)} object(s))", base=repo.path)
    return hits


def warn_dry_run(repo: Any, tracking: str, refs: list[str]) -> list[dict]:
    """``push --dry-run``: say on stderr that the real push would be refused."""
    import sys

    hits = scan(repo, outgoing_oids(repo, tracking, refs))
    if hits:
        print(
            f"tine: warning: {len(hits)} outgoing object(s) fail the {REDACTION_RULESET} "
            "scan; this push would be refused without --allow-unredacted",
            file=sys.stderr,
        )
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
    "Gate",
    "check",
    "enforce",
    "outgoing_oids",
    "run_report",
    "scan",
    "sign",
    "verify",
    "warn_dry_run",
]
