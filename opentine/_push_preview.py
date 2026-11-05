"""``tine push --dry-run``: exactly what a push would send, and a signed manifest.

Nothing here touches the network. The remote's side of each ref is what this
repository last saw of it -- its ``remotes/<name>/…`` tracking ref -- so the
preview is the pack a push would build when the remote has not moved since the
last fetch (a remote that moved on only shrinks it). For every outgoing ref it
lists ``old -> new``, the objects by kind with their stored bytes, and each run
with the redaction ruleset it was recorded under.

The manifest is canonical JSON (JCS). A key signs it in the ``tine-sig/3``
style: one header block over ``opentine.push-manifest.v1:`` + JCS of
``{body, header}``, so the manifest cannot pass for an artifact signature.
"""

from __future__ import annotations

from typing import Any

from opentine._signing_v4 import SCHEME_V3
from opentine._signing_verify import HEADER_KEYS, SignatureResult, sign_block, verify_block
from opentine.kernel import canonical_json
from opentine.repository._pack_fit import fitted_pack
from opentine.repository.pack import reachable

MANIFEST_KIND = "opentine.push-manifest"
MANIFEST_VERSION = 1
DOMAIN_PREFIX = b"opentine.push-manifest.v1:"


def tracking_ref(tracking: str, ref: str) -> str:
    return f"remotes/{tracking}/{ref.removeprefix('heads/')}"


def _ruleset(repo: Any, oid: str) -> str | None:
    """The redaction ruleset a run records; ``None`` before rulesets were recorded."""
    try:
        policies = repo.load_run(oid).policies
    except Exception:  # noqa: BLE001 - an unreadable run is reported, not fatal
        return None
    redaction = policies.get("redaction") if isinstance(policies, dict) else None
    value = redaction.get("ruleset") if isinstance(redaction, dict) else None
    return value if isinstance(value, str) else None


def outgoing(
    repo: Any, remote: str, tracking: str, refs: list[str], remote_ref: str | None = None
) -> dict[str, Any]:
    """The manifest body for pushing *refs* to *remote*, computed offline."""
    entries: list[dict[str, Any]] = []
    sent: set[str] = set()
    for ref in refs:
        new = repo.read_ref(ref)
        if not new:
            raise KeyError(f"local ref not found: {ref}")
        old = repo.read_ref(tracking_ref(tracking, ref))
        known = reachable(repo, [old], include_associated=False) if old and repo.has(old) else []
        _, missing = fitted_pack(repo, [new], known)
        sent.update(missing)
        entries.append({"ref": remote_ref or ref, "old": old, "new": new, "objects": len(missing)})
    kinds: dict[str, dict[str, int]] = {}
    for oid in sorted(sent):
        bucket = kinds.setdefault(oid.split(":", 1)[0], {"count": 0, "bytes": 0})
        bucket["count"] += 1
        bucket["bytes"] += repo.raw_size(oid)
    runs = [
        {"run": oid, "redaction_ruleset": _ruleset(repo, oid)}
        for oid in sorted(sent)
        if oid.startswith("run:")
    ]
    return {
        "kind": MANIFEST_KIND,
        "manifest_version": MANIFEST_VERSION,
        "remote": remote,
        "refs": entries,
        "objects": {
            "count": len(sent),
            "bytes": sum(bucket["bytes"] for bucket in kinds.values()),
            "by_kind": kinds,
        },
        "runs": runs,
    }


def _message(body: dict[str, Any], header: dict[str, Any]) -> bytes:
    view = {"body": body, "header": {key: header.get(key) for key in HEADER_KEYS}}
    return DOMAIN_PREFIX + canonical_json(view)


def sign(body: dict[str, Any], key: Any, *, algorithm: str, **header: Any) -> dict[str, Any]:
    """*body* with a ``signature`` block over its canonical bytes."""
    block = sign_block(
        lambda h: _message(body, h),
        key,
        algorithm=algorithm,
        scheme=SCHEME_V3,
        subject="push manifest",
        **header,
    )
    return {**body, "signature": block}


def verify(manifest: dict[str, Any], **keys: Any) -> SignatureResult:
    body = {key: value for key, value in manifest.items() if key != "signature"}
    return verify_block(
        manifest.get("signature"),
        lambda h: _message(body, h),
        schemes=(SCHEME_V3,),
        subject="push manifest",
        **keys,
    )


def encode(manifest: dict[str, Any]) -> bytes:
    return canonical_json(manifest)


__all__ = ["DOMAIN_PREFIX", "encode", "outgoing", "sign", "tracking_ref", "verify"]
