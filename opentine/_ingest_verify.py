"""``tine ingest verify``: check an ingest stream's chain, counts and policy (0.77).

Walks the stream from its held head back to the first batch and reports
findings. ``fail:`` findings (exit 1) are facts: a batch that is unsigned or
unreadable, a broken chain (``seq``, ``previous`` or index range), counts that
do not add up, events that disagree with their counts or with the signed
sampling policy, and a policy that is unsigned, unpinned, not held, signed by
an optimizer key or by a key without the pinned ``policy`` role. Roles are
read from the owner-pinned trust bundle only, so the check fails closed when
none is pinned. ``advisory:`` findings never block unless ``--strict``.
"""

from __future__ import annotations

from typing import Any

from opentine import _ingest_holds, _ingest_policy
from opentine._ingest_batch import CONVENTION
from opentine._ingest_policy import IngestError

_CLAIM_INTS = ("seq", "first_index", "next_index", "received", "captured", "dropped")


def _finding(level: str, code: str, batch: str | None, message: str) -> dict[str, Any]:
    return {"level": level, "code": code, "batch": batch, "message": message}


def _lines(text: Any) -> list[dict[str, Any]] | None:
    from opentine import _json_shallow

    if not isinstance(text, str):
        return None
    try:
        rows = [_json_shallow.loads(line) for line in text.split("\n") if line]
    except (ValueError, RecursionError):
        return None
    return rows if all(isinstance(r, dict) for r in rows) else None


def _check_policy(repo: Any, oid: Any, stream: str, roles: dict[str, Any], held: set[str],
                  memo: dict[str, Any]) -> tuple[dict[str, Any] | None, list]:  # fmt: skip
    if oid in memo:
        return memo[oid]
    out: list[dict[str, Any]] = []
    row = _ingest_holds.read(repo, oid, _ingest_policy.CONVENTION) if isinstance(oid, str) else None
    policy = None
    if row is None:
        out.append(_finding("fail", "ingest.policy-missing", None, f"policy {oid} is unreadable"))
    else:
        try:
            policy = _ingest_policy.claim(row["claim"])
        except IngestError as exc:
            out.append(_finding("fail", "ingest.policy-malformed", None, str(exc)))
        code = _ingest_policy.judge(row["signer"], roles)
        if code:
            out.append(_finding("fail", code, None, f"policy {oid} may not take effect"))
        if oid not in held:
            out.append(_finding("fail", "ingest.policy-not-held", None, f"{oid} is not held"))
        if row["target"] != _ingest_policy.anchor_id(stream) or (
            policy is not None and policy["stream"] != stream
        ):
            out.append(_finding("fail", "ingest.policy-stream", None, f"{oid} is for another "
                                "stream"))  # fmt: skip
    memo[oid] = (policy, out)
    return memo[oid]


def _check_batch(anchor: str, row: dict[str, Any], prior: dict[str, Any] | None,
                 policy: dict[str, Any] | None) -> list[dict[str, Any]]:  # fmt: skip
    oid, claim = row["id"], row["claim"]
    bad = []
    if not row["signed"]:
        bad.append(("ingest.batch-unsigned", "the batch signature does not verify"))
    if any(isinstance(claim.get(k), bool) or not isinstance(claim.get(k), int)
           for k in _CLAIM_INTS):  # fmt: skip
        return [_finding("fail", "ingest.batch-malformed", oid, "a count is not an integer")]
    want_seq = prior["claim"]["seq"] + 1 if prior else 0
    want_first = prior["claim"]["next_index"] if prior else 0
    if claim["seq"] != want_seq or claim["first_index"] != want_first:
        bad.append(("ingest.chain-order", f"seq {claim['seq']} / first index "
                    f"{claim['first_index']}, expected {want_seq} / {want_first}"))  # fmt: skip
    if row["previous"] != claim.get("previous") or row["target"] != anchor:
        bad.append(("ingest.batch-links", "previous_id or target disagrees with the claim"))
    by = claim.get("dropped_by")
    by_sum = sum(v for v in by.values() if isinstance(v, int)) if isinstance(by, dict) else -1
    counts_ok = (claim["captured"] + claim["dropped"] == claim["received"]
                 and claim["next_index"] - claim["first_index"] == claim["received"]
                 and by_sum == claim["dropped"])  # fmt: skip
    if not counts_ok:
        bad.append(("ingest.counts", "captured + dropped, the index range or dropped_by "
                    "do not add up"))  # fmt: skip
    if policy is not None and claim.get("policy_digest") != _ingest_policy.digest(policy):
        bad.append(("ingest.policy-digest", "the batch names another policy digest"))
    events = _lines(claim.get("events"))
    if events is None:
        bad.append(("ingest.events-malformed", "events is not JSON Lines of objects"))
    else:
        indexes = [e.get("i") for e in events]
        if len(events) != claim["captured"]:
            bad.append(("ingest.counts", f"{len(events)} events stored, {claim['captured']} "
                        "claimed"))  # fmt: skip
        if indexes != sorted(set(indexes)) or any(
            isinstance(i, bool) or not isinstance(i, int)
            or not claim["first_index"] <= i < claim["next_index"] for i in indexes):  # fmt: skip
            bad.append(("ingest.events-order", "event indexes are not increasing in range"))
        elif policy is not None and any(
            not isinstance(e.get("k"), str) or _ingest_policy.decide(policy, e["i"], e["k"])
            for e in events):  # fmt: skip
            bad.append(("ingest.sampling", "a stored event is one the policy drops"))
    return [_finding("fail", code, oid, message) for code, message in bad]


def verify(repo: Any, stream: str) -> dict[str, Any]:
    from opentine._key_roles_pin import resolve

    _ingest_policy.stream_name(stream)
    roles = resolve(repo.path)
    findings: list[dict[str, Any]] = []
    head = _ingest_holds.head(repo, stream)
    held = set(_ingest_holds.policies(repo, stream))
    ids: list[str] = []  # ids only: a long stream never sits in memory whole
    cursor, seen = head, set()
    while cursor is not None:
        if cursor in seen:
            findings.append(_finding("fail", "ingest.chain-cycle", cursor, "the chain loops"))
            break
        seen.add(cursor)
        row = _ingest_holds.read(repo, cursor, CONVENTION)
        if row is None or row["claim"].get("stream") != stream:
            findings.append(_finding("fail", "ingest.batch-missing", cursor,
                                     "a batch in the chain is missing or unreadable"))  # fmt: skip
            break
        ids.append(cursor)
        cursor = row["claim"].get("previous")
    memo: dict[str, Any] = {}
    anchor = _ingest_policy.anchor_id(stream)
    digests: dict[str, str] = {}
    total = dict.fromkeys(("received", "captured", "dropped"), 0)
    prior = None
    for oid in reversed(ids):
        row = _ingest_holds.read(repo, oid, CONVENTION)
        if row is None:  # read once already on the walk back: gone since
            findings.append(_finding("fail", "ingest.batch-missing", oid, "a batch vanished"))
            break
        policy, policy_findings = _check_policy(repo, row["claim"].get("policy"), stream, roles,
                                                held, memo)  # fmt: skip
        findings.extend({**f, "batch": oid} for f in policy_findings)
        found = _check_batch(anchor, row, prior, policy)
        findings.extend(found)
        sha = row["claim"].get("input_sha256")
        if isinstance(sha, str) and sha in digests and row["claim"].get("received"):
            findings.append(_finding("advisory", "ingest.duplicate-input", oid,
                                     f"same input bytes as {digests[sha]}"))  # fmt: skip
        digests.setdefault(str(sha), oid)
        for name in total:
            value = row["claim"].get(name)
            total[name] += value if type(value) is int else 0
        claim = row["claim"]
        malformed = any(f["code"] == "ingest.batch-malformed" for f in found)
        prior = None if malformed else {"claim": {k: claim.get(k) for k in ("seq", "next_index")}}
    if not held:
        findings.append(_finding("fail", "ingest.policy-missing", None, "no held policy"))
    fails = [f for f in findings if f["level"] == "fail"]
    return {"stream": stream, "head": head, "batches": len(ids), **total,
            "policies": sorted(held), "roles": roles.get("status") or "absent",
            "ok": not fails, "findings": findings}  # fmt: skip


__all__ = ["verify"]
