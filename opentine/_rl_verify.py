"""``tine ingest segments STREAM``: check sealed segments and their audits (0.84).

Walks the stream's segments from the held segment head and re-derives every
fact a segment or audit claims. ``fail:`` findings (exit 1): a segment that is
unsigned, sealed by a key without the pinned ``runner`` role or by an optimizer
key, out of order, not continuing the previous segment's batches, whose root
or counts do not match its batches, or whose op log seal commitment is
missing; an audit that is unsigned, not signed by a pinned ``auditor`` key, whose seed,
checkpoint, sample size or sample do not recompute, whose repository-source
counts do not recompute, or whose verdict is ``fail``. ``advisory:`` findings
(a segment without an audit, batches not sealed yet) block only with
``--strict``. Codes are ``tine ingest segments`` findings, not ``tine verify``
codes.
"""

from __future__ import annotations

from typing import Any

from opentine import _ingest_holds, _ingest_policy, _rl_audit, _rl_merkle, _rl_segment
from opentine._ingest_policy import IngestError
from opentine.repository import _oplog, _tlog_note
from opentine.repository._holds import INGEST_AUDIT
from opentine.repository._tlog import LogError

_RECOMPUTED = ("segment", "stream", "root", "episodes", "guarantee", "bound", "checkpoint",
               "seed", "positions", "checked")  # fmt: skip
_COUNTED = ("ok", "missing", "altered", "failures", "verdict")


def _finding(level: str, code: str, where: str | None, message: str) -> dict[str, Any]:
    return {"level": level, "code": code, "record": where, "message": message}


def _segment(repo: Any, oid: str, prior: dict[str, Any] | None, roles: dict[str, Any],
             stream: str, entries: list[bytes]) -> list[tuple[str, str]]:  # fmt: skip
    row = _rl_segment.read(repo, oid)
    claim, bad = row["claim"], []
    code = _ingest_policy.judge_writer(row["signer"], roles)
    if code:
        bad.append((code.replace("batch", "segment"), "the segment signer may not seal"))
    want_seq = prior["claim"]["seq"] + 1 if prior else 0
    want_prev = prior["id"] if prior else None
    if claim.get("seq") != want_seq or claim.get("previous") != want_prev or row[
        "previous"
    ] != want_prev or row["target"] != _ingest_policy.anchor_id(stream):  # fmt: skip
        bad.append(("ingest.segment-chain", f"seq {claim.get('seq')}, expected {want_seq}"))
    batches = claim.get("batches")
    stop = prior["claim"]["batches"][-1] if prior else None
    try:
        ok = (isinstance(batches, list) and batches and len(batches) <= _rl_segment.MAX_BATCHES
              and _rl_segment.batch_range(repo, stream, batches[-1], stop) == batches)  # fmt: skip
    except IngestError:
        ok = False
    if not ok:
        return [*bad, ("ingest.segment-batches", "the batches do not continue the chain")]
    found = _rl_segment.episodes(repo, stream, batches)
    root = "sha256:" + _rl_merkle.Tree(found["leaves"]).root().hex()
    if (found["problems"] or root != claim.get("root")
            or claim.get("episodes") != len(found["leaves"])
            or claim.get("first_index") != found["first_index"]
            or claim.get("next_index") != found["next_index"]):  # fmt: skip
        bad.append(("ingest.segment-root", "the root or counts do not match the batches"))
    if not _rl_segment.committed_in(entries, claim):
        bad.append(("ingest.segment-log", "the op log does not hold the seal commitment"))
    return bad


def _audit(repo: Any, oid: str, segment: str, roles: dict[str, Any]) -> list[tuple[str, str]]:
    row = _ingest_holds.read(repo, oid, _rl_audit.CONVENTION)
    if row is None:
        return [("ingest.audit-missing", f"{oid} is unreadable")]
    claim, bad = row["claim"], []
    code = _rl_audit.judge_auditor(row["signer"], roles)
    if code:
        bad.append((code, "the audit signer may not sign audits"))
    if row["target"] != segment or claim.get("segment") != segment:
        bad.append(("ingest.audit-target", "the audit names another segment"))
    guarantee = claim.get("guarantee") if isinstance(claim.get("guarantee"), dict) else {}
    checkpoint = claim.get("checkpoint") if isinstance(claim.get("checkpoint"), dict) else {}
    try:
        again = _rl_audit.evaluate(repo, segment, confidence=guarantee.get("confidence"),
                                   max_bad=guarantee.get("max_bad"),
                                   checkpoint=str(checkpoint.get("note")).encode())  # fmt: skip
    except (IngestError, ValueError, OSError) as exc:
        return [*bad, ("ingest.audit-recompute", f"the audit does not recompute: {exc}")]
    drift = [k for k in _RECOMPUTED if again[k] != claim.get(k)]
    if drift:
        bad.append(("ingest.audit-recompute", f"{', '.join(drift)} do not recompute"))
    source = claim.get("source") if isinstance(claim.get("source"), dict) else {}
    if source.get("kind") == "repository":
        if [again[k] for k in _COUNTED] != [claim.get(k) for k in _COUNTED]:
            bad.append(("ingest.audit-recompute", "the counts do not recompute"))
    elif source.get("kind") != "file" or claim.get("verdict") != (
        "pass" if claim.get("ok") == claim.get("checked") else "fail"
    ):  # fmt: skip
        bad.append(("ingest.audit-recompute", "the source or verdict is malformed"))
    if claim.get("verdict") != "pass":
        bad.append(("ingest.audit-failed", f"{claim.get('missing')} missing, "
                    f"{claim.get('altered')} altered of {claim.get('checked')}"))  # fmt: skip
    return bad


def verify(repo: Any, stream: str) -> dict[str, Any]:
    from opentine._key_roles_pin import resolve

    _ingest_policy.stream_name(stream)
    roles = resolve(repo.path)
    ids, broken = _rl_segment.chain(repo, stream)
    findings: list[dict[str, Any]] = []
    try:
        entries = _tlog_note.verify_log(_oplog.log_root(repo.path), _oplog.ORIGIN)
    except (OSError, LogError) as exc:
        entries = []
        findings.append(_finding("fail", "ingest.segment-log", None, f"op log: {exc}"))
    if broken is not None:
        findings.append(_finding("fail", "ingest.segment-missing", broken,
                                 "a segment in the chain is missing or loops"))  # fmt: skip
    rows, prior, episodes = [], None, 0
    for oid in ids:
        row = _rl_segment.read(repo, oid)
        found = _segment(repo, oid, prior, roles, stream, entries)
        audits = _ingest_holds.held(repo, INGEST_AUDIT + oid)
        for audit in audits:
            found.extend(_audit(repo, audit, oid, roles))
        if not audits:
            findings.append(_finding("advisory", "ingest.segment-unaudited", oid, "no audit"))
        findings.extend(_finding("fail", code, oid, message) for code, message in found)
        claim = row["claim"]
        episodes += claim["episodes"] if type(claim.get("episodes")) is int else 0
        rows.append({"id": oid, "seq": claim.get("seq"), "episodes": claim.get("episodes"),
                     "root": claim.get("root"), "audits": audits})  # fmt: skip
        prior = row
    last = prior["claim"]["batches"][-1] if prior and prior["claim"].get("batches") else None
    if _ingest_holds.head(repo, stream) not in (None, last):
        findings.append(_finding("advisory", "ingest.segment-pending", None,
                                 "batches after the last segment are not sealed yet"))  # fmt: skip
    fails = [f for f in findings if f["level"] == "fail"]
    return {"stream": stream, "segments": rows, "episodes": episodes,
            "roles": roles.get("status") or "absent", "ok": not fails,
            "findings": findings}  # fmt: skip


__all__ = ["verify"]
