"""The oversight policy (0.64): ``.tine/oversight.toml``, pinned by a signature.

The policy names risk tiers, each a k-of-n set of approver keys, and routes
that send items into tiers::

    version = 1
    [tiers.high]
    k = 2
    approvers = ["sha256:<fingerprint>", "sha256:<fingerprint>", "sha256:<fingerprint>"]
    [humans]                     # optional: keys one person holds count once
    alice = ["sha256:<a1>", "sha256:<a2>"]
    [[route]]
    source = "promotion"         # promotion | integrity | monitor | eval | budget | containment
                                 # | organism (0.72: untagging a model organism)
                                 # | transcript (0.74: behaviour flags, runs like them)
                                 # | ingest (0.77: stream gaps, policy violations)
    label = "prod*"              # promotion, eval, transcript: a label glob (default *)
    tier = "high"
    [[route]]
    source = "eval"
    metric = "pass_rate"         # pass_rate | mean_score of the candidate's evals
    above = 0.9                  # and/or below = ...
    tier = "high"
    [[route]]
    source = "monitor"
    actions = ["flag", "defer", "block"]
    tier = "high"

The file counts only when ``.tine/oversight.sig.json`` (an attestation-shaped
document, claim ``opentine.oversight-policy/1`` with the file's sha256) is
signed by a ``policy``-role key of the owner-pinned trust bundle
(:mod:`opentine._key_roles_pin`) that is not an ``optimizer`` key. Otherwise
the policy is ``unpinned`` and grants nothing: every routed item stays short of
its approvals. A tier's approvers count only while they also hold the pinned
``approver`` role and none of the ``optimizer``, ``monitor`` or ``scorer``
roles (key separation).
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import tomllib
from pathlib import Path
from typing import Any

FILE_NAME = "oversight.toml"
PIN_NAME = "oversight.sig.json"
POLICY = "opentine.oversight-policy/1"
SOURCES = ("promotion", "integrity", "monitor", "eval", "budget", "containment", "organism",
           "custody", "transcript", "ingest")  # fmt: skip
EVAL_METRICS = ("pass_rate", "mean_score")
BANNED_ROLES = ("optimizer", "monitor", "scorer")
MONITOR_ACTIONS = ("flag", "defer", "block")
_ROUTE_KEYS = {"source", "tier", "label", "metric", "above", "below", "actions"}


class OversightError(ValueError):
    """An oversight policy that cannot be used."""


def _keys(value: Any, where: str) -> list[str]:
    from opentine._key_roles import KeyRoleError, normalize_key

    if not isinstance(value, list) or not value:
        raise OversightError(f"{where} lists key fingerprints (at least one)")
    try:
        return sorted({normalize_key(v) for v in value})
    except KeyRoleError as exc:
        raise OversightError(f"{where}: {exc}") from exc


def _number(value: Any, where: str) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise OversightError(f"{where} must be a number")
    return float(value)


def _route(row: Any, tiers: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(row, dict) or set(row) - _ROUTE_KEYS:
        raise OversightError(f"a route is a table of {', '.join(sorted(_ROUTE_KEYS))}")
    if row.get("source") not in SOURCES or row.get("tier") not in tiers:
        raise OversightError("a route names a source (promotion, integrity, monitor, eval, "
                             "budget, containment, organism, custody, transcript, ingest) and a "
                             "declared tier")  # fmt: skip
    out = {"source": row["source"], "tier": row["tier"], "label": str(row.get("label", "*"))}
    if row["source"] == "eval":
        if row.get("metric") not in EVAL_METRICS:
            raise OversightError(f"an eval route's metric is one of {', '.join(EVAL_METRICS)}")
        if "above" not in row and "below" not in row:
            raise OversightError("an eval route needs a threshold: above and/or below")
        out["metric"] = row["metric"]
        for side in ("above", "below"):
            if side in row:
                out[side] = _number(row[side], f"route {side}")
    if row["source"] == "monitor":
        actions = row.get("actions", list(MONITOR_ACTIONS))
        if not isinstance(actions, list) or set(actions) - set(MONITOR_ACTIONS) or not actions:
            raise OversightError(f"monitor route actions are some of {', '.join(MONITOR_ACTIONS)}")
        out["actions"] = sorted(actions)
    return out


def parse(data: bytes) -> dict[str, Any]:
    """The checked policy: ``{"tiers", "humans", "routes", "sha256"}``."""
    try:
        document = tomllib.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise OversightError(f"{FILE_NAME}: {exc}") from exc
    if document.get("version") != 1 or set(document) - {"version", "tiers", "humans", "route"}:
        raise OversightError("the oversight policy is version = 1 with tiers, humans and route")
    tiers: dict[str, Any] = {}
    for name, tier in (document.get("tiers") or {}).items():
        if not isinstance(tier, dict) or set(tier) != {"k", "approvers"}:
            raise OversightError(f"tier {name} is a table of k and approvers")
        approvers = _keys(tier["approvers"], f"tier {name} approvers")
        k = tier["k"]
        if isinstance(k, bool) or not isinstance(k, int) or not 1 <= k <= len(approvers):
            raise OversightError(f"tier {name}: k must be between 1 and its {len(approvers)} keys")
        tiers[name] = {"k": k, "approvers": approvers}
    if not tiers:
        raise OversightError("the oversight policy declares at least one tier")
    humans: dict[str, str] = {}
    for person, keys in (document.get("humans") or {}).items():
        for fpr in _keys(keys, f"humans.{person}"):
            if humans.setdefault(fpr, person) != person:
                raise OversightError(f"{fpr} is listed for two humans")
    routes = [_route(row, tiers) for row in document.get("route") or []]
    return {"tiers": tiers, "humans": humans, "routes": routes,
            "sha256": hashlib.sha256(data).hexdigest()}  # fmt: skip


def sign(key: Any, data: bytes, at: str) -> dict[str, Any]:
    """The ``opentine.oversight-policy/1`` document over the policy bytes."""
    from opentine._signing_pins import key_fingerprint
    from opentine.attest_signing import sign_attestation

    digest = hashlib.sha256(data).hexdigest()
    payload = {"claim": {"schema": POLICY, "policy_sha256": digest}, "evidence_ids": [],
               "signer": key_fingerprint(key.public_key().public_bytes_raw()),
               "target_id": f"sha256:{digest}"}  # fmt: skip
    return {**payload, "signature": sign_attestation(payload, key, algorithm="ed25519",
                                                      signed_at=at)}  # fmt: skip


def roles(store: Path | None) -> tuple[dict[str, list[str]], str]:
    """``(roles, status)``: the key roles (any status: unpinned roles still refuse)."""
    from opentine._key_roles import KeyRoleError
    from opentine._key_roles_pin import resolve

    try:
        found = resolve(store)
    except KeyRoleError as exc:
        raise OversightError(f"key-role policy: {exc}") from exc
    return found["roles"] or {}, found["status"]


def banned(held: dict[str, list[str]]) -> set[str]:
    """Keys that may never approve: optimizer, monitor and scorer keys."""
    return {k for role in BANNED_ROLES for k in held.get(role, [])}


def load(store: Path | None) -> dict[str, Any]:
    """``{"status": pinned|unpinned|absent, "policy", "why", "roles", "role_status"}``."""
    from opentine import _oversight_floor as _floor
    from opentine._promote_pins import _who

    out: dict[str, Any] = {"status": "absent", "policy": None, "why": "", "roles": {},
                           "role_status": "absent", "floors": False}  # fmt: skip
    if store is None:
        return out
    try:
        data = (Path(store) / FILE_NAME).read_bytes()
    except FileNotFoundError:
        return out
    out["policy"] = parse(data)
    out["roles"], out["role_status"] = roles(Path(store))
    floors = _floor.pinned_tiers(Path(store))
    out["floors"] = floors is not None
    lacks = _floor.apply(out["policy"], floors) if floors else ""
    try:
        doc = json.loads((Path(store) / PIN_NAME).read_bytes())
    except (OSError, ValueError):
        doc = None
    claim = doc.get("claim") if isinstance(doc, dict) else None
    who = _who(doc) if isinstance(claim, dict) and claim.get("schema") == POLICY else None
    allowed = set(out["roles"].get("policy", [])) - set(out["roles"].get("optimizer", []))
    if lacks:
        why = lacks
    elif out["role_status"] != "pinned":
        why = "key roles are unpinned (no owner-signed trust bundle), so no policy key counts"
    elif who is None or claim.get("policy_sha256") != out["policy"]["sha256"]:
        why = f"no signed {POLICY} document in .tine/{PIN_NAME} covers these bytes"
    elif who not in allowed:
        why = f"the policy is signed by {who}, not a pinned policy-role (non-optimizer) key"
    else:
        return {**out, "status": "pinned"}
    return {**out, "status": "unpinned", "why": why}


def route(policy: dict[str, Any], item: dict[str, Any]) -> list[str]:
    """The tiers an item is routed into (sorted; empty: not routed)."""
    hit = set()
    for row in policy["routes"]:
        if row["source"] != item["source"] and not (
                row["source"] == "eval" and item["source"] == "promotion"):  # fmt: skip
            continue
        if item.get("label") is not None and not fnmatch.fnmatchcase(item["label"], row["label"]):
            continue
        if row["source"] == "monitor" and item.get("action") not in row["actions"]:
            continue
        if row["source"] == "eval":
            value = (item.get("metrics") or {}).get(row["metric"])
            if value is None or not (("above" in row and value > row["above"])
                                     or ("below" in row and value < row["below"])):  # fmt: skip
                continue
        hit.add(row["tier"])
    return sorted(hit)


def eval_metrics(folder: Path | None) -> dict[str, float]:
    """``pass_rate`` and ``mean_score`` of a verified eval folder (empty otherwise)."""
    from opentine._eval_run import verify_eval

    if folder is None:
        return {}
    try:
        checked = verify_eval(Path(folder))
    except (OSError, ValueError, KeyError):
        return {}
    if not checked.get("ok") or not checked.get("items"):
        return {}
    out = {"pass_rate": checked["passed"] / checked["items"]}
    if isinstance(checked.get("mean_score"), int | float):
        out["mean_score"] = float(checked["mean_score"])
    return out


__all__ = ["BANNED_ROLES", "FILE_NAME", "PIN_NAME", "POLICY", "SOURCES", "OversightError",
           "banned", "eval_metrics", "load", "parse", "roles", "route", "sign"]  # fmt: skip
