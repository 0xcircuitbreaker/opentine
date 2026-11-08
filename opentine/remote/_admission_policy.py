"""Named server-side trust policies for VSA admission (``tine serve --trust-policy``).

``--trust-policy NAME=FILE`` (repeatable) loads an ``opentine.admission-policy``
version 1 document, published as ``docs/schemas/opentine-admission-policy-1``::

    {"kind": "opentine.admission-policy", "version": 1,
     "refs": ["heads/*", "tags/*"],          # fnmatch globs, required
     "tenants": ["acme"],                    # optional: any tenant when absent
     "roles": ["writer"],                    # optional: the pusher holds one of these
     "subjects": ["ci@acme"],                # optional: the pusher is one of these
     "object_types": ["run", "annotation"],  # optional: what the ref may point at
     "levels": ["OPENTINE_ADMITTED"]}        # verifiedLevels the VSA records

Policies are tried in the order given; the first whose ``tenants`` and ``refs``
cover a ref update decides it. When none covers it the push is refused (403),
so naming any policy turns admission fail-closed. Every admitted ref update's
VSA names the deciding policy as ``opentine:trust-policy/NAME`` with the
sha256 of the policy file's bytes, so a reader can tell which rules admitted it.
Uploads are not ref updates: they pass, nothing is admitted until a ref moves.
The policy is operator configuration: a pushed repository can never select one.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from opentine.remote.interfaces import Identity

KIND = "opentine.admission-policy"
NAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
LISTS = ("refs", "tenants", "roles", "subjects", "object_types", "levels")
MAX_BYTES = 64 * 1024
MAX_ITEMS = 256


@dataclass(frozen=True)
class AdmissionPolicy:
    name: str
    digest: str
    rules: dict[str, tuple[str, ...]]

    def covers(self, tenant: str, ref: str) -> bool:
        tenants = self.rules.get("tenants")
        if tenants is not None and tenant not in tenants:
            return False
        return any(fnmatch.fnmatchcase(ref, pattern) for pattern in self.rules["refs"])

    def refusal(self, identity: Identity, facts: dict[str, Any]) -> str | None:
        roles, subjects = self.rules.get("roles"), self.rules.get("subjects")
        if roles is not None and not set(roles) & set(identity.roles):
            return "pusher holds none of the policy's roles"
        if subjects is not None and identity.subject not in subjects:
            return "pusher is not one of the policy's subjects"
        types = self.rules.get("object_types")
        if types is not None and str(facts.get("object_type")) not in types:
            return "ref target's object type is not allowed"
        return None

    def descriptor(self) -> dict[str, Any]:
        return {"uri": f"opentine:trust-policy/{self.name}", "digest": {"sha256": self.digest}}


def parse_policy(name: str, raw: bytes) -> AdmissionPolicy:
    if not NAME.fullmatch(name):
        raise ValueError(f"invalid trust policy name {name!r}: use [a-z0-9][a-z0-9._-]*")
    if len(raw) > MAX_BYTES:
        raise ValueError(f"trust policy {name!r} exceeds {MAX_BYTES} bytes")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise ValueError(f"trust policy {name!r} is not JSON: {exc}") from exc
    if not isinstance(value, dict) or value.get("kind") != KIND or value.get("version") != 1:
        raise ValueError(f"trust policy {name!r} is not an {KIND} version 1 document")
    unknown = set(value) - {"kind", "version", *LISTS}
    if unknown:
        raise ValueError(f"trust policy {name!r} has unknown fields: {sorted(unknown)}")
    rules: dict[str, tuple[str, ...]] = {}
    for field in LISTS:
        if field not in value:
            continue
        items = value[field]
        if (
            not isinstance(items, list)
            or not items
            or len(items) > MAX_ITEMS
            or not all(isinstance(item, str) and 0 < len(item) <= 256 for item in items)
        ):
            raise ValueError(f"trust policy {name!r}: {field} must be a non-empty string list")
        rules[field] = tuple(items)
    if "refs" not in rules:
        raise ValueError(f"trust policy {name!r} names no refs")
    rules.setdefault("levels", ("OPENTINE_ADMITTED",))
    return AdmissionPolicy(name, hashlib.sha256(raw).hexdigest(), rules)


def load_policies(specs: list[str]) -> list[AdmissionPolicy]:
    """``["NAME=FILE", ...]`` -> policies in the order given; names are unique."""
    policies: list[AdmissionPolicy] = []
    for spec in specs:
        name, sep, file = spec.partition("=")
        if not sep or not file:
            raise ValueError(f"--trust-policy expects NAME=FILE, got {spec!r}")
        if any(policy.name == name for policy in policies):
            raise ValueError(f"trust policy {name!r} is given twice")
        policies.append(parse_policy(name, Path(file).read_bytes()))
    return policies


class PolicyCheck:
    """A ``TrustPolicyAdmission`` check: ``(levels, policy descriptor)`` or 403."""

    def __init__(self, policies: list[AdmissionPolicy]):
        if not policies:
            raise ValueError("at least one trust policy is required")
        self.policies = tuple(policies)

    def __call__(
        self, identity: Identity, operation: str, facts: dict[str, Any]
    ) -> tuple[list[str], dict[str, Any]] | list[str]:
        if operation != "update_ref":
            return []
        tenant = str(facts.get("tenant") or identity.tenant)
        ref = str(facts.get("name", ""))
        for policy in self.policies:
            if policy.covers(tenant, ref):
                why = policy.refusal(identity, facts)
                if why:
                    raise PermissionError(f"trust policy {policy.name} refused the push: {why}")
                return list(policy.rules["levels"]), policy.descriptor()
        raise PermissionError("no trust policy admits this ref")
