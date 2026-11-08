"""JSON Schemas for the 0.46 CI integrations and server trust policies.

``opentine-admission-policy-1`` is a ``tine serve --trust-policy`` file (SPEC
8.14); ``tine-ci-gate-1`` is the summary ``python -m opentine._ci_gate`` (and
so ``actions/gate`` and the GitLab component) writes.
"""

from __future__ import annotations

from typing import Any

from opentine._schema_defs import BOOL, STR, closed, doc

_LIST: dict[str, Any] = {"type": "array", "minItems": 1, "maxItems": 256,
                         "items": {"type": "string", "minLength": 1, "maxLength": 256}}  # fmt: skip

SCHEMAS: dict[str, dict[str, Any]] = {
    "opentine-admission-policy-1": doc(
        "opentine-admission-policy-1",
        "opentine.admission-policy (version 1)",
        "A named server-side trust policy for `tine serve --trust-policy NAME=FILE` (SPEC "
        "8.14). `refs` are fnmatch globs; the optional lists narrow tenants, pusher roles "
        "(any one) and subjects, and the ref target's object type; `levels` are the VSA's "
        "verifiedLevels (default OPENTINE_ADMITTED). First covering policy decides.",
        closed(
            ["kind", "version", "refs"],
            {
                "kind": {"const": "opentine.admission-policy"},
                "version": {"const": 1},
                "refs": _LIST,
                "tenants": _LIST,
                "roles": _LIST,
                "subjects": _LIST,
                "object_types": _LIST,
                "levels": _LIST,
            },
        ),
    ),
    "tine-ci-gate-1": doc(
        "tine-ci-gate-1",
        "tine-ci-gate/1",
        "The CI gate's summary: one row per `tine verify`, `tine eval verify` output and "
        "admission VSA checked; `ok` only when there was at least one check and all passed. "
        "Rows carry fixed classes and sanitized names, never tool output or secrets.",
        closed(
            ["schema", "ok", "checks"],
            {
                "schema": {"const": "tine-ci-gate/1"},
                "ok": BOOL,
                "checks": {
                    "type": "array",
                    "items": closed(
                        ["check", "name", "ok", "class"],
                        {
                            "check": {"enum": ["verify", "eval", "vsa"]},
                            "name": STR,
                            "ok": BOOL,
                            "class": {
                                "enum": [
                                    "passed",
                                    "failed",
                                    "error",
                                    "unreadable",
                                    "malformed",
                                    "valid",
                                    "bad-signature",
                                    "wrong-subject",
                                    "wrong-policy",
                                    "missing-level",
                                ]
                            },
                            "detail": STR,
                        },
                    ),
                },
            },
        ),
    ),
}

KIND_SCHEMAS: dict[str, str] = {"opentine.admission-policy": "opentine-admission-policy-1"}

__all__ = ["KIND_SCHEMAS", "SCHEMAS"]
