"""The redaction ruleset as data: what ``tine redact rules --json`` prints (0.45.1).

The redactor is code (``opentine.redaction.STEPS``), not a rule file, so this
module is the published description of it: one row per step, in the order the
byte scan runs them, under the ruleset name a redaction report records
(``opentine-redaction/2``). The web reads it to show which rules a report ran.
``tests/test_0451_redaction_followups.py`` holds the row count to ``STEPS`` so a
step added without a row (or a row without a step) fails the suite.

``digest`` is the SHA-256 of the canonical JSON of ``{ruleset, rules}``; two
exports with the same digest describe the same scan.
"""

from __future__ import annotations

import hashlib
from typing import Any

from opentine._redact_obfuscated import REDACTION_RULESET
from opentine._redact_shapes import TOKEN_NEEDLES

SCHEMA = "tine-redaction-rules/1"
MARKER = "[REDACTED]"

#: (id, family, what the step removes), in ``redaction.STEPS`` order.
RULES: tuple[tuple[str, str, str], ...] = (
    ("pem-private-key", "private-key", "PEM private-key blocks, whole"),
    ("putty-private-key", "private-key", "PuTTY .ppk private-key files"),
    ("base64-private-key", "private-key", "base64-wrapped PEM private keys"),
    ("base64-text", "encoded", "secrets inside base64-wrapped text, re-scanned decoded"),
    ("quoted-secret-field", "field", "string values of JSON fields with a credential name"),
    ("named-header", "header", "values of credential headers given by name"),
    ("reversed-named-header", "header", "credential header values given before the name"),
    ("header-pair", "header", "credential header name/value pairs"),
    ("quoted-header-line", "header", "quoted credential header lines"),
    ("quoted-header", "header", "quoted credential header values"),
    ("quoted-token", "field", 'values of a quoted "token" key'),
    ("line-assignment", "assignment", "NAME=value lines whose NAME is a credential name"),
    ("header-line", "header", "Authorization-style header lines"),
    ("assignment", "assignment", "inline name: value / name=value credential assignments"),
    ("bearer", "header", "Bearer tokens"),
    ("cli-flag", "cli", "--password / --token style flag values"),
    ("disguised-token", "token", "URL-escaped, zero-width-split or fullwidth vendor tokens"),
    ("vendor-token", "token", "vendor token shapes (see token_prefixes)"),
    ("url-userinfo", "url", "user:password@ in URLs"),
    ("query-secret", "url", "credential query-string parameters"),
    ("inline-header", "header", "header values inside command lines"),
    ("prefixed-password", "cli", "MYSQL_PWD= / PGPASSWORD= style prefixes"),
    ("flag-password", "cli", "-p<password> style flags"),
    ("curl-user", "cli", "curl -u user:password"),
    ("mysql-password", "cli", "mysql client passwords"),
    ("redis-password", "cli", "redis-cli -a passwords"),
    ("docker-login", "cli", "docker login -p passwords"),
    ("netrc", "file", ".netrc password entries"),
    ("netrc-line", "file", "one-line .netrc machine/password entries"),
    ("docker-auth", "file", "docker config.json auth values"),
    ("xml-secret", "file", "XML elements with a credential name"),
    ("url-slash-password", "url", "passwords in scheme://user/password@ URLs"),
    ("entropy", "entropy", "high-entropy values under key-like names"),
)


def export() -> dict[str, Any]:
    """The ruleset document (without the CLI ``command`` key)."""
    from opentine.kernel import canonical_json

    rules = [
        {"order": index, "id": rule_id, "family": family, "description": text}
        for index, (rule_id, family, text) in enumerate(RULES)
    ]
    digest = hashlib.sha256(canonical_json({"ruleset": REDACTION_RULESET, "rules": rules}))
    return {
        "schema": SCHEMA,
        "ruleset": REDACTION_RULESET,
        "rules_version": 1,
        "digest": "sha256:" + digest.hexdigest(),
        "marker": MARKER,
        "rules": rules,
        "token_prefixes": sorted({needle.decode("ascii") for needle in TOKEN_NEEDLES}),
    }


__all__ = ["MARKER", "RULES", "SCHEMA", "export"]
