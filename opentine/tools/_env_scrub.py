"""The environment a tool subprocess inherits, scrubbed of credentials."""

from __future__ import annotations

import os
import re
from collections.abc import Iterable

from opentine._redact_shapes import QUERY_SECRET, TOKEN_SHAPES, URL_USERINFO

#: Environment names a tool subprocess never needs and must never be handed.
_SENSITIVE_PAT = re.compile(
    r"(KEY|SECRET|TOKEN|PASSWORD|PASSPHRASE|CREDENTIAL|AUTH|MNEMONIC|SEED_PHRASE|HEADERS)",
    re.IGNORECASE,
)
#: A header-shaped value under any name (``X-Api-Key=...``, ``Authorization=Bearer ...``):
#: SDK and OTLP header variables carry gateway credentials (final pass 2, #6).
_HEADER_VALUE = re.compile(
    rb"(?i)(?:^|[\s,;\"'{])(?:proxy-)?(?:authorization|x-api-key|api-key|cookie)\s*[:=]"
    rb"|\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}"
)
#: Credential spellings the substring list above missed (audit 0.9.1, D-4):
#: ``MYSQL_PWD``, ``PGPASS``, ``GH_PAT``, ``SENTRY_DSN``, ``*_WEBHOOK_URL``,
#: ``*_CONNECTION_STRING``, ``SIGNING_PRIVATE``, ``*_COOKIE``. ``PWD``/``OLDPWD``
#: themselves are directories, and ``PATH`` is not ``PAT``. Round 3 added the
#: unlock tokens that live only in the environment: ``BORG_PASSPHRASE``,
#: ``LDAP_BIND_PW``, Bitwarden's ``BW_SESSION``, 1Password's ``OP_SESSION_<acct>``.
_SENSITIVE_SUFFIX = re.compile(r"(?:PASS|PASSWD|_PWD|_PW|_PAT|_DSN|_SESSION)$", re.IGNORECASE)
_SENSITIVE_PART = re.compile(
    r"(?:^|_)(?:PRIVATE|WEBHOOK|COOKIE|CREDS|CONNECTION_STRING|CONN_STR|OP_SESSION)(?:_|$)"
    # ASP.NET Core's ``ConnectionStrings__<Name>`` and any ``*CONNECTIONSTRING*``.
    r"|CONNECTION_?STRINGS?",
    re.IGNORECASE,
)
#: A credential carried as a key=value pair rather than userinfo or a token shape:
#: ADO.NET/ODBC ``Server=db;User Id=sa;Password=x;``, JDBC ``...?user=a&password=b``.
_KEYED_SECRET = re.compile(
    rb"(?i)(?:^|[;?&\s])(?:password|passwd|pwd|pass|secret|token|api[_-]?key|access[_-]?key)"
    rb"\s*=\s*[^;&\s]"
)

#: A signed URL's credential parameter, with or without a leading ``?``/``&``: an
#: Azure SAS (``se=…&sp=…&sig=…``), S3 / GCS presigned URLs
#: (``X-Amz-Signature``, ``X-Amz-Credential``, ``X-Goog-Signature``,
#: ``X-Goog-Credential``) grant access on their own, under any variable name.
_SIGNED_URL = re.compile(
    rb"(?i)(?:^|[?&;\s])(?:sig|signature|x-amz-signature|x-amz-credential|"
    rb"x-amz-security-token|x-goog-signature|x-goog-credential|token|access_token|"
    rb"id_token)=[^&\s]{8,}"
)


def _sensitive(name: str, value: str) -> bool:
    if _SENSITIVE_PAT.search(name) or _SENSITIVE_SUFFIX.search(name):
        return True
    if _SENSITIVE_PART.search(name):
        return True
    # By value, whatever the name: ``DATABASE_URL=postgres://u:pw@db``, a proxy
    # with credentials, a vendor token or a private key under an innocent name.
    raw = value.encode("utf-8", "replace")
    return bool(
        TOKEN_SHAPES.search(raw)
        or URL_USERINFO.search(raw)
        or _HEADER_VALUE.search(raw)
        or _KEYED_SECRET.search(raw)
        or QUERY_SECRET.search(raw)
        or _SIGNED_URL.search(raw)
        or b"PRIVATE KEY-----" in raw
    )


def clean_env(inherit_env: bool, env_allowlist: Iterable[str]) -> dict[str, str]:
    """The environment a bounded subprocess may see, scrubbed on inheritance.

    One spelling for every tool that spawns a process. The shell tool used to
    hand ``dict(os.environ)`` over verbatim on ``inherit_env``, so an
    ANTHROPIC_API_KEY left the host and came straight back into model context
    through the command's own output, while the python tool scrubbed the same
    names — a divergence that only exists while the helper is written twice.
    """
    if inherit_env:
        return {key: value for key, value in os.environ.items() if not _sensitive(key, value)}
    return {name: os.environ[name] for name in env_allowlist if name in os.environ}
