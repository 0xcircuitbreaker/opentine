"""The credential field names and suffixes ``_canon_redact._redact`` recognizes.

Kept apart so the walk does not rebuild them on every call, and so the walk's
module stays within the line cap. Standard library only, like its importer.
"""

from __future__ import annotations

import re

CREDENTIAL_NAMES = frozenset(
    (
        "api_key apikey api_token access_key secret_access_key secret_key access_token "
        "refresh_token auth_token bearer_token id_token session_token password passwd "
        "passphrase secret client_secret private_key credential credentials authorization "
        "proxy_authorization cookie set_cookie jwt bearer x_amz_security_token "
        "ocp_apim_subscription_key pwd connection_string conn_str dsn webhook_url "
        "private_key_id key_data"
    ).split()
)

SECRET_SUFFIXES = (
    "_api_key",
    "_api_token",
    "_access_key",
    "_access_token",
    "_authorization",
    "_auth_token",
    "_bearer_token",
    "_client_secret",
    "_cookie",
    "_credential",
    "_credentials",
    "_id_token",
    "_passphrase",
    "_password",
    "_passwd",
    "_private_key",
    "_proxy_authorization",
    "_refresh_token",
    "_secret",
    "_session_token",
    "_secret_key",
    "_set_cookie",
    # A string under any *_token name is a token (GITHUB_TOKEN, hf_token,
    # PRIVATE-TOKEN, X-Vault-Token); numeric counters such as input_tokens
    # are exempt (``_canon_redact._token_counter``), as they always were.
    "_token",
    "_account_key",
    "_encryption_key",
    "_master_key",
    "_signing_key",
    "_ssh_key",
    "_subscription_key",
    "_connection_string",
    "_dsn",
    "_webhook_url",
    # ``MYSQL_PWD``, ``LDAP_BIND_PW``, ``AZURE_STORAGE_KEY``, a kubeconfig's
    # ``client-key-data`` (base64 of a PEM private key).
    "_pwd",
    "_pw",
    "_storage_key",
    "_key_data",
)

_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")
_COMPACT_SUFFIXES = tuple(suffix.replace("_", "") for suffix in SECRET_SUFFIXES)


def secret_name(raw: str) -> bool:
    """Whether a field named *raw* holds a credential, as the record walk decides.

    The text redactor's quoted-field rule (``"MYSQL_PWD": "…"``) asks this, so a
    name the walk redacts in a dict is redacted when the same object is text.
    Same normalization as ``_canon_redact._field_name`` (camelCase split, lowered,
    ``-`` read as ``_``) and the same names, suffixes and plural trim as
    ``_canon_redact._secret_field``.
    """
    name = _CAMEL_BOUNDARY.sub("_", raw.strip().strip("\"'")).lower().replace("-", "_")
    candidates = (name, name[:-1]) if name.endswith("s") else (name,)
    return any(
        item in CREDENTIAL_NAMES
        or item.endswith(SECRET_SUFFIXES)
        or item.replace("_", "").endswith(_COMPACT_SUFFIXES)
        for item in candidates
    )
