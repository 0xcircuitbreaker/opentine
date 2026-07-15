"""Sign a pricing snapshot without ever placing the private key in the repository."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine._canon import _canonical_bytes, atomic_write_text


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("catalog", type=Path)
    parser.add_argument("--key", required=True, type=Path, help="Ed25519 private PEM outside git")
    parser.add_argument("--key-id", required=True)
    args = parser.parse_args()

    raw = args.catalog.read_text(encoding="utf-8")
    data = json.loads(raw)
    body = {key: value for key, value in data.items() if key not in {"catalog_id", "signature"}}
    digest = hashlib.sha256(_canonical_bytes(body)).hexdigest()
    private = serialization.load_pem_private_key(args.key.read_bytes(), password=None)
    if not isinstance(private, Ed25519PrivateKey):
        raise TypeError("catalog signing key is not Ed25519")
    signature = base64.b64encode(private.sign(_canonical_bytes(body))).decode("ascii")
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )

    raw, id_count = re.subn(
        r'(?m)^  "catalog_id": "[^"]+",$',
        f'  "catalog_id": "sha256:{digest}",',
        raw,
    )
    raw, key_count = re.subn(
        r'(?m)^    "key_id": "[^"]+",$',
        f'    "key_id": "{args.key_id}",',
        raw,
    )
    raw, signature_count = re.subn(
        r'(?m)^    "value": "[^"]+"$',
        f'    "value": "{signature}"',
        raw,
    )
    if (id_count, key_count, signature_count) != (1, 1, 1):
        raise ValueError("catalog signature fields were not unique")
    atomic_write_text(args.catalog, raw, fsync=True)
    print(f"catalog_id=sha256:{digest}")
    print(f"key_id={args.key_id}")
    print(f"public_key={base64.b64encode(public).decode('ascii')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
