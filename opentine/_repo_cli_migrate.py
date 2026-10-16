"""The key flags of ``tine migrate-v3``, checked the way ``tine verify`` checks them.

The verb had none, so a signed source always imported as ``no-key`` although
``--allow-unverified`` promised a signature check. ``--key-env`` / ``--key-file``
/ ``--pubkey`` / ``--trust-embedded-key`` now make the source's signature a
condition of the import (``migrate_v2``'s strict mode), and ``--pin`` restricts
a trust-on-first-use check to the pinned keys, as on ``verify``; the import is
then checked against the key that passed the pin.
"""

from __future__ import annotations

import argparse
from typing import Any

from opentine._cli_verify_report import read_once, signature_block
from opentine._repo_cli_keys import verification_keys, verification_pins
from opentine._signing_keys import SignatureError
from opentine._signing_pins import apply_pins, used_key_fingerprint
from opentine.core import Run


def migration_keys(args: argparse.Namespace) -> dict[str, Any]:
    """``migrate_v2``'s key arguments; a source failing ``--pin`` is refused here."""
    keys = verification_keys(args)
    pins = verification_pins(args)
    if pins and not args.allow_unverified:
        source = read_once(args.source)
        result = Run.verify_signature(source, **keys)
        block = signature_block(source)
        fingerprint = used_key_fingerprint(block, keys["public_key"])
        pinned = apply_pins(result, fingerprint, pins)
        if not pinned.ok:
            raise SignatureError(f"refusing to migrate: {pinned.reason} (state={pinned.state})")
        # ``migrate_v2`` reads the source again: hand it the key that passed the
        # pin, not "trust whatever key is embedded", so a file swapped in between
        # cannot be imported under someone else's signature.
        if keys["public_key"] is None and isinstance(block, dict):
            keys = {**keys, "public_key": block.get("public_key"), "trust_embedded": False}
    return keys


__all__ = ["migration_keys"]
