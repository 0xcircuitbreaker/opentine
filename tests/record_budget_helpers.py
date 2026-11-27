"""Fixed Ed25519 keys for the 0.87 record-budget tests."""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine._signing_pins import key_fingerprint

SEEDS = {"runner": 21, "policy": 22, "optimizer": 23, "stranger": 24}


def key(name: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes([SEEDS[name]]) * 32)


def fpr(name: str) -> str:
    return key_fingerprint(key(name).public_key().public_bytes_raw())
