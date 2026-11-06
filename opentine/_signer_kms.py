"""``kms:aws:ARN`` and ``kms:gcp:RESOURCE``: Ed25519 keys held by a cloud KMS.

:class:`KmsSigner` is the abstract backend: a subclass says how to fetch the
public key and how to ask for a pure Ed25519 signature (never a pre-hashed
Ed25519ph one, which no tine verifier accepts). Each takes an injectable
``client`` so tests run against a fake; without one it builds the SDK client
from the optional extra (``opentine[kms-aws]`` = boto3,
``opentine[kms-gcp]`` = google-cloud-kms).

* AWS KMS: key spec ``ECC_NIST_EDWARDS25519``, ``SigningAlgorithm
  ED25519_SHA_512``, ``MessageType RAW`` (a 4096-byte message limit).
* GCP Cloud KMS: algorithm ``EC_SIGN_ED25519``, a ``cryptoKeyVersions/N``
  resource, signed over ``data`` (a 64 KiB limit).
"""

from __future__ import annotations

from typing import Any

from opentine._signer import BaseSigner
from opentine._signing_keys import SignatureError


def _raw_public(der_or_pem: bytes) -> bytes:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        if der_or_pem.lstrip().startswith(b"-----BEGIN"):
            key = serialization.load_pem_public_key(der_or_pem)
        else:
            key = serialization.load_der_public_key(der_or_pem)
    except ValueError as exc:
        raise SignatureError("KMS returned an unreadable public key") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise SignatureError("the KMS key is not Ed25519")
    return key.public_bytes_raw()


class KmsSigner(BaseSigner):
    """Abstract KMS backend: ``_fetch_public`` and ``_kms_sign`` per provider."""

    provider = "abstract"
    max_message = 4096

    def __init__(self, key: str, client: Any = None) -> None:
        self.key = key
        self.client = client if client is not None else self._default_client()
        self.uri = f"kms:{self.provider}:{key}"
        self._public: bytes | None = None

    def _default_client(self) -> Any:  # pragma: no cover - needs a cloud SDK
        raise NotImplementedError

    def _fetch_public(self) -> bytes:  # pragma: no cover - abstract
        raise NotImplementedError

    def _kms_sign(self, message: bytes) -> bytes:  # pragma: no cover - abstract
        raise NotImplementedError

    @property
    def public_key(self) -> bytes:
        if self._public is None:
            self._public = _raw_public(self._fetch_public())
        return self._public

    def sign(self, message: bytes) -> bytes:
        if len(message) > self.max_message:
            raise SignatureError(
                f"kms:{self.provider} signs at most {self.max_message} bytes of raw message; "
                f"this one is {len(message)}"
            )
        try:
            return bytes(self._kms_sign(message))
        except SignatureError:
            raise
        except Exception as exc:  # noqa: BLE001 - SDK errors vary by provider
            raise SignatureError(f"kms:{self.provider}: {exc}") from exc


class AwsKmsSigner(KmsSigner):
    provider = "aws"

    def _default_client(self) -> Any:
        try:
            import boto3
        except ImportError as exc:
            raise SignatureError("kms:aws needs: pip install 'opentine[kms-aws]'") from exc
        region = self.key.split(":")[3] if self.key.startswith("arn:") else None
        return boto3.client("kms", region_name=region or None)

    def _fetch_public(self) -> bytes:
        reply = self.client.get_public_key(KeyId=self.key)
        spec = reply.get("KeySpec") or reply.get("CustomerMasterKeySpec")
        if spec and spec != "ECC_NIST_EDWARDS25519":
            raise SignatureError(f"kms:aws key spec is {spec}, not ECC_NIST_EDWARDS25519")
        return bytes(reply["PublicKey"])

    def _kms_sign(self, message: bytes) -> bytes:
        reply = self.client.sign(
            KeyId=self.key,
            Message=message,
            MessageType="RAW",
            SigningAlgorithm="ED25519_SHA_512",
        )
        return reply["Signature"]


class GcpKmsSigner(KmsSigner):
    provider = "gcp"
    max_message = 64 * 1024

    def _default_client(self) -> Any:
        try:
            from google.cloud import kms
        except ImportError as exc:
            raise SignatureError("kms:gcp needs: pip install 'opentine[kms-gcp]'") from exc
        return kms.KeyManagementServiceClient()

    def _fetch_public(self) -> bytes:
        reply = self.client.get_public_key(request={"name": self.key})
        algorithm = str(getattr(reply, "algorithm", "") or "")
        if algorithm and "ED25519" not in algorithm:
            raise SignatureError(f"kms:gcp key algorithm is {algorithm}, not EC_SIGN_ED25519")
        pem = reply.pem
        return pem.encode() if isinstance(pem, str) else bytes(pem)

    def _kms_sign(self, message: bytes) -> bytes:
        return self.client.asymmetric_sign(request={"name": self.key, "data": message}).signature


PROVIDERS = {"aws": AwsKmsSigner, "gcp": GcpKmsSigner}


def kms_signer(rest: str, client: Any = None) -> KmsSigner:
    """``aws:ARN`` or ``gcp:RESOURCE`` (the part after ``kms:``)."""
    provider, _, key = rest.partition(":")
    if provider not in PROVIDERS or not key:
        raise SignatureError("a KMS signer is kms:aws:ARN or kms:gcp:RESOURCE")
    return PROVIDERS[provider](key, client=client)


__all__ = ["PROVIDERS", "AwsKmsSigner", "GcpKmsSigner", "KmsSigner", "kms_signer"]
