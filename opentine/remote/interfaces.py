"""Enterprise extension seams for the minimal self-hosted remote."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass(frozen=True)
class Identity:
    subject: str
    tenant: str
    roles: tuple[str, ...] = ("reader",)
    claims: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        fields = {"subject": self.subject, "tenant": self.tenant}
        if not isinstance(self.roles, tuple):
            raise ValueError("identity roles must be a tuple of strings")
        if len(self.roles) > 64:
            raise ValueError("identity cannot contain more than 64 roles")
        fields.update({f"role[{index}]": role for index, role in enumerate(self.roles)})
        if any(not isinstance(value, str) or not value for value in fields.values()):
            raise ValueError("identity fields must be non-empty strings")
        try:
            encoded = {name: value.encode("utf-8") for name, value in fields.items()}
        except UnicodeEncodeError as exc:
            raise ValueError("identity fields must be valid UTF-8 text") from exc
        if len(encoded["subject"]) > 4_096 or len(encoded["tenant"]) > 128:
            raise ValueError("identity subject or tenant exceeds its size limit")
        if any(len(value) > 128 for name, value in encoded.items() if name.startswith("role[")):
            raise ValueError("identity role exceeds its size limit")


@dataclass(frozen=True)
class AuditEvent:
    event_id: str
    timestamp: str
    tenant: str
    actor: str
    action: str
    outcome: str
    details: dict[str, Any] = field(default_factory=dict)


class ObjectStore(Protocol):
    def has(self, tenant: str, oid: str) -> bool: ...
    def get(self, tenant: str, oid: str) -> bytes: ...
    def put(self, tenant: str, oid: str, data: bytes) -> None: ...
    def list(
        self, tenant: str, *, limit: int | None = None, truncate: bool = False
    ) -> list[str]: ...


class IndexBackend(Protocol):
    def record_object(
        self, tenant: str, oid: str, size: int, target_id: str | None = None
    ) -> None: ...
    def associated_objects(self, tenant: str, target_id: str, limit: int) -> list[str]: ...
    def list_refs(self, tenant: str) -> dict[str, str]: ...
    def read_ref(self, tenant: str, name: str) -> str | None: ...
    def update_ref(
        self, tenant: str, name: str, new_oid: str, expected_old: str | None
    ) -> bool: ...
    def search(self, tenant: str, query: dict[str, Any]) -> list[str]: ...


class IdentityProvider(Protocol):
    def authenticate(self, headers: dict[str, str]) -> Identity: ...


class AuthorizationPolicy(Protocol):
    def authorize(self, identity: Identity, action: str, tenant: str) -> bool: ...


class KeyProvider(Protocol):
    def encrypt(self, tenant: str, plaintext: bytes) -> bytes: ...
    def decrypt(self, tenant: str, ciphertext: bytes) -> bytes: ...


class AuditSink(Protocol):
    def append(self, event: AuditEvent) -> None: ...


class RetentionHook(Protocol):
    def retain_until(self, tenant: str, oid: str) -> str | None: ...
    def before_delete(self, tenant: str, oid: str) -> None: ...


class AdmissionPolicy(Protocol):
    def admit(self, identity: Identity, operation: str, facts: dict[str, Any]) -> None: ...
