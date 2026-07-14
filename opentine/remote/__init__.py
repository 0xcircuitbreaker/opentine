"""Minimal self-hosted OpenTine v3 remote."""

from opentine.remote._oidc import JWTVerifier, OIDCError
from opentine.remote.app import RemoteApp
from opentine.remote.backend import FilesystemObjectStore, SQLiteBackend
from opentine.remote.interfaces import (
    AdmissionPolicy,
    AuditEvent,
    AuditSink,
    AuthorizationPolicy,
    Identity,
    IdentityProvider,
    IndexBackend,
    KeyProvider,
    ObjectStore,
    RetentionHook,
)
from opentine.remote.security import (
    KMSKeyProvider,
    LocalKeyProvider,
    OIDCIdentityProvider,
    RoleAuthorizationPolicy,
    StaticTokenIdentityProvider,
)
from opentine.remote.server import reference_app
from opentine.remote.service import RemoteService

__all__ = [
    "AdmissionPolicy",
    "AuditEvent",
    "AuditSink",
    "AuthorizationPolicy",
    "FilesystemObjectStore",
    "Identity",
    "IdentityProvider",
    "IndexBackend",
    "KeyProvider",
    "KMSKeyProvider",
    "JWTVerifier",
    "LocalKeyProvider",
    "ObjectStore",
    "OIDCIdentityProvider",
    "OIDCError",
    "RemoteApp",
    "RemoteService",
    "RetentionHook",
    "RoleAuthorizationPolicy",
    "SQLiteBackend",
    "StaticTokenIdentityProvider",
    "reference_app",
]
