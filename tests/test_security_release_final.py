"""Adversarial regressions for the final v0.3.0 security sign-off."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from opentine._canon import _redact
from opentine.kernel import KernelError
from opentine.redaction import redact_blob
from opentine.remote.backend import SQLiteBackend
from opentine.remote.interfaces import AuditEvent, Identity
from opentine.remote.security import RoleAuthorizationPolicy
from opentine.remote.service import RemoteService
from opentine.repository._http import require_secure_remote
from opentine.repository.store import Repo


def test_local_repository_rejects_symlinked_internal_write_directory(tmp_path: Path):
    repo = Repo.init(tmp_path / "worktree")
    run_id = repo.put("run", {"events": [], "manifests": {}, "roots": [], "tips": []})
    outside = tmp_path / "outside"
    outside.mkdir()
    heads = repo.path / "refs" / "heads"
    heads.rmdir()
    try:
        heads.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are not available")

    with pytest.raises(KernelError, match="symlink"):
        repo.update_ref("heads/main", run_id)
    assert not (outside / "main").exists()


def test_audit_append_never_launders_an_interior_chain_deletion(tmp_path: Path):
    backend = SQLiteBackend(tmp_path / "audit.sqlite3", audit_key=b"a" * 32)
    for index in range(3):
        backend.append(AuditEvent(str(index), str(index), "acme", "alice", "fetch", "ok", {}))
    with sqlite3.connect(backend.path) as database:
        database.execute("DROP TRIGGER audit_no_delete")
        database.execute("DELETE FROM audit WHERE event_id='1'")

    # Appends authenticate the tail and external head in O(1); the explicit
    # full-chain check and startup remain the historical integrity backstops.
    backend.append(AuditEvent("next", "4", "acme", "alice", "fetch", "ok", {}))
    assert backend.verify_audit_chain() is False
    assert backend.audit_status() == "invalid"
    with pytest.raises(RuntimeError, match="audit chain verification failed"):
        SQLiteBackend(backend.path, audit_key=b"a" * 32)
    with sqlite3.connect(backend.path) as database:
        assert database.execute("SELECT count(*) FROM audit").fetchone()[0] == 3


def test_cross_tenant_denial_is_attributed_to_the_callers_tenant():
    class Sink:
        def __init__(self):
            self.events = []

        def append(self, event):
            self.events.append(event)

    sink = Sink()
    service = RemoteService(object(), object(), object(), RoleAuthorizationPolicy(), audit=sink)
    identity = Identity("mallory", "attacker", ("reader",))

    with pytest.raises(PermissionError):
        service._authorize(identity, "fetch", "victim")
    assert len(sink.events) == 1
    assert sink.events[0].tenant == "attacker"
    assert sink.events[0].details == {"requested_tenant": "victim"}


def test_camel_scoped_and_secret_key_credentials_are_redacted():
    raw = {
        name: "ordinary-secret-value"
        for name in (
            "openaiApiKey",
            "awsSecretAccessKey",
            "githubAccessToken",
            "azureClientSecret",
            "databasePassword",
        )
    }
    cleaned = json.loads(redact_blob(json.dumps(raw).encode()))
    assert set(cleaned.values()) == {"[REDACTED]"}
    assert set(_redact({"STRIPE_SECRET_KEY": "secret", "JWT_SECRET_KEY": "secret"}).values()) == {
        "[REDACTED]"
    }


def test_plaintext_remote_requires_a_literal_loopback_address():
    require_secure_remote("http://127.0.0.1:8787", allow_insecure=False)
    require_secure_remote("http://127.42.0.9:8787", allow_insecure=False)
    require_secure_remote("http://[::1]:8787", allow_insecure=False)
    with pytest.raises(ValueError, match="requires HTTPS"):
        require_secure_remote("http://localhost:8787", allow_insecure=False)
    with pytest.raises(ValueError, match="requires HTTPS"):
        require_secure_remote("http://127.0.0.1.example:8787", allow_insecure=False)
