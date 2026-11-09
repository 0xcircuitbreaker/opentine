"""0.50 "leave the hosted service": export a tenant, import it elsewhere, verify the same.

Everything a tenant holds on one ``tine serve`` -- runs and their refs,
attestations and annotations, tombstones of purged blobs, Reviews with their
signed gate decisions, the project manifest chain, share metadata and the
transparency log -- is exported with ``tine tenant export`` (formats frozen at
0.48 only), imported into a fresh ``tine serve`` and from there into a plain
local repository with ``tine tenant import``, and ``tine verify . --offline
--json`` prints the same bytes for both servers' copies. CI runs this file in
its own job on every push to main, so every release is cut from a tree where
it passed (ROADMAP 0.50).
"""

from __future__ import annotations

import json
import sys
import threading
from pathlib import Path
from wsgiref.simple_server import WSGIRequestHandler, make_server

import pytest

from opentine import _bundle, _review, _schemas, _tombstone, cli
from opentine.graph import Run, StepKind
from opentine.remote import Identity, LocalKeyProvider, StaticTokenIdentityProvider, server
from opentine.repository import Repo, _review_store, _tombstones
from opentine.repository import client as repository_client
from opentine.repository._purge import purge
from opentine.repository.pack import reachable

TOKEN = "tok-" + "w" * 28
SEED = "11" * 32
GATE_SEED = "22" * 32
SECRET = "the step text an erasure request removed"


class _Quiet(WSGIRequestHandler):
    def log_message(self, *args):  # keep test output clean
        pass


def _serve(root: Path):
    identities = StaticTokenIdentityProvider({TOKEN: Identity("w", "acme", ("admin",))})
    app = server.reference_app(root, identities=identities, keys=LocalKeyProvider(b"k" * 32))
    httpd = make_server("127.0.0.1", 0, app, handler_class=_Quiet)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, f"http://127.0.0.1:{httpd.server_port}", app


def _tine(monkeypatch, capsys, *argv: str) -> tuple[int, str]:
    capsys.readouterr()
    monkeypatch.setattr(sys, "argv", ["tine", *argv])
    code = 0
    try:
        cli.main()
    except SystemExit as exc:
        code = int(exc.code or 0) if not isinstance(exc.code, str) else 1
    return code, capsys.readouterr().out


def _json(monkeypatch, capsys, *argv: str) -> dict:
    code, out = _tine(monkeypatch, capsys, *argv)
    assert code == 0, out
    document = json.loads(out)
    assert _schemas.validate_output(document) == [], document
    return document


@pytest.fixture
def services(tmp_path, monkeypatch):
    for name in ("TINE_REMOTE_TOKEN", "TINE_WEB_URL"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    old, old_url, old_app = _serve(tmp_path / "old-srv")
    new, new_url, new_app = _serve(tmp_path / "new-srv")
    token = tmp_path / "token"
    token.write_text(TOKEN + "\n")
    token.chmod(0o600)
    flags = ("--tenant", "acme", "--token-file", str(token), "--allow-insecure")
    yield {"old": old_url, "new": new_url, "flags": flags, "new_app": new_app, "old_app": old_app}
    old.shutdown()
    new.shutdown()


def _source(tmp_path: Path) -> tuple[Repo, list[str], str]:
    repo = Repo.init(tmp_path / "work")
    runs = []
    for label, text in (("alpha", "first"), ("beta", SECRET)):
        run = Run(id=label, metadata={"label": label})
        run.add_step(StepKind.done, {"text": text})
        runs.append(repo.put_run(run, ref=f"heads/{label}").run_id)
    repo.attest(runs[0], {"reviewed": True}, signer="alice", key=b"a" * 32, key_id="k1")
    blob = next(oid for oid in reachable(repo, [runs[1]], include_associated=False)
                if oid.startswith("blob:") and SECRET.encode() in repo.get(oid).body)  # fmt: skip
    tomb = _tombstone.sign(_tombstone.build(blob, "erasure request", "alice"), b"t" * 32,
                           algorithm="hmac-sha256", key_id="t1")  # fmt: skip
    purge(repo, tomb)
    return repo, runs, blob


def _key(path: Path, seed: str) -> str:
    path.write_text(seed, encoding="utf-8")
    return path.as_posix()


def _seed_tenant(services, tmp_path, monkeypatch, capsys) -> tuple[list[str], str]:
    """Push two runs (one attested, one with a purged blob), a Review and a share link."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    repo, runs, blob = _source(tmp_path)
    for ref in ("heads/alpha", "heads/beta"):
        repository_client.push(repo, services["old"], tenant="acme", token=TOKEN, ref=ref,
                               remote_ref=ref, allow_insecure=True)  # fmt: skip
    gate = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(GATE_SEED))
    reviewer = gate.public_key().public_bytes_raw().hex()
    work = repo.path.parent.as_posix()
    author = ("--ed25519-key-file", _key(tmp_path / "author.key", SEED))
    approver = ("--ed25519-key-file", _key(tmp_path / "gate.key", GATE_SEED))
    remote = ("--remote", services["old"], *services["flags"])
    for argv in (
        ("create", "leave", "--title", "Leave", "--gate", "ship", "--reviewer", reviewer,
         *author),
        ("add", "leave", "--run", runs[0], "--finding", "low:portable", *author),
        ("gate", "leave", "ship", "--approve", *approver),
        ("push", "leave", *remote),
    ):  # fmt: skip
        _json(monkeypatch, capsys, "review", *argv, "--repo", work, "--json")
    _json(monkeypatch, capsys, "project", "init", "app", "--tenant", "acme", "--forge", "github",
          "--url", "https://github.com/acme/app", "--forge-repo-id", "R_1", *author,
          "--repo", work, "--json")  # fmt: skip
    _json(monkeypatch, capsys, "project", "push", *remote, "--repo", work, "--json")
    _json(monkeypatch, capsys, "share", "create", runs[0], "--ttl", "1h", *remote,
          "--repo", work, "--json")  # fmt: skip
    return runs, blob


def _export(monkeypatch, capsys, services, side: str, out: Path) -> dict:
    return _json(monkeypatch, capsys, "tenant", "export", "--remote", services[side],
                 *services["flags"], "--out", str(out), "--json")  # fmt: skip


def _verify(monkeypatch, capsys, repo: Path, runs: list[str], blob: str) -> str:
    """``tine verify . --offline --json`` in *repo*: fsck plus one report per ref'd run.

    The attested run passes; the run whose blob was purged cannot load that
    blob and fails the same way everywhere (the tombstone keeps its oid).
    """
    monkeypatch.chdir(repo)  # the same spelling of the path on every side
    code, out = _tine(monkeypatch, capsys, "verify", ".", "--offline", "--json")
    rows = {row["run_id"]: row for row in json.loads(out)["runs"]}
    assert sorted(rows) == sorted(runs) and rows[runs[0]]["ok"], out
    assert not rows[runs[1]]["ok"] and blob in rows[runs[1]]["reason"], out
    assert code == 1, out
    return out


def _tree(folder: Path) -> dict[str, bytes]:
    return {p.relative_to(folder).as_posix(): p.read_bytes()
            for p in sorted(folder.rglob("*")) if p.is_file()}  # fmt: skip


def test_leave_the_hosted_service_and_verify_byte_identically(
    services, tmp_path, monkeypatch, capsys
):
    runs, blob = _seed_tenant(services, tmp_path, monkeypatch, capsys)
    exported = _export(monkeypatch, capsys, services, "old", tmp_path / "out-old")
    heads = sorted(name for name in exported["refs"] if name.startswith("heads/"))
    assert heads == ["heads/alpha", "heads/beta"] and exported["skipped_refs"] == []
    assert exported["reviews"] == ["leave"] and exported["shares"] == 1
    assert exported["project_versions"] == 1
    assert exported["log_entries"] >= 2
    shares = (tmp_path / "out-old" / "shares.json").read_text("utf-8")
    assert "tine_share_" not in shares  # metadata only: a token never leaves the server

    # Into a fresh tine serve, then out again: the same bundle and Review bytes.
    moved = _json(monkeypatch, capsys, "tenant", "import", str(tmp_path / "out-old"),
                  "--remote", services["new"], *services["flags"], "--json")  # fmt: skip
    assert moved["refs"] == exported["refs"] and moved["reviews"] == ["leave"]
    assert services["new_app"].service.objects.tombstoned("acme", blob)
    again = _export(monkeypatch, capsys, services, "new", tmp_path / "out-new")
    assert again["refs"] == exported["refs"] and again["reviews"] == ["leave"]
    old_tree, new_tree = _tree(tmp_path / "out-old"), _tree(tmp_path / "out-new")
    for name in ("tenant.tbundle", "reviews/leave.json", "project/000000.json"):
        assert old_tree[name] == new_tree[name], name
    review = json.loads(old_tree["reviews/leave.json"])
    assert _review.verify_bundle(review)["status"] == "approved"

    # Into plain local repositories, from each server's export.
    reports: dict[str, str] = {}
    for side in ("old", "new"):
        target = tmp_path / f"local-{side}"
        Repo.init(target)
        local = _json(monkeypatch, capsys, "tenant", "import", str(tmp_path / f"out-{side}"),
                      "--repo", target.as_posix(), "--json")  # fmt: skip
        assert local["refs"] == exported["refs"] and local["reviews"] == ["leave"]
        repo = Repo.open(target)
        assert repo.list_refs() == exported["refs"]
        assert _tombstones.read(repo, blob) is not None and not repo.has(blob)
        assert _review_store.load(repo, "leave") == review
        reports[side] = _verify(monkeypatch, capsys, target, runs, blob)
    reports["work"] = _verify(monkeypatch, capsys, tmp_path / "work", runs, blob)
    assert reports["old"] == reports["new"]  # byte for byte
    # The working repository also holds its local project chain; every run reads the same.
    rows = {side: json.loads(text)["runs"] for side, text in reports.items()}
    assert rows["old"] == rows["work"]


def test_an_export_folder_holds_only_frozen_formats(services, tmp_path, monkeypatch, capsys):
    _seed_tenant(services, tmp_path, monkeypatch, capsys)
    _export(monkeypatch, capsys, services, "old", tmp_path / "out")
    tree = _tree(tmp_path / "out")
    assert sorted(tree) == ["log/checkpoint.json", "log/entries.json", "project/000000.json",
                            "reviews/leave.json", "shares.json", "tenant.tbundle"]  # fmt: skip
    checked = _bundle.verify(tree["tenant.tbundle"])
    assert checked.tombstones and checked.refs
    name, errors = _schemas.validate(json.loads(tree["reviews/leave.json"]),
                                     "opentine-review-bundle-1")  # fmt: skip
    assert name == "opentine-review-bundle-1" and errors == []
    name, errors = _schemas.validate(json.loads(tree["project/000000.json"]), "opentine-project-1")
    assert name == "opentine-project-1" and errors == []


def test_import_refuses_to_move_a_ref_or_read_a_missing_folder(
    services, tmp_path, monkeypatch, capsys
):
    _seed_tenant(services, tmp_path, monkeypatch, capsys)
    _export(monkeypatch, capsys, services, "old", tmp_path / "out")
    target = Repo.init(tmp_path / "taken")
    run = Run(id="other")
    run.add_step(StepKind.done, {"text": "other"})
    target.put_run(run, ref="heads/alpha")
    where = ("--repo", (tmp_path / "taken").as_posix())
    code, _ = _tine(monkeypatch, capsys, "tenant", "import", str(tmp_path / "out"), *where)
    assert code != 0
    assert Repo.open(tmp_path / "taken").read_ref("heads/beta") is None  # all or nothing
    code, _ = _tine(monkeypatch, capsys, "tenant", "import", str(tmp_path / "missing"), *where)
    assert code != 0
