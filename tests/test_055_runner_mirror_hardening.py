"""0.55 hardening of the code mirror and the review runner.

The mirror fetch is held to the size limit while it runs, code reads serve only
commits the mirror's refs reach, upstream credentials never land in
``link.json`` or a response; the runner's egress guard pins the addresses it
resolved at start, a VSA from any trusted runner key counts, hosted mode
refuses to start outside the network sandbox, and the eval judges get the
runner's model credentials and count in the push's cost.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import stat
import sys
from decimal import Decimal
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine import _merge_gates, _project, _review_runner, _runner_sandbox
from opentine.remote import _mirror_store
from tests._mirror_fixture import call, fixture_repo, git, make_app, put_project

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="needs git on PATH")
T = "/v1/tenants/acme/project/"
RUN = "run:sha256:" + "7" * 64
AT = "2026-11-01T12:00:00Z"

# A stand-in ``git`` whose fetch never ends and keeps writing into the mirror.
FLOOD = """\
import os, subprocess, sys, time
argv = sys.argv[1:]
if "fetch" not in argv:
    sys.exit(subprocess.call([REAL_GIT, *argv]))
where = argv[argv.index("--git-dir") + 1]
os.makedirs(os.path.join(where, "objects", "pack"), exist_ok=True)
with open(os.path.join(where, "objects", "pack", "tmp_pack_flood"), "wb") as out:
    while True:
        out.write(b"x" * 65536)
        out.flush()
        time.sleep(0.01)
"""


def test_the_fetch_is_killed_when_the_mirror_passes_its_size_limit(tmp_path, monkeypatch):
    from opentine import _mirror_fetch, _mirror_git

    script = tmp_path / "flood.py"
    script.write_text(f"REAL_GIT = {shutil.which('git')!r}\n" + FLOOD, encoding="utf-8")
    real = _mirror_fetch.command_for

    def flood(repo, args, pin=()):  # a Python stand-in runs the same on every OS
        return [sys.executable, str(script), *real(repo, args, pin)[1:]]

    monkeypatch.setattr(_mirror_fetch, "command_for", flood)
    dest = tmp_path / "mirror"
    with pytest.raises(_mirror_git.GitError) as caught:
        _mirror_git.fetch((tmp_path / "up").as_uri(), dest, allow_local=True, timeout=20,
                          max_bytes=256 * 1024)  # fmt: skip
    assert caught.value.code == "mirror.limit-exceeded"
    assert not dest.exists()


def test_the_limit_outranks_a_failing_git_exit(tmp_path, monkeypatch):
    from opentine import _mirror_fetch, _mirror_git

    script = tmp_path / "overshoot.py"  # writes past the limit, then exits non-zero at once
    script.write_text("import os, sys\nwhere = sys.argv[sys.argv.index('--git-dir') + 1]\n"
                      "open(os.path.join(where, 'big'), 'wb').write(b'x' * 300000)\n"
                      "sys.exit(128)\n", encoding="utf-8")  # fmt: skip
    real = _mirror_fetch.command_for
    monkeypatch.setattr(_mirror_fetch, "command_for",
                        lambda repo, args, pin=(): [sys.executable, str(script),
                                                    *real(repo, args, pin)[1:]])  # fmt: skip
    dest = tmp_path / "mirror"
    with pytest.raises(_mirror_git.GitError) as caught:
        _mirror_git.fetch((tmp_path / "up").as_uri(), dest, allow_local=True, timeout=20,
                          max_bytes=256 * 1024)  # fmt: skip
    assert caught.value.code == "mirror.limit-exceeded"
    assert not dest.exists()


def test_remove_tree_deletes_read_only_files_and_never_fails_silently(tmp_path, monkeypatch):
    from opentine import _mirror_fetch

    pack = tmp_path / "m" / "objects" / "pack"
    pack.mkdir(parents=True)
    (pack / "a.pack").write_bytes(b"p")
    (pack / "a.pack").chmod(0o444)  # git writes packs read-only; Windows will not delete those
    calls = []
    real = _mirror_fetch.shutil.rmtree

    def windows_like(path, **kw):  # fail on the read-only file the way Windows does
        handler = kw.get("onexc") or kw.get("onerror")
        target = pack / "a.pack"
        if not target.stat().st_mode & stat.S_IWUSR:
            calls.append(target)
            handler(os.unlink, str(target), PermissionError(13, "denied"))
        real(path)

    monkeypatch.setattr(_mirror_fetch.shutil, "rmtree", windows_like)
    _mirror_fetch.remove_tree(tmp_path / "m")
    assert calls and not (tmp_path / "m").exists()
    (tmp_path / "kept").mkdir()
    monkeypatch.setattr(_mirror_fetch.shutil, "rmtree", lambda path, **kw: None)
    with pytest.raises(OSError):
        _mirror_fetch.remove_tree(tmp_path / "kept")


def test_a_commit_the_refs_no_longer_reach_is_not_served(tmp_path):
    commits = fixture_repo(tmp_path / "upstream")
    app = make_app(tmp_path)
    put_project(app)
    assert call(app, "PUT", T + "mirror", {"url": (tmp_path / "upstream").as_uri()}).status == 200
    tree = call(app, "GET", T + "code/tree", query=f"ref={commits['feature']}")
    assert tree.status == 200, tree.body
    git(tmp_path / "upstream", "branch", "-f", "feature", "main")  # force-push away
    root = app.service.objects.root
    cfg = _mirror_store.config({"allow_local": True})
    assert _mirror_store.sync(root, "acme", cfg, force=True)["status"] == "synced"
    # the old commit is still in the object store, but no ref reaches it
    repo = _mirror_store.repo(root, "acme")
    assert git(repo, "cat-file", "-t", commits["feature"]) == "commit"
    for path in ("code/tree", "code/history"):
        gone = call(app, "GET", T + path, query=f"ref={commits['feature']}")
        assert gone.status == 404, (path, gone.body)
    assert call(app, "GET", T + "code/tree", query=f"ref={commits['first']}").status == 200


def test_upstream_credentials_never_reach_link_json_or_a_response(tmp_path):
    app = make_app(tmp_path)
    url, salt = "https://alice:s3cret-token@git.example.org/app.git", bytes(range(16))
    put_project(app, visibility="private",
                locator={"commitment": _project.commitment(url, salt)})  # fmt: skip
    root = app.service.objects.root
    linked = _mirror_store.link(root, "acme", {"url": url, "salt": salt.hex()},
                                _mirror_store.config({}))  # fmt: skip
    assert linked["upstream"] == "https://git.example.org/app.git"
    place = _mirror_store.directory(root, "acme")
    assert "s3cret" not in (place / "link.json").read_text("utf-8")
    secret = place / "credential"
    assert secret.read_text("utf-8") == "alice:s3cret-token"
    if os.name == "posix":  # Windows has no POSIX modes; the directory's ACLs guard it there
        assert stat.S_IMODE(secret.stat().st_mode) == 0o600
    from opentine import _mirror_fetch

    env = _mirror_fetch._auth_env("alice:s3cret-token")
    assert env["GIT_CONFIG_KEY_0"] == "http.extraHeader"
    assert "s3cret" not in env["GIT_CONFIG_VALUE_0"]  # base64 in a header, not the URL
    assert "s3cret" not in call(app, "GET", T + "mirror").body.decode()


def test_the_egress_guard_pins_the_addresses_resolved_at_start(monkeypatch):
    answers = {"models.example": "93.184.216.34"}

    def fake(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (answers[host], port))]

    monkeypatch.setattr(_runner_sandbox.socket, "getaddrinfo", fake)
    policy = _runner_sandbox.policy(["https://models.example/v1"], [])
    with _runner_sandbox.EgressGuard(policy) as guard:
        assert guard.addresses == {("93.184.216.34", 443)}
        answers["models.example"] = "93.184.216.35"  # a later DNS answer
        with socket.socket() as sock, pytest.raises(_runner_sandbox.EgressRefused):
            sock.connect(("93.184.216.35", 443))
    answers["models.example"] = "10.0.0.5"  # a private address is never pinned
    with _runner_sandbox.EgressGuard(policy) as guard:
        assert guard.addresses == set()
        with socket.socket() as sock, pytest.raises(_runner_sandbox.EgressRefused):
            sock.connect(("10.0.0.5", 443))
    with _runner_sandbox.EgressGuard(policy, allow_private=True) as guard:
        assert guard.addresses == {("10.0.0.5", 443)}


def test_a_vsa_from_the_second_trusted_runner_key_counts():
    from opentine.intoto import sign_statement
    from opentine.remote._vsa import build_vsa

    old, new = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    statement = build_vsa("runner", "heads/main", RUN, ["OPENTINE_REVIEWED"],
                          verifier="opentine:review-runner", time_verified=AT)  # fmt: skip
    envelope = sign_statement(statement, new)
    raws = [k.public_key().public_bytes_raw() for k in (old, new)]
    policy = _review_runner.gate_policy(raws, levels=("OPENTINE_REVIEWED",))
    policy["evals"] = None
    _merge_gates.check_policy(policy)
    result = _merge_gates.evaluate(policy, {"vsa": [envelope]}, RUN, "heads/main")
    assert result["ok"] is True, result
    only_old = _review_runner.gate_policy(raws[:1], levels=("OPENTINE_REVIEWED",))
    only_old["evals"] = None
    assert _merge_gates.evaluate(only_old, {"vsa": [envelope]}, RUN, "heads/main")["ok"] is False


def test_hosted_mode_refuses_without_the_network_sandbox(monkeypatch):
    with pytest.raises(_runner_sandbox.NoNetworkSandbox, match="OPENTINE_RUNNER_NETWORK"):
        _runner_sandbox.require_network_sandbox({})
    monkeypatch.setattr(_runner_sandbox, "direct_egress", lambda target: True)
    with pytest.raises(_runner_sandbox.NoNetworkSandbox, match="got through"):
        _runner_sandbox.require_network_sandbox({"OPENTINE_RUNNER_NETWORK": "allowlist"})
    monkeypatch.setattr(_runner_sandbox, "direct_egress", lambda target: False)
    _runner_sandbox.require_network_sandbox({"OPENTINE_RUNNER_NETWORK": "allowlist"})
    monkeypatch.delenv("OPENTINE_RUNNER_NETWORK", raising=False)
    with pytest.raises(_runner_sandbox.NoNetworkSandbox):
        _review_runner.run_push(None, "r", None, None, {}, config={"models": []},
                                mode="hosted", out=Path("."))  # fmt: skip


class _Judge:
    async def complete(self, messages, temperature=0.0):
        return {"text": "fine\nSCORE: 1", "cost": 0.25}


def test_eval_judges_get_the_model_credential_and_count_in_the_cost(tmp_path, monkeypatch):
    from opentine import _eval_judge
    from opentine._eval_ci import run_ci

    seen = []
    monkeypatch.setattr(_eval_judge, "_model", lambda spec, api_key=None: seen.append(
        (spec, api_key)) or _Judge())  # fmt: skip
    monkeypatch.setenv("XDG_DATA_HOME", (tmp_path / "data").as_posix())
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".tine").mkdir()
    item = {"id": "q", "input": "1", "expected": "1", "output": "1", "run": RUN}
    (tmp_path / "d.jsonl").write_text(json.dumps(item) + "\n", encoding="utf-8")
    config = tmp_path / ".tine" / "evals.toml"
    config.write_text('[[eval]]\nname = "j"\ndataset = "d.jsonl"\nscorer = "llm-judge:m:x"\n',
                      "utf-8")  # fmt: skip
    found = run_ci(config, Ed25519PrivateKey.generate(), tmp_path / "out", repo_path=tmp_path,
                   created_at=AT, credentials={"m": "sk-judge"})  # fmt: skip
    assert seen == [("m:x", "sk-judge")]
    assert found["ok"] is True and Decimal(found["cost"]) == Decimal("0.25")
    review = {"cost": {"total": "1.5", "unknown_members": 0}}
    cost = _review_runner._cost(review, found)
    assert Decimal(cost["total"]) == Decimal("1.75") and Decimal(cost["evals"]) == Decimal("0.25")


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")
def test_mirror_records_are_owner_only(tmp_path):
    from opentine.remote import _mirror_store

    target = tmp_path / "link.json"
    _mirror_store._write(target, {"upstream": "https://example.invalid/private.git"})
    assert target.stat().st_mode & 0o777 == 0o600
    _mirror_store._write(target, {"upstream": "https://example.invalid/other.git"})
    assert target.stat().st_mode & 0o777 == 0o600


# A stand-in ``git`` whose fetch hands the writing to a grandchild, as ``git fetch``
# does with ``index-pack``; the grandchild records its pid so the test can check it.
FLOOD_CHILD = """\
import os, subprocess, sys
argv = sys.argv[1:]
if "fetch" not in argv:
    sys.exit(subprocess.call([REAL_GIT, *argv]))
where = argv[argv.index("--git-dir") + 1]
os.makedirs(os.path.join(where, "objects", "pack"), exist_ok=True)
writer = (
    "import os, sys, time\\n"
    "open(sys.argv[2], 'w').write(str(os.getpid()))\\n"
    "out = open(sys.argv[1], 'wb')\\n"
    "while True:\\n"
    "    out.write(b'x' * 65536); out.flush(); time.sleep(0.01)\\n"
)
child = subprocess.Popen([sys.executable, "-c", writer,
                          os.path.join(where, "objects", "pack", "tmp_pack_child"), PIDFILE])
sys.exit(child.wait())
"""


def _alive(pid: int) -> bool:
    if os.name == "nt":
        import ctypes

        handle = ctypes.windll.kernel32.OpenProcess(0x1000 | 0x100000, False, pid)
        if not handle:
            return False
        try:
            return ctypes.windll.kernel32.WaitForSingleObject(handle, 0) != 0
        finally:
            ctypes.windll.kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    with open(f"/proc/{pid}/stat", encoding="ascii") as stat_file:
        return stat_file.read().split()[2] != "Z"


def test_the_limit_kill_reaches_the_process_that_writes_the_pack(tmp_path, monkeypatch):
    from opentine import _mirror_fetch, _mirror_git

    pidfile = tmp_path / "writer.pid"
    script = tmp_path / "flood_child.py"
    script.write_text(f"REAL_GIT = {shutil.which('git')!r}\nPIDFILE = {str(pidfile)!r}\n"
                      + FLOOD_CHILD, encoding="utf-8")  # fmt: skip
    real = _mirror_fetch.command_for
    monkeypatch.setattr(_mirror_fetch, "command_for",
                        lambda repo, args, pin=(): [sys.executable, str(script),
                                                    *real(repo, args, pin)[1:]])  # fmt: skip
    dest = tmp_path / "mirror"
    with pytest.raises(_mirror_git.GitError) as caught:
        _mirror_git.fetch((tmp_path / "up").as_uri(), dest, allow_local=True, timeout=60,
                          max_bytes=256 * 1024)  # fmt: skip
    assert caught.value.code == "mirror.limit-exceeded"
    assert not dest.exists()
    assert not _alive(int(pidfile.read_text(encoding="ascii")))
