#!/usr/bin/env python3
"""The 0.34 peer compatibility check (ROADMAP §2 invariant 5, 1.0 criterion 3).

The current tree writes a repository, a pack and ``.tine`` artifacts with some
of the 0.45-0.49 features that leave bytes on disk (the 0.46 project manifest,
a signed tombstone and its purged blob, the 0.47 prompt registry and team
memory, a trace-recorded run, the default pack and artifact writers), and
serves main and a project over HTTP with ``tine serve``'s reference app. A 0.34
interpreter then reads every file and fetches over HTTP. Merge, review,
eval-verdict and forge objects are not exercised yet.

    python scripts/peer_compat_034.py --old-python /path/to/venv-0.34/bin/python
    python scripts/peer_compat_034.py --old-path /path/to/opentine-0.34-source

``--old-python`` is an interpreter with ``opentine[zstd]==0.34.0`` installed
(CI); ``--old-path`` holds the 0.34 ``opentine`` package and is put first on
the current interpreter's ``sys.path`` (``git archive v0.34.0 opentine``, the
offline test). The summary is JSON on stdout; exit 1 on any failure that is not
a pinned ``KNOWN_GAPS`` entry, or on a pinned gap that starts passing.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import urllib.request
from collections.abc import Iterator
from pathlib import Path
from typing import Any

WHEN = "2026-11-09T00:00:00Z"
TOKEN = "peer-compat-token"  # noqa: S105 - a loopback test token

#: Runs under the 0.34 interpreter: argv = [old_path or "", manifest.json].
READER = r"""
import json, sys
if sys.argv[1]:
    sys.path.insert(0, sys.argv[1])
import opentine
from opentine import Repo, Run
m = json.load(open(sys.argv[2], encoding="utf-8"))
out = {"version": opentine.__version__, "checks": {}}
def check(name, fn):
    try:
        out["checks"][name] = {"ok": True, "detail": fn()}
    except Exception as exc:
        out["checks"][name] = {"ok": False, "detail": f"{type(exc).__name__}: {exc}"}
repo = Repo.open(m["repo"])
check("fsck", lambda: [str(e) for e in repo.fsck().errors])
def refs():
    got = set(repo.list_refs())
    return [r for r in m["refs"] if r not in got and "refs/" + r not in got]
check("list_refs", refs)
check("get_every_object", lambda: len([repo.get(oid) for oid in m["oids"]]))
check("load_run", lambda: len([repo.load_run(rid) for rid in m["runs"]]))
def artifacts(key):
    for path in m[key]:
        Run.load(path)
        assert Run.verify_integrity(path) is not False, path
    return len(m[key])
check("artifact_legacy", lambda: artifacts("artifacts"))
check("artifact_default", lambda: artifacts("artifacts_default"))
def pack():
    fresh = Repo.init(m["scratch"] + "/from-pack")
    fresh.import_pack(open(m["pack"], "rb").read())
    assert fresh.fsck().ok
    return len(list(fresh.iter_oids()))
check("import_pack", pack)
def http():
    fresh = Repo.init(m["scratch"] + "/from-http")
    fresh.fetch(m["url"], tenant=m["tenant"], token=m["token"], allow_insecure=True)
    assert fresh.fsck().ok
    return fresh.load_run(m["main_runs"][-1]).id
check("http_fetch", http)
print(json.dumps(out, sort_keys=True))
"""

#: What a 0.34 reader may fail, each with the reason it is allowed. Anything else
#: that fails fails the job, and so does a pinned gap that starts passing.
KNOWN_GAPS = {
    "artifact_default": "the default .tine writer is v5 (0.40+). ROADMAP §2 lets a new file "
    "format become the default two minor releases after its reader ships; 0.34 is served "
    "by `tine --for-legacy` (artifact_legacy).",
}
REGISTRY_NOTE = (
    "a 0.34 reader opening a current repository directory reports the 0.46 project ref "
    "(project/manifest) and the 0.47 prompt and memory refs (prompts/*, memory/*) as "
    "illegal ref names and skips them; every object still reads, and a 0.34 HTTP fetch "
    "from a server holding a project succeeds. Renaming them would be a format change "
    "after the 0.48 cutoff"
)
REGISTRY_REF = re.compile(r"^(refs/)?(prompts|memory|project)/")
REGISTRY_FSCK = re.compile(r"ref file '(prompts|memory|project)/")


def judge(result: dict[str, Any]) -> dict[str, Any]:
    """Apply ``KNOWN_GAPS`` and the registry-ref rule to the reader's raw checks."""
    checks, failures, notes = result.get("checks", {}), [], {}
    for name, check in sorted(checks.items()):
        if name in KNOWN_GAPS:
            if check["ok"]:
                failures.append(f"{name}: pinned as a known gap but passed; unpin it")
            notes[name] = KNOWN_GAPS[name]
        elif not check["ok"]:
            failures.append(f"{name}: {check['detail']}")
    missing = (checks.get("list_refs") or {}).get("detail") or []
    errors = (checks.get("fsck") or {}).get("detail") or []
    registry = [e for e in errors if REGISTRY_FSCK.search(e)]
    if [r for r in missing if not REGISTRY_REF.match(r)]:
        failures.append(f"list_refs: 0.34 does not list {missing}")
    if [e for e in errors if e not in registry]:
        failures.append(f"fsck: {[e for e in errors if e not in registry]}")
    if registry or missing:
        notes["registry_refs"] = REGISTRY_NOTE
    if not checks:
        failures.append(result.get("error") or "the 0.34 reader produced no checks")
    if result.get("version") != "0.34.0":
        failures.append(f"the reader ran opentine {result.get('version')}, not 0.34.0")
    return {**result, "ok": not failures, "failures": failures, "known_gaps": notes}


@contextlib.contextmanager
def _env(name: str, value: str) -> Iterator[None]:
    before = os.environ.get(name)
    os.environ[name] = value
    try:
        yield
    finally:
        if before is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = before


def write(base: Path) -> dict[str, Any]:
    """Write the current tree's files under *base*; return the reader's manifest."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from opentine import _memory, _project, _prompt, _tombstone
    from opentine._format_v4 import FORMAT_ENV
    from opentine.graph import Run, StepKind
    from opentine.policies import PolicySet
    from opentine.repository import Repo, _project_ref
    from opentine.repository import _registry_refs as registry
    from opentine.repository._purge import purge
    from opentine.trace import Recorder, TraceEvent

    def new_run(label: str, text: str) -> Run:
        run = Run(id=label, model_info="m", user_prompt="p", policies=PolicySet().to_dict())
        run.add_step(StepKind.done, {"text": text})
        return run

    repo = Repo.init(base / "repo")
    runs = [repo.put_run(new_run(n, f"{n} done"), ref="heads/main").run_id for n in "ab"]
    recorder = Recorder.start(repo, ref="heads/traced", capture=False)
    recorder.append(TraceEvent("model", 1, "trace", "span", outputs={"text": "ok"}))
    runs.append(recorder.finalize())
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    prompt = _prompt.build("review", "R {{d}}", created_at=WHEN)
    registry.push_prompt(repo, _prompt.sign(prompt, key))
    note = _memory.build("team", "testing", "use the venv", author="alice", created_at=WHEN)
    registry.add_note(repo, _memory.sign(note, key))
    owner = key.public_key().public_bytes_raw().hex()
    slot = {"role": "primary", "forge": "github", "forge_repo_id": None,
            "upstream_visibility": "public", "default_branch": "main",
            "locator": {"url": "https://example.com/acme/app"}}  # fmt: skip
    manifest = _project.build("app", "acme", owners=[owner], slots=[slot], created_at=WHEN)
    project = _project.sign(manifest, key)
    _project_ref.write(repo, project, owner_key=owner)  # the 0.46 project/ namespace
    erased = repo.put_run(new_run("gone", "erase this text"), ref="heads/erased").run_id
    purged = []
    for oid in list(repo.iter_oids()):
        if oid.startswith("blob:") and b"erase this text" in repo.get(oid).body:
            tomb = _tombstone.build(oid, "erasure", "alice")
            purge(repo, _tombstone.sign(tomb, b"ab" * 32, algorithm="hmac-sha256", key_id="k1"))
            purged.append(oid)
    legacy, default = [], []
    for rid in runs[:2]:
        stem = rid.replace(":", "_")
        repo.load_run(rid).save(base / f"{stem}.v5.tine")
        with _env(FORMAT_ENV, "4"):  # ``tine --for-legacy``: readers before 0.40
            repo.load_run(rid).save(base / f"{stem}.legacy.tine")
        default.append((base / f"{stem}.v5.tine").as_posix())
        legacy.append((base / f"{stem}.legacy.tine").as_posix())
    (base / "main.pack").write_bytes(repo.pack())
    return {
        "repo": (base / "repo").as_posix(),
        "runs": runs,
        "main_runs": runs[:2],
        "erased_run": erased,
        "purged": purged,
        "refs": sorted(repo.list_refs()),
        "oids": sorted(o for o in repo.iter_oids() if o not in purged),
        "artifacts": legacy,
        "artifacts_default": default,
        "pack": (base / "main.pack").as_posix(),
        "scratch": base.as_posix(),
        "project": project,
    }


def serve(manifest: dict[str, Any]) -> Any:
    """Serve main at a loopback URL with the current reference app."""
    from wsgiref.simple_server import WSGIRequestHandler, make_server

    from opentine.remote import Identity, LocalKeyProvider, StaticTokenIdentityProvider, server
    from opentine.repository import Repo
    from opentine.repository.pack import reachable

    class Quiet(WSGIRequestHandler):
        def log_message(self, *args: Any) -> None:
            pass

    identities = StaticTokenIdentityProvider({TOKEN: Identity("alice", "acme", ("writer",))})
    root = Path(manifest["scratch"]) / "srv"
    app = server.reference_app(root, identities=identities, keys=LocalKeyProvider(b"k" * 32))
    writer = app.service.authenticate({"authorization": f"Bearer {TOKEN}"})
    repo = Repo.open(manifest["repo"])  # main only: a purged blob is a shallow boundary
    main = sorted(reachable(repo, manifest["main_runs"]))
    app.service.install_pack(writer, "acme", repo.pack(main))
    app.service.update_ref(writer, "acme", "heads/main", repo.read_ref("heads/main"), None)
    httpd = make_server("127.0.0.1", 0, app, handler_class=Quiet)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    manifest.update(url=f"http://127.0.0.1:{httpd.server_port}", tenant="acme", token=TOKEN)
    body = json.dumps({"expected_old": None, "manifest": manifest.pop("project")}).encode()
    put = urllib.request.Request(f"{manifest['url']}/v1/tenants/acme/project", body, method="PUT",
                                 headers={"Authorization": f"Bearer {TOKEN}",
                                          "Content-Type": "application/json"})  # fmt: skip
    with urllib.request.urlopen(put, timeout=60) as response:  # noqa: S310 - loopback
        assert response.status in (200, 201), response.status  # 0.34 fetches past a project
    return httpd


def run(old_python: str | None, old_path: str | None, base: Path) -> dict[str, Any]:
    manifest = write(base)
    httpd = serve(manifest)
    try:
        (base / "manifest.json").write_text(json.dumps(manifest), "utf-8")
        (base / "reader.py").write_text(READER, "utf-8")
        argv = [old_python, "-I"] if old_python else [sys.executable]
        env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
        done = subprocess.run(
            [
                *argv,
                (base / "reader.py").as_posix(),
                old_path or "",
                (base / "manifest.json").as_posix(),
            ],  # fmt: skip
            capture_output=True,
            text=True,
            env=env,
            cwd=base,
            timeout=600,  # fmt: skip
        )
    finally:
        httpd.shutdown()
    lines = done.stdout.strip().splitlines()
    if done.returncode != 0 or not lines:
        return judge({"error": done.stderr[-4000:]})
    return judge(json.loads(lines[-1]))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="The 0.34 peer compatibility check.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--old-python", help="an interpreter with opentine==0.34.0 installed")
    group.add_argument("--old-path", help="a directory holding the 0.34 opentine package")
    parser.add_argument("--out", help="also write the JSON summary to this file")
    args = parser.parse_args(argv)
    with tempfile.TemporaryDirectory(prefix="peer034-") as tmp:
        summary = run(args.old_python, args.old_path, Path(tmp))
    text = json.dumps(summary, indent=2, sort_keys=True)
    print(text)
    if args.out:
        Path(args.out).write_text(text + "\n", "utf-8")
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
