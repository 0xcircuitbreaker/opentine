"""``tine init --auto``: one command from a clean machine to captured, signable runs.

Steps, in order, each skipped when already done:

1. the v3 repository (``Repo.init``), unless one is already there;
2. a local Ed25519 signing key, ``agent-keys/local.key`` (encrypted PKCS#8; the
   passphrase comes from the usual sources, see :mod:`opentine._key_store`);
   with no passphrase source the key is skipped and the step says how to make it;
3. per-turn hooks for every agent CLI found here (:mod:`opentine._agent_detect`)
   that ``tine enable`` knows, through the same reversible edit ``tine enable``
   makes, then ``hooks.capture`` in the repository config. Captured payloads
   go through the redactor when they are written, so a secret an agent sees is
   scrubbed before it reaches an object, long before anything is pushed;
4. the OTLP receiver and MCP proxy commands, printed, not started: both are
   long-running servers the user starts where the agent runs;
5. with ``--push-beside-git`` inside a git work tree, the ``pre-push`` hook
   ``tine git install-hook --push`` installs, so runs travel with the commits
   that name them. That push runs the pre-push redaction gate first and never
   blocks the code push. Without the flag the step is only offered.

``--dry-run`` reports the plan and writes nothing.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any

LOCAL_KEY = "local"
OTLP_ENDPOINT = "http://127.0.0.1:4318"


def detected() -> list[str]:
    """Agent CLIs present here that ``tine enable`` can wire, sorted."""
    from opentine import _agent_detect
    from opentine._cli_enable import ENABLE_AGENTS

    found = []
    for name, binary, folder, _capture in _agent_detect.agents():
        if name in ENABLE_AGENTS and (shutil.which(binary) or folder.is_dir()):
            found.append(name)
    return sorted(found)


def _repository(path: Path, dry_run: bool) -> tuple[Path, str]:
    from opentine.repo import Repo

    try:
        return Path(Repo.open(path).path), "exists"
    except Exception:  # noqa: BLE001 - any failure to open means there is none yet
        if dry_run:
            return path, "would create"
        return Path(Repo.init(path).path), "created"


def _key(dry_run: bool) -> dict[str, Any]:
    from opentine._agent_keys import key_paths

    private, public = key_paths(LOCAL_KEY)
    row: dict[str, Any] = {"step": "key", "path": str(private)}
    if private.exists():
        return {**row, "status": "exists"}
    if dry_run:
        return {**row, "status": "would create"}
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from opentine._canon import atomic_write_text
    from opentine._key_store import PassphraseUnavailable, write_private
    from opentine.signing import generate_ed25519

    seed, public_hex = generate_ed25519()
    private.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        write_private(private, Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed)))
    except PassphraseUnavailable:
        return {
            **row,
            "status": "skipped",
            "detail": f"no passphrase source; run `tine keygen --agent {LOCAL_KEY}`",
        }
    atomic_write_text(public, public_hex + "\n")
    return {**row, "status": "created"}


def _hooks(repo: Path, agents: list[str], dry_run: bool) -> list[dict[str, Any]]:
    from opentine._cli_enable import _config, _enable_one, _set_capture

    rows = []
    for name in agents:
        row = {"step": "hooks", "agent": name, "path": str(_config(name))}
        if dry_run:
            rows.append({**row, "status": "would enable"})
            continue
        try:
            _enable_one(name, repo, False)
            rows.append({**row, "status": "enabled"})
        except (OSError, ValueError) as exc:
            rows.append({**row, "status": "refused", "detail": str(exc)})
    if not dry_run and any(r["status"] == "enabled" for r in rows):
        _set_capture(repo)
    return rows


def _git_top(path: Path) -> Path | None:
    try:
        done = subprocess.run(["git", "-C", str(path), "rev-parse", "--show-toplevel"],
                              capture_output=True, text=True, check=False, timeout=30)  # fmt: skip
    except (OSError, subprocess.SubprocessError):
        return None
    return Path(done.stdout.strip()) if done.returncode == 0 and done.stdout.strip() else None


def _push(path: Path, wanted: bool, dry_run: bool) -> dict[str, Any]:
    top = _git_top(path)
    if top is None:
        return {"step": "push", "status": "not a git work tree"}
    if not wanted:
        return {
            "step": "push",
            "status": "offered",
            "detail": "pass --push-beside-git (or run `tine git install-hook --push`)",
        }
    if dry_run:
        return {"step": "push", "status": "would install", "path": str(top)}
    from opentine import _git_push_sync
    from opentine._git_link_hook import install_hook

    hook = install_hook(top, hook=_git_push_sync.HOOK, text=_git_push_sync.script())
    return {"step": "push", "status": "installed", "path": str(hook)}


def wiring(repo: Path) -> list[dict[str, Any]]:
    """The OTLP and MCP proxy setup, as commands for the user to start."""
    import shlex

    quoted = shlex.quote(str(repo))
    return [
        {"step": "otlp", "status": "printed",
         "detail": f"tine serve --otlp --repo {quoted}; then OTEL_EXPORTER_OTLP_ENDPOINT="
                   f"{OTLP_ENDPOINT}"},
        {"step": "mcp-proxy", "status": "printed",
         "detail": f"tine mcp-proxy --repo {quoted} -- <your MCP server command>"},
    ]  # fmt: skip


def run(path: str, *, push_beside_git: bool = False, dry_run: bool = False,
        agents: list[str] | None = None) -> dict[str, Any]:  # fmt: skip
    """Set everything up; one row per step."""
    repo, status = _repository(Path(path), dry_run)
    names = detected() if agents is None else sorted(agents)
    steps = [{"step": "repository", "status": status, "path": str(repo)}, _key(dry_run)]
    if not names:
        steps.append({"step": "hooks", "status": "no agent CLI found",
                      "detail": "install one, then run `tine init --auto` again"})  # fmt: skip
    steps += _hooks(repo, names, dry_run)
    steps += wiring(repo)
    from opentine import _init_frameworks

    steps += _init_frameworks.rows(Path(path), OTLP_ENDPOINT)
    steps.append(_push(Path(path), push_beside_git, dry_run))
    failed = any(s["status"] == "refused" for s in steps)
    return {"repo": str(repo), "agents": names, "dry_run": dry_run, "steps": steps,
            "status": "fail" if failed else "ok"}  # fmt: skip


__all__ = ["LOCAL_KEY", "OTLP_ENDPOINT", "detected", "run", "wiring"]
