"""``tine hook resume``: continue an ended agent session with one message (0.46).

Steering (:mod:`opentine._hook_mailbox`) reaches an agent that is still
running, at its next turn end. A session that already ended is continued by its
own CLI's documented resume command, run here without a shell::

    tine hook resume --agent codex --session ID --message TEXT [--repo PATH] [--dry-run]

* Codex: ``codex exec resume ID TEXT`` (non-interactive resume, then the
  prompt);
* Gemini CLI: ``gemini --resume ID --prompt TEXT``;
* Claude Code: ``claude --resume ID --print TEXT``.

With ``--repo`` the message is first recorded as a ``steer`` step (actor
``steer``, ``opentine.steer.from: "resume"``) on the session's capture run,
``heads/capture/<agent>/<digest>`` (:func:`opentine._hook_protocol.session_ref`),
when that run exists, so the history shows where the session was picked up.
The resumed agent's own hooks then keep capturing into the same run.
``--dry-run`` prints the plan as JSON and neither records nor runs anything.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

RESUMERS = {
    "codex": ("codex", "exec", "resume", "{session}", "{message}"),
    "gemini": ("gemini", "--resume", "{session}", "--prompt", "{message}"),
    "claude-code": ("claude", "--resume", "{session}", "--print", "{message}"),
}
_SESSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}")
MAX_MESSAGE = 64 * 1024


def argv(agent: str, session: str, message: str) -> list[str]:
    """The resume command for *agent*; refuses what could be read as an option."""
    if agent not in RESUMERS:
        raise ValueError(f"tine hook resume supports --agent {', '.join(sorted(RESUMERS))}")
    if not _SESSION.fullmatch(session or ""):
        raise ValueError("--session must be the agent's session id (letters, digits, ._:-)")
    if not message or message.startswith("-") or len(message.encode()) > MAX_MESSAGE:
        raise ValueError("--message must be 1..64 KiB of text that does not start with '-'")
    return [part.format(session=session, message=message) for part in RESUMERS[agent]]


def record(repo_path: str, agent: str, session: str, message: str) -> str | None:
    """Append the message as a steer step to the session's capture run; its ref, or None."""
    from opentine._hook_mailbox import steer_steps
    from opentine._hook_protocol import _Lock, session_ref
    from opentine.repo import Repo
    from opentine.repository._paths import internal_path
    from opentine.trace.recorder import Recorder

    repo = Repo.open(Path(repo_path))
    ref = session_ref(agent, session)
    with _Lock(internal_path(Path(repo.path), f"capture-{ref.rsplit('/', 1)[1]}.lock")):
        try:
            if not repo.read_ref(ref):
                return None
        except ValueError:
            return None
        recorder = Recorder.resume(repo, ref, ref=ref)
        mail = {"id": 0, "from": "resume", "sent_ms": int(time.time() * 1000), "text": message}
        for step in steer_steps(session, [mail]):
            recorder.append(step)
    return ref


def run(agent: str | None, session: str | None, message: str | None, repo: str | None,
        dry_run: bool) -> int:  # fmt: skip
    command = argv(agent or "", session or "", message or "")
    plan: dict[str, Any] = {"command": "hook resume", "agent": agent, "session": session,
                            "argv": command, "recorded": None}  # fmt: skip
    if dry_run:
        sys.stdout.write(json.dumps({**plan, "dry_run": True}) + "\n")
        return 0
    if repo:
        plan["recorded"] = record(repo, agent or "", session or "", message or "")
    try:
        return subprocess.run(command, check=False).returncode  # noqa: S603 - no shell
    except FileNotFoundError as exc:
        raise ValueError(f"{command[0]} is not on PATH: cannot resume the session") from exc


__all__ = ["RESUMERS", "argv", "record", "run"]
