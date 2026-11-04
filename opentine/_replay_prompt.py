"""Which prompt a harness replay may send to a live agent.

A run's recorded ``user_prompt`` is text whoever wrote the artifact chose, so
``tine replay --harness`` sends it only when one of these holds:

* ``--prompt`` replaces it;
* the artifact carries a valid Ed25519 signature by the key its agent identity
  claims (``key_fpr``), and that key is trusted for that agent -- one of this
  user's own agent keys, or pinned for an agent name the identity claims in a
  trusted ``.tine/agents.toml``. Both ``tine-sig`` schemes cover ``user_prompt``;
* ``--trust-recorded-prompt`` says the operator has read it.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from opentine._agent_identity import run_identity
from opentine._agent_keys import agent_pins, local_fingerprints, scoped_allows
from opentine._artifact_io import artifact_signature, read_artifact_json
from opentine._signing_pins import used_key_fingerprint


def recorded_prompt_signed(path: Path, run: Any) -> bool:
    """Whether *path* is signed by the trusted key of the agent *run* claims.

    The verdict rests only on a signature block whose embedded key is the
    claimed one, checked against that key alone, so a decoy block naming the
    pinned key cannot lend its fingerprint to another block's valid signature.
    The prompt and identity are re-read from the verified bytes and must equal
    the ones about to be sent.
    """
    from opentine import _cli_who_trust as who_trust
    from opentine._graph_serde import load_run_data
    from opentine.core import Run

    record = run_identity(run) or {}
    claimed = record.get("key_fpr")
    if not claimed:
        return False
    try:
        data = read_artifact_json(path)
        _, _, agents = who_trust.scope_paths(argparse.Namespace())
        pins = agent_pins(agents)
        signed = load_run_data(data, Run)
    except (OSError, RecursionError, ValueError, TypeError, KeyError):
        return False
    if claimed not in local_fingerprints() and not scoped_allows(pins, record, claimed):
        return False
    if signed.user_prompt != run.user_prompt or run_identity(signed) != record:
        return False
    keys = [_embedded_key(block) for block in _signature_blocks(data)]
    key = next((k for k in keys if k and used_key_fingerprint(_ed(k)) == claimed), None)
    return key is not None and Run.verify_signature(data, public_key=key).ok


def _ed(key: str) -> dict[str, str]:
    return {"alg": "ed25519", "public_key": key}


def _embedded_key(block: Any) -> str | None:
    if isinstance(block, dict) and block.get("alg") == "ed25519":
        key = block.get("public_key")
        return key if isinstance(key, str) else None
    return None


def _signature_blocks(data: Any) -> list[Any]:
    blocks = data.get("signatures") if isinstance(data, dict) else None
    if isinstance(blocks, list):
        return blocks
    return [artifact_signature(data)]


def replay_task(args: argparse.Namespace, run: Any, path: Path) -> str:
    """The prompt to send, or exit 1 when the recorded one is not trusted."""
    from opentine._cli_common import console

    task = args.prompt or run.user_prompt
    if not task:
        console.print("[red]--prompt is required when replaying a harness run.[/]")
        raise SystemExit(1)
    vouched = getattr(args, "trust_recorded_prompt", False)
    if not args.prompt and not vouched and not recorded_prompt_signed(path, run):
        console.print(
            "[red]Refusing to send the artifact's recorded prompt to a live agent:[/] it is "
            "not signed by a trusted key of the agent the run claims. Pass --prompt, or "
            "--trust-recorded-prompt once you have read it."
        )
        raise SystemExit(1)
    return task


__all__ = ["recorded_prompt_signed", "replay_task"]
