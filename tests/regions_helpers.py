"""A signed EVOLVE-BLOCK region pin for promotion fixtures (0.87)."""

from __future__ import annotations

from pathlib import Path

from tests.promote_helpers import fingerprint, key

POLICY = "8d" * 32
AT = "2026-11-27T00:00:00Z"


def policy_role() -> str:
    """The ``key-roles.toml`` line that makes :data:`POLICY` a policy-role key."""
    return f'policy = ["{fingerprint(POLICY)}"]\n'


def pin_regions(root: Path, globs: tuple[str, ...] = ("evolve/**",)) -> dict:
    """Sign the region pin of *root* (key roles already pinned with :func:`policy_role`)."""
    from opentine._regions_pin import pin

    return pin(Path(root), list(globs), key(POLICY), AT)


__all__ = ["AT", "POLICY", "pin_regions", "policy_role"]
