"""Deterministic arithmetic context isolated from caller process state."""

from __future__ import annotations

from decimal import ROUND_HALF_EVEN, Context, localcontext

_CONTEXT = Context(prec=256, rounding=ROUND_HALF_EVEN, Emin=-999999, Emax=999999)


def billing_context():
    """Return a fresh context manager for all billing arithmetic."""
    return localcontext(_CONTEXT)
