"""``tine gc --sweep-expired`` (0.52): remove a ``tine serve`` object store's
expired orphan chunks.

The store is the one ``tine serve --root DIR`` would open
(``TINE_REMOTE_OBJECT_STORE``, :mod:`opentine.remote._worm_config`). A chunk is
removed only when no ``chunked/`` record names it (finished or in-flight
uploads alike) and its retention has ended and it carries no legal hold; the
removal is fenced against concurrent uploads (:mod:`opentine.remote._worm_fence`).
The filesystem store keeps no chunks, so it reports nothing to sweep.
``--json`` follows ``tine-cli-gc-1``.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
from typing import Any

from opentine._cli_errors import fail
from opentine._cli_json import emit


def add_sweep_flags(command: argparse.ArgumentParser) -> None:
    command.add_argument(
        "--sweep-expired",
        action="store_true",
        help="Only remove a tine serve object store's expired orphan chunks (no packing)",
    )
    command.add_argument("--state", default=".tine-remote", help="tine serve --root (sweep)")
    command.add_argument("--tenant", action="append", help="Sweep only this tenant (repeatable)")


def _tenants(store: Any) -> list[str]:
    seen: set[str] = set()
    for key in store.client.keys(store.prefix):
        seen.add(key[len(store.prefix) :].split("/", 1)[0])
    return sorted(seen)


def sweep(args: argparse.Namespace) -> dict[str, Any]:
    from opentine.remote import _worm_config
    from opentine.remote.backend import valid_tenant
    from opentine.remote.security import LocalKeyProvider

    keys = LocalKeyProvider.from_env() if os.environ.get("TINE_KMS_KEY") else None
    store = _worm_config.object_store_from_env(Path(args.state).resolve(), keys)
    if store is None:
        return {"command": "gc", "action": "sweep-expired", "store": "filesystem",
                "tenants": [], "swept": 0}  # fmt: skip
    tenants = [valid_tenant(t) for t in args.tenant] if args.tenant else _tenants(store)
    try:
        rows = [store.sweep_expired(tenant) for tenant in tenants]
    except (AttributeError, TypeError) as exc:  # a 0.49-0.51 record needs its manifest unsealed
        raise ValueError("TINE_KMS_KEY is required to read chunk records older than 0.52") from exc
    scheme = (os.environ.get(_worm_config.STORE_ENV) or "").split("://", 1)[0]
    return {"command": "gc", "action": "sweep-expired", "store": scheme, "tenants": rows,
            "swept": sum(row["swept"] for row in rows)}  # fmt: skip


def cmd_sweep(args: argparse.Namespace) -> None:
    try:
        body = sweep(args)
    except (OSError, ValueError, RuntimeError) as exc:
        fail(str(exc), prefix="tine gc --sweep-expired: ")
    if args.json:
        emit(body)
        return
    for row in body["tenants"]:
        print(f"{row['tenant']}\tswept {row['swept']}\tretained {row['retained']}\t"
              f"chunks {row['chunks']}")  # fmt: skip
    print(f"swept {body['swept']} expired orphan chunk(s) from the {body['store']} store")


__all__ = ["add_sweep_flags", "cmd_sweep", "sweep"]
