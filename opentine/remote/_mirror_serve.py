"""``tine serve --mirror``: turn the code mirror on and poll it (0.55, ``caps.project.mirror``)."""

from __future__ import annotations

import argparse
import threading
from typing import Any

from opentine.remote import _mirror_store as store


def add_mirror_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--mirror", action="store_true", help="Serve a read-only code mirror of linked projects"
    )
    parser.add_argument(
        "--mirror-poll-seconds", type=int, default=store.DEFAULTS["poll_seconds"],
        help="Sync every linked mirror this often (0: webhook-triggered sync only)",
    )  # fmt: skip
    parser.add_argument(
        "--mirror-max-mb", type=int, default=store.DEFAULTS["max_repo_bytes"] // (1024 * 1024),
        help="Largest upstream a mirror holds (MiB)",
    )  # fmt: skip
    parser.add_argument(
        "--mirror-allow-local", action="store_true",
        help="Allow file:// upstreams (self-host and tests only)",
    )  # fmt: skip


def mirror_options(args: argparse.Namespace) -> dict[str, Any] | None:
    if not getattr(args, "mirror", False):
        return None
    if args.mirror_poll_seconds < 0 or args.mirror_max_mb < 1:
        raise SystemExit("--mirror-poll-seconds and --mirror-max-mb must be positive")
    return {"poll_seconds": args.mirror_poll_seconds, "allow_local": args.mirror_allow_local,
            "max_repo_bytes": args.mirror_max_mb * 1024 * 1024, "poller": True}  # fmt: skip


def attach_mirror(service: Any, options: dict[str, Any] | None) -> None:
    """Set ``service.mirror`` (``None`` keeps it off); ``poller`` starts the poll thread."""
    service.mirror = None if options is None else store.config(options)
    root = getattr(service.objects, "root", None)
    cfg = service.mirror
    if cfg is None or root is None or not cfg["poller"] or not cfg["poll_seconds"]:
        return
    stop = threading.Event()

    def loop() -> None:
        while not stop.wait(cfg["poll_seconds"]):
            store.poll(root, cfg)

    service.mirror_poller = stop
    threading.Thread(target=loop, name="tine-mirror-poll", daemon=True).start()


__all__ = ["add_mirror_arguments", "attach_mirror", "mirror_options"]
