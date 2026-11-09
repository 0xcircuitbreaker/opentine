#!/usr/bin/env python3
"""The full-size ``caps.coord`` scale test: 1,000 tasks x 50 workers (ROADMAP 0.47).

    python scripts/coord_scale.py                       # an in-process tine serve
    python scripts/coord_scale.py --tasks 1000 --workers 50 --crash-every 7
    python scripts/coord_scale.py --url https://host --tenant t --token-file F

Without ``--url`` it starts a throwaway ``tine serve`` service (SQLite index,
filesystem objects) in a temporary directory and drives it over its WSGI app,
one HTTP client per worker. It prints the report of
:func:`opentine.coord._scale.run` as JSON and exits 1 unless ``lost``,
``duplicated`` and ``stale_accepted`` are all 0. CI runs a scaled-down copy
(``tests/test_047_coord_remote.py``).
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path


def _local(root: Path):
    import httpx

    from opentine.remote import (
        FilesystemObjectStore,
        Identity,
        LocalKeyProvider,
        RemoteApp,
        RemoteService,
        RoleAuthorizationPolicy,
        SQLiteBackend,
        StaticTokenIdentityProvider,
    )

    identities = StaticTokenIdentityProvider({"w": Identity("w", "scale", ("writer",))})
    service = RemoteService(
        FilesystemObjectStore(root / "objects", LocalKeyProvider(b"k" * 32)),
        SQLiteBackend(root / "remote.sqlite3"),
        identities,
        RoleAuthorizationPolicy(),
    )
    app = RemoteApp(service, root / "state")
    return lambda: httpx.Client(
        base_url="http://remote",
        transport=httpx.WSGITransport(app=app),
        headers={"Authorization": "Bearer w"},
        timeout=120,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--tasks", type=int, default=1000)
    parser.add_argument("--workers", type=int, default=50)
    parser.add_argument("--crash-every", type=int, default=0, help="Abandon every Nth claim")
    parser.add_argument("--url", help="A running tine serve (default: an in-process one)")
    parser.add_argument("--tenant", default="scale")
    parser.add_argument("--token-file", metavar="PATH")
    args = parser.parse_args(argv)

    from opentine._cli_task_remote import RemoteTasks
    from opentine.coord import _scale

    with tempfile.TemporaryDirectory() as room:
        if args.url:
            from opentine.repository._http import client

            token = Path(args.token_file).read_text("utf-8").strip() if args.token_file else None

            def make_client():
                return client(args.url, token, timeout=120)

            tenant = args.tenant
        else:
            make_client, tenant = _local(Path(room)), "scale"
        report = _scale.run(
            lambda: RemoteTasks(make_client(), tenant, timeout=120),
            args.tasks,
            args.workers,
            crash_every=args.crash_every,
        )
    print(json.dumps(report, sort_keys=True))
    return 0 if report["lost"] == report["duplicated"] == report["stale_accepted"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
