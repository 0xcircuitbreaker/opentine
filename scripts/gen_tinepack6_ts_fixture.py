"""Write ``tests/vectors/tinepack6/ts-refusal.json``: a TINEPACK6 pack and bundle (0.81).

The Python reader decodes both; the TS verifier has no HEC decoder yet and
must refuse both with ``unsupported pack format TINEPACK6`` (reason code
``pack.version-unsupported``) instead of misparsing them. The objects come
from a golden compat repository (the last by name), so the fixture is small::

    uv run python scripts/gen_tinepack6_ts_fixture.py
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from opentine import _bundle  # noqa: E402
from opentine.repository import Repo  # noqa: E402
from opentine.repository.pack import inspect_pack  # noqa: E402

OUT = ROOT / "tests" / "vectors" / "tinepack6" / "ts-refusal.json"
CODE = "pack.version-unsupported"
MESSAGE = "unsupported pack format TINEPACK6"


def build() -> dict:
    source = sorted((ROOT / "tests" / "fixtures" / "compat").glob("v*/repo"))[-1]
    with tempfile.TemporaryDirectory() as scratch:
        shutil.copytree(source, Path(scratch) / "repo")
        repo = Repo.open(Path(scratch) / "repo")
        bundle = _bundle.create(repo, pack_format="TINEPACK6")
    checked = _bundle.verify(bundle)
    pack_id, objects, _ = inspect_pack(checked.pack)
    return {
        "bundle_hex": bundle.hex(),
        "pack_hex": checked.pack.hex(),
        "python": {"objects": [oid for oid, _ in objects], "pack_id": pack_id},
        "source": f"tests/fixtures/compat/{source.parent.name}/repo",
        "ts": {
            "bundle": {"code": f"bundle.pack-invalid:{CODE}", "message": MESSAGE},
            "pack": {"code": CODE, "message": MESSAGE},
        },
    }


def main() -> int:
    OUT.write_text(json.dumps(build(), indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print(OUT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
