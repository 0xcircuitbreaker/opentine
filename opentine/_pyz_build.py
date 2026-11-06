"""Build ``tine-verify.pyz`` reproducibly from the installed package's own sources.

The zipapp holds ``__main__.py`` and a ``tine_verify`` package: the stdlib-only
verifier in :mod:`opentine._pyz` plus two modules vendored verbatim from
opentine (``kernel.py`` and ``_ed25519_order.py``). It is byte-identical across
builds of the same sources: entries are written in sorted order, stored (not
deflated, so no zlib version can change a byte), with one fixed timestamp
(``SOURCE_DATE_EPOCH``, else 1980-01-01), mode 0644, a Unix creator and no
extra fields, and every text file has LF line endings whatever the checkout.
Used by ``scripts/build_verifier.py`` and ``tine evidence export --with-verifier``.
"""

from __future__ import annotations

import io
import os
import time
import zipfile
from pathlib import Path

PACKAGE = Path(__file__).resolve().parent
NAME = "tine-verify.pyz"
SHEBANG = b"#!/usr/bin/env python3\n"
#: Modules vendored verbatim from opentine: each imports the stdlib only.
VENDORED = ("kernel.py", "_ed25519_order.py")
_MAIN = b"from tine_verify._pyz._cli import main\n\nraise SystemExit(main())\n"
_INIT = b'"""tine-verify.pyz: opentine\'s offline verifier, standard library only."""\n'
_EPOCH_FLOOR = 315532800  # 1980-01-01T00:00:00Z, the earliest time a zip can hold


def _text(path: Path) -> bytes:
    return path.read_bytes().replace(b"\r\n", b"\n")


def sources() -> dict[str, bytes]:
    """Every archive member, by name, with its bytes."""
    members = {"__main__.py": _MAIN, "tine_verify/__init__.py": _INIT}
    for name in VENDORED:
        members[f"tine_verify/{name}"] = _text(PACKAGE / name)
    for path in sorted((PACKAGE / "_pyz").glob("*.py")):
        members[f"tine_verify/_pyz/{path.name}"] = _text(path)
    return members


def _timestamp(epoch: int | None) -> tuple[int, int, int, int, int, int]:
    if epoch is None:
        text = os.environ.get("SOURCE_DATE_EPOCH", "").strip()
        epoch = int(text) if text.isdigit() else _EPOCH_FLOOR
    return time.gmtime(max(epoch, _EPOCH_FLOOR))[:6]


def build_bytes(epoch: int | None = None) -> bytes:
    """The archive's bytes: the shebang, then a deterministic zip."""
    stamp = _timestamp(epoch)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as archive:
        for name, data in sorted(sources().items()):
            info = zipfile.ZipInfo(name, date_time=stamp)
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, data)
    return SHEBANG + buffer.getvalue()


def build(out: Path, epoch: int | None = None) -> Path:
    """Write the zipapp to *out* (a file path, or a directory to hold ``tine-verify.pyz``)."""
    target = out / NAME if out.is_dir() else out
    target.write_bytes(build_bytes(epoch))
    return target


__all__ = ["NAME", "build", "build_bytes", "sources"]
