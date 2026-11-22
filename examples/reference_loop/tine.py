"""Run ``tine`` commands in this process and read their ``--json`` output.

Every step of the reference loop goes through the same commands a person would
type. :func:`tine` calls :func:`opentine.cli.main` with the arguments, captures
stdout and returns ``(exit_code, json_object)``. :func:`isolated` points the
trust configuration (the pinned owner key and the bundle serials) at a folder
inside the work directory, so the example never reads or writes the user's own
``$XDG_CONFIG_HOME/opentine``.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import warnings
from collections.abc import Iterator
from pathlib import Path
from typing import Any

_ENV = ("XDG_CONFIG_HOME", "OPENTINE_TRUST_OWNER", "OPENTINE_TRUST_BUNDLE")


class TineError(RuntimeError):
    """A command the loop needs failed unexpectedly."""


def tine(*argv: str) -> tuple[int, dict[str, Any]]:
    """``(exit_code, parsed JSON or {})`` for one in-process ``tine`` invocation."""
    from opentine import cli

    out, err = io.StringIO(), io.StringIO()
    code = 0
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            cli.main([str(a) for a in argv])
        except SystemExit as exc:
            code = exc.code if isinstance(exc.code, int) else (0 if exc.code is None else 1)
    text = out.getvalue().strip()
    try:
        body = json.loads(text) if text.startswith("{") else {}
    except ValueError:
        body = {}
    if not body and err.getvalue().strip():
        body = {"stderr": err.getvalue().strip()[-2000:]}
    return code, body


def must(*argv: str) -> dict[str, Any]:
    """:func:`tine` that raises :class:`TineError` on a non-zero exit."""
    code, body = tine(*argv)
    if code != 0:
        raise TineError(f"tine {' '.join(map(str, argv[:3]))} exited {code}: {body}")
    return body


@contextlib.contextmanager
def isolated(config: Path, owner_vkey: str | None = None) -> Iterator[None]:
    """Use *config* as ``$XDG_CONFIG_HOME`` (and pin *owner_vkey*) for the block."""
    saved = {name: os.environ.get(name) for name in _ENV}
    os.environ["XDG_CONFIG_HOME"] = Path(config).as_posix()
    os.environ.pop("OPENTINE_TRUST_BUNDLE", None)
    if owner_vkey:
        os.environ["OPENTINE_TRUST_OWNER"] = owner_vkey
    else:
        os.environ.pop("OPENTINE_TRUST_OWNER", None)
    try:
        with warnings.catch_warnings():
            # The example's keys are throwaway hex files made for one run; a real
            # deployment keeps them encrypted (tine key encrypt) or in a KMS.
            warnings.filterwarnings("ignore", message=".*plaintext-hex private key")
            yield
    finally:
        for name, value in saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


__all__ = ["TineError", "isolated", "must", "tine"]
