"""``tine doctor --bundle PATH.tar.gz``: the support bundle as a diagnostics tarball.

A path ending ``.tar.gz`` or ``.tgz`` gets a gzip tarball instead of the single
JSON document; any other path keeps the 0.45 JSON form. Members:

* ``doctor.json``: the redacted report (:func:`opentine._doctor.bundle`);
* ``agents.json``: each supported agent CLI, whether it is present, how it is
  captured and whether its hook file carries opentine's shim (yes/no only);
* ``hooks/<agent>.json``: the hook file each ``tine enable`` agent reads,
  passed through :func:`opentine.redaction.redact_value` (a hook command can
  carry a token in its arguments).

Every member is scanned after redaction, the same way the JSON bundle is: one
credential-shaped byte left anywhere and nothing is written. Members carry a
fixed mtime and owner so the same machine state gives the same bytes.
"""

from __future__ import annotations

import gzip
import io
import shutil
import tarfile
from typing import Any

SUFFIXES = (".tar.gz", ".tgz")


def wanted(path: str) -> bool:
    return path.lower().endswith(SUFFIXES)


def _agents() -> list[dict[str, Any]]:
    from opentine import _agent_detect
    from opentine._cli_enable import ENABLE_AGENTS, _config

    rows = []
    for name, binary, folder, capture in _agent_detect.agents():
        present = bool(shutil.which(binary) or folder.is_dir())
        row: dict[str, Any] = {"agent": name, "capture": capture, "present": present}
        if name in ENABLE_AGENTS:
            path = _config(name)
            text = path.read_text("utf-8", "replace") if path.is_file() else ""
            row["hook_file"] = str(path)
            row["shim_installed"] = "hook capture --agent" in text
        rows.append(row)
    return rows


def _hook_files() -> dict[str, Any]:
    from opentine._cli_enable import ENABLE_AGENTS, _config
    from opentine._cli_hook_agents import read_config

    out: dict[str, Any] = {}
    for name in ENABLE_AGENTS:
        try:
            document: Any = read_config(_config(name))
        except (OSError, ValueError) as exc:
            document = {"unreadable": type(exc).__name__}
        if document:
            out[name] = document
    return out


def _member(name: str, value: Any) -> tuple[str, bytes]:
    from opentine.kernel import canonical_json
    from opentine.redaction import redact_blob, redact_value

    data = canonical_json(redact_value(value))
    if redact_blob(data) != data:
        raise ValueError(f"support bundle member {name} still holds credential-shaped bytes; "
                         "not written")  # fmt: skip
    return name, data


def tarball(body: dict[str, Any]) -> bytes:
    """The gzip tarball; ``ValueError`` if any member keeps a secret shape."""
    from opentine._doctor import bundle

    members = [("doctor.json", bundle(body)), _member("agents.json", _agents())]
    members += [_member(f"hooks/{name}.json", doc) for name, doc in sorted(_hook_files().items())]
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name, data in members:
            info = tarfile.TarInfo(name)
            info.size, info.mtime, info.mode = len(data), 0, 0o644
            info.uname = info.gname = ""
            archive.addfile(info, io.BytesIO(data))
    return gzip.compress(raw.getvalue(), mtime=0)


__all__ = ["SUFFIXES", "tarball", "wanted"]
