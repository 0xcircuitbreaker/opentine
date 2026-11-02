"""``tine export RUN --format citation | ro-crate``: cite a run in a paper.

``citation`` writes a ``CITATION.cff`` (Citation File Format 1.2.0) and
``ro-crate`` writes an ``ro-crate-metadata.json`` (RO-Crate 1.1 JSON-LD). Both
name the run id, its verified integrity digest (``sha256:...``, see SPEC §3.5),
every model the run recorded, the run's own creation time and the opentine
version that wrote the citation. Nothing else varies, so the output is a pure
function of the run file and the opentine version: no clock, no host, no path.

A run whose digest does not verify is refused: a citation pins the bytes it
names, and a digest that does not match them would cite nothing.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

CFF_VERSION = "1.2.0"
RO_CRATE_CONTEXT = "https://w3id.org/ro/crate/1.1/context"
RO_CRATE_SPEC = "https://w3id.org/ro/crate/1.1"
OPENTINE_URL = "https://github.com/0xcircuitbreaker/opentine"
CITATION_FORMATS = ("citation", "ro-crate")


def facts(path: Path, run: Any) -> dict[str, Any]:
    """The run facts both formats carry; raises ValueError for an unverified run."""
    from opentine._version import __version__
    from opentine.core import Run

    result = Run.verify_integrity(path)
    if not result.ok:
        raise ValueError(f"cannot cite a run whose digest does not verify: {result.reason}")
    models = {run.model_info} | {getattr(s, "model_info", "") for s in run.steps}
    stamp = run.created_at if isinstance(run.created_at, int | float) else 0
    created = datetime.fromtimestamp(stamp, tz=UTC)
    return {
        "run_id": run.id,
        "digest": f"sha256:{result.actual}",
        "models": sorted(m for m in models if isinstance(m, str) and m),
        "created": created.isoformat().replace("+00:00", "Z"),
        "date": created.date().isoformat(),
        "version": __version__,
        "file": path.name,
    }


def _q(value: str) -> str:
    """A YAML double-quoted scalar: JSON string syntax is valid YAML."""
    return json.dumps(value)


def to_cff(f: dict[str, Any]) -> str:
    models = ", ".join(f["models"]) or "unrecorded"
    lines = [
        f"cff-version: {CFF_VERSION}",
        "message: " + _q("If you use this agent run, please cite it as below."),
        "type: dataset",
        "title: " + _q(f"opentine run {f['run_id']}"),
        "abstract: " + _q(f"Recorded agent run {f['run_id']} (models: {models})."),
        "authors:",
        "  - name: " + _q("opentine"),
        "    website: " + _q(OPENTINE_URL),
        "date-released: " + _q(f["date"]),
        "identifiers:",
        "  - type: other",
        "    value: " + _q(f["digest"]),
        "    description: " + _q("opentine integrity digest (SPEC section 3.5)"),
        "  - type: other",
        "    value: " + _q(f"opentine-run:{f['run_id']}"),
        "    description: " + _q(f"run id; recorded {f['created']}"),
        "  - type: other",
        "    value: " + _q(f"opentine:{f['version']}"),
        "    description: " + _q("opentine version that wrote this citation"),
        "keywords:",
        *(f"  - {_q(m)}" for m in ["opentine", "agent run", *f["models"]]),
    ]
    return "\n".join(lines) + "\n"


def to_ro_crate(f: dict[str, Any]) -> dict[str, Any]:
    models = [
        {"@id": f"#model-{i}", "@type": "SoftwareApplication", "name": m}
        for i, m in enumerate(f["models"])
    ]
    return {
        "@context": RO_CRATE_CONTEXT,
        "@graph": [
            {
                "@id": "ro-crate-metadata.json",
                "@type": "CreativeWork",
                "conformsTo": {"@id": RO_CRATE_SPEC},
                "about": {"@id": "./"},
            },
            {
                "@id": "./",
                "@type": "Dataset",
                "name": f"opentine run {f['run_id']}",
                "description": f"Recorded agent run {f['run_id']}.",
                "identifier": f["digest"],
                "dateCreated": f["created"],
                "datePublished": f["date"],
                "keywords": ["opentine", "agent run", *f["models"]],
                "hasPart": [{"@id": f["file"]}],
                "mentions": [{"@id": m["@id"]} for m in models],
            },
            {
                "@id": f["file"],
                "@type": "File",
                "name": f"opentine-run:{f['run_id']}",
                "encodingFormat": "application/json",
                "identifier": f["digest"],
                "dateCreated": f["created"],
                "creator": {"@id": OPENTINE_URL},
            },
            {
                "@id": OPENTINE_URL,
                "@type": "SoftwareApplication",
                "name": "opentine",
                "version": f["version"],
            },
            *models,
        ],
    }


def render(fmt: str, path: Path, run: Any) -> bytes:
    """The document bytes for *fmt*; raises ValueError for an unverified run."""
    f = facts(path, run)
    if fmt == "citation":
        return to_cff(f).encode("utf-8")
    from opentine._cli_json import serialize

    return (serialize(to_ro_crate(f)) + "\n").encode("utf-8")


def cli_export(
    fmt: str, path: Path, run: Any, output: Path | None, compress: Any, endpoint: Any
) -> None:
    from opentine._cli_common import BRAND, _terminal, console
    from opentine._codec_io import standard_frame
    from opentine._export_write import write_private

    if endpoint is not None:
        raise ValueError(f"--format {fmt} writes a file; it cannot be pushed to --endpoint")
    data = render(fmt, path, run)
    if output is None:
        print(data.decode("utf-8"), end="")
        return
    write_private(output, standard_frame(data, compress) if compress else data)
    console.print(f"[{BRAND}]# Exported[/] {fmt} [{BRAND}]to[/] {_terminal(output)}")


__all__ = ["CFF_VERSION", "CITATION_FORMATS", "cli_export", "facts", "render", "to_cff"]
