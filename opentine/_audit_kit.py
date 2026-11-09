"""``tine audit-kit build``: a self-contained, air-gapped audit kit (0.49).

Layout (every path relative to ``--out``)::

    README.md                what is here and how to check it offline
    REPORT.md, report.html   the verification report recorded at build time
    tine-verify.pyz          the stdlib-only verifier (``opentine._pyz_build``)
    verify.html              the TS verifier as one offline page, runs embedded
    evidence/                ``tine evidence export --with-verifier`` of the runs
    reports/NAME.html        each run's deterministic evidence page
    crate/STEM/              the Provenance Run Crate beside a copy of its run
    attestations/            ``replay/v1`` DSSE envelope and its signer key
    trust/witnesses.json     the pinned witness set, ``trust/log-keys/`` its logs
    source/                  a ``tine bundle`` input, byte for byte
    ae/                      the artifact-evaluation package
    kit.json                 the build summary (``tine-cli-audit-kit-build-1``)
    SHA256SUMS               ``sha256sum`` lines for every other file, sorted

The kit adds no object kind and no wire format: it places existing ones
(SPEC Part 8) and is checked by :mod:`opentine._audit_kit_check`. ``--zip``
also writes a deterministic zip of the directory.
"""

from __future__ import annotations

import shutil
import zipfile
from pathlib import Path
from typing import Any

from opentine._audit_kit_parts import check, sha256_file

SUMS = "SHA256SUMS"
SUMMARY = "kit.json"
_ZIP_TIME = (1980, 1, 1, 0, 0, 0)


def sums_text(root: Path) -> bytes:
    lines = [
        f"{sha256_file(p)}  {p.relative_to(root).as_posix()}"
        for p in sorted(root.rglob("*"), key=lambda q: q.relative_to(root).as_posix())
        if p.is_file() and p.relative_to(root).as_posix() != SUMS
    ]
    return ("\n".join(lines) + "\n").encode("utf-8")


def write_zip(root: Path, target: Path) -> None:
    """A deterministic zip: sorted names, fixed times and modes, under ``root.name/``."""
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(root.rglob("*"), key=lambda q: q.relative_to(root).as_posix()):
            if not path.is_file():
                continue
            info = zipfile.ZipInfo(f"{root.name}/{path.relative_to(root).as_posix()}", _ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, path.read_bytes())


def _evidence(out: Path, sources: list[Path], opts: dict[str, Any]) -> list[dict[str, Any]]:
    from opentine._evidence_export import write_evidence
    from opentine._evidence_report import evidence, render_html
    from opentine._verify_chain import _read, build_report

    verify = opts["verify_args"]
    runs = [(p, _read(p)[0], build_report(verify, p, str(p)).as_json()) for p in sources]
    write_evidence(out / "evidence", runs, trust_files=opts["trust_files"],
                   operator=opts["operator"], version=opts["version"],
                   signing_key=opts.get("signing_key"), with_verifier=True)  # fmt: skip
    (out / "reports").mkdir()
    for path, data, report in runs:
        page = render_html(evidence(path, data, report))
        (out / "reports" / f"{path.stem}.html").write_bytes(page.encode("utf-8"))
    return [{"source": p, "report": r, "run_id": _run_id(d)} for p, d, r in runs]


def _run_id(data: Any) -> str | None:
    value = data.get("run_id") or data.get("id") if isinstance(data, dict) else None
    return value if isinstance(value, str) else None


def _run_rows(out: Path, built: list[dict[str, Any]]) -> list[dict[str, Any]]:
    from opentine._audit_kit_parts import run_digest

    rows = []
    for item in built:
        name = Path(item["source"]).name
        stored = out / "evidence" / "runs" / name
        digest = run_digest(stored)
        report = item["report"]
        run_id = item["run_id"]
        rows.append({"run_id": run_id or Path(name).stem, "file": f"runs/{name}",
                     "digest": digest, "ok": bool(report["ok"])})  # fmt: skip
    return rows


def _page(out: Path, rows: list[dict[str, Any]], title: str) -> None:
    from opentine import _codec
    from opentine._artifact_io import MAX_TINE_ARTIFACT_BYTES
    from opentine._audit_kit_page import embedded, verify_html

    runs = []
    for row in rows:
        raw = (out / "evidence" / row["file"]).read_bytes()
        body = _codec.unwrap(raw, limit=MAX_TINE_ARTIFACT_BYTES)
        runs.append(embedded(row["file"], row["digest"], body))
    (out / "verify.html").write_bytes(verify_html(runs, title).encode("utf-8"))


def build_kit(out: Path, sources: list[Path], opts: dict[str, Any]) -> dict[str, Any]:
    """Write the kit into the new or empty directory *out*; return its summary."""
    from opentine import _audit_kit_parts as parts
    from opentine._audit_kit_ae import write_ae
    from opentine._audit_kit_page import report_html, report_markdown
    from opentine._cli_json import serialize
    from opentine._pyz_build import build

    out.mkdir(parents=True, exist_ok=True)
    checks: list[dict[str, str]] = list(opts.get("pre_checks", []))
    built = _evidence(out, sources, opts)
    rows = _run_rows(out, built)
    for row in rows:
        detail = f"{row['digest']} verified offline" if row["ok"] else "failed offline verify"
        checks.append(check(f"run:{row['file']}", row["ok"], detail))
    build(out)
    for row in rows:
        checks.append(parts.write_crate(out, out / "evidence" / row["file"]))
    if len(rows) == 1:
        checks.append(parts.replay_attestation(out, out / "evidence" / rows[0]["file"],
                      copy=opts.get("replay_copy"), attest_key=opts.get("attest_key"),
                      pubkey=opts.get("replay_pubkey")))  # fmt: skip
    else:
        checks.append(check("replay", None, "replay attestation is per run; kit has several"))
    checks.append(parts.write_witnesses(out, opts.get("witnesses", []),
                                        opts.get("log_keys", []), opts.get("quorum")))  # fmt: skip
    if opts.get("bundle") is not None:
        (out / "source").mkdir()
        shutil.copyfile(opts["bundle"], out / "source" / Path(opts["bundle"]).name)
    _page(out, rows, f"{opts['source']['kind']} {opts['source']['name']}")
    summary = {
        "command": "audit-kit-build", "kit_version": 1, "tine_version": opts["version"],
        "source": opts["source"], "runs": [{k: r[k] for k in ("run_id", "file", "digest")}
                                           for r in rows],
        "checks": checks, "ok": all(c["outcome"] != "fail" for c in checks),
    }  # fmt: skip
    (out / "REPORT.md").write_bytes(report_markdown(summary).encode("utf-8"))
    (out / "report.html").write_bytes(report_html(summary).encode("utf-8"))
    write_ae(out, summary)
    (out / SUMMARY).write_bytes((serialize(summary) + "\n").encode("utf-8"))
    (out / SUMS).write_bytes(sums_text(out))
    return {**summary, "files": len((out / SUMS).read_bytes().splitlines()) + 1}


__all__ = ["SUMMARY", "SUMS", "build_kit", "sums_text", "write_zip"]
