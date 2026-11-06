"""``tine evidence report --format pdf``: a PDF derivative of the canonical HTML report.

Needs the optional ``opentine[pdf]`` extra (pikepdf). The PDF is written from
the same scrubbed evidence document as the HTML and carries that document's
canonical JSON as an embedded file (``evidence.json``, ``/AFRelationship
/Data``), so the PDF is never the only copy of the evidence.

Determinism: ``/CreationDate`` and ``/ModDate`` are the run's ``created_at`` (or
the epoch), there is no XMP or producer string, streams are uncompressed and the
trailer ``/ID`` is derived from the content (qpdf's deterministic ID). The tests
check two writes are byte-identical, but only the HTML is the gated, canonical
artifact: pikepdf/qpdf output may differ between their versions.

Text is set in the PDF base-14 Courier, which a reader supplies; no system font
is read at write time. Embedding a bundled font (and so full PDF/A-3 conformance)
is deferred.
"""

from __future__ import annotations

import datetime
import io
from typing import Any

from opentine._evidence_report import canonical

_LINES_PER_PAGE = 60
_WIDTH = 95


class PdfUnavailable(RuntimeError):
    """pikepdf is not installed."""


def _pdf_date(stamp: Any) -> str:
    try:
        when = datetime.datetime.fromtimestamp(float(stamp), datetime.UTC)
    except (TypeError, ValueError, OverflowError, OSError):
        when = datetime.datetime(1970, 1, 1, tzinfo=datetime.UTC)
    return when.strftime("D:%Y%m%d%H%M%SZ")


def _lines(doc: dict[str, Any]) -> list[str]:
    verify = doc["verify"]
    out = [f"Evidence report  {doc['schema']}", f"Run: {doc['run_id']}", f"Source: {doc['source']}"]
    out.append(f"Verification: {verify.get('verdict', 'pass' if verify.get('ok') else 'fail')}")
    out += ["", "Offline verification"]
    for check in verify.get("checks") or []:
        if isinstance(check, dict):
            out.append(f"  {check.get('outcome', '')!s:6} {check.get('name', '')}")
    out += ["", "Timeline"]
    for row in doc["timeline"]:
        out.append(f"  {row['index']:>4} {row['kind']:<12} {row['tool']:<20} {row['time']}")
    out += ["", "The canonical evidence JSON is attached as evidence.json."]
    wrapped: list[str] = []
    for line in out:
        line = line.encode("latin-1", "replace").decode("latin-1")
        wrapped += [line[i : i + _WIDTH] for i in range(0, max(len(line), 1), _WIDTH)]
    return wrapped


def _escape(text: str) -> bytes:
    raw = text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    return raw.encode("latin-1", "replace")


def render_pdf(doc: dict[str, Any]) -> bytes:
    try:
        import pikepdf
    except ImportError as exc:
        raise PdfUnavailable("PDF reports need pikepdf: pip install 'opentine[pdf]'") from exc
    pdf = pikepdf.new()
    font = pdf.make_indirect(
        pikepdf.Dictionary(
            Type=pikepdf.Name.Font, Subtype=pikepdf.Name.Type1, BaseFont=pikepdf.Name.Courier
        )
    )
    lines = _lines(doc)
    for start in range(0, len(lines), _LINES_PER_PAGE):
        body = b"BT /F1 9 Tf 11 TL 36 806 Td\n"
        for line in lines[start : start + _LINES_PER_PAGE]:
            body += b"(" + _escape(line) + b") '\n"
        page = pikepdf.Page(
            pikepdf.Dictionary(
                Type=pikepdf.Name.Page,
                MediaBox=[0, 0, 595, 842],
                Resources=pikepdf.Dictionary(Font=pikepdf.Dictionary(F1=font)),
                Contents=pdf.make_stream(body + b"ET\n"),
            )
        )
        pdf.pages.append(page)
    run = doc.get("run") if isinstance(doc.get("run"), dict) else {}
    date = _pdf_date(run.get("created_at"))
    attachment = pikepdf.AttachedFileSpec(
        pdf,
        canonical(doc).encode("utf-8"),
        filename="evidence.json",
        mime_type="application/json",
        creation_date=date,
        mod_date=date,
        relationship=pikepdf.Name.Data,
    )
    pdf.attachments["evidence.json"] = attachment
    pdf.Root.AF = pikepdf.Array([attachment.obj])
    pdf.docinfo = pdf.make_indirect(
        pikepdf.Dictionary(
            Title=pikepdf.String(f"tine evidence {doc['run_id']}"),
            CreationDate=pikepdf.String(date),
            ModDate=pikepdf.String(date),
        )
    )
    buffer = io.BytesIO()
    pdf.save(
        buffer,
        deterministic_id=True,
        compress_streams=False,
        object_stream_mode=pikepdf.ObjectStreamMode.disable,
    )
    return buffer.getvalue()


__all__ = ["PdfUnavailable", "render_pdf"]
