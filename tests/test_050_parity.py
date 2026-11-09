"""0.50 (ROADMAP 1.0 criterion 2): Python, TS and pyz agree on every pinned vector.

``scripts/check_parity.py`` asks the reference adapter, the built
``tine-verify.pyz`` and (when ``ts/verifier`` is built) the TS verifier for
every case of the suite and fails on any disagreement or gap. CI runs it with
``--require-ts`` in the ``parity`` job; here the TS column runs only when a
build is present, so the suite stays offline.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

from tests import freeze_inventory as inventory

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check_parity.py"


def _module():
    spec = importlib.util.spec_from_file_location("check_parity", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_every_implementation_agrees_on_every_case(capsys):
    assert _module().run() == 0
    out = capsys.readouterr().out
    assert "parity: ok (0 disagreement(s) or gap(s))" in out
    manifest = json.loads((ROOT / "docs/conformance/MANIFEST.json").read_text("utf-8"))
    assert f"total: {manifest['totals']['cases']} cases" in out


def test_a_disagreement_fails_the_check(monkeypatch, capsys):
    module = _module()
    real = module._records

    def tampered() -> dict:
        records = real()
        records["fleet.tofu"] = {**records["fleet.tofu"], "output": {"state": "forged"}}
        return records

    monkeypatch.setattr(module, "_records", tampered)
    assert module.run() == 1
    captured = capsys.readouterr()
    assert "pyz disagrees: fleet.tofu" in captured.err
    assert "python disagrees: fleet.tofu" in captured.err


def test_only_repository_storage_is_outside_the_pyz():
    """The pyz's exclusions are the storage families, by name, and nothing else."""
    assert set(inventory.STORAGE) == {
        "16-bounds", "22-layout", "24-refs", "26-reflog", "27-shallow", "28-pack",
        "29-localpack", "99-repair",
    }  # fmt: skip


def test_the_freeze_page_lists_every_inventoried_kind_and_family():
    page = (ROOT / "docs" / "FREEZE.md").read_text("utf-8")
    rows = {line.split("|")[1].strip(): line for line in page.splitlines() if line.startswith("| ")}
    for kind, (_section, names, _schemas, families, _pyz) in inventory.KINDS.items():
        assert kind in rows, f"docs/FREEZE.md has no row for {kind}"
        for item in (*names, *families):
            assert item in rows[kind], (kind, item)
    assert "SPEC.md#s-5.5" in page and "scripts/check_parity.py" in page


def test_ci_runs_the_parity_check_with_the_ts_column_required():
    workflow = (ROOT / ".github/workflows/ci.yml").read_text("utf-8")
    assert "scripts/check_parity.py --require-ts" in workflow


def test_a_pyz_crash_is_not_a_refusal(monkeypatch, capsys):
    """A pyz that raises a programming error on a reject case does not agree with it."""
    module = _module()
    real = module._built_pyz

    class Crashing:
        def __init__(self, inner):
            self._inner = inner

        def __getattr__(self, name):
            return getattr(self._inner, name)

        def answer(self, op, *args):
            if op == "artifact.parse":
                raise KeyError("bug")
            return self._inner.answer(op, *args)

    @module.contextlib.contextmanager
    def crashing():
        with real() as conform:
            yield Crashing(conform)

    monkeypatch.setattr(module, "_built_pyz", crashing)
    assert module.run() == 1
    assert "pyz disagrees: artifact.duplicate-key" in capsys.readouterr().err


def test_a_ts_disagreement_gap_or_stray_skip_fails_the_check(monkeypatch, capsys):
    """The TS column fails the check on a failed case, a missing row or a stray skip."""
    module = _module()
    ids = list(module._records())
    writer_skips = ("redact.blob.assignment", "sig.attest.sign-covers-the-stored-claim")
    changes = [
        (lambda r: r["fleet.tofu"].update(status="fail", detail="x"), "ts disagrees: fleet.tofu"),
        (lambda r: r.pop("fleet.tofu"), "ts gap: fleet.tofu"),
        (lambda r: r["fleet.tofu"].update(status="skip"), "ts gap: fleet.tofu"),
        (lambda r: r["fleet.tofu"].update(status="unsupported"), "ts disagrees: fleet.tofu"),
    ]
    for change, message in changes:
        rows = {cid: {"id": cid, "status": "pass", "reason": None, "detail": ""} for cid in ids}
        for cid in writer_skips:
            rows[cid]["status"] = "skip"
        change(rows)
        monkeypatch.setattr(module, "_ts_rows", lambda rows=rows: rows)
        assert module.run(require_ts=True) == 1
        assert message in capsys.readouterr().err
