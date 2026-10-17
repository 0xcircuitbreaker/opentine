"""0.10 final pass: a catalog's signature block cannot smuggle unsigned content.

The ``signature`` object sits outside the signed bytes, and its contents were
copied into every billed step's provenance. A validly signed catalog with a
padded signature (a cloned ``.tine/pricing.json``) therefore grew every run
record by the padding.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from opentine.billing._catalog_verify import signature_fields
from opentine.billing.catalog import BUNDLED_CATALOG, CatalogError, PricingCatalog

FIXTURE = Path(__file__).parent / "fixtures" / "pricing" / "release_catalog_2026_07_20.json"


def _bundled() -> dict:
    return json.loads(BUNDLED_CATALOG.read_text(encoding="utf-8"))


@pytest.mark.parametrize("extra", [{"note": "A" * 100_000}, {"pad": 1}, {"public_key": "x"}])
def test_a_signature_block_with_extra_fields_is_refused(extra):
    data = _bundled()
    data["signature"] = {**data["signature"], **extra}
    with pytest.raises(CatalogError, match="unexpected fields"):
        PricingCatalog.from_dict(data, source="ws/.tine/pricing.json")


@pytest.mark.parametrize("field", ["algorithm", "key_id", "value"])
def test_signature_fields_must_be_short_strings(field):
    data = _bundled()
    for bad in (None, 7, "x" * 10_000):
        data["signature"] = {**_bundled()["signature"], field: bad}
        with pytest.raises(CatalogError):
            PricingCatalog.from_dict(data)


def test_the_bundled_and_release_catalogs_still_load_signed():
    for path in (BUNDLED_CATALOG, FIXTURE):
        catalog = PricingCatalog.load(path)
        assert catalog.signed


def test_provenance_carries_only_the_known_signature_fields():
    data = _bundled()
    catalog = PricingCatalog.from_dict(data)
    (provenance,) = catalog.provenance
    assert set(provenance["signature"]) == {"algorithm", "key_id", "value"}
    # An unverified load (an opted-in unsigned overlay path) never copies extras.
    padded = copy.deepcopy(data)
    padded["signature"]["note"] = "A" * 100_000
    unverified = PricingCatalog.from_dict(padded, verify=False)
    (provenance,) = unverified.provenance
    assert provenance["signature"] == {
        key: data["signature"][key] for key in provenance["signature"]
    }
    assert "note" not in provenance["signature"]
    assert "A" * 1000 not in repr(provenance)


def test_signature_fields_drops_non_strings_and_oversized_values():
    assert signature_fields(None) is None
    assert signature_fields({"algorithm": "ed25519", "value": "v" * 300, "x": "y"}) == {
        "algorithm": "ed25519"
    }


# --- final pass 6 #3: a catalog layer that is not a regular file never blocks -- #


def _load_within(seconds: float, **kwargs):
    import threading

    from opentine.billing import catalog as catalog_module

    result: dict = {}

    def work():
        try:
            result["catalog"] = catalog_module.load_catalogs(**kwargs)
        except Exception as exc:  # noqa: BLE001 -- surfaced by the assertion below
            result["error"] = exc

    thread = threading.Thread(target=work, daemon=True)
    thread.start()
    thread.join(seconds)
    assert not thread.is_alive(), "pricing load blocked on a non-regular catalog file"
    return result


@pytest.mark.skipif(not hasattr(__import__("os"), "mkfifo"), reason="POSIX FIFOs")
@pytest.mark.parametrize("kind", ["fifo", "dev-zero", "dev-null-dir"])
def test_a_workspace_catalog_that_is_not_a_regular_file_is_skipped_not_read(
    tmp_path: Path, monkeypatch, kind
):
    import os

    from opentine.billing import catalog as catalog_module

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.delenv("OPENTINE_TRUST_WORKSPACE_PRICING", raising=False)
    overlay = tmp_path / "ws" / ".tine" / "pricing.json"
    overlay.parent.mkdir(parents=True)
    if kind == "fifo":
        os.mkfifo(overlay)
    elif kind == "dev-zero":
        overlay.symlink_to("/dev/zero")
    else:
        overlay.mkdir()
    skipped: list[Path] = []
    monkeypatch.setattr(catalog_module, "workspace_overlay_hook", skipped.append)

    result = _load_within(5.0, workspace=tmp_path / "ws")

    assert "error" not in result, result.get("error")
    assert result["catalog"].lookup("anthropic", "claude-opus-5-5") is not None
    assert skipped == [overlay]


def test_reading_a_device_or_fifo_catalog_raises_instead_of_blocking(tmp_path: Path):
    import os

    if not hasattr(os, "mkfifo"):
        pytest.skip("POSIX FIFOs")
    fifo = tmp_path / "pricing.json"
    os.mkfifo(fifo)
    with pytest.raises(CatalogError, match="not a regular file"):
        PricingCatalog.load(fifo)


def test_a_symlink_to_a_regular_catalog_file_still_loads(tmp_path: Path):
    link = tmp_path / "pricing.json"
    link.symlink_to(BUNDLED_CATALOG)
    assert PricingCatalog.load(link).signed
