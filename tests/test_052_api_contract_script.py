"""0.52: scripts/check_api_contract.py reports /api/* routes the OpenAPI document lacks."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "api_contract" / "staging-routes.txt"


def _script():
    spec = importlib.util.spec_from_file_location(
        "check_api_contract", ROOT / "scripts" / "check_api_contract.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_fixture_reports_exactly_the_undocumented_routes(capsys):
    assert _script().main([str(FIXTURE)]) == 1
    out = capsys.readouterr().out.splitlines()
    assert out[:-1] == [
        "undocumented: GET /api/tenants/:tenant/billing",
        "undocumented: POST /api/tenants/:tenant/members/:subject",
    ]
    assert out[-1] == "15 /api routes checked, 2 undocumented"


def test_json_dumps_and_a_clean_list_pass(tmp_path, capsys):
    dump = tmp_path / "routes.json"
    rows = [
        {"method": "get", "path": "/api/capabilities"},
        {"method": "GET", "path": "/api/tenants/:t/holds"},
    ]
    dump.write_text(json.dumps(rows), encoding="utf-8")
    assert _script().main([dump.as_posix()]) == 0
    assert capsys.readouterr().out.strip() == "2 /api routes checked, 0 undocumented"


def test_another_prefix_mapping_and_an_unreadable_dump(tmp_path, capsys):
    dump = tmp_path / "routes.txt"
    dump.write_text("GET /backend/session\nGET /backend/nope\n", encoding="utf-8")
    assert _script().main([dump.as_posix(), "--map", "/backend=/v1"]) == 1
    assert "undocumented: GET /backend/nope" in capsys.readouterr().out
    dump.write_text("not a route line\n", encoding="utf-8")
    assert _script().main([dump.as_posix()]) == 2
