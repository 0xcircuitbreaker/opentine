"""A deleted parent lineage record must fail the regression gate closed."""

from tests.key_roles_helpers import isolated_trust_config  # noqa: F401
from tests.test_072_trends_review import gate, trends
from tests.trends_helpers import build


def test_deleted_parent_record_fails_the_gate(tmp_path, capsys):
    root, v = build(tmp_path)
    f = root / ".tine" / "lineage" / "variants" / (v["child"][7:] + ".json")
    assert f.exists()
    f.unlink()
    out = trends(root, capsys)
    assert {"variant": v["worse"], "code": "lineage.parent-missing"} in out["unchecked"]
    assert gate(root, capsys) == 1
