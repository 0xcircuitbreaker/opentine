"""A case-insensitive filesystem (macOS, Windows) must not let a case variant slip past."""

import pytest

from opentine._cli_auditor import _check_placement


def test_a_case_variant_of_the_repository_path_is_refused(tmp_path):
    repo = tmp_path / "Repo"
    repo.mkdir()
    variant = tmp_path / "rEPO" / "g1.json"
    with pytest.raises(ValueError, match="inside the repository"):
        _check_placement(variant, [repo], False)


def test_the_opt_in_still_applies_to_a_case_variant(tmp_path):
    repo = tmp_path / "Repo"
    repo.mkdir()
    _check_placement(tmp_path / "rEPO" / "g1.json", [repo], True)
