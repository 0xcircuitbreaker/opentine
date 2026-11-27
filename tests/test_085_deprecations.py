"""0.85: owner-approved deprecations warn and keep working (docs/DEPRECATION.md)."""

from __future__ import annotations

import argparse
import warnings

import pytest

from opentine import _cli_deprecated, _cli_groups, _cli_registry


@pytest.mark.parametrize("call", [
    lambda: __import__("opentine.policies", fromlist=["x"]).secure_profile("."),
    lambda: __import__("opentine.policies", fromlist=["x"]).dev_profile("."),
    lambda: __import__("opentine.policies", fromlist=["x"]).isolated_profile("."),
    lambda: __import__("opentine.billing.engine", fromlist=["x"]).now_utc(),
    lambda: __import__("opentine.remote.backend", fromlist=["x"]).valid_ref("heads/main"),
])  # fmt: skip
def test_deprecated_python_names_warn_and_still_answer(call):
    with pytest.warns(DeprecationWarning, match="deprecated since 0.85"):
        assert call() is not None


def test_execute_unsafe_legacy_warns(monkeypatch):
    from opentine.tools import python as pytool

    monkeypatch.setattr(pytool, "run_bounded", lambda *a, **k: (_ for _ in ()).throw(OSError("x")))
    with pytest.warns(DeprecationWarning, match="execute_unsafe_legacy"):
        assert pytool.execute_unsafe_legacy("print(1)").startswith("Error:")


def test_linked_objects_warns():
    from opentine.repository import ops

    with pytest.warns(DeprecationWarning, match="linked_objects"):
        with pytest.raises(Exception):  # noqa: B017 - no repository: only the warning matters
            ops.linked_objects(None, "sha256:" + "0" * 64)  # type: ignore[arg-type]


@pytest.mark.parametrize("old,new", [(["keys", "lint"], ["key", "lint"]),
                                     (["plugin", "export", "d"], ["plugins", "export", "d"]),
                                     (["price", "r1"], ["pricing", "reprice", "r1"])])  # fmt: skip
def test_old_nouns_print_a_notice_and_the_new_ones_reach_the_same_verb(old, new, capsys,
                                                                       monkeypatch):  # fmt: skip
    monkeypatch.delenv("OPENTINE_NO_DEPRECATION", raising=False)
    _cli_groups.notice(old)
    assert " ".join(new[:2]) in capsys.readouterr().err
    _cli_groups.notice(new)
    assert capsys.readouterr().err == ""
    assert _cli_groups.rewrite(new)[: len(old) - 1] == old[: len(old) - 1]
    monkeypatch.setenv("OPENTINE_NO_DEPRECATION", "1")
    _cli_groups.notice(old)
    assert capsys.readouterr().err == ""
    assert set(_cli_registry.DEPRECATED) == {"keys", "plugin", "price"}


def test_sign_key_is_an_alias_of_key_with_one_notice(capsys, monkeypatch):
    monkeypatch.delenv("OPENTINE_NO_DEPRECATION", raising=False)
    monkeypatch.setattr(_cli_deprecated, "_SEEN", set())
    parser = argparse.ArgumentParser()
    parser.add_argument("--key", "--sign-key", dest="sign_key",
                        action=_cli_deprecated.SignKeyAction)  # fmt: skip
    assert parser.parse_args(["--key", "a"]).sign_key == "a"
    assert capsys.readouterr().err == ""
    assert parser.parse_args(["--sign-key", "b"]).sign_key == "b"
    assert parser.parse_args(["--sign-key", "c"]).sign_key == "c"
    assert capsys.readouterr().err.count("--sign-key") == 1


def test_every_sign_key_command_takes_key():
    from opentine import cli

    parser = cli._build_parser()
    seen, stack = 0, [parser]
    while stack:
        current = stack.pop()
        for action in current._actions:
            if isinstance(action, argparse._SubParsersAction):
                stack.extend(action.choices.values())
            elif "--sign-key" in action.option_strings and action.dest == "sign_key":
                seen += 1
                if isinstance(action, _cli_deprecated.SignKeyAction):
                    assert "--key" in action.option_strings
    assert seen >= 6


def test_no_warning_without_a_deprecated_call():
    from opentine.policies import PolicySet

    with warnings.catch_warnings():
        warnings.simplefilter("error")
        PolicySet()
