"""Group spellings (``tine repo storage gc``) resolve exactly like the old verbs."""

from __future__ import annotations

import pytest

from opentine import _cli_groups, _cli_registry, cli

from .cli_group_pairs import PAIRS
from .test_cli_alias_compat import plain, v3  # noqa: F401  (fixtures)

# Recorded per invocation, not part of what the handler is asked to do.
_VOLATILE = {"tine_argv"}


def _resolved(argv):
    parser, args = cli.parse(list(argv))
    handler, args, via_repo = cli.resolve(parser, args)
    fields = {k: v for k, v in vars(args).items() if k not in _VOLATILE}
    return handler, via_repo, fields


@pytest.mark.parametrize("pair", PAIRS, ids=[" ".join(p[2]) for p in PAIRS])
def test_group_spelling_matches_old_spelling(pair, request) -> None:
    where, old, new = pair
    request.getfixturevalue(where)
    assert _resolved(new) == _resolved(old)


def test_every_group_word_has_a_pair() -> None:
    for group, (_, words) in _cli_registry.GROUPS.items():
        mine = [new for _, _, new in PAIRS if new[0] == group]
        spelled = {tuple(new[1:3]) for new in mine} | {(new[1],) for new in mine}
        for key in words:
            assert key in spelled, (group, key)


def test_agent_group_keeps_its_own_subcommands(plain) -> None:  # noqa: F811
    for word in ("id", "show", "trust", "keys"):
        assert _cli_groups.rewrite(["agent", word, "x"]) == ["agent", word, "x"]
    words = {key[0] for key in _cli_registry.GROUPS["agent"][1]}
    assert words.isdisjoint({"id", "show", "trust", "keys"})
    _, args = cli.parse(["agent", "who", "--json"])
    assert args.command == "who" and args.json


def test_verify_routes_a_bundle_file_only(plain) -> None:  # noqa: F811
    from opentine._bundle import MAGIC

    (plain / "b.tbundle").write_bytes(MAGIC + b"x" * 40)
    (plain / "r.tine").write_bytes(b"{}")
    assert _resolved(["verify", "b.tbundle"]) == _resolved(["bundle", "verify", "b.tbundle"])
    assert _cli_groups.rewrite(["verify", "r.tine"]) == ["verify", "r.tine"]
    assert _cli_groups.rewrite(["verify", "missing"]) == ["verify", "missing"]
    flagged = ["verify", "b.tbundle", "--require-signature"]
    assert _cli_groups.rewrite(flagged) == flagged


def test_original_argv_is_recorded(plain) -> None:  # noqa: F811
    _, args = cli.parse(["repo", "storage", "gc", "--json"])
    assert args.tine_argv == ["repo", "storage", "gc", "--json"]
    assert args.command == "gc" and args.json


def test_passthrough_tail_is_never_rewritten() -> None:
    argv = ["repo", "migrate", "r1", "--", "--to-v3"]
    assert _cli_groups.rewrite(argv) == ["migrate", "r1", "--", "--to-v3"]
    assert _cli_groups.rewrite(["repo", "migrate", "--to-v3", "x"]) == ["migrate-v3", "x"]
    assert _cli_groups.rewrite(["gc"]) == ["gc"]


def test_builtin_group_beats_a_trusted_alias_and_warns(v3, capsys) -> None:  # noqa: F811
    cli.main(["config", "alias.repo", "log"])
    capsys.readouterr()
    _, args = cli.parse(["repo", "storage", "du"])
    assert args.command == "du"
    assert "alias.repo is shadowed" in capsys.readouterr().err


def test_deprecation_notice_is_opt_in(plain, monkeypatch, capsys) -> None:  # noqa: F811
    cli.parse(["gc"])
    assert capsys.readouterr().err == ""
    monkeypatch.setitem(_cli_registry.DEPRECATED, "gc", "tine repo storage gc")
    monkeypatch.setattr(_cli_groups, "DEPRECATED", _cli_registry.DEPRECATED)
    cli.parse(["gc", "--json"])
    assert "tine repo storage gc" in capsys.readouterr().err
    cli.parse(["repo", "storage", "gc"])  # the new spelling never warns
    assert capsys.readouterr().err == ""
    monkeypatch.setenv("OPENTINE_NO_DEPRECATION", "1")
    cli.parse(["gc"])
    assert capsys.readouterr().err == ""


def test_help_lists_group_subcommands(capsys) -> None:
    with pytest.raises(SystemExit):
        cli.main(["repo", "--help"])
    out = capsys.readouterr().out
    for word in ("init", "storage", "integrate", "migrate"):
        assert word in out
    cli.main(["help", "repo"])
    assert "storage" in capsys.readouterr().out
