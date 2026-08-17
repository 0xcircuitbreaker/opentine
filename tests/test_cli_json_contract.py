"""One ``--json`` contract, one serializer, one receipt — pinned.

Phase 4 of the Interop release is about *not drifting*. Three near-duplicates
had grown up in the CLI, and each one is a place where two commands could start
disagreeing without any test noticing:

1. **``tine pricing`` was half scriptable.** ``show`` had ``--json``; ``list``,
   ``check`` and ``update`` did not, so the one command family a CI job most
   wants to diff — what a model costs — could only be screen-scraped. All four
   take it now, all four go through the shared writer, and the module docstring
   of ``_cli_json_pricing`` *is* the schema: the key sets are read back out of
   it, so a field added without a line of prose fails here.
2. **``tine export`` re-spelled ``json.dumps``.** Its ``--output``/wire path had
   its own copy of the parameters ``emit`` uses. One serializer now, so the
   document a collector receives and the document a file gets cannot diverge.
3. **``tine run`` had three receipts.** Script mode, ``--harness`` and
   ``--model`` each wrote their own save + ``Saved:`` + tree tail. One helper
   now, and the literal lives in exactly one module.

Plus two facts about the surface that documentation kept getting wrong: how many
subcommands ``tine`` actually ships, and that the five v3 plumbing verbs emit
bare JSON *by design* and take no ``--json`` flag.

Everything is driven in process through ``opentine.cli.main(argv)``; nothing
shells a binary.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from opentine import cli
from opentine._cli_json import emit, serialize
from opentine.billing import BUNDLED_CATALOG, PricingCatalog, load_catalogs
from opentine.repo_cli import REPO_COMMANDS

ROOT = Path(cli.__file__).resolve().parents[1]
PACKAGE = Path(cli.__file__).parent
#: The v3 verbs that print bare JSON unconditionally. Their bytes are pinned by
#: tests/test_repo_cli_routing.py; this file only pins the *policy*.
PLUMBING_VERBS = ("fsck", "object", "migrate-v3", "fetch", "push")


def _invoke(capsys, *argv: str) -> tuple[int, str]:
    """Drive one in-process ``tine`` invocation; return (exit code, stdout)."""
    code = 0
    try:
        cli.main(list(argv))
    except SystemExit as exc:
        code = int(exc.code or 0)
    return code, capsys.readouterr().out


def _payload(capsys, *argv: str) -> tuple[int, dict]:
    code, out = _invoke(capsys, *argv)
    return code, json.loads(out)


def _documented_keys(section: str) -> set[str]:
    """The keys one ``tine ...`` section of ``_cli_json_pricing``'s docstring lists."""
    from opentine import _cli_json_pricing

    blocks = [
        block
        for block in (_cli_json_pricing.__doc__ or "").split("``tine ")
        if block.startswith(section)
    ]
    assert len(blocks) == 1, f"{section!r} is not one heading in the docstring"
    return set(re.findall(r"^    ``(\w+)``", blocks[0], re.MULTILINE))


# --------------------------------------------------------------------------- #
# tine pricing --json
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "argv",
    [
        ("pricing", "list", "--provider", "mistral"),
        ("pricing", "show", "kimi", "kimi-k2.6"),
        ("pricing", "check"),
    ],
)
def test_pricing_default_rendering_is_unchanged_and_is_not_json(capsys, argv) -> None:
    code, printed = _invoke(capsys, *argv)

    assert code == 0
    with pytest.raises(json.JSONDecodeError):
        json.loads(printed)


def test_pricing_list_json_is_the_documented_object_and_honours_the_filters(capsys) -> None:
    code, payload = _payload(capsys, "pricing", "list", "--json", "--provider", "mistral")

    assert code == 0
    assert set(payload) == _documented_keys("pricing list --json")
    assert payload["command"] == "pricing-list"
    catalog = load_catalogs()
    assert payload["catalog_id"] == catalog.id and payload["catalog_hash"] == catalog.hash
    assert payload["count"] == len(payload["cards"]) > 0
    assert {card["provider"] for card in payload["cards"]} == {"mistral"}
    # The listing is the table's order, not the catalog's.
    keys = [(card["provider"], card["model"], card["effective_from"]) for card in payload["cards"]]
    assert keys == sorted(keys)


def test_pricing_list_json_filters_can_select_nothing_without_failing(capsys) -> None:
    code, payload = _payload(capsys, "pricing", "list", "--json", "--provider", "no-such-provider")

    assert code == 0
    assert payload["count"] == 0 and payload["cards"] == []


def test_pricing_show_json_keeps_its_flattened_card_and_names_its_catalog(capsys) -> None:
    code, payload = _payload(capsys, "pricing", "show", "kimi", "kimi-k2.6", "--json")

    assert code == 0
    assert _documented_keys("pricing show PROVIDER MODEL --json") <= set(payload)
    catalog = load_catalogs()
    card = catalog.lookup("kimi", "kimi-k2.6")
    assert payload == {
        "command": "pricing-show",
        "catalog_id": catalog.id,
        "catalog_hash": catalog.hash,
        **json.loads(json.dumps(card.to_dict())),
    }


def test_pricing_check_json_is_the_documented_object(capsys) -> None:
    code, payload = _payload(capsys, "pricing", "check", "--json")

    assert code == 0
    assert set(payload) == _documented_keys("pricing check PATH --json")
    assert payload["command"] == "pricing-check"
    assert payload["ok"] is True and payload["signed"] is True and payload["state"] == "signed"
    assert payload["path"] == str(BUNDLED_CATALOG)
    # check reports the file it read, not the effective overlay: it is the
    # bundled catalog's own id and card count that must come back.
    bundled = PricingCatalog.load(BUNDLED_CATALOG)
    assert payload["catalog_id"] == bundled.id and payload["catalog_hash"] == bundled.hash
    assert payload["cards"] == len(bundled.cards) > 0


def test_pricing_update_json_is_the_documented_object_and_still_installs(capsys, tmp_path) -> None:
    dest = tmp_path / "catalog.json"

    code, payload = _payload(
        capsys, "pricing", "update", str(BUNDLED_CATALOG), "--dest", str(dest), "--json"
    )

    assert code == 0
    assert dest.is_file(), "--json must not turn the install into a dry run"
    assert set(payload) == _documented_keys("pricing update SOURCE --json")
    assert payload["command"] == "pricing-update"
    assert payload["source"] == str(BUNDLED_CATALOG) and payload["dest"] == str(dest)
    assert payload["signed"] is True and payload["cards"] > 0


def test_pricing_failure_stays_human_text_and_exits_one(capsys, tmp_path) -> None:
    """A catalog that will not load is not an object with ``ok: false``."""
    broken = tmp_path / "broken.json"
    broken.write_text('{"schema": "opentine-pricing/1"}', encoding="utf-8")

    code, printed = _invoke(capsys, "pricing", "check", str(broken), "--json")

    assert code == 1
    with pytest.raises(json.JSONDecodeError):
        json.loads(printed)


def test_every_pricing_subcommand_takes_json(capsys) -> None:
    """No pricing verb may be human-only: the flag is added in one loop."""
    for verb in ("list", "show", "check", "update"):
        code, printed = _invoke(capsys, "pricing", verb, "--help")
        assert code == 0
        assert "--json" in printed, f"pricing {verb} lost --json"


# --------------------------------------------------------------------------- #
# one serializer
# --------------------------------------------------------------------------- #


def test_emit_is_serialize(capsys) -> None:
    payload = {"b": 1, "a": {"z": [1, 2], "y": "✓"}}

    emit(payload)

    assert capsys.readouterr().out == serialize(payload) + "\n"
    assert serialize(payload, indent=None) == json.dumps(
        json.loads(serialize(payload)), sort_keys=True
    )


def test_export_does_not_respell_the_serializer() -> None:
    """Export's stdout, file and wire bodies must all come from one function."""
    source = (PACKAGE / "_cli_export.py").read_text(encoding="utf-8")

    assert "json.dumps" not in source, "export grew its own JSON spelling again"
    assert source.count("serialize(") >= 2, "export must serialize both the file and the wire body"


def test_export_stdout_and_output_file_are_the_same_bytes(tmp_path, capsys, monkeypatch) -> None:
    from opentine import Run, RunStatus, StepKind

    monkeypatch.chdir(tmp_path)
    run = Run(id="serializer_shared", model_info="mock-model", user_prompt="prompt")
    step = run.add_step(StepKind.model, {"text": "ask"}, {"text": "answer"}, usage={"input": 3})
    run.add_step(StepKind.done, {"text": "done"}, parent_id=step.id)
    run.status = RunStatus.completed
    artifact = tmp_path / "run.tine"
    run.save(artifact)

    code, printed = _invoke(capsys, "export", str(artifact))
    assert code == 0

    written = tmp_path / "spans.json"
    code, _ = _invoke(capsys, "export", str(artifact), "--output", str(written))
    assert code == 0
    assert written.read_text(encoding="utf-8") == printed


# --------------------------------------------------------------------------- #
# one run receipt
# --------------------------------------------------------------------------- #


def test_the_saved_receipt_has_exactly_one_home() -> None:
    """Script, --harness and --model modes must not each print their own tail."""
    owners = sorted(
        path.name
        for path in PACKAGE.glob("_cli_*.py")
        if "BRAND}]Saved:" in path.read_text(encoding="utf-8")
    )

    assert owners == ["_cli_import.py", "_cli_render.py"], (
        "the tine run receipt was copied again; it belongs to _cli_render._save_run_receipt "
        "(_cli_import writes a different, one-line import receipt)"
    )


def test_all_three_run_modes_end_in_the_shared_receipt() -> None:
    execute = (PACKAGE / "_cli_execute.py").read_text(encoding="utf-8")
    run_model = (PACKAGE / "_cli_run_model.py").read_text(encoding="utf-8")

    # script mode and --harness live in _cli_execute; --model in _cli_run_model.
    # The tail now also takes the overwrite waiver: script and --model pass the
    # user's ``args.force``, while --harness claims the slot before the agent
    # starts (it checkpoints into --save) and so finishes writing its own file.
    assert execute.count("_save_run_receipt(run, args.save, args.force)") == 1
    assert execute.count("_save_run_receipt(run, args.save, force=True)") == 1
    assert run_model.count("_save_run_receipt(run, args.save, args.force)") == 1


def test_shared_receipt_writes_the_default_location_and_returns_it(
    tmp_path, capsys, monkeypatch
) -> None:
    from opentine import Run, RunStatus, StepKind
    from opentine._cli_render import _save_run_receipt

    run = Run(id="receipt_shared", model_info="mock-model", user_prompt="prompt")
    run.add_step(StepKind.done, {"text": "done"})
    run.status = RunStatus.completed

    chosen = _save_run_receipt(run, str(tmp_path / "explicit.tine"))
    printed = capsys.readouterr().out
    assert chosen == tmp_path / "explicit.tine" and chosen.is_file()
    assert "Saved:" in printed.replace("\n", "") and "receipt_" in printed

    import opentine._cli_common as common

    monkeypatch.setattr(common, "RUNS_DIR", tmp_path / ".tine_runs")
    default = _save_run_receipt(run, None)
    capsys.readouterr()
    assert default == tmp_path / ".tine_runs" / f"{run.id}.tine" and default.is_file()


# --------------------------------------------------------------------------- #
# the surface the docs describe
# --------------------------------------------------------------------------- #


def test_readme_states_the_real_subcommand_count() -> None:
    """README's headline number is the router's, not a number someone remembered."""
    readme = ROOT / "README.md"
    if not readme.is_file():  # pragma: no cover - source checkout only
        pytest.skip("README.md is not part of an installed distribution")
    stated = re.findall(r"`tine` ships (\d+) subcommands", readme.read_text(encoding="utf-8"))

    assert len(stated) == 1, "README must state the subcommand count exactly once"
    assert int(stated[0]) == len(cli.LEGACY_COMMANDS) + len(REPO_COMMANDS)


def test_plumbing_verbs_take_no_json_flag(capsys) -> None:
    """The five bare-JSON verbs are byte-pinned: a --json flag would imply a choice."""
    for verb in PLUMBING_VERBS:
        code, printed = _invoke(capsys, verb, "--help")
        assert code == 0
        assert "--json" not in printed, f"{verb} must emit bare JSON unconditionally"


def test_documented_json_verbs_all_actually_take_json() -> None:
    """Every verb the README lists under `--json` really accepts the flag."""
    import argparse

    from opentine._cli_parser import _build_parser

    parser = _build_parser()
    choices: dict[str, argparse.ArgumentParser] = {}
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            choices = dict(action.choices)
    documented = (
        "show verify ls search stats cost replay diff import tag repo-log repo-show repo-diff "
        "repo-search context repo-fork repo-resume attest evaluate promote"
    ).split()
    missing = [
        name
        for name in documented
        if not any(
            option == "--json"
            for action in choices[name]._actions
            for option in action.option_strings
        )
    ]

    assert missing == [], f"README promises --json for verbs that reject it: {missing}"
