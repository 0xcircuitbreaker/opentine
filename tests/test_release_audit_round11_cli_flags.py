"""Round 11 release-audit regressions: no `tine` flag may be silently dropped.

Round 10 closed the silent-ignore class in ``tine run``/``fork``/``replay`` and
built ``opentine._cli_flags`` for it.  It then *reported* two more instances it
was not allowed to touch, which this module closes together with every sibling
found by a mechanical sweep of the parser against the handlers:

* ``tine sign RUN --overwrite`` without ``--save`` accepted a flag the in-place
  signing path never consults (``_cli_security`` only guards a separate --save
  destination), so the artifact was rewritten and the flag reported nothing.
* ``tine migrate RUN --dry-run --save out.tine`` (and ``--in-place``) printed a
  preview and exited 0 having written nothing at the requested path.
* ``tine keygen --force`` with neither ``--out`` nor ``--pub`` prints both halves
  of the keypair to stdout, so there is no file for --force to replace: exactly
  the shape of ``sign --overwrite`` without ``--save``.
* ``tine verify RUN --pubkey P --trust-embedded-key`` ignored the TOFU request
  because ``verify_artifact`` prefers an explicit public key, and mixing HMAC key
  material with Ed25519 key material let the *artifact* choose which of the
  operator's keys was consulted — a signature downgrade that still exits 0.

The same sweep turned up two non-flag defects in the same handlers, where a flag
leads straight to an interpreter traceback instead of a message: an unreadable
``--key-file``/``--pubkey``/``--ed25519-key-file`` (OSError) and ``tine sign
RUN --force`` on an artifact that cannot be parsed at all (ValueError).

``test_no_flag_of_these_commands_is_silently_ignored`` is the class-level gate:
it runs every flag of the four commands this module owns against a baseline and
requires each one to change something observable or to be refused by name.  The
four documented exemptions carry their justification inline.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from opentine import Run, RunStatus, StepKind, cli
from opentine._cli_flags import FLAG_DEFAULTS, KEY_MATERIAL_FLAGS
from opentine._cli_parser import _build_parser
from opentine.signing import HAS_ED25519, generate_ed25519

ROOT = Path(__file__).resolve().parents[1]
LEGACY = ROOT / "tests" / "fixtures" / "golden_v0_linear.tine"
KEY_ENV = "TINE_ROUND11_KEY"
HMAC_KEY = "r" * 40
needs_ed25519 = pytest.mark.skipif(not HAS_ED25519, reason="ed25519 needs the crypto extra")


# --------------------------------------------------------------------------- #
# fixtures and a real end-to-end invoker
# --------------------------------------------------------------------------- #


def _source(path: Path) -> Run:
    run = Run(id="round11_source", model_info="mock-model", user_prompt="test prompt")
    run.add_step(StepKind.think, {"text": "thinking"})
    run.add_step(StepKind.done, {"text": "done"})
    run.status = RunStatus.completed
    run.save(path)
    return run


@pytest.fixture
def workspace(monkeypatch, tmp_path: Path) -> Path:
    """A directory holding every artifact and key the four commands need."""
    monkeypatch.setenv(KEY_ENV, HMAC_KEY)
    monkeypatch.setattr(cli, "RUNS_DIR", tmp_path / ".tine_runs")
    monkeypatch.chdir(tmp_path)
    run = _source(tmp_path / "source.tine")
    run.save(tmp_path / "signed.tine", sign_key=HMAC_KEY.encode(), sign_algorithm="hmac-sha256")
    (tmp_path / "hmac.key").write_text(HMAC_KEY + "\n", encoding="utf-8")
    (tmp_path / "adir").mkdir()
    shutil.copy(LEGACY, tmp_path / "legacy.tine")
    if HAS_ED25519:
        seed, public = generate_ed25519()
        (tmp_path / "ed.hex").write_text(seed + "\n", encoding="utf-8")
        (tmp_path / "ed.pub").write_text(public + "\n", encoding="utf-8")
        run.save(tmp_path / "ed.tine", sign_key=seed, sign_algorithm="ed25519")
    return tmp_path


def _invoke(monkeypatch, capsys, *argv: str) -> tuple[int, str]:
    """Drive ``cli.main()`` exactly as the console script does; return (code, output)."""
    monkeypatch.setattr(sys, "argv", ["tine", *argv])
    code = 0
    try:
        cli.main()
    except SystemExit as exc:  # the CLI's only failure channel
        code = int(exc.code or 0)
    # rich hard-wraps at the terminal width, so compare on collapsed whitespace.
    return code, re.sub(r"\s+", " ", capsys.readouterr().out)


# --------------------------------------------------------------------------- #
# (1) tine sign --overwrite without --save
# --------------------------------------------------------------------------- #


def test_sign_refuses_overwrite_without_save(workspace, monkeypatch, capsys):
    before = (workspace / "source.tine").read_bytes()

    code, out = _invoke(
        monkeypatch, capsys, "sign", "source.tine", "--key-env", KEY_ENV, "--overwrite"
    )

    assert code == 1
    assert "--overwrite has no effect without --save" in out
    assert "always rewrites the source artifact" in out
    assert (workspace / "source.tine").read_bytes() == before, "refusal still signed in place"


def test_sign_in_place_still_works_without_overwrite(workspace, monkeypatch, capsys):
    code, out = _invoke(monkeypatch, capsys, "sign", "source.tine", "--key-env", KEY_ENV)
    assert code == 0, out
    assert Run.verify_signature("source.tine", hmac_key=HMAC_KEY.encode()).ok


def test_sign_still_honours_overwrite_for_a_save_destination(workspace, monkeypatch, capsys):
    (workspace / "out.tine").write_text("occupied\n", encoding="utf-8")
    base = ["sign", "source.tine", "--key-env", KEY_ENV, "--save", "out.tine"]

    refused, out = _invoke(monkeypatch, capsys, *base)
    assert refused == 1 and "pass --overwrite to replace it" in out

    code, out = _invoke(monkeypatch, capsys, *base, "--overwrite")
    assert code == 0, out
    assert Run.verify_signature("out.tine", hmac_key=HMAC_KEY.encode()).ok


# --------------------------------------------------------------------------- #
# (2) tine migrate --dry-run with a destination
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("extra", "flag"),
    [(["--save", "out.tine"], "--save"), (["--in-place"], "--in-place")],
    ids=["save", "in-place"],
)
def test_migrate_refuses_a_destination_with_dry_run(workspace, monkeypatch, capsys, extra, flag):
    before = (workspace / "legacy.tine").read_bytes()

    code, out = _invoke(monkeypatch, capsys, "migrate", "legacy.tine", "--dry-run", *extra)

    assert code == 1
    assert f"{flag} has no effect with --dry-run" in out
    assert "A dry run only reports" in out
    assert not (workspace / "out.tine").exists(), "exited 1 but wrote the destination anyway"
    assert (workspace / "legacy.tine").read_bytes() == before


def test_migrate_still_previews_and_still_writes(workspace, monkeypatch, capsys):
    code, out = _invoke(monkeypatch, capsys, "migrate", "legacy.tine", "--dry-run")
    assert code == 0 and "Migration preview" in out
    assert not (workspace / "out.tine").exists()

    code, out = _invoke(monkeypatch, capsys, "migrate", "legacy.tine", "--save", "out.tine")
    assert code == 0, out
    assert Run.verify_integrity(workspace / "out.tine").ok

    code, out = _invoke(monkeypatch, capsys, "migrate", "legacy.tine", "--in-place")
    assert code == 0, out
    assert Run.load(workspace / "legacy.tine").format_version >= 2


def test_migrate_dry_run_still_honours_force_on_a_tampered_artifact(workspace, monkeypatch, capsys):
    """--force is *not* refused with --dry-run: the preview itself is fail-closed."""
    data = json.loads((workspace / "source.tine").read_text(encoding="utf-8"))
    data["metadata"]["integrity"]["digest"] = "0" * 64
    (workspace / "tampered.tine").write_text(json.dumps(data), encoding="utf-8")

    code, out = _invoke(monkeypatch, capsys, "migrate", "tampered.tine", "--dry-run")
    assert code == 1 and "Refusing to migrate" in out

    code, out = _invoke(monkeypatch, capsys, "migrate", "tampered.tine", "--dry-run", "--force")
    assert code == 0, out


# --------------------------------------------------------------------------- #
# (3) sibling: tine keygen --force with nothing to overwrite
# --------------------------------------------------------------------------- #


def test_keygen_refuses_force_when_it_writes_no_file(workspace, monkeypatch, capsys):
    code, out = _invoke(monkeypatch, capsys, "keygen", "--force")

    assert code == 1
    assert "--force has no effect without --out or --pub" in out
    assert "private (seed hex)" not in out, "a key was generated before the refusal"
    assert not list(workspace.glob("sweep*"))


def test_keygen_without_force_still_prints_a_keypair(workspace, monkeypatch, capsys):
    code, out = _invoke(monkeypatch, capsys, "keygen")
    assert code == 0 and "private (seed hex)" in out and "public (hex)" in out


@needs_ed25519
def test_keygen_still_honours_force_for_a_real_destination(workspace, monkeypatch, capsys):
    (workspace / "k.hex").write_text("occupied\n", encoding="utf-8")

    refused, out = _invoke(monkeypatch, capsys, "keygen", "--out", "k.hex")
    assert refused == 1 and "already exists" in out
    assert (workspace / "k.hex").read_text(encoding="utf-8") == "occupied\n"

    code, out = _invoke(monkeypatch, capsys, "keygen", "--out", "k.hex", "--force")
    assert code == 0, out
    assert len((workspace / "k.hex").read_text(encoding="utf-8").strip()) == 64


# --------------------------------------------------------------------------- #
# (4) sibling: tine verify accepted two keys and let the artifact pick one
# --------------------------------------------------------------------------- #

CONFLICTS = [
    (["--key-env", KEY_ENV], ["--key-file", "hmac.key"], False),
    (["--key-env", KEY_ENV], ["--pubkey", "ed.pub"], True),
    (["--key-env", KEY_ENV], ["--trust-embedded-key"], True),
    (["--key-file", "hmac.key"], ["--pubkey", "ed.pub"], True),
    (["--key-file", "hmac.key"], ["--trust-embedded-key"], True),
    (["--pubkey", "ed.pub"], ["--trust-embedded-key"], True),
]


@pytest.mark.parametrize(
    ("first", "second", "ed"),
    CONFLICTS,
    ids=lambda v: "+".join(v) if isinstance(v, list) else str(v),
)
def test_verify_refuses_two_pieces_of_key_material(
    workspace, monkeypatch, capsys, first, second, ed
):
    if ed and not HAS_ED25519:
        pytest.skip("ed25519 needs the crypto extra")

    code, out = _invoke(monkeypatch, capsys, "verify", "signed.tine", *first, *second)

    assert code == 1
    assert first[0] in out and second[0] in out
    assert "cannot be combined" in out
    assert "SIGNATURE OK" not in out, "verified against a key the artifact chose"


def test_verify_hmac_artifact_no_longer_reports_ok_while_ignoring_a_pinned_key(
    workspace, monkeypatch, capsys
):
    """The downgrade: an ed25519 pin plus a leaked HMAC key used to exit 0 on HMAC."""
    if not HAS_ED25519:
        pytest.skip("ed25519 needs the crypto extra")
    code, out = _invoke(
        monkeypatch, capsys, "verify", "signed.tine", "--pubkey", "ed.pub", "--key-env", KEY_ENV
    )
    assert code == 1 and "cannot be combined" in out


@pytest.mark.parametrize(
    "extra",
    [["--key-env", KEY_ENV], ["--key-file", "hmac.key"]],
    ids=["key-env", "key-file"],
)
def test_verify_still_honours_each_key_flag_on_its_own(workspace, monkeypatch, capsys, extra):
    code, out = _invoke(monkeypatch, capsys, "verify", "signed.tine", *extra)
    assert code == 0, out
    assert "SIGNATURE OK" in out and "alg=hmac-sha256" in out


@needs_ed25519
@pytest.mark.parametrize(
    ("extra", "marker"),
    [(["--pubkey", "ed.pub"], "SIGNATURE OK"), (["--trust-embedded-key"], "TOFU")],
    ids=["pubkey", "trust-embedded-key"],
)
def test_verify_still_honours_each_ed25519_flag_on_its_own(
    workspace, monkeypatch, capsys, extra, marker
):
    code, out = _invoke(monkeypatch, capsys, "verify", "ed.tine", *extra)
    assert code == 0, out
    assert marker in out


# --------------------------------------------------------------------------- #
# (5) a flag must not lead to a traceback either
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "argv",
    [
        ["verify", "signed.tine", "--key-file", "missing.key"],
        ["verify", "signed.tine", "--key-file", "adir"],
        ["verify", "signed.tine", "--pubkey", "missing.pub"],
        ["sign", "source.tine", "--key-file", "missing.key"],
        ["sign", "source.tine", "--key-file", "adir"],
        ["sign", "source.tine", "--algorithm", "ed25519", "--ed25519-key-file", "missing.hex"],
    ],
    ids=lambda argv: "-".join(argv[2:]).replace("--", ""),
)
def test_an_unreadable_key_file_is_reported_not_raised(workspace, monkeypatch, capsys, argv):
    code, out = _invoke(monkeypatch, capsys, *argv)
    assert code == 1
    assert "No such file" in out or "Is a directory" in out
    assert "FAILED" in out or "Signing failed" in out


def test_sign_reports_an_unparseable_artifact_that_force_waved_through(
    workspace, monkeypatch, capsys
):
    """--force waives the integrity refusal, and then Run.load met raw bytes."""
    (workspace / "corrupt.tine").write_text("not json at all", encoding="utf-8")

    code, out = _invoke(
        monkeypatch, capsys, "sign", "corrupt.tine", "--force", "--key-env", KEY_ENV
    )

    assert code == 1
    assert "Signing failed" in out and "Expecting value" in out


def test_the_cli_prints_no_traceback_for_a_mistyped_key_path(workspace):
    """End to end through the console entry point: stderr must stay empty."""
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    env[KEY_ENV] = HMAC_KEY
    result = subprocess.run(
        [sys.executable, "-m", "opentine.cli", "sign", "source.tine", "--key-file", "missing.key"],
        cwd=workspace,
        capture_output=True,
        text=True,
        env=env,
    )
    assert result.returncode == 1, result.stdout + result.stderr
    assert "Traceback" not in result.stderr, result.stderr
    assert "Signing failed" in result.stdout


# --------------------------------------------------------------------------- #
# class-level gate: sweep every flag of the four commands this module owns
# --------------------------------------------------------------------------- #

_HEX = re.compile(r"\b[0-9a-f]{16,}\b")
_VOLATILE = {"signed_at", "started_at", "ended_at", "created_at", "updated_at", "at", "timestamp"}


def _stable(value: object) -> object:
    """Strip the fields that differ between two identical invocations."""
    if isinstance(value, dict):
        return {k: _stable(v) for k, v in sorted(value.items()) if k not in _VOLATILE}
    if isinstance(value, list):
        return [_stable(item) for item in value]
    if isinstance(value, str):
        return _HEX.sub("<hex>", value)
    return value


def _snapshot(root: Path) -> dict[str, object]:
    """Everything an observer can see in the tree, minus timestamps and random hex."""
    out: dict[str, object] = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        raw = path.read_bytes()
        try:
            out[str(path.relative_to(root))] = _stable(json.loads(raw))
        except (UnicodeDecodeError, ValueError):
            try:
                out[str(path.relative_to(root))] = _HEX.sub("<hex>", raw.decode("utf-8"))
            except UnicodeDecodeError:
                out[str(path.relative_to(root))] = len(raw)
    return out


# (command, baseline argv, flag argv, expectation).  "honoured" = the flag must
# change something observable; "refused" = it must exit 1 naming itself.
SWEEP: list[tuple[list[str], list[str], str]] = [
    # tine sign
    (["sign", "source.tine", "--key-env", KEY_ENV], ["--overwrite"], "refused"),
    (["sign", "source.tine", "--key-env", KEY_ENV], ["--save", "out.tine"], "honoured"),
    (["sign", "source.tine", "--key-env", KEY_ENV], ["--key-id", "k1"], "honoured"),
    (["sign", "source.tine", "--key-env", KEY_ENV], ["--signer", "ops@example"], "honoured"),
    (["sign", "source.tine", "--key-env", KEY_ENV], ["--key-file", "hmac.key"], "refused"),
    (["sign", "source.tine", "--key-env", KEY_ENV], ["--algorithm", "ed25519"], "honoured"),
    (["sign", "source.tine", "--key-env", KEY_ENV], ["--ed25519-key-file", "ed.hex"], "refused"),
    (["sign", "tampered.tine", "--key-env", KEY_ENV], ["--force"], "honoured"),
    (
        ["sign", "source.tine", "--algorithm", "ed25519", "--ed25519-key-file", "ed.hex"],
        ["--key-env", KEY_ENV],
        "refused",
    ),
    # tine verify
    (["verify", "signed.tine"], ["--key-env", KEY_ENV], "honoured"),
    (["verify", "signed.tine"], ["--key-file", "hmac.key"], "honoured"),
    (["verify", "signed.tine"], ["--require-signature"], "honoured"),
    (["verify", "ed.tine"], ["--pubkey", "ed.pub"], "honoured"),
    (["verify", "ed.tine"], ["--trust-embedded-key"], "honoured"),
    (["verify", "signed.tine", "--key-env", KEY_ENV], ["--key-file", "hmac.key"], "refused"),
    (["verify", "signed.tine", "--key-env", KEY_ENV], ["--pubkey", "ed.pub"], "refused"),
    (["verify", "signed.tine", "--key-env", KEY_ENV], ["--trust-embedded-key"], "refused"),
    (["verify", "ed.tine", "--pubkey", "ed.pub"], ["--trust-embedded-key"], "refused"),
    # tine keygen
    (["keygen"], ["--force"], "refused"),
    (["keygen"], ["--out", "k.hex"], "honoured"),
    (["keygen"], ["--pub", "k.pub"], "honoured"),
    (["keygen", "--out", "k.hex"], ["--pub", "k.hex"], "refused"),
    # tine migrate
    (["migrate", "legacy.tine"], ["--save", "out.tine"], "honoured"),
    (["migrate", "legacy.tine"], ["--in-place"], "honoured"),
    (["migrate", "legacy.tine"], ["--to", "1"], "honoured"),
    (["migrate", "legacy.tine", "--dry-run"], ["--save", "out.tine"], "refused"),
    (["migrate", "legacy.tine", "--dry-run"], ["--in-place"], "refused"),
    (["migrate", "legacy.tine", "--save", "out.tine"], ["--in-place"], "refused"),
    (["migrate", "tampered.tine"], ["--force"], "honoured"),
    # --save onto a path that already holds an artifact: --force is the overwrite
    # waiver there, which is its second, independent job.
    (["migrate", "legacy.tine", "--save", "signed.tine"], ["--force"], "honoured"),
]

REFUSAL_PHRASES = ("no effect", "cannot be combined", "must name different files")

# The three combinations that are deliberately neither honoured nor refused, each
# with the reason.  Nothing else may join this list without the same argument.
EXEMPT = """
1. `tine migrate RUN --dry-run` with no destination: identical to the default,
   because printing the preview *is* what migrate does when given nowhere to
   write.  The flag only ever forces that default, and every command line where
   it could disagree with a destination is now refused above.
2. `tine sign RUN --force` / `tine migrate RUN --force` on an artifact whose
   integrity is intact, and `tine keygen --out P --force` when P does not exist:
   a waiver with nothing to waive.  Whether there is anything to waive depends on
   the artifact and the filesystem, not on the command line, so refusing it would
   make one command line valid or invalid according to a file's contents.
3. `tine verify RUN --require-signature` alongside a key: redundant rather than
   ignored.  Supplying a key already arms the fail-closed check, so the outcome
   is identical either way -- the flag never loses to another flag.
"""


@pytest.mark.parametrize(
    ("base", "extra", "expectation"), SWEEP, ids=lambda v: "+".join(v) if isinstance(v, list) else v
)
def test_no_flag_of_these_commands_is_silently_ignored(
    workspace, monkeypatch, capsys, base, extra, expectation
):
    if not HAS_ED25519 and any("ed" in part for part in base + extra):
        pytest.skip("ed25519 needs the crypto extra")
    data = json.loads((workspace / "source.tine").read_text(encoding="utf-8"))
    data["metadata"]["integrity"]["digest"] = "0" * 64
    (workspace / "tampered.tine").write_text(json.dumps(data), encoding="utf-8")

    base_code, base_out, base_files = _in_a_copy(workspace, monkeypatch, capsys, base, "base")
    code, out, files = _in_a_copy(workspace, monkeypatch, capsys, [*base, *extra], "flag")

    if expectation == "refused":
        assert code == 1, f"{extra} was accepted: {out}"
        assert extra[0] in out, f"{extra} was refused without naming itself: {out}"
        assert any(phrase in out for phrase in REFUSAL_PHRASES), out
        return
    assert (code, out, files) != (base_code, base_out, base_files), (
        f"{extra} changed nothing observable: exit {code}, same output, same files"
    )


def _in_a_copy(
    workspace: Path, monkeypatch, capsys, argv: list[str], name: str
) -> tuple[int, str, dict[str, object]]:
    """Run *argv* in a pristine copy of the workspace so the two halves cannot interact."""
    room = workspace.parent / name
    shutil.rmtree(room, ignore_errors=True)
    shutil.copytree(workspace, room)
    monkeypatch.chdir(room)
    monkeypatch.setattr(cli, "RUNS_DIR", room / ".tine_runs")
    code, out = _invoke(monkeypatch, capsys, *argv)
    return code, out, _snapshot(room)


def test_the_sweep_covers_every_flag_of_the_commands_this_module_owns():
    """The table above is the audit result; a new flag must land in it or fail here."""
    parser = _build_parser()
    subs = next(
        action for action in parser._actions if hasattr(action, "choices") and action.choices
    )
    exercised = {token for _, extra, _ in SWEEP for token in extra if token.startswith("--")}
    exercised |= {token for base, _, _ in SWEEP for token in base if token.startswith("--")}
    missing = []
    for command in ("sign", "verify", "keygen", "migrate"):
        for action in subs.choices[command]._actions:
            for option in action.option_strings:
                if option in ("-h", "--help") or option in exercised:
                    continue
                if option == "--dry-run":  # exemption 1, argued in EXEMPT
                    continue
                missing.append(f"tine {command} {option}")
    assert not missing, f"flags outside the round-11 sweep table: {missing}"
    assert "waiver with nothing to waive" in EXEMPT


def test_key_material_flags_are_declared_with_their_parser_defaults():
    """`given()` reads FLAG_DEFAULTS, so a missing entry raises instead of refusing."""
    parser = _build_parser()
    subs = next(
        action for action in parser._actions if hasattr(action, "choices") and action.choices
    )
    for dest in (*KEY_MATERIAL_FLAGS, "force", "out", "pub", "overwrite", "in_place", "save"):
        assert dest in FLAG_DEFAULTS, dest
    for command in ("sign", "verify", "keygen", "migrate"):
        for action in subs.choices[command]._actions:
            if action.dest in FLAG_DEFAULTS:
                flag, default = FLAG_DEFAULTS[action.dest]
                assert action.default == default, f"tine {command} {flag}"
                assert flag in action.option_strings, f"tine {command} {flag}"


def test_help_text_does_not_promise_the_refused_combinations(capsys):
    """--help must not advertise a combination the handler now refuses.

    `_cli_parser` belongs to another group, so this asserts consistency rather
    than adding prose: --overwrite already points at --save and --force at the
    key file, and no option's help may promise a partner flag that is refused.
    """
    parser = _build_parser()
    subs = next(
        action for action in parser._actions if hasattr(action, "choices") and action.choices
    )
    helps = {
        (command, option): action.help or ""
        for command in ("sign", "verify", "keygen", "migrate")
        for action in subs.choices[command]._actions
        for option in action.option_strings
    }
    assert "--save destination" in helps[("sign", "--overwrite")]
    assert "key file" in helps[("keygen", "--force")]
    for (command, option), text in helps.items():
        for refused in ("--save", "--in-place") if command == "migrate" else ():
            assert not (option == "--dry-run" and refused in text), (
                f"tine {command} --dry-run help offers {refused}, which is now refused"
            )
    for command in ("sign", "keygen", "migrate", "verify"):
        with pytest.raises(SystemExit):
            _build_parser().parse_args([command, "--help"])
        printed = capsys.readouterr().out
        for option in (option for (cmd, option) in helps if cmd == command):
            assert option in printed, f"tine {command} {option} is missing from --help"
