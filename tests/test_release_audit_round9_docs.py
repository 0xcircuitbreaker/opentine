"""Round-9 release audit: CHANGELOG claims must match the shipped code.

Two superseded 0.3.0 bullets stood as factual statements about the shipped
build while their corrections sat hundreds of lines later:

* the "Added (provider and harness coverage)" bullet claimed every hosted
  OpenAI-compatible adapter requests ``stream_options.include_usage`` on
  streams, which commit 262bb5e deliberately reverted (Mistral answers the
  field with HTTP 422);
* the "Fixed (first release audit)" bullet documented ``--force`` as the
  overwrite flag for ``tine sign --save``, which commit 988acf5 split into
  ``--overwrite`` (``--force`` retains the integrity-override meaning).

These tests pin the release notes to the code so the claims cannot drift
apart again without a failure.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

from opentine._cli_parser import _build_parser
from opentine.models._chat import ChatCompletions

CHANGELOG = Path(__file__).resolve().parent.parent / "CHANGELOG.md"

#: Hosted adapters commit 262bb5e removed from the provider-level default set.
REVERTED_PROVIDERS = {"together", "mistral", "nous"}


def _changelog_text() -> str:
    return CHANGELOG.read_text(encoding="utf-8")


def _bullets(text: str) -> list[str]:
    """Split markdown into top-level bullets with wrapped lines rejoined."""
    bullets: list[str] = []
    for line in text.splitlines():
        if line.startswith("- "):
            bullets.append(line[2:])
        elif line.startswith("  ") and bullets:
            bullets[-1] += " " + line.strip()
    return bullets


def _subparser(name: str) -> argparse.ArgumentParser:
    parser = _build_parser()
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return action.choices[name]
    raise AssertionError("tine parser has no subcommands")


def test_changelog_does_not_claim_blanket_stream_usage() -> None:
    text = _changelog_text()
    assert "Every hosted OpenAI-compatible adapter now requests usage" not in text


def test_changelog_stream_usage_set_matches_code() -> None:
    match = re.search(
        r"provider-level default set is exactly\s+([^;]*);",
        _changelog_text(),
    )
    assert match, "CHANGELOG must enumerate the provider-level default set"
    documented = set(re.findall(r"`([^`]+)`", match.group(1)))
    assert documented == ChatCompletions._stream_usage_providers


def test_reverted_providers_stay_out_of_default_set() -> None:
    # Guards the code side of the claim: 262bb5e's revert must not quietly
    # regress, or the reworded bullet becomes false in the other direction.
    assert not REVERTED_PROVIDERS & ChatCompletions._stream_usage_providers


def test_sign_save_overwrite_flag_matches_cli() -> None:
    sign_options = {
        option for action in _subparser("sign")._actions for option in action.option_strings
    }
    assert {"--save", "--overwrite", "--force"} <= sign_options
    keygen_options = {
        option for action in _subparser("keygen")._actions for option in action.option_strings
    }
    assert "--force" in keygen_options and "--overwrite" not in keygen_options

    for bullet in _bullets(_changelog_text()):
        if "`tine sign --save`" in bullet and (
            "overwrite" in bullet.lower() or "refuse" in bullet.lower()
        ):
            assert "`--overwrite`" in bullet, bullet
