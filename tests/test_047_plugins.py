"""0.47 plugin API: entry-point plugins load only through the allow-list and loading rules.

Each test installs a throwaway distribution (``*.dist-info`` with METADATA,
entry_points.txt and RECORD) into a temporary directory on ``sys.path``; the
"site-packages" the rules trust is patched to that directory where a test
needs it to be trusted.
"""

from __future__ import annotations

import json
import os
import sys
import uuid
from pathlib import Path

import pytest

from opentine import _plugins_rules, cli, plugins
from opentine._eval_scorers import ScorerError, parse
from opentine._schemas import validate_output

SCORER = "def score(output, item):\n    return 1.0 if output == item.get('expected') else 0.0\n"


def _install(site: Path, module: str, body: str, *, group="opentine.scorers", name="demo",
             version="1.0", dist="acme-plugins") -> Path:  # fmt: skip
    package = site / module
    package.mkdir(parents=True)
    (package / "__init__.py").write_text(body, encoding="utf-8")
    info = site / f"{dist.replace('-', '_')}-{version}.dist-info"
    info.mkdir()
    (info / "METADATA").write_text(
        f"Metadata-Version: 2.1\nName: {dist}\nVersion: {version}\n", encoding="utf-8"
    )
    (info / "entry_points.txt").write_text(f"[{group}]\n{name} = {module}\n", encoding="utf-8")
    (info / "RECORD").write_text(
        f"{module}/__init__.py,,\n{info.name}/METADATA,,\n", encoding="utf-8"
    )
    return package


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    monkeypatch.delenv(plugins.DISABLE_ENV, raising=False)
    site = tmp_path / "site"
    site.mkdir()
    monkeypatch.syspath_prepend(str(site))
    monkeypatch.setattr(_plugins_rules, "trusted_roots", lambda: [site.resolve()])
    module = "plug_" + uuid.uuid4().hex[:10]
    yield site, module
    for name in [m for m in sys.modules if m.startswith(module)]:
        del sys.modules[name]


def _tine(capsys, *argv: str) -> tuple[int, dict]:
    capsys.readouterr()
    code = 0
    try:
        cli.main(list(argv))
    except SystemExit as exc:
        code = int(exc.code or 0)
    return code, json.loads(capsys.readouterr().out)


def test_listing_reads_metadata_only_and_blocks_what_is_not_allowed(env, capsys, tmp_path):
    site, module = env
    marker = tmp_path / "imported"
    _install(site, module, f"open({marker.as_posix()!r}, 'w').close()\n" + SCORER)
    code, out = _tine(capsys, "plugins", "list", "--json")
    assert code == 0 and validate_output(out) == []
    (row,) = [p for p in out["plugins"] if p["value"] == module]
    assert row["allowed"] is False and "allow-list" in row["reason"]
    with pytest.raises(plugins.PluginError, match="allow-list"):
        plugins.load("scorer", "demo")
    assert not marker.exists(), "neither listing nor a refused load may import plugin code"


def test_allow_pins_the_distribution_and_version_then_loads(env, capsys):
    site, module = env
    _install(site, module, SCORER)
    code, out = _tine(capsys, "plugins", "allow", "scorer", "demo", "--json")
    assert code == 0 and out["plugins"][0]["allowed"] is True and validate_output(out) == []
    saved = json.loads(Path(os.environ["XDG_CONFIG_HOME"], "opentine", "plugins.json").read_text())
    assert saved["allow"] == [
        {"kind": "scorer", "name": "demo", "distribution": "acme-plugins", "version": "1.0"}
    ]
    assert _tine(capsys, "plugins", "check", "scorer", "demo", "--json")[0] == 0
    scorer = parse("plugin:demo")
    assert scorer.id == "plugin" and scorer.version.startswith("1+sha256:")
    assert scorer({"expected": "x"}, "x") == (1.0, "")


def test_a_new_version_needs_a_new_entry(env, capsys):
    site, module = env
    _install(site, module, SCORER, version="2.0")
    from opentine._plugins_allow import add

    add("scorer", "demo", "acme-plugins", "1.0")
    with pytest.raises(plugins.PluginError, match="allow-list"):
        plugins.load("scorer", "demo")


def test_a_distribution_outside_site_packages_is_refused(env, monkeypatch):
    site, module = env
    _install(site, module, SCORER)
    monkeypatch.setattr(_plugins_rules, "trusted_roots", lambda: [site.parent / "elsewhere"])
    from opentine._plugins_allow import add

    add("scorer", "demo", "acme-plugins", "1.0")
    with pytest.raises(plugins.PluginError, match="outside this interpreter's site-packages"):
        plugins.load("scorer", "demo")


def test_a_shadowing_module_earlier_on_the_path_is_refused(env, monkeypatch, tmp_path):
    site, module = env
    _install(site, module, SCORER)
    shadow = tmp_path / "cwd"
    (shadow / module).mkdir(parents=True)
    (shadow / module / "__init__.py").write_text("def score(o, i):\n    return 1.0\n")
    monkeypatch.syspath_prepend(str(shadow))
    from opentine._plugins_allow import add

    add("scorer", "demo", "acme-plugins", "1.0")
    with pytest.raises(plugins.PluginError, match="does not resolve to a file"):
        plugins.load("scorer", "demo")


def test_an_incomplete_interface_and_the_kill_switch(env, monkeypatch):
    site, module = env
    _install(site, module, "VALUE = 1\n", group="opentine.signers", name="hsm")
    from opentine._plugins_allow import add

    add("signer", "hsm", "acme-plugins", "1.0")
    with pytest.raises(plugins.PluginError, match="does not provide sign, public_key"):
        plugins.load("signer", "hsm")
    monkeypatch.setenv(plugins.DISABLE_ENV, "1")
    with pytest.raises(plugins.PluginError, match="disabled"):
        plugins.load("signer", "hsm")


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits")
def test_an_allow_list_others_can_write_is_refused(env, capsys):
    from opentine._plugins_allow import add, path

    add("scorer", "demo", "acme-plugins", "1.0")
    path().chmod(0o666)
    code, out = _tine(capsys, "plugins", "list", "--json")
    assert code == 2 and "writable by other users" in out["error"]["message"]


def test_scorer_plugin_refusal_is_a_scorer_error(env):
    with pytest.raises(ScorerError, match="no scorer plugin"):
        parse("plugin:missing")


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits")
def test_a_sticky_world_writable_module_directory_is_still_refused(env):
    site, module = env
    package = _install(site, module, SCORER)
    package.chmod(0o1777)  # sticky: others cannot replace files, but can add submodules
    from opentine._plugins_allow import add

    add("scorer", "demo", "acme-plugins", "1.0")
    try:
        with pytest.raises(plugins.PluginError, match="writable by other users"):
            plugins.load("scorer", "demo")
    finally:
        package.chmod(0o755)


def test_allow_refuses_to_guess_between_two_distributions(env, capsys, tmp_path):
    site, module = env
    _install(site, module, SCORER)
    _install(site, module + "b", SCORER, dist="other-plugins")
    code, out = _tine(capsys, "plugins", "allow", "scorer", "demo", "--json")
    assert code == 2 and "2 distributions provide" in out["error"]["message"]
    assert not Path(os.environ["XDG_CONFIG_HOME"], "opentine", "plugins.json").exists()
