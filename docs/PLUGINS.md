# Plugins and `tine experts`

0.47 adds an entry-point plugin API for four extension points, and
`tine experts PATH`. The normative rules are [SPEC §8.19](SPEC.md#s-8.19).

## Writing a plugin

A plugin is an ordinary Python distribution that declares an entry point in
one of four groups:

| kind       | group                 | the loaded object provides                              |
|------------|-----------------------|---------------------------------------------------------|
| `importer` | `opentine.importers`  | `load(path) -> opentine.graph.Run`                       |
| `signer`   | `opentine.signers`    | `sign(payload: bytes) -> bytes`, `public_key() -> str`   |
| `scorer`   | `opentine.scorers`    | `score(output, item) -> bool \| float in 0..1 \| {"score": n}` |
| `snapshot` | `opentine.snapshots`  | `snapshot(path) -> dict`, `restore(snapshot, path)`      |

```toml
# pyproject.toml of acme-scorers
[project.entry-points."opentine.scorers"]
toxicity = "acme_scorers.toxicity"
```

The entry point may name a module or an object; whatever it loads must have
the callables in the table, or loading fails with the missing names.

## Loading rules

Nothing loads by itself. Installing a package, importing `opentine`,
opening a repository or running an unrelated command never imports plugin
code; `tine plugins list` reads package metadata only. A plugin is imported
only when a command names it (for example `tine eval run --scorer
plugin:toxicity`) and every rule holds:

1. **Allow-listed.** `$XDG_CONFIG_HOME/opentine/plugins.json`
   (`~/.config/opentine/plugins.json`) pins the kind, entry-point name,
   distribution and exact version. Only this user file is read: a cloned
   repository or the current directory can never add a plugin. Upgrading the
   package needs a new entry.
2. **Installed, not dropped in.** The distribution lives in this
   interpreter's site-packages (or the user site). One found through the
   current directory or `PYTHONPATH` is refused. Editable installs are refused
   too, because the module is not a file the distribution's `RECORD` lists.
3. **Not shadowed.** The module resolves, before import, to a file the
   distribution installed, so a same-named `acme_scorers/` in the current
   directory cannot be what runs.
4. **Not writable by others** (POSIX): the allow-list, its directory, the
   plugin's module file and its directory are not group- or world-writable (a
   sticky bit does not exempt a directory), and the allow-list and its
   directory are owned by you or root.

`OPENTINE_NO_PLUGINS=1` turns loading off.

These rules decide *which* code runs; they are not a sandbox. A loaded
plugin runs with the full rights of the `tine` process, so adding an entry
is a trust decision, like installing the package was.

## Commands

```
tine plugins list [--kind K] [--json]      # installed plugins, allowed or why not
tine plugins allow scorer NAME [--json]    # pin the installed distribution + version
tine plugins check scorer NAME [--json]    # load it and check its interface
```

`--json` follows `tine-cli-plugins-1`; the allow-list file follows
`opentine-plugin-allow-1`.

Scorers are wired into `tine eval run --scorer plugin:NAME`: the verdict's
`scorer` is `plugin` and its `scorer_version` pins the plugin's name,
distribution and version, so a verdict scored by another release of the
plugin does not compare as the same scorer. The importer, signer and snapshot
groups are available to Python callers through `opentine.plugins.load(kind,
name)`; `tine import`, `tine sign` and `tine rewind` do not consult them yet.

## `tine experts PATH`

```
tine experts PATH [--rev REV] [--pubkey KEY] [--limit N] [--json]
```

Blames every committed text file under `PATH` at `REV` (default `HEAD`) and
ranks who wrote it. A line that the commit's line attribution note
(`tine git attribute`, `refs/notes/tine`) credits to a run counts for that
**agent**, by model; every other line counts for the **human** commit author,
by e-mail. For agents, `runs` counts the distinct runs credited and
`verified_runs` those whose note is signed validly (by `--pubkey` when given)
and whose content hashes still match. Rows are ordered by lines, then verified
runs, then kind and id. Only committed history is read, never the work tree,
and nothing is fetched. `--json` follows `tine-experts-1`.
