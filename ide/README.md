# OpenTine IDE extensions (0.48)

Two editor integrations, both thin clients of the `tine` CLI. They never read
`.tine/` themselves and make no network call of their own; every answer comes
from:

- `tine blame FILE --lines --json` (`tine-blame/1`, the per-line shape): the
  **AI-blame gutter** labels each line an agent run wrote with the model and the
  run's short digest, and the hover names the run, step and commit;
- `tine why FILE:LINE --json` then `tine verify RUN --offline --json`:
  **Verify this line's provenance** names the commit, the run and the causal
  slice behind the line under the caret and reports the offline verifier's
  verdict as it is (a line with no run is never called verified; a run not held
  in this repository is reported as not verified).

`tine` is called with an argument list, never through a shell, in the
workspace root, with repository-relative POSIX paths on every platform.

Neither runs anything in a workspace or project the user has not trusted (VS
Code: `untrustedWorkspaces.supported: false`; JetBrains: the trusted-project
check), and the `tine` executable is a machine/application setting, so a
repository's own settings cannot point it at a program of its choosing. A
file whose repository-relative path starts with `-` is refused rather than
handed to `tine`, where it would read as an option.

## `vscode/`: VS Code

TypeScript, pinned dev dependencies only (`typescript`, `@types/node`,
`@types/vscode`; no runtime dependencies). Commands: **OpenTine: Toggle AI
blame gutter** and **OpenTine: Verify this line's provenance** (also in the
editor context menu). Settings: `opentine.tinePath`, `opentine.timeoutSeconds`.

```
cd ide/vscode
npm ci --ignore-scripts --no-audit --no-fund
npm test                    # tsc, then node --test against a fake tine
npm audit --audit-level=low
```

CI runs exactly these three steps. The tests cover everything but the thin
`extension.ts` glue (which needs a running VS Code): parsing, wording, argument
lists and the process runner, end to end against `test/fixtures/fake-tine.cjs`.
Packaging a `.vsix` (`npx @vscode/vsce package`) is not part of CI.

## `jetbrains/`: IntelliJ Platform (skeleton)

Kotlin and Gradle (Kotlin 2.0.21, IntelliJ Platform Gradle Plugin 2.1.0,
IntelliJ IDEA Community 2024.2.4 as the target, since-build 242). Actions:
**OpenTine: Toggle AI Blame Gutter** (editor gutter menu, Tools menu) and
**OpenTine: Verify This Line's Provenance** (editor context menu); the `tine`
path is under Settings, Tools, OpenTine. The IDE-independent core
(`dev.opentine.ide.core`: the CLI runner, the `tine-blame/1` and `tine why`
parsers, the verdict wording) has JUnit tests against the VS Code fixture.

```
cd ide/jetbrains
gradle test          # the core's unit tests
gradle buildPlugin   # build/distributions/opentine-jetbrains-0.0.0.zip
```

**Not built in CI.** Both tasks download the IntelliJ Platform (about 1 GB)
and need a JDK 17 toolchain; the repository's CI has no such job, so this
plugin is a skeleton. During the 0.48 work the core and its tests were compiled
and passed once with Kotlin 2.0.21, Gson 2.11.0 and JUnit 4.13.2 outside this
build; the IDE classes (`TineSettings.kt`, `Actions.kt`) and `plugin.xml` have
not been compiled against the platform or run in an IDE. No Gradle wrapper is
committed; use Gradle 8.10 or newer.

Neither directory is part of the Python sdist (`pyproject.toml` excludes
`/ide`, in step with `scripts/check_release_inventory.py`).
