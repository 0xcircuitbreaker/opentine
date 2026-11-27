# Region pins

A region pin fixes the code an optimizer may not change. Mark the editable
parts of a file with `EVOLVE-BLOCK-START` / `EVOLVE-BLOCK-END` comment lines,
sign the baseline once with a `policy`-role key, and every later check reports
an edit outside the marked regions.

```bash
tine integrity region-pin --glob "evolve/**" --key policy.key --repo .
tine integrity region-check --repo . --json
```

- The signer must be a `policy`-role key from the owner-pinned trust bundle
  (`key-roles.toml`) that is not also an `optimizer` key. The signature is
  bound to the key that made it; a pin signed by any other key pins nothing.
- The pin is `.tine/integrity/regions.json`, an existing `attestation` object
  whose claim follows the `opentine.integrity.regions/1` convention. No new
  object kind and no new `tine verify` code are added; the findings are
  command-level `fail:` codes.
- `tine integrity check` adds the region findings whenever a pin is filed.
- `tine promote`: the policy key `regions` is `"advisory"` by default
  (findings are advice and never block) and `"required"` under
  `profile = "rsi"`, where any finding refuses `promote.region-modified` and a
  missing or unsigned pin refuses `promote.regions-unpinned`.

**Upgrading an rsi profile.** From 0.87.0 a promotion under `profile = "rsi"`
without a signed region pin is refused. File a pin (`tine integrity
region-pin`) before the next promotion.

The full layout, the finding table and the limits are in
[INTEGRITY.md](INTEGRITY.md#editable-regions-087). Model allowlists, budgets
and judge caps in the record proxy are in [BUDGETS.md](BUDGETS.md).

## Limits

- An older pin signed by the same policy key can be copied back together with
  the older locked code; pins are not monotonic (the protected-list pin has the
  same property).
- Only Python files are tokenized. In other languages a region can open a
  block comment or string that runs across locked code.
- A region can make the locked lines after it unreachable (`return`, `raise`,
  an endless loop).
- Files outside the pinned globs are covered only by the protected list.
- Promotion judges the `--repo` working tree, not the candidate's own tree.
