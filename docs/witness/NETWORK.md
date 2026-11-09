# The witness-network registry

A hosted OpenTine log publishes the witness set it requires as one JSON
document, `opentine-witness-network/1` (schema:
`docs/schemas/opentine-witness-network-1.schema.json`; example:
`deploy/witness/network.example.json`). It is configuration a verifier pins —
the same information as `--witnesses N-of-M --witness-vkey ... --log-vkey ...`
— not a new signed object kind, so it does not cross the 0.48 format freeze.

```json
{
  "schema": "opentine-witness-network/1",
  "description": "optional free text",
  "log": {"origin": "log.example.org/main", "vkey": "<signed-note verifier key>"},
  "policy": {"quorum": "2-of-3"},
  "witnesses": [
    {"name": "witness.example.org", "operator": "Example Org",
     "url": "https://witness.example.org", "vkeys": ["<cosignature/v1 vkey>"],
     "contact": "mailto:ops@example.org", "jurisdiction": "DE"}
  ]
}
```

## Policy

`tine verify TARGET --offline --witnesses network.json` refuses a registry
(exit 4) unless:

- the quorum `N-of-M` names exactly the `M` listed witnesses, `M >= 3`, and
  `N` is a strict majority (`2N > M`), so two disjoint quorums — a split view —
  cannot both exist;
- every witness has a distinct `name`, `operator` and `url`; URLs are `https`
  (`http` only on loopback, for tests);
- each `vkeys` entry (1 to 4, current first, for rotation) is a C2SP
  `cosignature/v1` key under that witness's name, and no key is listed twice;
- `log.vkey` is a signed-note key for `log.origin`.

Then every checkpoint in TARGET (a bundle with transparency receipts, an
`opentine-tlog-receipt/1` file or a bare checkpoint) must carry the log's
signature under `log.vkey` and cosignatures from at least `N` distinct
witnesses. A cosignature by any listed key of a witness counts once for that
witness. `--witness-vkey` and `--log-vkey` are refused alongside a registry.

## Distribution

Fetch the registry once over an authenticated channel (the log operator's
repository, signed release, or the hosted service's pinned page), review the
diff of every change, and check it in next to your verification config. The
registry is not fetched by `tine verify`: verification stays offline.

## Status

The hosted log's production registry is not yet published; that is outstanding
for the maintainers (see "Status" in
`OPERATING.md`).
