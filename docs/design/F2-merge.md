# F2: merging run histories (design, 0.43)

Status: design only. 0.43 ships the `parents` run field and nothing that
writes a merge. Merge, pick and the merge queue are 0.45+ (ROADMAP F2).

## Problem

A fleet runs many agents on one task. Each member records its own run, often
forked from a shared supervisor run. Today the only relation between runs is
`forked_from`: one run continues one other. There is no way to record "this
run combines the work of runs A and B", so a supervisor that takes two workers'
results has no history object for it, and `tine log --graph` shows the workers
as dead ends.

## The object: `parents`

A run MAY carry `parents`: a non-empty list of unique run oids (SPEC 1.5.3).

- **Omitted when empty.** Writers never emit `parents: []`, and readers reject
  it, so every run written before 0.43 (and every run without parents after it)
  keeps its oid. `tests/test_run_parents_0_43.py` checks this against every
  released fixture repository.
- **Links.** Each parent is a link (`kernel.validate_links`), so `fsck`, `gc`,
  packs, bundles and push/fetch keep the parent runs like events.
- **Order matters.** `parents[0]` is the *first parent*, the run the merge was
  made on (the "ours" side); the rest are merged in. First-parent walks give
  the mainline history, as in git.
- **Not `forked_from`.** `forked_from` stays the run a fork or resume
  continues. A merge run normally has no `forked_from`; a fork of a merge does
  not copy its `parents`.

## Merge semantics (0.45+)

A run is a DAG of events, not a tree of files, so a merge is defined over
events.

1. **Base.** The merge base of runs `A` and `B` is the newest run reachable from
   both through `parents` and `forked_from`. Shared events (same oid) are
   identical by content addressing, so the common prefix needs no comparison.
2. **Event union.** The merged run's `events` are the base's events, then `A`'s
   new events, then `B`'s, each in its own order. That preserves the SPEC
   ordering rule (every parent event strictly earlier). `roots` and `tips` are
   recomputed; the merged run has one tip per side unless a merge event is
   added.
3. **Merge event.** The writer appends one `merge` step whose `parent_ids` are
   both sides' tips and whose outputs name the merged runs. Its presence makes
   the run single-tipped again.
4. **Workspace trees.** When both sides carry tree snapshots (0.38), the merge
   step's `tree` is a three-way merge of base, ours and theirs trees, per path:
   unchanged on one side takes the other; identical changes take either;
   anything else is a **conflict**.
5. **Conflicts are objects.** A conflict is recorded, not resolved silently: an
   annotation on the merge run (`kind: "conflict"`) listing each path with the
   three blob oids. The merge run's status is `paused` until a resolution
   (a later run with this one as `parents[0]`) clears them.
6. **Cost and manifests.** Cost is never summed across the merge: each event
   is counted once (the fleet cost rule from 0.13). Manifests (`pricing`,
   `policy`) come from the first parent; a differing `policy` on another parent
   is a conflict.

## Merge queue (0.45+)

Fleet members finish in any order. A merge queue under
`coord/merge-queue/<target>` (an `opentine-coord/1` record, like tasks) holds
the runs waiting to merge into a head. A worker claims the queue head with a
lease (0.43 tasks) and its fencing token; the ref move that lands the merge is
a compare-and-swap of the head, applied with the run's annotation in one ref
transaction (`POST ref-txn` on a remote). A stale fencing token is refused, so
two mergers never land on top of each other.

## Compatibility

- Readers before 0.43 hash and validate a run with `parents` correctly (an
  unknown field is additive, SPEC 5.2) but do not follow it as a link: their
  `gc` could drop a parent run that no ref names. The release that first writes
  merges will raise `min_reader` for repositories holding them.
- The `.tine` v2 artifact does not carry `parents`; a v4 artifact will, as an
  optional field in the run record.
- `tine verify` treats parents as provenance: a merge run's attestation covers
  its own oid, which commits to the parent oids.

## Open questions

- Whether `tine log --graph` should draw `forked_from` and `parents` edges in
  one graph or as two layers.
- An upper bound on octopus merges (the field allows 64 parents).
- Whether a conflict annotation should be signed by the merging agent's key.
