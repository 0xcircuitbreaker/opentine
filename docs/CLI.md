# CLI spellings

Since 0.16 related verbs are reachable under a noun group. A group spelling is
rewritten to the old verb before parsing, so both take the same flags and give
the same output and exit code. The old spellings keep working unchanged.

| Old spelling | New spelling |
| --- | --- |
| `tine init` | `tine repo init` |
| `tine config` | `tine repo config` |
| `tine worktree` | `tine repo worktree` |
| `tine branch` | `tine repo branch` |
| `tine reset` | `tine repo reset` |
| `tine reflog` | `tine repo reflog` |
| `tine archive` | `tine repo archive` |
| `tine pack` | `tine repo pack` |
| `tine migrate` | `tine repo migrate` |
| `tine serve` | `tine repo serve` |
| `tine du` | `tine repo storage du` |
| `tine gc` | `tine repo storage gc` |
| `tine repack` | `tine repo storage repack` |
| `tine prune` | `tine repo storage prune` |
| `tine compress` | `tine repo storage compress` |
| `tine fsck` | `tine repo storage fsck` |
| `tine reindex` | `tine repo storage reindex` |
| `tine hook` | `tine repo integrate hook` |
| `tine plugin` | `tine repo integrate plugin` |
| `tine harnesses` | `tine repo integrate harnesses` |
| `tine git` | `tine repo integrate git` |
| `tine push` | `tine share push` |
| `tine fetch` | `tine share fetch` |
| `tine pull` | `tine share pull` |
| `tine clone` | `tine share clone` |
| `tine remote` | `tine share remote` |
| `tine bundle` | `tine share bundle` |
| `tine archive` | `tine share archive` |
| `tine sign` | `tine trust sign` |
| `tine keygen` | `tine trust keygen` |
| `tine attest` | `tine trust attest` |
| `tine evaluate` | `tine trust evaluate` |
| `tine promote` | `tine trust promote` |
| `tine verify-tag` | `tine trust verify-tag` |
| `tine who` | `tine agent who` |
| `tine actions` | `tine agent actions` |
| `tine touched` | `tine agent touched` |
| `tine blame` | `tine agent blame` |
| `tine audit` | `tine agent audit` |
| `tine migrate-v3` | `tine repo migrate --to-v3` |
| `tine bundle verify FILE` | `tine verify FILE` (FILE is a bundle, no other arguments) |

`tine agent id|show|trust|keys` are unchanged. `tine GROUP --help` lists a group;
`tine help --all` lists every command.
