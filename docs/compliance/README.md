# Compliance profiles (draft)

**Draft — not legal advice, pending counsel review.** The ROADMAP's 0.48
acceptance asks for an external counsel sign-off recorded in this repository.
**That sign-off is outstanding:** no counsel has reviewed these profiles, and
each one says so (`"counsel_review": "outstanding"`). Do not rely on them for a
legal opinion.

`tine compliance check RUN --profile NAME` reads one of these files and says,
for each requirement, whether the run's OpenTine evidence shows it
(`evidenced`), does not (`missing`), or whether no log can show it
(`out-of-scope`). See [CLI.md](../CLI.md#compliance-profiles-tine-compliance-048)
and SPEC §12.5.

| Profile | Primary texts | Articles and rules cited |
|---|---|---|
| `fre-902` | US Federal Rules of Evidence | 902(13), 902(14), 901(a), 901(b)(9), 902(11), 803(6)(A)-(C) |
| `eu-ai-act` | Regulation (EU) 2024/1689 | Art. 12(1), 12(2)(a)-(c), 12(3)(a)-(d), 19(1)-(2), 26(1), (2), (4), (5), (6) |
| `eidas` | Regulation (EU) 910/2014 as amended by 2024/1183 | Art. 3(10), (11), (25), (26), (33), (48), (52); 25(1)-(2); 26(1)(a)-(d); 35(1)-(2); 36(1); 41(1)-(2); 42; 45i; 45j; 45k(1)-(2); 45l |

The files are YAML in its JSON-compatible flow style (comment lines, then one
JSON object) so the standard library reads them; the schema is
`docs/schemas/opentine-compliance-profile-1.schema.json`. A profile maps
requirements to evidence; it never decides whether a system is "high-risk",
whether a signature is "qualified", or whether a record is admissible.

To record a counsel review: the reviewer's name, date and scope go in this
file, and each reviewed profile's `counsel_review` becomes `recorded`.
