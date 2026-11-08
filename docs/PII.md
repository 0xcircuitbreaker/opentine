# PII detection and hybrid search (0.46)

OpenTine removes credentials from everything it stores (`opentine-redaction/2`,
[SECURITY_MODEL.md](SECURITY_MODEL.md)). 0.46 adds `opentine-redaction/3`:
that ruleset plus personal data, used where you ask for it:

* `tine redact check --pii` writes **version 2 redaction reports** (SPEC
  4.13.1): each finding names the object and the detectors that fired, never
  the matched text, and the report records the classifier by name.
* `tine repo-search --hybrid` embeds only text that has been through both
  rulesets, so a vector cannot carry a secret or a person's details.

Write-side redaction is unchanged: stored objects are scrubbed of credentials
only. Nothing in this document sends text off the machine.

## Detectors

Every detector is a pattern that proposes a candidate and a validator that
confirms it (`opentine/_pii_ids.py`). Earlier detectors win overlaps.

| Detector | Pattern | Validator |
|---|---|---|
| `email` | RFC 5322 local part `@` dotted domain | no leading, trailing or doubled dots; label hyphens |
| `iban` | country, check digits, 4-character groups | the country's ISO 13616 length and ISO 7064 mod 97-10 |
| `card` | 13-19 digits, optional space or dash groups | issuer prefix (Visa, Mastercard, Amex, Discover, Diners, JCB) and Luhn |
| `gov-id:us-ssn` | `NNN-NN-NNNN` | SSA rules: area not 000, 666 or 9xx; group not 00; serial not 0000; published samples refused |
| `gov-id:uk-nino` | two letters, six digits, A-D | HMRC prefix letters and excluded pairs (so the specimen `QQ123456C` is not a hit) |
| `gov-id:es-dni` | DNI `NNNNNNNNL` or NIE `[XYZ]NNNNNNNL` | mod 23 check letter |
| `phone` | E.164 with `+`, or NANP | 10-15 digits; without `+` only the NANP shape, area and exchange not starting 0/1 |
| `address` | US-style street number, name and suffix (optionally unit, city, state, ZIP); UK postcode | none (shape only) |

## The classifier layer

Patterns find what has a shape. The classifier layer finds what has a meaning,
and is pluggable but always local. `--classifier` (or `OPENTINE_PII_CLASSIFIER`)
takes:

* `rules` (default) — `rules/1`, a small cue-word classifier shipped with
  opentine: a capitalised name after `my name is`, `Name:`, `Dear`, `Patient:`,
  `Customer:`, `Signed` or an honorific (`person`), and a date after `DOB`,
  `date of birth` or `born on` (`dob`). Its spans are reported as
  `classifier:person` and `classifier:dob`.
* `none` — patterns only.
* `MODULE:ATTR` — any object importable on this machine with a `name` and a
  `classify(text)` method returning `(start, end, kind)` triples. A spec that
  looks like a URL is refused; there is no remote classifier and no option to
  add one.

A local NER model plugs in through that interface. For example, with spaCy's
`en_core_web_sm` model installed locally:

```python
# my_pii.py
import spacy

class SpacyNer:
    name = "spacy/en_core_web_sm"

    def __init__(self):
        self.nlp = spacy.load("en_core_web_sm")  # loaded from disk, never fetched

    def classify(self, text):
        return [(e.start_char, e.end_char, "person")
                for e in self.nlp(text).ents if e.label_ == "PERSON"]
```

`tine redact check --pii --classifier my_pii:SpacyNer` then records
`classifier: "spacy/en_core_web_sm"` in each report.

## Recall and precision

Measured on the labelled fixture corpus `tests/fixtures/pii/corpus.jsonl`
(39 lines of agent-transcript-style text, with hard negatives: timestamps,
versions, hashes, Luhn-invalid numbers, bad IBAN check digits, invalid SSN
areas, wrong DNI letters, specimen ids), with the default `rules/1`
classifier. A hit counts only when its kind and exact text match a label.
`python scripts/pii_eval.py` prints this table and a test holds it to the code.

<!-- pii-eval:begin -->
| Detector | TP | FP | FN | Precision | Recall |
|---|---:|---:|---:|---:|---:|
| `address` | 4 | 2 | 1 | 0.667 | 0.800 |
| `card` | 3 | 0 | 0 | 1.000 | 1.000 |
| `classifier:dob` | 1 | 0 | 0 | 1.000 | 1.000 |
| `classifier:person` | 4 | 1 | 1 | 0.800 | 0.800 |
| `email` | 5 | 0 | 0 | 1.000 | 1.000 |
| `gov-id:es-dni` | 2 | 0 | 0 | 1.000 | 1.000 |
| `gov-id:uk-nino` | 2 | 0 | 0 | 1.000 | 1.000 |
| `gov-id:us-ssn` | 1 | 0 | 0 | 1.000 | 1.000 |
| `iban` | 3 | 0 | 0 | 1.000 | 1.000 |
| `phone` | 6 | 0 | 1 | 1.000 | 0.857 |
| **all** | 31 | 3 | 3 | 0.912 | 0.912 |
<!-- pii-eval:end -->

Known misses, kept in the corpus on purpose: national phone numbers without a
country code outside the NANP (`020 7946 0958`), non-US street addresses
(`12 Rue de Rivoli`), names with no cue word (`Contact Bob Smith`), and
capitalised phrases that look like streets (`2 Fast Way tests`) or follow a
cue (`Dear Team`). The corpus is small; read the numbers as a regression
floor, not as a claim about your data.

## Hybrid search

```text
tine repo-search QUERY --hybrid [--embedder hash|MODULE:ATTR] [--json]
pip install 'opentine[embed]'   # optional: numpy for the similarity scan
```

`--hybrid` fuses two rankings by reciprocal rank fusion (`1 / (60 + rank)`
summed over the lists a run appears in, ties by run id): the FTS5 BM25 ranking
of the derived search index and the cosine ranking of a derived embedding
index at `.tine/index/embed.sqlite` (format `opentine-embed/1`). The same
filters as a plain search then apply (`--model`, `--min-score`,
`--signed-only`, `--include-unsuccessful`), so `--hybrid` changes order and
recall, never what a filter admits.

* **Redacted text only.** A run's indexed text goes through the credential
  ruleset and then the PII detectors and classifier before it is embedded.
* **Derived.** Delete the file and the next `--hybrid` search writes it again.
  Vectors are keyed by run and embedder name, and runs the index has not seen
  are embedded at query time. The FTS5 index is written when missing.
* **Local embedders.** The default, `hash` (`hash-ngram/1`), hashes words and
  character trigrams into 256 signed buckets: standard library, deterministic,
  good at spelling overlap, blind to meaning. `MODULE:ATTR` (or
  `OPENTINE_EMBEDDER`) names any local object with `name`, `dim` and
  `embed(texts) -> list[list[float]]`, such as an adapter around a
  sentence-transformers model loaded from disk. URLs are refused.

`--json` adds `hybrid: true` and `embedder` to the `tine-search-results-1`
output.
