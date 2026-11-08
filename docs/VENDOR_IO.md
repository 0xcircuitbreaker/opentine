# Vendor I/O: Langfuse, Arize Phoenix, Braintrust, LangSmith (0.46)

```sh
tine export RUN --format langfuse|phoenix|braintrust|langsmith [--output FILE]
tine import FILE --format langfuse|phoenix|braintrust|langsmith --repo PATH | --save OUT.tine
```

Everything is **file based and offline**. An export is the JSON body the
vendor's public ingestion API takes, written to stdout or `--output` (never
pushed: `--endpoint` is refused), redacted on the way out like every other
export. You review the file, then upload it with your own credentials. An
import reads that body back, or the vendor's own export of the same records.
Both directions go through OpenTine's OTLP/JSON exporter and importer
(`opentine/_vendor_io.py`), so a vendor file imports with exactly the kind,
usage and content rules of `--format otel-json`.

| vendor | `tine export` writes | upload it with | `tine import` also reads |
|---|---|---|---|
| Langfuse | `{"batch": [...]}`: `trace-create`, `span-create`, `generation-create` (`usageDetails`), `score-create` | `POST /api/public/ingestion` | `GET /api/public/traces/{id}` objects (`observations`, `scores`), a list, or a `{"data": [...]}` page |
| Phoenix | `{"data": [spans], "span_annotations": [...]}`, OpenInference attributes | `data`: `POST /v1/projects/{project}/spans`; `span_annotations`: `POST /v1/span_annotations` | REST spans (`GET /v1/projects/{project}/spans`), a list, JSON Lines; nested attributes |
| Braintrust | `{"events": [rows]}` (`span_id`, `root_span_id`, `span_parents`, `scores`, `metrics`, `span_attributes`) | `POST /v1/project_logs/{id}/insert` (or an experiment's `/insert`) | the `/fetch` page, a list, JSON Lines |
| LangSmith | `{"post": [runs], "feedback": [...]}` (`dotted_order`, `run_type`, `usage_metadata`) | `post`: `POST /runs/batch`; each `feedback`: `POST /feedback` | `{"runs": [...]}`, a list (`Client.list_runs`), JSON Lines with feedback lines |

What is carried: span tree (parent links), name, kind (`model` / `tool`;
anything else is a chain/task span), start and end time (microseconds),
input and output, model, input/output token counts, error status and
message, and evaluation results. LangSmith needs UUIDs, so its ids are
name-based UUIDs of the OpenTine span ids. Known losses: OpenTine step kinds
other than model and tool (`human`, `subagent`, `error`) come back as model
steps; cost, billing and cache/reasoning token buckets are not written to any
vendor file.

## Evaluation results and `gen_ai.evaluation.result`

An evaluation is `{name, score, label, explanation}`, the fields of the OTel
GenAI `gen_ai.evaluation.result` span event. Every vendor score imported is
kept on its step as the `opentine.evaluation.results` attribute and written
back as each vendor's **native** score record on export; the OTLP bridge also
emits it as a `gen_ai.evaluation.result` span event (Phoenix's export carries
the event in the span's `events` too).

Whether a vendor *displays* a `gen_ai.evaluation.result` span event that
arrives over its OTLP endpoint could not be verified offline, and nothing in
the vendors' public documentation says that it does. Status per vendor:

| vendor | native score record (what `tine export` writes) | `gen_ai.evaluation.result` over OTLP |
|---|---|---|
| Langfuse | `score-create` (numeric `value`, or `CATEGORICAL` label; `comment`) — shown as a score | **untested**: not documented as mapped to scores; expect it, at most, as a span event |
| Phoenix | `span_annotations` (`result.score/label/explanation`, `annotator_kind: CODE`) — shown as an annotation | **untested**: Phoenix lists span events; not documented as an annotation |
| Braintrust | `scores` (numbers in [0, 1] only; others and labels under `metadata["opentine.evaluations"]`) | **untested**: not documented |
| LangSmith | `feedback` (`key`, `score`, `value`, `comment`) — shown as feedback | **untested**: not documented |

"Untested" means no live vendor instance was exercised: the shapes above are
pinned by `tests/test_046_vendor_io.py` against the vendors' published API
schemas, not against a running service. Report what your instance shows.
