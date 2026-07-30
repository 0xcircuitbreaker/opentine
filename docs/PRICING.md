# Pricing and usage accounting

OpenTine records normalized consumption and estimates cost from a pinned,
effective-dated catalog. A provider response is not a final invoice: taxes,
credits, enterprise commitments, regional adjustments, rounding, and provider
post-processing may differ.

## Public records

`Usage` has exclusive `input`, `output`, `cache_read`, `cache_write_5m`,
`cache_write_1h`, and `reasoning` dimensions, an optional provider `total`, and
typed provider-specific `extra` dimensions. Exclusive buckets prevent cached or
reasoning tokens from being charged twice.

`BillingResult` reports one of `complete`, `partial`, `unknown`, or `unmetered`,
along with `amount_usd`, `known_subtotal_usd`, warnings, the calculation inputs,
catalog provenance, the applicable rate-card ID, and its effective date.

`RateCard` identifies one provider/model (plus aliases), effective range,
per-million-token rates, context thresholds, service modifiers or exact
service-specific rates, currency, source URLs, and verification date.
`PricingCatalog` performs deterministic provider + model + date resolution.

All arithmetic uses `Decimal`. The legacy numeric response field `cost` remains
the known USD subtotal for compatibility. For incomplete billing, `cost` can be
non-zero while `billing.amount_usd` is `null`.

## Resolution and lifecycle

Resolution order is:

1. an explicit adapter/run `rates=` override, when the model check below allows it;
2. an explicitly selected catalog or `TINE_PRICING_CATALOG`;
3. workspace `.tine/pricing.json`;
4. user `$XDG_CONFIG_HOME/opentine/pricing.json`;
5. the bundled signed snapshot;
6. an `unknown` result—never another provider's price.

A `rates=` override wins only when the model the provider reports resolves to the
same rate card as the model that was requested. If the provider echoes a
different model identifier, the override is discarded, the catalog card for the
*reported* model is used instead, and two warnings are appended: `provider
reported model 'X' for requested model 'Y'` and `explicit rates were ignored for
the different model`. When the catalog prices the reported model the status stays
`complete`, so a caller who encoded a negotiated rate is billed the list price
and learns of it only from `billing.warnings`—check them before trusting
`amount_usd`. When the catalog does not price it, the result is `unknown`; the
override is not reinstated either way. Equivalence is decided by resolved
rate-card ID, so a catalog alias, or Ollama's conventional `:latest` tag, still
counts as the same model. An `unmetered` adapter keeps its override
unconditionally.

Supplying `base_url=` to `OpenAI`, or setting `OPENAI_BASE_URL`, selects the
provider identity `openai-compatible` by default. Even if that endpoint exposes
a model named `gpt-4o`, OpenTine will report unknown pricing unless the caller
explicitly selects a provider or supplies a `rates=` override.

Later local layers win while effective dates remain deterministic. A local
catalog must have its own matching `catalog_id` hash; it may be unsigned so an
enterprise can express negotiated discounts or infrastructure costs without
altering the signed upstream snapshot.

### Streamed calls and reported usage

Every price on this page is applied to usage the provider reports. An
OpenAI-compatible endpoint sends no usage chunk during a stream unless the
request carries `stream_options={"include_usage": True}`, so a rate card alone is
not enough to price a streamed call.

OpenTine adds that field by default for the providers `openai`,
`openai-compatible`, `qwen`, `xai`, `glm`, and `glm-cn`, and the `Kimi`,
`DeepSeek`, `Groq`, and `OpenRouter` adapters request it for themselves. The list
is an allowlist rather than a default because the field is not universally
accepted: Mistral answers it with HTTP 422 `extra_forbidden`, which fails the
whole call rather than losing a number. `Together`, `Mistral`, `Ministral`, and
`Hermes` therefore send nothing, as do `OpenAICompatible` and the local presets
that leave `default_include_usage` at `False`.

A streamed call to one of those adapters reports no usage at all, so the result
is `status: "unknown"`, `amount_usd: null`, `cost: 0.0`, and the warning
`provider did not report usage; cost is unknown`—even though this document
advertises rate cards for Together, Mistral, and Ministral. On an `unmetered`
adapter the status stays `unmetered` and the warning reads `provider did not
report usage; API cost remains unmetered`; the token counts are lost either way.
Non-streamed `complete()` calls are unaffected.

Pass `include_usage=True` to the adapter if your deployment does accept the
field, and confirm on a short streamed call that `billing.status` is not
`unknown` before relying on streamed cost.

### Models newer than the bundled snapshot

The bundled snapshot is signed, so it can only gain cards when the release key
re-signs it — editing the file in place fails verification with `catalog id/hash
mismatch` and takes billing down with it. Until the next signed release, price a
newly launched model with an unsigned overlay.

The repository carries a ready-made three-card overlay at
`docs/pricing-overlay-claude-5.json`, covering `claude-opus-5`,
`claude-mythos-5` (Project Glasswing), and `claude-haiku-4-5`. It is present in a
source checkout and in the source distribution, but the wheel contains only the
`opentine` package, so `pip install opentine` does not put that file anywhere on
disk. A single-card overlay is reproduced here so the recipe works either way; it
carries that file's `claude-opus-5` rates without its `fast` service modifier or
its metadata:

```bash
mkdir -p "${XDG_CONFIG_HOME:-$HOME/.config}/opentine"
cat > "${XDG_CONFIG_HOME:-$HOME/.config}/opentine/pricing.json" <<'JSON'
{
  "schema": "opentine-pricing/1",
  "generated_at": "2026-07-25T00:00:00Z",
  "cards": [
    {
      "id": "anthropic:claude-opus-5:2026-06-24",
      "provider": "anthropic",
      "model": "claude-opus-5",
      "effective_from": "2026-06-24",
      "rates": {
        "input": "5",
        "output": "25",
        "reasoning": "25",
        "cache_read": "0.50",
        "cache_write_5m": "6.25",
        "cache_write_1h": "10"
      },
      "service_modifiers": {
        "batch": "0.5",
        "batch_us": "0.55",
        "us": "1.1"
      },
      "source_urls": [
        "https://platform.claude.com/docs/en/about-claude/pricing"
      ],
      "verified_at": "2026-07-25"
    }
  ],
  "catalog_id": "sha256:affafa21b064e5f30592383bbc2cad164d6ce38c2d1dd8eb7df6e06511b7341a"
}
JSON
tine pricing show anthropic claude-opus-5
```

A workspace overlay at `.tine/pricing.json` takes the same content and outranks
the user one.

An overlay carries its own `catalog_id`, so recompute it after any edit. The
stored value is the **`sha256:`-prefixed** digest, not the bare hex that
`catalog_hash()` returns — storing the bare hex fails every load with `catalog
id/hash mismatch`, which takes all billing down rather than just the overlay:

```python
from opentine.billing.catalog import catalog_hash
data.pop("catalog_id", None)
data["catalog_id"] = f"sha256:{catalog_hash(data)}"   # note the prefix
```

Note that a merged catalog reports `signed=false` once any layer is unsigned; the
bundled layer's own signature is still verified and enforced on load.

Prices are never downloaded during inference. Catalog updates are explicit and
must verify their Ed25519 signature before installation:

```bash
tine pricing list
tine pricing show anthropic claude-sonnet-5 --at 2026-08-31
tine pricing check /path/to/catalog.json
tine pricing update https://trusted.example/pricing.json
```

The digest-covered run manifest pins the resolved catalog ID/hash, each
underlying layer's ID/hash/signature metadata, the selected rate card, effective
date, normalized usage, rates, context rule, currency conversion, and service
modifier. Signed catalogs can therefore update independently of package
releases without making an old run depend on today's catalog.

## Frontier snapshot

The bundled snapshot generated on 2026-07-20 includes these required frontier
cards (USD per million tokens):

| Family | Input | Cache read | Output | Other rules |
|---|---:|---:|---:|---|
| GPT-5.6 Sol (`gpt-5.6`) | 5.00 | 0.50 | 30.00 | cache writes; >272K input multipliers; batch/flex/priority |
| GPT-5.6 Terra | 2.50 | 0.25 | 15.00 | same dimensions and threshold rules |
| GPT-5.6 Luna | 1.00 | 0.10 | 6.00 | same dimensions and threshold rules |
| Claude Fable 5 | 10.00 | 1.00 | 50.00 | 5m write 12.50; 1h write 20.00; US inference 1.1x |
| Claude Opus 4.5–4.8 | 5.00 | 0.50 | 25.00 | exact model IDs; 5m write 6.25; 1h write 10.00; 4.6+ US inference 1.1x |
| Claude Sonnet 5 | 2.00 | 0.20 | 10.00 | introductory through 2026-08-31; US inference 1.1x |
| Claude Sonnet 5 | 3.00 | 0.30 | 15.00 | effective 2026-09-01; US inference 1.1x |

The catalog also contains provider-scoped cards for current defaults and
frontier families from Kimi, DeepSeek, Google Gemini, Grok/xAI, GLM/Z.AI, Qwen,
Groq, Together, Mistral/Ministral, and OpenRouter Hermes. Use `tine pricing
list` for the exact effective records rather than copying rates into code.
Direct Nous/Hermes rates are dynamic in the upstream service, so that card is
intentionally `unknown` until a local overlay supplies a price.

The current snapshot includes Kimi K3 ($3 input, $0.30 cache hit, and $15
output per MTok), Gemini 3.5 Flash, GLM-5.2, DeepSeek V4
Pro/Flash, and the current DeepSeek `deepseek-chat`/`deepseek-reasoner` aliases.
Gemini audio and cached-audio tokens remain separate dimensions, and exact
Batch/Flex/Priority rates are pinned where a scalar modifier would be wrong.
Grok 4.5 and 4.3 apply xAI's higher rate to every token dimension once total
prompt input exceeds 200K. Alibaba's proprietary `qwen-plus` is intentionally
not aliased to the distinct `qwen3.6-27b` card; it remains visibly unpriced until
its region-, context-, and thinking-mode-dependent rates are represented.
Qwen3.7-Max's pay-as-you-go promotion is effective-dated through 2026-07-23;
explicit 5-minute cache writes/hits and automatic implicit-cache hits retain
their distinct provider rates.
The direct GLM adapter prices the Z.AI global endpoint; a China-region key uses
provider identity `glm-cn` and remains visibly unpriced unless a regional local
overlay is supplied.

Anthropic's adapter sends an explicit `inference_geo` when configured and uses
the geography reported in response usage for billing. US-only inference on
supported current models applies the documented 1.1x multiplier across input,
output, cache writes, and cache reads; it composes with the Batch discount.
GPT-4o's May launch, August price cut, and October prompt-cache discount are
separate effective records, so historical runs do not receive backdated rates.
Mistral records use the provider's API IDs (`mistral-large-2512`,
`mistral-small-2603`, `mistral-medium-3-5`, and `ministral-14b-2512`) while the
documented `*-latest` names remain aliases.
Kimi Batch requests use the provider's exact per-dimension rates rather than a
rounded scalar discount. Groq Flex/on-demand tiers retain their documented
real-time prices, Llama Batch receives its 50% discount, and public-tier model
shutdown dates are recorded as lifecycle metadata. Cards remain priceable for
enterprise committed-spend customers, whom Groq explicitly exempts.

Release maintainers sign snapshots with
`python -m scripts.sign_pricing_catalog ... --key /secure/private.pem --key-id ...`.
Private release keys must remain outside the source tree; old public keys stay
trusted after a public release unless they are explicitly revoked. The `r3` key
is the first public OpenTine catalog trust anchor; unpublished pre-release keys
were retired before v0.3.0 because durable private-key custody could not be
demonstrated.

Primary rate sources are linked on every card, including the
[OpenAI model catalog](https://developers.openai.com/api/docs/models),
[Anthropic pricing](https://platform.claude.com/docs/en/about-claude/pricing),
[Kimi models and pricing](https://platform.kimi.ai/docs/models),
[DeepSeek pricing](https://api-docs.deepseek.com/quick_start/pricing/),
[Gemini pricing](https://ai.google.dev/gemini-api/docs/pricing),
[xAI pricing](https://docs.x.ai/developers/pricing),
[Z.AI pricing](https://docs.z.ai/guides/overview/pricing), and
[Alibaba Model Studio pricing](https://www.alibabacloud.com/help/en/model-studio/model-pricing).

## Local infrastructure rates

Ollama and other local adapters preserve usage while reporting `unmetered` API
cost by default. Optional input/output token rates and compute-second rates let
a workspace estimate infrastructure cost. `unmetered` means “no metered API
price,” not “the hardware is free.”

Normal cost budgets warn and continue using the known subtotal. Set
`Budget(strict_cost=True)` to halt before the next model call once any hosted
price or observed usage dimension becomes indeterminate.
