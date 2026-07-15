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

1. an explicit adapter/run `rates=` override;
2. an explicitly selected catalog or `TINE_PRICING_CATALOG`;
3. workspace `.tine/pricing.json`;
4. user `$XDG_CONFIG_HOME/opentine/pricing.json`;
5. the bundled signed snapshot;
6. an `unknown` result—never another provider's price.

Later local layers win while effective dates remain deterministic. A local
catalog must have its own matching `catalog_id` hash; it may be unsigned so an
enterprise can express negotiated discounts or infrastructure costs without
altering the signed upstream snapshot.

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

The bundled snapshot verified on 2026-07-15 includes these required frontier
cards (USD per million tokens):

| Family | Input | Cache read | Output | Other rules |
|---|---:|---:|---:|---|
| GPT-5.6 Sol (`gpt-5.6`) | 5.00 | 0.50 | 30.00 | cache writes; >272K input multipliers; batch/flex/priority |
| GPT-5.6 Terra | 2.50 | 0.25 | 15.00 | same dimensions and threshold rules |
| GPT-5.6 Luna | 1.00 | 0.10 | 6.00 | same dimensions and threshold rules |
| Claude Fable 5 | 10.00 | 1.00 | 50.00 | 5m write 12.50; 1h write 20.00 |
| Claude Opus 4.5–4.8 | 5.00 | 0.50 | 25.00 | 5m write 6.25; 1h write 10.00 |
| Claude Sonnet 5 | 2.00 | 0.20 | 10.00 | introductory through 2026-08-31 |
| Claude Sonnet 5 | 3.00 | 0.30 | 15.00 | effective 2026-09-01 |

The catalog also contains provider-scoped cards for current defaults and
frontier families from Kimi, DeepSeek, Google Gemini, Grok/xAI, GLM/Z.AI, Qwen,
Groq, Together, Mistral/Ministral, and OpenRouter Hermes. Use `tine pricing
list` for the exact effective records rather than copying rates into code.
Direct Nous/Hermes rates are dynamic in the upstream service, so that card is
intentionally `unknown` until a local overlay supplies a price.

The current snapshot includes Gemini 3.5 Flash, GLM-5.2, DeepSeek V4
Pro/Flash, and the current DeepSeek `deepseek-chat`/`deepseek-reasoner` aliases.
Gemini audio and cached-audio tokens remain separate dimensions, and exact
Batch/Flex/Priority rates are pinned where a scalar modifier would be wrong.
The direct GLM adapter prices the Z.AI global endpoint; a China-region key uses
provider identity `glm-cn` and remains visibly unpriced unless a regional local
overlay is supplied.

Release maintainers sign snapshots with
`python -m scripts.sign_pricing_catalog ... --key /secure/private.pem --key-id ...`.
Private release keys must remain outside the source tree; old public keys stay
trusted so previously signed snapshots continue to verify.

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
