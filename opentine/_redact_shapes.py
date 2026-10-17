"""Credential shapes recognised anywhere in free text, by their own form.

A stdlib-only leaf split out of ``redaction`` for the module line cap. Each
pattern is bounded or anchored on a fixed vendor prefix, so a scan stays linear
in its input (the round-4 linearity assertion covers ``redact_blob`` end to end).
"""

from __future__ import annotations

import re

# High-confidence secret token shapes, scrubbed regardless of the surrounding field name.
TOKEN_SHAPES = re.compile(
    rb"(?i)\b(?:"
    rb"sk-[A-Za-z0-9_-]{16,}"  # OpenAI / Anthropic style
    rb"|(?:AKIA|ASIA)[0-9A-Z]{16}"  # AWS access key id, long-lived and STS
    rb"|gh[oprsu]_[A-Za-z0-9]{20,}"  # GitHub tokens
    rb"|github_pat_[A-Za-z0-9_]{22,}"  # GitHub fine-grained PAT
    rb"|xox[baprs]-[A-Za-z0-9-]{10,}"  # Slack tokens
    rb"|xoxe(?:\.xox[bp])?-[0-9]-[A-Za-z0-9-]{20,}"  # Slack refresh / rotating tokens
    rb"|xapp-[0-9]-[A-Za-z0-9-]{20,}"  # Slack app-level token
    rb"|xai-[A-Za-z0-9]{40,}"  # xAI
    rb"|gsk_[A-Za-z0-9]{40,}"  # Groq
    rb"|r8_[A-Za-z0-9]{30,}"  # Replicate
    rb"|pplx-[A-Za-z0-9]{40,}"  # Perplexity
    rb"|ya29\.[A-Za-z0-9_-]{20,}"  # Google OAuth access token
    rb"|GOCSPX-[A-Za-z0-9_-]{20,}"  # Google OAuth client secret
    rb"|whsec_[A-Za-z0-9+/=_]{20,}"  # Stripe / Svix webhook signing secret
    rb"|AIza[0-9A-Za-z_-]{30,}"  # Google API key
    rb"|[rs]k_(?:live|test)_[0-9A-Za-z]{16,}"  # Stripe
    rb"|gl(?:pat|rt|dt|ptt|oas|ft|cbt|soat|imt|agent|ffct)-[0-9A-Za-z_-]{20,}"  # GitLab
    rb"|hf_[A-Za-z0-9]{30,}"  # Hugging Face
    rb"|npm_[A-Za-z0-9]{36,}"  # npm
    rb"|pypi-[A-Za-z0-9_-]{40,}"  # PyPI upload token
    rb"|SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}"  # SendGrid
    rb"|hvs\.[A-Za-z0-9_-]{20,}"  # HashiCorp Vault service token
    rb"|eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"  # JWT
    rb"|hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9/_-]{20,}"  # Slack webhook
    rb"|discord(?:app)?\.com/api/webhooks/[0-9]{5,}/[A-Za-z0-9_-]{20,}"  # Discord webhook
    rb")"
)
# The password in a URL's userinfo ("postgres://admin:PW@db", "https://bob:PW@git"),
# keeping scheme, user and host. Every run is bounded, so the scan stays linear.
URL_USERINFO = re.compile(
    rb"(?i)\b([a-z][a-z0-9+.-]{1,20}://[^\s/:@'\"<>]{0,256}:)([^\s/@'\"<>]{1,256})(@)"
)
# Credential-bearing query parameters: signed-URL signatures and tokens in URLs.
QUERY_SECRET = re.compile(
    rb"(?i)([?&](?:sig|signature|x-amz-signature|x-amz-security-token|x-goog-signature|"
    rb"token|access_token|id_token|api_key|apikey|key|auth|code)=)([^&\s\"'#<>]{8,})"
)
