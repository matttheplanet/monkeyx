# AI Data Handling & Egress Posture

MonkeyX's AI modules send scan data to an **external AI provider** (Anthropic
direct, Anthropic via AWS Bedrock, OpenAI, or the `claude` CLI) — or to a
**local** model (Ollama), which keeps data on your network. This document is the
authoritative description of *what leaves the host, when, and how much of it is
anonymized*. Read it before running an AI-enabled workflow on a client
engagement.

> **TL;DR** — Only run AI modules if sending scan data to your configured
> provider is authorized for the engagement. `ai_analyze` and
> `ai_analyze_gowitness` alias client IPs/domains in the **text** they send;
> `ai_analyze_gowitness` still sends the **screenshot images unaltered**, and the
> experimental `ai_validate` sends **raw** data. For
> engagements where no scan data may leave your network, use the **Ollama** local
> provider (see `AI_SETUP.md`).

---

## When AI runs (it is not on by default)

AI modules run **only** when you explicitly select them:

- Among the shipped workflows, AI modules appear only in `deep` (`ai_analyze` +
  `ai_analyze_gowitness`). The `fast` and `standard` workflows contain **no** AI
  module (`standard`'s `analyze` step is local heuristic analysis, not an AI call).
- Or when you list one with `-m` (e.g. `-m ai_analyze`).

Selecting an AI workflow/module is the de-facto opt-in. There is currently **no**
separate `--ai` on/off flag and **no** interactive consent prompt.

### Provider auto-selection caveat

If no provider is configured (no `~/.monkeyx/credentials.yaml`, no
`MONKEYX_AI_PROVIDER`), MonkeyX **auto-selects the `claude-code` provider when the
`claude` CLI is found on `PATH`**. So on a machine with the Claude CLI installed
and authenticated, running an AI module can send data out even without an
explicit provider config. If that is not what you want, either don't select AI
modules or set `ai.default_provider: ollama` in your credentials file.

### `--dry-run` makes no external calls

Under `--dry-run`, every network-egress module (`ai_analyze`,
`ai_analyze_gowitness`, `ai_validate`, and `shodan_enrich`) is
replaced by a synthetic fixture and makes **no** external call. Use `--dry-run`
to exercise a pipeline without any data leaving the host.

---

## Per-module egress

| Module | Status | What is sent | Anonymized? |
|--------|--------|--------------|-------------|
| `ai_analyze` | supported | Normalized findings, ports, service/version strings, finding prose | **Yes (text)** — IPs→`H1…`, domains→`D1…` before egress, restored in the response. See limitation below. |
| `ai_analyze_gowitness` | supported | **Screenshot JPEGs** + URL/title/technology metadata | **Text only.** Metadata IPs/domains are aliased; the **screenshot images are sent unaltered**. |
| `ai_validate` | **experimental** | Raw hosts + raw scanner evidence (nuclei `matched-at` URLs, nmap script output, banners); the agent then drives real tools at the real host | **No** |

### Anonymization — what it does and does not cover

`core/anonymize.py` is the single implementation. It builds a bidirectional
map (client IPs → `H1, H2, …`; domains → `D1, D2, …`), replaces those tokens in
outgoing **text**, and restores them in the provider's response so the report you
read is fully de-anonymized while the provider only ever saw the aliases.

Limitations — be honest about these with the client:

1. **Text tokens only.** Only recognized IP and domain substrings are aliased.
   Service banners, product/version strings, URL *paths*, and free-text finding
   prose still egress verbatim (only the IP/domain tokens *inside* them are
   replaced).
2. **Images cannot be anonymized.** `ai_analyze_gowitness` must send the
   screenshot to a vision model to analyze it. A screenshot inherently renders
   hostnames, logos, page text, and on-screen data — none of which can be aliased
   without destroying the image. Aliasing the surrounding metadata reduces the
   text channel but the **image itself still carries identifying content**.
3. **Experimental modules do not anonymize at all.** `ai_validate`
   sends raw client data. Treat it as "raw egress" until it is hardened.

### Local audit record of what was sent

Every AI request and response is written to `logs/ai-interactions.log` (the
shared egress sink) — the system prompt, user prompt, and response of each call,
recorded **post-aliasing** so the log reflects exactly what the provider saw. It
is the local audit trail of what left the host for each AI call.

---

## Recommendations for sensitive engagements

- If scan data must not leave your network, set `ai.default_provider: ollama`
  (local model — see `AI_SETUP.md` → "Provider 2: Ollama"). No data leaves your
  network.
- Otherwise, confirm in writing that sending scan data (including screenshots,
  for `ai_analyze_gowitness`) to your configured provider is authorized.
- Prefer `ai_analyze` (text, aliased) over the experimental `ai_validate`
  (raw) when you want to minimize what leaves the host.
- Use `--dry-run` to rehearse a pipeline with zero egress.

---

*Implementation: `core/anonymize.py` (aliasing), `modules/ai_analyze.py`,
`modules/ai_analyze_gowitness.py`, `core/credentials.py` (provider resolution),
`workflows.py:_PASSTHROUGH_DRY_RUN` (dry-run egress guard).*
