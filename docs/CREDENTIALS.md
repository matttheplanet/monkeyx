# Credential Store

> Part of the MonkeyX Core docs. See [`../CLAUDE.md`](../CLAUDE.md) for the index.

## Credential store (`~/.monkeyx/credentials.yaml`)

Central config for API keys used by modules (AI providers, enrichment services). Loaded by `core/credentials.py`.

```yaml
ai:
  default_provider: anthropic
  anthropic:
    # Direct API: set api_key. For AWS Bedrock instead: comment out api_key,
    # set aws_region (auth via ~/.aws/credentials or IAM role — no key needed).
    api_key: sk-ant-...
    # aws_region: us-east-1
    model: claude-opus-4-6          # plain name; a full Bedrock inference-profile ARN also works
  openai:
    api_key: sk-...
    model: gpt-4o
  ollama:
    base_url: http://localhost:11434
    model: llama3:70b
  claude-code:
    # No API key — uses existing Claude Code CLI auth
    model: sonnet      # sonnet | opus | haiku
    max_turns: 3       # agentic iteration cap (engine default if omitted)

enrichment:
  shodan:
    api_key: ...
  censys:
    api_id: ...
    api_secret: ...
  greynoise:
    api_key: ...
  virustotal:
    api_key: ...
```

Environment variables override file values: `MONKEYX_AI_PROVIDER`, `MONKEYX_AI_API_KEY`, `MONKEYX_AI_MODEL`, and per-service `MONKEYX_{SERVICE}_API_KEY` (e.g. `MONKEYX_SHODAN_API_KEY`).

Enrichment keys are optional and looked up by service name (`core.credentials.get_enrichment_key` / `get_enrichment_config`), so any service the code asks for works the same way. Leave a block fully commented when unused — a present-but-fake value is treated as a real key and fails auth instead of skipping cleanly.

**Provider options for `default_provider`:**
- `anthropic` — Direct Anthropic API or AWS Bedrock. Supports all AI modules including `ai_validate` (which requires tool_use). Set `api_key` for the direct API; set `aws_region` (and omit `api_key`) to use the `AnthropicBedrock()` client, which authenticates via the AWS credential chain (`~/.aws/credentials`, env vars, or instance role). Bedrock mode requires the `anthropic[bedrock]` pip package.
- `openai` — OpenAI API (`model: gpt-4o` by default). Works with `ai_analyze` but NOT `ai_validate`.
- `ollama` — Local Ollama (`base_url`, `model`). Works with `ai_analyze` but NOT `ai_validate`.
- `claude-code` — Calls the local `claude` CLI in print mode. No separate API key — uses your existing Claude Code CLI auth. `model` accepts `sonnet | opus | haiku` or a full model ID; `max_turns` caps agentic iterations. Works with `ai_analyze` but NOT `ai_validate` (no tool_use support).

If no provider is configured (no `default_provider`, no `MONKEYX_AI_PROVIDER`) but the `claude` CLI is on `PATH`, MonkeyX auto-selects `claude-code`.

See `~/.monkeyx/credentials.yaml.example` for the full template, and [`AI_SETUP.md`](AI_SETUP.md) for per-provider setup, Bedrock auth variants (`aws_access_key`/`aws_profile`/…), and cost-estimation knobs (`model_family`, `input_price_per_1m`, `context_window`, `max_output_tokens`).
