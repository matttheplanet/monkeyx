# AI Analysis Module — Setup Guide

The `ai_analyze` module uses AI to identify attack paths and generate prioritized, evidence-grounded recommendations from your scan data. This guide covers setting up each supported AI provider.

> ⚠️ **Data handling.** With any *external* provider (Anthropic / Bedrock /
> OpenAI / `claude` CLI), AI modules send scan data off your host.
> `ai_analyze` and `ai_analyze_gowitness` alias client IPs/domains in the **text**
> they send; `ai_analyze_gowitness` still sends **screenshot images unaltered**,
> and the experimental `ai_validate` sends **raw** data. For
> engagements where no scan data may leave your network, use the **Ollama** local
> provider below. See **[AI_DATA_HANDLING.md](AI_DATA_HANDLING.md)** for the full
> egress posture and limitations.

---

## Prerequisites

- MonkeyX installed with `pip install -r requirements.txt`
- A completed scan with `normalize` module output (JSONL files in `data/`)
- The `pyyaml` package (included in requirements.txt)

---

## Quick Start

1. Locate your credentials file.

   If you installed via `install-monkeyx.sh`, `~/.monkeyx/credentials.yaml` already exists (created from the template at install time) — skip to step 2 and edit it in place. **Don't re-copy the example over it** — that would overwrite your keys.

   If you're running from a clone (no installer), create it from the template:

   ```bash
   cp ~/.monkeyx/credentials.yaml.example ~/.monkeyx/credentials.yaml
   ```

   Any MonkeyX command auto-creates the `.example` template on first run if it's missing.

2. Edit `~/.monkeyx/credentials.yaml` and configure your provider (see sections below).

3. Run the AI analysis (no fleet required — these are all local modules):

```bash
monkeyx --continue ./output -m normalize analyze ai_analyze
```

Or with a live scan (fleet required for ax_nmap_tcp/ax_nuclei):

```bash
monkeyx -f myfleet -t targets.txt -od ./output -m ax_nmap_tcp ax_nuclei normalize analyze ai_analyze
```

---

## Provider 1: Claude Code CLI (Recommended — No API Key Needed)

Uses your existing Claude Code CLI authentication. No separate API key or billing setup required — it routes through whatever model/provider you've configured in Claude Code (including Bedrock inference profiles).

### Requirements

- `claude` CLI installed and authenticated
- Run `claude` once interactively to confirm it works

### Configuration

```yaml
# ~/.monkeyx/credentials.yaml
ai:
  default_provider: claude-code
  claude-code:
    model: sonnet
    max_turns: 3
```

### Model options

The `model` field accepts the same values as Claude Code's `--model` flag:

| Value | Description |
|-------|-------------|
| `sonnet` | Claude Sonnet (default, good balance of speed/quality) |
| `opus` | Claude Opus (highest quality, slower) |
| `haiku` | Claude Haiku (fastest, lower quality) |

If you're using a Bedrock inference profile in Claude Code (via `ANTHROPIC_API_PROVIDER=bedrock`), the alias routes through your profile automatically. You don't need to put the ARN here.

### max_turns

Controls how many agentic iterations the CLI can make per query. Default is `3`. Higher values allow more follow-up reasoning but cost more; lower it to `1` (single-shot) for the cheapest passes.

### Environment variables for Claude Code

These are set in your shell, not in credentials.yaml — they configure the `claude` CLI itself:

```bash
export ANTHROPIC_API_PROVIDER=bedrock          # Use AWS Bedrock
export AWS_REGION=us-east-1                     # Must match your inference profile
export AWS_ACCESS_KEY_ID=AKIA...                # Or use ~/.aws/credentials
export AWS_SECRET_ACCESS_KEY=...
```

### Verify

```bash
claude --bare -p "Say hello" --model sonnet --max-turns 1
```

If that returns a response, the provider is working.

---

## Provider 2: Ollama (Local Model — Free, Private, No Internet)

Runs a model locally on your machine or server. No data leaves your network. Good for sensitive engagements where scan data cannot be sent to external APIs.

### Requirements

- [Ollama](https://ollama.com) installed and running
- A model pulled locally (e.g. `ollama pull llama3:70b`)

### Install Ollama

```bash
# macOS
brew install ollama

# Linux
curl -fsSL https://ollama.com/install.sh | sh

# Start the server (runs on port 11434 by default)
ollama serve
```

### Pull a model

Choose based on your hardware:

| Model | VRAM Required | Quality for Security Analysis |
|-------|--------------|-------------------------------|
| `llama3:8b` | ~5 GB | Basic — misses nuance |
| `llama3:70b` | ~40 GB | Good — catches most patterns |
| `mixtral:8x7b` | ~26 GB | Good — fast for its quality |
| `qwen2.5:72b` | ~40 GB | Good — strong reasoning |
| `deepseek-r1:70b` | ~40 GB | Strong — good at chaining logic |

```bash
ollama pull llama3:70b
```

### Configuration

```yaml
# ~/.monkeyx/credentials.yaml
ai:
  default_provider: ollama
  ollama:
    base_url: http://localhost:11434
    model: llama3:70b
```

If Ollama is running on a different machine:

```yaml
  ollama:
    base_url: http://192.168.1.50:11434
    model: llama3:70b
```

### Verify

```bash
curl http://localhost:11434/api/generate -d '{"model":"llama3:70b","prompt":"hello","stream":false}'
```

### Notes

- The model works purely from its training data and your scan results (as with every provider — `ai_analyze` does not use web search)
- Quality scales directly with model size — 70B+ recommended for meaningful security analysis
- First query may be slow while the model loads into memory; subsequent queries are fast
- If running on a remote GPU server, ensure port 11434 is accessible from your MonkeyX host

---

## Provider 3: AWS Bedrock (Recommended for Enterprise)

Access Claude models via AWS Bedrock. Uses your existing AWS credentials — no Anthropic API key needed. Ideal for enterprise environments with existing AWS infrastructure.

### Requirements

- AWS account with Bedrock model access enabled for Claude
- IAM permissions: `bedrock:InvokeModel`, `bedrock:InvokeModelWithResponseStream`
- Python package: `pip install 'anthropic[bedrock]>=0.40.0'` (included in requirements.txt)

### Enable model access

In the AWS Console:
1. Go to **Amazon Bedrock** → **Model access**
2. Request access to Anthropic Claude models
3. Wait for approval (usually instant for on-demand)

### Configuration

```yaml
# ~/.monkeyx/credentials.yaml
ai:
  default_provider: anthropic
  anthropic:
    aws_region: us-east-1
    model: claude-opus-4-6
```

No `api_key` field — when `aws_region` is present, MonkeyX uses `AnthropicBedrock()` which picks up AWS credentials from the standard chain.

### Using an inference profile

If you have a custom inference profile (cross-region, provisioned throughput), use the full ARN as the model:

```yaml
  anthropic:
    aws_region: us-east-1
    model: arn:aws:bedrock:us-east-1:123456789012:application-inference-profile/abc123
```

### Cost estimates for inference-profile ARNs

MonkeyX estimates AI cost from token counts (shown in `logs/costs-*.txt`). A
regular inference-profile ARN embeds the model name
(`.../us.anthropic.claude-sonnet-4-...`), so the price is matched automatically.
An **application**-inference-profile ARN (`.../abc123`) embeds no model name, so
the estimate would read `$0.0000` unless you supply the per-1M-token rates
explicitly:

```yaml
  anthropic:
    aws_region: us-east-1
    model: arn:aws:bedrock:us-east-1:123456789012:application-inference-profile/abc123
    input_price_per_1m: 3.0      # USD per 1M input tokens (match your model)
    output_price_per_1m: 15.0    # USD per 1M output tokens
```

The override wins over the built-in table when present. Omit it and cost simply
stays `$0.0000` (token counts and fleet node-hours are still tracked).

### AWS credentials

Credentials are resolved via the standard AWS SDK chain (in order):

1. Environment variables: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`
2. Shared credentials file: `~/.aws/credentials`
3. AWS config file: `~/.aws/config` (with profile)
4. IAM instance role (EC2/ECS)

```bash
# Option A: Environment variables
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_REGION=us-east-1

# Option B: AWS CLI profile (recommended)
aws configure --profile monkeyx
export AWS_PROFILE=monkeyx
```

### Available models on Bedrock

| Model ID | Notes |
|----------|-------|
| `claude-opus-4-6` | Recommended default — highest quality analysis |
| `claude-sonnet-4-6` | Fast, capable — lower-cost alternative |
| `claude-haiku-4-5-20251001` | Budget option, quick passes |

### Verify

```bash
aws bedrock-runtime invoke-model \
  --model-id anthropic.claude-3-5-sonnet-20241022-v2:0 \
  --region us-east-1 \
  --body '{"anthropic_version":"bedrock-2023-05-31","max_tokens":50,"messages":[{"role":"user","content":"hello"}]}' \
  /dev/stdout
```

Or via Python:

```python
from anthropic import AnthropicBedrock
client = AnthropicBedrock(aws_region="us-east-1")
resp = client.messages.create(model="claude-opus-4-6", max_tokens=50, messages=[{"role":"user","content":"hello"}])
print(resp.content[0].text)
```

---

## Provider 4: Anthropic API (Direct)

Direct access to Claude models via Anthropic's API.

### Requirements

- Anthropic API key from [console.anthropic.com](https://console.anthropic.com)
- Active billing on your Anthropic account

### Configuration

```yaml
# ~/.monkeyx/credentials.yaml
ai:
  default_provider: anthropic
  anthropic:
    api_key: sk-ant-api03-YOUR-KEY-HERE
    model: claude-opus-4-6
```

### Model options

| Model | Cost | Speed | Quality |
|-------|------|-------|---------|
| `claude-haiku-4-5-20251001` | Lowest | Fastest | Good for quick passes |
| `claude-sonnet-4-6` | Medium | Fast | Lower-cost alternative |
| `claude-opus-4-6` | Highest | Slower | Recommended default — best analysis quality |

### Verify

```bash
curl https://api.anthropic.com/v1/messages \
  -H "x-api-key: sk-ant-api03-YOUR-KEY" \
  -H "anthropic-version: 2023-06-01" \
  -H "content-type: application/json" \
  -d '{"model":"claude-opus-4-6","max_tokens":50,"messages":[{"role":"user","content":"hello"}]}'
```

---

## Provider 5: OpenAI API

Access to GPT-4o and other OpenAI models.

### Requirements

- OpenAI API key from [platform.openai.com](https://platform.openai.com)
- Active billing on your OpenAI account

### Configuration

```yaml
# ~/.monkeyx/credentials.yaml
ai:
  default_provider: openai
  openai:
    api_key: sk-YOUR-KEY-HERE
    model: gpt-4o
```

### Model options

| Model | Cost | Notes |
|-------|------|-------|
| `gpt-4o` | Medium | Recommended — fast and capable |
| `gpt-4o-mini` | Low | Budget option, lower quality analysis |
| `o1` | High | Stronger reasoning, slower |

### Verify

```bash
curl https://api.openai.com/v1/chat/completions \
  -H "Authorization: Bearer sk-YOUR-KEY" \
  -H "Content-type: application/json" \
  -d '{"model":"gpt-4o","max_tokens":50,"messages":[{"role":"user","content":"hello"}]}'
```

---

## Environment Variable Overrides

You can override credentials.yaml settings per-run without editing the file:

```bash
# Use a different provider for one run
MONKEYX_AI_PROVIDER=ollama monkeyx --continue ./output -m ai_analyze

# Override API key
MONKEYX_AI_API_KEY=sk-ant-different-key monkeyx --continue ./output -m ai_analyze

# Override model (e.g. down to a lower-cost model for a quick pass)
MONKEYX_AI_MODEL=claude-sonnet-4-6 monkeyx --continue ./output -m ai_analyze
```

---

## Analysis Depth Presets

Control how much data the AI processes (affects cost and completeness):

| Depth | Max Hosts | Max Findings/Host | Use Case |
|-------|-----------|-------------------|----------|
| `quick` | 20 | 10 | Fast check, low cost |
| `standard` | 50 | 25 | Default — good coverage |
| `balanced` | 100 | 30 | Broader coverage between standard and deep |
| `deep` | 150 | 50 | Thorough analysis, higher cost |
| `unlimited` | All | All | Complete coverage (claude-code/local recommended) |

The `--ai-depth` CLI flag accepts `quick`, `standard`, `deep`, `unlimited` (default `standard`). `balanced` is only selectable via the `ai_depth` kwarg or a workflow step's `args`.

```bash
# Quick pass (cheapest)
monkeyx --continue ./output -m ai_analyze --ai-depth=quick

# Deep analysis
monkeyx --continue ./output -m ai_analyze --ai-depth=deep

# Unlimited (recommended with claude-code or ollama where cost is fixed/free)
monkeyx --continue ./output -m ai_analyze --ai-depth=unlimited
```

If data is truncated due to limits, the report will include a clear warning banner at the top listing what was capped and instructions to re-run with higher depth.

---

## Running the Full AI Analysis Pipeline

The standard flow is (no fleet required — all three modules run locally):

```bash
# After scanning completes:
monkeyx --continue ./output -m normalize analyze ai_analyze
```

This runs:
1. `normalize` — converts raw scan output to structured JSONL
2. `analyze` — produces static analysis (service categories, high-value targets)
3. `ai_analyze` — AI-powered attack paths, vulnerability research, recommendations

### Output files

| File | Location | Content |
|------|----------|---------|
| `*-ai-analysis.json` | `output/data/` | Structured JSON with all AI results |
| `*-ai-analysis.md` | `output/reports/` | Main Markdown report (attack paths, research, recommendations) |
| `*-attack-paths.md` | `output/reports/` | Separate attack paths document with kill chains |

---

## Evaluating the AI Modules

The AI modules are non-deterministic, so "did my change help?" needs
measurement. The **offline** eval harness (`eval_ai.py` + `core/eval_harness.py`)
scores an `ai_validate` run against a hand-labeled corpus case
(`tests/corpus/<name>/`) and reports precision / recall / accuracy — no API key
or network. Use it to gate AI-module changes. Full workflow (corpus layout,
scoring commands, adding a case): see **[AI_MODULES.md](AI_MODULES.md) →
"Evaluation harness"**.

---

## Troubleshooting

### "No AI provider configured"

You haven't created `~/.monkeyx/credentials.yaml` yet. If it genuinely doesn't exist (installer users already have it), create it from the template — then edit and configure your provider:

```bash
[ -f ~/.monkeyx/credentials.yaml ] || cp ~/.monkeyx/credentials.yaml.example ~/.monkeyx/credentials.yaml
```

### "Claude Code CLI not found"

The `claude` binary isn't in your PATH. Install Claude Code:

```bash
npm install -g @anthropic-ai/claude-code
claude  # authenticate interactively
```

### "No normalized scan data found"

Add `normalize` before `ai_analyze` in your module list:

```bash
monkeyx --continue ./output --dry-run -m normalize analyze ai_analyze
```

### Ollama connection refused

Ensure the Ollama server is running:

```bash
ollama serve  # start in background or separate terminal
curl http://localhost:11434/api/tags  # verify it responds
```

### "Streaming is required for operations that may take longer than 10 minutes"

This is resolved in the current version — MonkeyX now uses streaming for all Anthropic/Bedrock requests. If you see this error, ensure you have the latest code pulled.

### Bedrock "AccessDeniedException" or "UnrecognizedClientException"

- Verify model access is enabled in AWS Console → Bedrock → Model access
- Check IAM permissions include `bedrock:InvokeModel` and `bedrock:InvokeModelWithResponseStream`
- Confirm `aws_region` in credentials.yaml matches where you enabled model access
- Verify AWS credentials: `aws sts get-caller-identity`

### API rate limits or quota exceeded

- Anthropic/OpenAI: Check your account billing and rate limits
- Bedrock: Check your account's tokens-per-minute quota in AWS Service Quotas
- Use `--ai-depth=quick` to reduce the number of API calls
- Switch to `claude-code` or `ollama` for unlimited local usage

### Report says "data truncated"

Your scan has more hosts/findings than the current depth allows. Re-run with a higher depth:

```bash
monkeyx --continue ./output -m ai_analyze --ai-depth=deep
# or
monkeyx --continue ./output -m ai_analyze --ai-depth=unlimited
```
