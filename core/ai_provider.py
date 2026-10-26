"""AI provider abstraction for MonkeyX modules.

Supports Anthropic, OpenAI, Ollama (local), and Claude Code CLI.
Provider selection and credentials are resolved via core.credentials.
"""

import json
import logging
import subprocess
import shutil

from core.credentials import get_ai_provider

logger = logging.getLogger('monkeyx.core.ai_provider')

DEFAULT_MAX_TOKENS = 8192

COST_PER_1M_TOKENS = {
    "claude-sonnet-4-6": {"input": 3.0, "output": 15.0},
    "claude-opus-4-6": {"input": 15.0, "output": 75.0},
    "claude-haiku-4-5-20251001": {"input": 0.8, "output": 4.0},
    "gpt-4o": {"input": 2.5, "output": 10.0},
    "gpt-4o-mini": {"input": 0.15, "output": 0.6},
}

# Substring -> family rates, checked when the model id isn't an exact key. Bedrock
# inference-profile ARNs embed the model name
# (arn:...:inference-profile/us.anthropic.claude-sonnet-4-...), so a substring
# match recovers the price the exact-key lookup misses. Ordered most- to
# least-specific so "haiku"/"opus" win before the generic "sonnet"/"claude".
_COST_FAMILY_SUBSTRINGS = (
    ("haiku", {"input": 0.8, "output": 4.0}),
    ("opus", {"input": 15.0, "output": 75.0}),
    ("sonnet", {"input": 3.0, "output": 15.0}),
    ("gpt-4o-mini", {"input": 0.15, "output": 0.6}),
    ("gpt-4o", {"input": 2.5, "output": 10.0}),
)


def _family_rates(name: str):
    """Return family rates for a model-name/family string via substring match.

    Shared by the id-substring path and the explicit `model_family` config hint.
    """
    if not name:
        return None
    lowered = name.lower()
    for needle, family_rates in _COST_FAMILY_SUBSTRINGS:
        if needle in lowered:
            return family_rates
    return None


def resolve_cost_rates(model: str, config: dict | None = None):
    """Resolve per-1M-token {input, output} rates for a model id.

    Order: (1) explicit per-1M price override (input_price_per_1m/output_price_per_1m
    from credentials.yaml); (2) `model_family` config hint (sonnet/opus/haiku/gpt-4o
    -> built-in rates) — the friendly override for an opaque
    application-inference-profile ARN like .../exampleprofileid that embeds no model
    name; (3) exact COST_PER_1M_TOKENS key; (4) substring family match for
    inference-profile ARNs that embed the model name. Returns None if unknown.

    (2) and (3)/(4) exist because a bare application-inference-profile ARN carries
    no model name, so automatic pricing can't identify the rate — the operator
    supplies it via `model_family` (easiest) or explicit per-1M prices (exact).
    """
    if config:
        try:
            in_p = config.get("input_price_per_1m")
            out_p = config.get("output_price_per_1m")
            if in_p is not None and out_p is not None:
                return {"input": float(in_p), "output": float(out_p)}
        except (TypeError, ValueError):
            pass
        hinted = _family_rates(config.get("model_family"))
        if hinted:
            return hinted
    if not model:
        return None
    rates = COST_PER_1M_TOKENS.get(model)
    if rates:
        return rates
    return _family_rates(model)


# Max OUTPUT tokens: the Messages API `max_tokens` ceiling (how long a *reply*
# may be). This is NOT the context window (input budget — that's ai_analyze's
# *_CONTEXT_WINDOW) and NOT DEFAULT_MAX_TOKENS (the default request size). The
# current Claude Opus/Sonnet families cap at 128K output tokens; we always stream
# (client.messages.stream), which is required at that size. We assume a max-size
# model by default — only a family with a KNOWN-lower output cap needs an entry
# in _MAX_OUTPUT_FAMILY_SUBSTRINGS (verify against the Models API `max_tokens`
# field before adding one; an operator can also set `max_output_tokens` in
# credentials.yaml for an opaque application-inference-profile ARN).
DEFAULT_MAX_OUTPUT_TOKENS = 128000
_MAX_OUTPUT_FAMILY_SUBSTRINGS = (
    # e.g. ("haiku", 8192) — left empty until each family's cap is confirmed.
)


def resolve_max_output_tokens(model: str, config: dict | None = None) -> int:
    """Resolve the max_tokens (output) ceiling for a model id.

    Order: (1) explicit `max_output_tokens` override from credentials.yaml — the
    escape hatch for an opaque application-inference-profile ARN whose model caps
    below the default; (2) substring family match for a known-lower family;
    (3) DEFAULT_MAX_OUTPUT_TOKENS (128K — assumes a current max-size Claude model).
    """
    if config:
        try:
            override = config.get("max_output_tokens")
            if override:
                return int(override)
        except (TypeError, ValueError):
            pass
    lowered = (model or "").lower()
    for needle, cap in _MAX_OUTPUT_FAMILY_SUBSTRINGS:
        if needle in lowered:
            return cap
    return DEFAULT_MAX_OUTPUT_TOKENS


def display_model_name(model: str, config: dict | None = None) -> str:
    """A client-safe model label — never a Bedrock ARN carrying an AWS account id.

    Bedrock inference-profile models arrive as full ARNs, e.g.
    ``arn:aws:bedrock:us-east-2:123456789012:inference-profile/us.anthropic.claude-sonnet-4-...``,
    which embed our **internal AWS account id**. That value must never appear in a
    client deliverable. We keep only the trailing profile id (after the last '/'),
    which for a standard system-defined profile is the model name
    (``us.anthropic.claude-sonnet-4-...``) and carries no account id. For an opaque
    application-inference-profile whose id embeds no model name
    (``.../exampleprofileid``), we fall back to the operator's ``model_family`` hint, or
    a generic provider label — never the raw ARN. Non-ARN model ids (direct
    Anthropic/OpenAI/Ollama) pass through unchanged.
    """
    if not model:
        return (config or {}).get("model_family") or "default"
    if model.startswith("arn:") or "inference-profile/" in model:
        tail = model.rsplit("/", 1)[-1]
        # Opaque application-inference-profile id (no embedded model name) ->
        # friendly hint/generic, so we never surface the account-id-bearing ARN.
        if _family_rates(tail) is None:
            return (config or {}).get("model_family") or "Anthropic (Bedrock)"
        return tail
    return model


# Per-content cap so the egress log stays bounded even across an agent loop's
# ~100 turns (the full ai_validate conversation is re-sent each turn).
_EGRESS_LOG_MAX_CHARS = 20000


def log_ai_interaction(logs_dir: str | None, call_index, phase: str,
                       provider: str, model: str,
                       system_prompt: str | None = None, content: str = "",
                       max_chars: int = _EGRESS_LOG_MAX_CHARS, label: str = "") -> None:
    """Append one AI request/response to ``logs/ai-interactions.log``.

    The single egress-accounting sink shared by ``AIProvider.query`` and the
    ``ai_validate`` agent loop, so EVERY external AI call is recorded in one place
    (ai_validate previously bypassed this and logged 0 of its ~100 calls, making
    the shipped log understate egress by ~96%). The ``model`` label is passed
    through ``display_model_name`` by callers so no Bedrock account-id ARN lands
    in the log. Content is clipped to ``max_chars`` to keep the file bounded, and
    every write is best-effort — an OS error never interrupts a scan.
    """
    if not logs_dir:
        return
    import os
    os.makedirs(logs_dir, exist_ok=True)
    log_path = os.path.join(logs_dir, "ai-interactions.log")

    def _clip(s: str | None) -> str:
        s = s or ""
        if len(s) <= max_chars:
            return s
        return s[:max_chars] + f"\n...[truncated {len(s) - max_chars} chars]"

    try:
        with open(log_path, "a", encoding="utf-8") as f:
            label_str = f" | {label}" if label else ""
            f.write(f"\n{'='*80}\n")
            f.write(f"[Call #{call_index}] {phase.upper()}{label_str} | provider={provider} model={model}\n")
            f.write(f"{'='*80}\n")
            if phase == "request":
                if system_prompt is not None:
                    f.write(f"\n--- SYSTEM PROMPT ---\n{_clip(system_prompt)}\n")
                f.write(f"\n--- USER PROMPT ({len(content)} chars) ---\n{_clip(content)}\n")
            else:
                f.write(f"\n--- RESPONSE ({len(content)} chars) ---\n{_clip(content)}\n")
    except OSError:
        pass


class AIProvider:
    """Thin wrapper normalizing differences between AI providers."""

    def __init__(self, provider_name: str | None = None, logs_dir: str | None = None):
        self.config = get_ai_provider(provider_name)
        self.name = self.config["name"]
        self._logs_dir = logs_dir
        self._call_index = 0
        self.usage = {
            "calls": 0,
            "input_tokens": 0,
            "output_tokens": 0,
            # Prompt-cache accounting (Anthropic). input_tokens already EXCLUDES
            # cached tokens; these track them separately so the cost estimate can
            # price cache reads (~0.1x) and writes (~1.25x) correctly.
            "cache_read_tokens": 0,
            "cache_creation_tokens": 0,
            "total_cost_usd": 0.0,
            "total_duration_s": 0.0,
            "provider": self.name,
            "model": self.config.get("model", "default"),
        }
        logger.info("AI provider initialized: %s (model: %s)",
                    self.name, self.config.get("model", "default"))

    def query(self, system_prompt: str, user_prompt: str,
              max_tokens: int = DEFAULT_MAX_TOKENS,
              log_label: str = "") -> str:
        """Send a prompt and return the text response.

        ``log_label`` is an optional tag recorded in the egress log so callers
        that make several similar calls (e.g. ai_analyze's multi-pass: a pure
        pass, a KB-grounded pass, a reconcile pass) are distinguishable in
        logs/ai-interactions.log rather than a wall of identical entries.
        """
        if not user_prompt:
            raise ValueError("Empty prompt passed to AI provider")
        logger.debug("AI query: provider=%s prompt_len=%d label=%s",
                     self.name, len(user_prompt), log_label or "-")

        self._call_index += 1
        self._log_interaction("request", system_prompt, user_prompt, log_label)

        if self.name == "anthropic":
            result = self._query_anthropic(system_prompt, user_prompt, max_tokens)
        elif self.name == "openai":
            result = self._query_openai(system_prompt, user_prompt, max_tokens)
        elif self.name == "ollama":
            result = self._query_ollama(system_prompt, user_prompt, max_tokens)
        elif self.name == "claude-code":
            result = self._query_claude_code(system_prompt, user_prompt, max_tokens)
        else:
            raise ValueError(f"Unknown AI provider: {self.name}")

        self._log_interaction("response", None, result, log_label)
        return result

    def get_usage_summary(self) -> dict:
        """Return accumulated usage stats with estimated cost.

        Sets `cost_unknown` when tokens were spent but the model couldn't be
        priced (e.g. an opaque application-inference-profile ARN with no
        `model_family`/price override) — so consumers report "unknown" rather
        than a misleading $0.0000.
        """
        summary = dict(self.usage)
        summary["cost_unknown"] = False
        cache_read = summary.get("cache_read_tokens", 0)
        cache_creation = summary.get("cache_creation_tokens", 0)
        billable_in = summary["input_tokens"] + cache_read + cache_creation
        if not summary["total_cost_usd"] and billable_in:
            model = self.config.get("model", "")
            rates = resolve_cost_rates(model, self.config)
            if rates:
                # Cache reads bill at ~0.1x the input rate, 5-min cache writes at
                # ~1.25x; uncached input at full rate.
                summary["total_cost_usd"] = (
                    (summary["input_tokens"] / 1_000_000) * rates["input"]
                    + (cache_read / 1_000_000) * rates["input"] * 0.1
                    + (cache_creation / 1_000_000) * rates["input"] * 1.25
                    + (summary["output_tokens"] / 1_000_000) * rates["output"]
                )
                summary["cost_is_estimate"] = True
            else:
                summary["cost_unknown"] = True
        summary["total_tokens"] = (summary["input_tokens"] + summary["output_tokens"]
                                   + cache_read + cache_creation)
        return summary

    def _log_interaction(self, phase: str, system_prompt: str | None, content: str,
                         log_label: str = "") -> None:
        """Log AI request/response to logs/ai-interactions.log (shared egress sink)."""
        log_ai_interaction(
            self._logs_dir, self._call_index, phase, self.name,
            display_model_name(self.config.get("model"), self.config),
            system_prompt=system_prompt, content=content, label=log_label)

    def query_json(self, system_prompt: str, user_prompt: str,
                   max_tokens: int = DEFAULT_MAX_TOKENS,
                   log_label: str = "") -> dict:
        """Send a prompt expecting JSON output, parse and return dict."""
        prompt = user_prompt + "\n\nIMPORTANT: Respond with ONLY valid JSON. No markdown, no explanation, no code fences."
        response = self.query(system_prompt, prompt, max_tokens, log_label=log_label)
        return self._parse_json_response(response)

    def _create_anthropic_client(self):
        """Create the appropriate Anthropic client (direct API or Bedrock)."""
        import anthropic

        aws_region = self.config.get("aws_region")
        if aws_region:
            # Bedrock gets its OWN identity, isolated from the ambient AWS
            # credential chain. That chain often belongs to a different account
            # (e.g. the Axiom fleet account); without an explicit identity here,
            # Bedrock silently inherits it and 403s against an inference profile
            # it can't reach. Forward whichever of profile / explicit keys the
            # operator set in credentials.yaml; if none are set we fall back to
            # the default chain (single-account setups keep working).
            bedrock_kwargs = {"aws_region": aws_region}
            for cfg_key, arg in (
                ("aws_profile", "aws_profile"),
                ("aws_access_key", "aws_access_key"),
                ("aws_secret_key", "aws_secret_key"),
                ("aws_session_token", "aws_session_token"),
            ):
                val = self.config.get(cfg_key)
                if val:
                    bedrock_kwargs[arg] = val
            return anthropic.AnthropicBedrock(**bedrock_kwargs)

        api_key = self.config.get("api_key")
        if not api_key:
            raise ValueError("Anthropic API key not configured (set api_key or aws_region for Bedrock)")
        return anthropic.Anthropic(api_key=api_key)

    def _query_anthropic(self, system: str, user: str, max_tokens: int) -> str:
        client = self._create_anthropic_client()
        model = self.config.get("model", "claude-opus-4-6")

        is_bedrock = bool(self.config.get("aws_region"))
        # Clamp to the model's OUTPUT ceiling (all providers — 128K is the direct
        # Anthropic cap too, not just Bedrock; an over-large max_tokens 400s either
        # way). The deep/unlimited presets can request up to 200K.
        cap = resolve_max_output_tokens(model, self.config)
        if max_tokens > cap:
            logger.info("Clamping max_tokens from %d to %d (model output limit)", max_tokens, cap)
            max_tokens = cap

        # Cache the system prompt: it's static per analysis pass and re-sent on
        # every call (recommendations runs once per host batch, ×2 under multipass,
        # plus the synthesis pass). cache_control marks it as an ephemeral (5-min
        # TTL) prefix so repeated calls read it at ~0.1x instead of full input
        # price. Prefixes below the model's minimum cacheable size simply don't
        # cache (no error, no extra cost); batches fire back-to-back so the TTL
        # never lapses. Works on both the direct API and Bedrock.
        kwargs = {
            "model": model,
            "max_tokens": max_tokens,
            "system": [{"type": "text", "text": system,
                        "cache_control": {"type": "ephemeral"}}],
            "messages": [{"role": "user", "content": user}],
        }

        logger.info("Anthropic request (stream): model=%s max_tokens=%d bedrock=%s",
                    model, max_tokens, is_bedrock)

        with client.messages.stream(**kwargs) as stream:
            response = stream.get_final_message()

        if hasattr(response, "usage"):
            self.usage["input_tokens"] += getattr(response.usage, "input_tokens", 0)
            self.usage["output_tokens"] += getattr(response.usage, "output_tokens", 0)
            self.usage["cache_read_tokens"] += getattr(response.usage, "cache_read_input_tokens", 0) or 0
            self.usage["cache_creation_tokens"] += getattr(response.usage, "cache_creation_input_tokens", 0) or 0
        self.usage["calls"] += 1

        return self._extract_anthropic_text(response)

    def _query_openai(self, system: str, user: str, max_tokens: int) -> str:
        from openai import OpenAI

        api_key = self.config.get("api_key")
        if not api_key:
            raise ValueError("OpenAI API key not configured")

        client = OpenAI(api_key=api_key)
        model = self.config.get("model", "gpt-4o")

        kwargs = {
            "model": model,
            "max_tokens": max_tokens,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }

        logger.info("OpenAI request: model=%s max_tokens=%d", model, max_tokens)
        response = client.chat.completions.create(**kwargs)

        if hasattr(response, "usage") and response.usage:
            self.usage["input_tokens"] += getattr(response.usage, "prompt_tokens", 0)
            self.usage["output_tokens"] += getattr(response.usage, "completion_tokens", 0)
        self.usage["calls"] += 1

        return response.choices[0].message.content

    def _query_ollama(self, system: str, user: str, max_tokens: int) -> str:
        import requests

        base_url = self.config.get("base_url", "http://localhost:11434")
        model = self.config.get("model", "llama3:70b")

        logger.info("Ollama request: model=%s base_url=%s", model, base_url)
        resp = requests.post(f"{base_url}/api/chat", json={
            "model": model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "stream": False,
            "options": {"num_predict": max_tokens},
        }, timeout=300)
        resp.raise_for_status()

        data = resp.json()
        self.usage["calls"] += 1
        self.usage["input_tokens"] += data.get("prompt_eval_count", 0)
        self.usage["output_tokens"] += data.get("eval_count", 0)

        return data["message"]["content"]

    def _query_claude_code(self, system: str, user: str, max_tokens: int) -> str:
        """Query via the Claude Code CLI (claude -p).

        Uses existing Claude Code authentication — no separate API key needed.
        Passes the user prompt via stdin to avoid argument length limits.
        Retries once on failure (handles transient rate limits / API errors).
        """
        import time

        claude_bin = shutil.which("claude")
        if not claude_bin:
            raise ValueError(
                "Claude Code CLI not found. Install it or use a different provider."
            )

        model = self.config.get("model")
        max_turns = int(self.config.get("max_turns", "3"))

        cmd = [
            claude_bin, "--bare", "-p",
            "--system-prompt", system,
            "--output-format", "json",
            "--max-turns", str(max_turns),
        ]
        if model:
            cmd.extend(["--model", model])

        max_attempts = 2
        for attempt in range(1, max_attempts + 1):
            logger.info("Claude Code request (attempt %d/%d): model=%s max_turns=%s prompt_len=%d",
                        attempt, max_attempts, model, max_turns, len(user))
            result = subprocess.run(
                cmd,
                input=user,
                capture_output=True,
                text=True,
                timeout=600,
            )

            stdout = result.stdout.strip()
            stderr = result.stderr.strip()

            # Parse JSON output for metadata
            response_data = None
            if stdout:
                try:
                    response_data = json.loads(stdout)
                except json.JSONDecodeError:
                    pass

            if result.returncode == 0 and response_data:
                num_turns = response_data.get("num_turns", "?")
                duration_ms = response_data.get("duration_ms", 0)
                cost_usd = response_data.get("total_cost_usd", 0)
                duration_s = duration_ms / 1000 if duration_ms else 0

                logger.info("Claude Code response: turns=%s/%s duration=%.1fs cost=$%.4f",
                            num_turns, max_turns, duration_s, cost_usd or 0)
                print(f"    [claude-code] turns: {num_turns}/{max_turns} | "
                      f"time: {duration_s:.1f}s | cost: ${cost_usd:.4f}" if cost_usd else
                      f"    [claude-code] turns: {num_turns}/{max_turns} | time: {duration_s:.1f}s")

                self.usage["calls"] += 1
                self.usage["total_cost_usd"] += cost_usd or 0
                self.usage["total_duration_s"] += duration_s
                self.usage["input_tokens"] += response_data.get("input_tokens", 0)
                self.usage["output_tokens"] += response_data.get("output_tokens", 0)

                return response_data.get("result") or stdout or ""

            elif result.returncode == 0 and stdout:
                return stdout

            # Handle failure
            error_detail = ""
            if response_data:
                error_detail = (
                    response_data.get("result")
                    or response_data.get("error")
                    or response_data.get("message")
                    or stderr
                )
            if not error_detail:
                error_detail = stderr or stdout or "(no output captured)"

            logger.error("Claude Code CLI failed (attempt %d, exit %d): %s",
                         attempt, result.returncode, error_detail)

            if "max turns" in error_detail.lower():
                raise RuntimeError(
                    f"Claude Code reached max turns ({max_turns}). "
                    f"The dataset may require more reasoning iterations. "
                    f"Increase max_turns in ~/.monkeyx/credentials.yaml under claude-code: "
                    f"(e.g. max_turns: 5)"
                )

            if attempt < max_attempts:
                logger.info("Retrying in 5 seconds...")
                time.sleep(5)

        raise RuntimeError(
            f"Claude Code CLI failed after {max_attempts} attempts (exit {result.returncode}): {error_detail}"
        )

    def _extract_anthropic_text(self, response) -> str:
        """Extract text from Anthropic response content blocks."""
        parts = []
        for block in response.content:
            if block.type == "text":
                parts.append(block.text)
        return "\n".join(parts)

    def _parse_json_response(self, text: str) -> dict:
        """Extract JSON from a response that may contain markdown fences or surrounding prose."""
        cleaned = text.strip()

        # Try direct parse first
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            pass

        # Strip markdown code fences
        if "```" in cleaned:
            lines = cleaned.split("\n")
            in_fence = False
            json_lines = []
            for line in lines:
                if line.strip().startswith("```") and not in_fence:
                    in_fence = True
                    continue
                elif line.strip() == "```" and in_fence:
                    in_fence = False
                    continue
                elif in_fence:
                    json_lines.append(line)
            if json_lines:
                try:
                    return json.loads("\n".join(json_lines))
                except json.JSONDecodeError:
                    pass

        # Try to find JSON object in the response (first { to last })
        first_brace = cleaned.find("{")
        last_brace = cleaned.rfind("}")
        if first_brace != -1 and last_brace > first_brace:
            try:
                return json.loads(cleaned[first_brace:last_brace + 1])
            except json.JSONDecodeError:
                pass

        logger.warning("Failed to parse AI JSON response, returning raw text in wrapper")
        return {"raw_response": text}
