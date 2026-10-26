"""Cost-rate resolution for AI usage pricing.

Covers the case that matters for Bedrock application-inference-profile ARNs
(…/application-inference-profile/exampleprofileid): they carry no model name, so
the rate must come from an operator override — either `model_family` (borrow a
built-in rate) or explicit input_price_per_1m/output_price_per_1m.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.ai_provider import (
    DEFAULT_MAX_OUTPUT_TOKENS,
    resolve_cost_rates,
    resolve_max_output_tokens,
)

_OPAQUE = "arn:aws:bedrock:us-east-2:1:application-inference-profile/exampleprofileid"
_NAMED_ARN = "arn:aws:bedrock:us-east-2:1:inference-profile/us.anthropic.claude-haiku-4-5"


def test_opaque_arn_without_override_is_unpriceable():
    # No model name to infer from, no override -> None (cost stays N/A, never wrong).
    assert resolve_cost_rates(_OPAQUE, {}) is None
    assert resolve_cost_rates(_OPAQUE, None) is None


def test_model_family_hint_prices_opaque_arn():
    assert resolve_cost_rates(_OPAQUE, {"model_family": "sonnet"}) == {"input": 3.0, "output": 15.0}
    assert resolve_cost_rates(_OPAQUE, {"model_family": "haiku"}) == {"input": 0.8, "output": 4.0}


def test_explicit_prices_win_over_model_family():
    rates = resolve_cost_rates(_OPAQUE, {
        "input_price_per_1m": 4.0, "output_price_per_1m": 20.0, "model_family": "haiku",
    })
    assert rates == {"input": 4.0, "output": 20.0}


def test_named_arn_still_auto_prices_without_override():
    assert resolve_cost_rates(_NAMED_ARN, {}) == {"input": 0.8, "output": 4.0}


def test_exact_model_key():
    assert resolve_cost_rates("claude-sonnet-4-6", {}) == {"input": 3.0, "output": 15.0}


def test_unknown_family_returns_none():
    assert resolve_cost_rates(_OPAQUE, {"model_family": "nonsense"}) is None


# --- max_tokens (output) ceiling ----------------------------------------- #

def test_max_output_defaults_to_max_size_model():
    # Assume a current max-size Claude model (128K output) when we can't tell.
    assert resolve_max_output_tokens(_OPAQUE, {}) == DEFAULT_MAX_OUTPUT_TOKENS
    assert resolve_max_output_tokens(_OPAQUE, None) == DEFAULT_MAX_OUTPUT_TOKENS
    assert resolve_max_output_tokens("claude-sonnet-4-6", {}) == DEFAULT_MAX_OUTPUT_TOKENS
    assert resolve_max_output_tokens("", {}) == DEFAULT_MAX_OUTPUT_TOKENS


def test_max_output_explicit_override_wins():
    assert resolve_max_output_tokens(_OPAQUE, {"max_output_tokens": 8192}) == 8192


def test_max_output_malformed_override_falls_through_not_crash():
    assert resolve_max_output_tokens(_OPAQUE, {"max_output_tokens": "oops"}) == DEFAULT_MAX_OUTPUT_TOKENS
    assert resolve_max_output_tokens(_OPAQUE, {"max_output_tokens": None}) == DEFAULT_MAX_OUTPUT_TOKENS


def test_malformed_explicit_prices_fall_through_not_crash():
    # Non-numeric override must not raise; falls through to model_family / id.
    rates = resolve_cost_rates(_OPAQUE, {
        "input_price_per_1m": "oops", "output_price_per_1m": None, "model_family": "opus",
    })
    assert rates == {"input": 15.0, "output": 75.0}
