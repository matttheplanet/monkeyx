"""Bedrock client gets its OWN AWS identity, isolated from the ambient chain.

The common deployment splits Bedrock (one AWS account) from the Axiom fleet
(another account, whose creds are the ambient default chain on the box). Without
forwarding an explicit identity, Bedrock inherits the fleet creds and 403s. These
tests pin that credentials.yaml's aws_profile / explicit keys reach the client.
"""
import os
import sys
import types

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.ai_provider import AIProvider


def _provider(config):
    p = AIProvider.__new__(AIProvider)   # bypass __init__ (no real credentials.yaml)
    p.config = config
    return p


def _capture_bedrock(monkeypatch):
    """Patch anthropic.AnthropicBedrock to record the kwargs it was built with."""
    seen = {}
    fake = types.ModuleType("anthropic")

    def AnthropicBedrock(**kwargs):
        seen.update(kwargs)
        return object()

    def Anthropic(**kwargs):
        seen["_direct_api"] = kwargs
        return object()

    fake.AnthropicBedrock = AnthropicBedrock
    fake.Anthropic = Anthropic
    monkeypatch.setitem(sys.modules, "anthropic", fake)
    return seen


def test_aws_profile_is_forwarded(monkeypatch):
    seen = _capture_bedrock(monkeypatch)
    _provider({"aws_region": "us-east-2", "aws_profile": "bedrock"})._create_anthropic_client()
    assert seen == {"aws_region": "us-east-2", "aws_profile": "bedrock"}


def test_explicit_keys_are_forwarded(monkeypatch):
    seen = _capture_bedrock(monkeypatch)
    _provider({
        "aws_region": "us-east-2",
        "aws_access_key": "AKIA...",
        "aws_secret_key": "shh",
        "aws_session_token": "tok",
    })._create_anthropic_client()
    assert seen["aws_access_key"] == "AKIA..."
    assert seen["aws_secret_key"] == "shh"
    assert seen["aws_session_token"] == "tok"


def test_region_only_falls_back_to_default_chain(monkeypatch):
    # Single-account setups keep working: only aws_region, no identity overrides.
    seen = _capture_bedrock(monkeypatch)
    _provider({"aws_region": "us-east-2"})._create_anthropic_client()
    assert seen == {"aws_region": "us-east-2"}


def test_empty_overrides_are_not_passed(monkeypatch):
    # Blank/None values in credentials.yaml must not be forwarded (would override
    # the default chain with nothing and break auth).
    seen = _capture_bedrock(monkeypatch)
    _provider({"aws_region": "us-east-2", "aws_profile": "", "aws_access_key": None})._create_anthropic_client()
    assert seen == {"aws_region": "us-east-2"}
