"""Client deliverables must never carry a Bedrock ARN's internal AWS account id.

Regression: `ai-analysis.md` (and the other AI reports) rendered the raw
`model` config value as "Model". For a Bedrock inference-profile ARN that value
is `arn:aws:bedrock:<region>:<ACCOUNT_ID>:inference-profile/...`, leaking our
internal AWS account id into a report shipped to the client. `display_model_name`
strips the ARN structure down to the model id (no account id), and falls back to
a friendly label for an opaque application-inference-profile ARN.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.ai_provider import display_model_name

_ACCOUNT_ID = "123456789012"


class TestBedrockArnRedaction:
    def test_standard_inference_profile_arn_drops_account_id(self):
        arn = (f"arn:aws:bedrock:us-east-2:{_ACCOUNT_ID}:"
               "inference-profile/us.anthropic.claude-sonnet-4-6-20250514-v1:0")
        out = display_model_name(arn)
        assert _ACCOUNT_ID not in out
        assert not out.startswith("arn:")
        assert out == "us.anthropic.claude-sonnet-4-6-20250514-v1:0"

    def test_opaque_application_profile_falls_back_to_hint(self):
        arn = f"arn:aws:bedrock:us-east-2:{_ACCOUNT_ID}:application-inference-profile/exampleprofileid"
        out = display_model_name(arn, {"model_family": "sonnet"})
        assert _ACCOUNT_ID not in out
        assert "exampleprofileid" not in out
        assert out == "sonnet"

    def test_opaque_application_profile_generic_when_no_hint(self):
        arn = f"arn:aws:bedrock:us-east-2:{_ACCOUNT_ID}:application-inference-profile/exampleprofileid"
        out = display_model_name(arn, {})
        assert _ACCOUNT_ID not in out
        assert not out.startswith("arn:")
        assert out == "Anthropic (Bedrock)"


class TestNonArnPassThrough:
    def test_direct_anthropic_model_unchanged(self):
        assert display_model_name("claude-sonnet-4-6") == "claude-sonnet-4-6"

    def test_openai_model_unchanged(self):
        assert display_model_name("gpt-4o") == "gpt-4o"

    def test_bare_bedrock_profile_id_without_arn_unchanged(self):
        # A system-defined profile configured without the ARN wrapper — already
        # account-id-free, so it passes through as-is.
        m = "us.anthropic.claude-sonnet-4-6-20250514-v1:0"
        assert display_model_name(m) == m

    def test_empty_model_falls_back(self):
        assert display_model_name("") == "default"
        assert display_model_name(None, {"model_family": "opus"}) == "opus"
