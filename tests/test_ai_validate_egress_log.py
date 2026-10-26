"""ai_validate's external calls must be recorded in the shipped egress log.

Regression: ai_validate ran its agentic loop through its own Anthropic client,
bypassing AIProvider's logging, so logs/ai-interactions.log captured only
ai_analyze's handful of calls — understating egress by ~96% while still shipping
in the client ZIP as "the egress record". Each agent turn now logs a
request+response entry via the shared `log_ai_interaction` sink.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.ai_provider import log_ai_interaction
import modules.ai_validate as av


# --- Fake Anthropic client to drive the loop deterministically ------------- #

class _Block:
    def __init__(self, type, text=None, name=None, input=None, id="b1"):
        self.type = type
        self.text = text
        self.name = name
        self.input = input or {}
        self.id = id


class _Usage:
    input_tokens = 10
    output_tokens = 5


class _Response:
    def __init__(self, blocks):
        self.content = blocks
        self.usage = _Usage()


class _Stream:
    def __init__(self, response):
        self._response = response

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def get_final_message(self):
        return self._response


class _Messages:
    def __init__(self, responses):
        self._responses = list(responses)

    def stream(self, **kwargs):
        return _Stream(self._responses.pop(0))


class _Client:
    def __init__(self, responses):
        self.messages = _Messages(responses)


def _run(monkeypatch, responses, tmp_path):
    logs_dir = str(tmp_path / "logs")
    monkeypatch.setattr(av, "_create_anthropic_client", lambda config: _Client(responses))
    counter = [0]
    finding = {"target": "example.com", "action": "check something"}
    result = av._run_agent_loop(
        finding, set(), [], set(), {"model": "claude-sonnet-4-6"},
        "claude-sonnet-4-6", logs_dir=logs_dir, egress_counter=counter)
    log_path = os.path.join(logs_dir, "ai-interactions.log")
    text = open(log_path, encoding="utf-8").read() if os.path.exists(log_path) else ""
    return result, counter, text


def test_single_turn_logs_request_and_response(monkeypatch, tmp_path):
    responses = [_Response([_Block("text", text="VERDICT: refuted — no evidence")])]
    result, counter, text = _run(monkeypatch, responses, tmp_path)
    assert counter[0] == 1
    assert "[Call #1] REQUEST" in text
    assert "[Call #1] RESPONSE" in text
    assert "SYSTEM PROMPT" in text  # first request logs the system prompt


def test_multi_turn_increments_counter_and_logs_each_call(monkeypatch, tmp_path):
    # Turn 1: a tool call (blocked by empty scope) -> loop continues.
    # Turn 2: a text verdict -> loop returns.
    responses = [
        _Response([_Block("tool_use", name="dig_lookup",
                          input={"target": "example.com"})]),
        _Response([_Block("text", text="VERDICT: unclear")]),
    ]
    result, counter, text = _run(monkeypatch, responses, tmp_path)
    assert counter[0] == 2
    assert "[Call #2] REQUEST" in text
    assert "[Call #2] RESPONSE" in text
    # System prompt logged only on the first turn, not re-logged each call.
    assert text.count("--- SYSTEM PROMPT ---") == 1


def test_no_account_id_arn_in_egress_log(monkeypatch, tmp_path):
    # A Bedrock ARN passed as the model must be redacted in the log label.
    logs_dir = str(tmp_path / "logs")
    monkeypatch.setattr(av, "_create_anthropic_client",
                        lambda config: _Client([_Response([_Block("text", text="VERDICT: refuted")])]))
    arn = "arn:aws:bedrock:us-east-2:123456789012:inference-profile/us.anthropic.claude-sonnet-4-6-v1:0"
    av._run_agent_loop({"target": "example.com", "action": "x"}, set(), [], set(),
                       {"model": arn}, arn, logs_dir=logs_dir, egress_counter=[0])
    text = open(os.path.join(logs_dir, "ai-interactions.log"), encoding="utf-8").read()
    assert "123456789012" not in text
    assert "arn:aws:bedrock" not in text


def test_no_egress_counter_means_no_logging(monkeypatch, tmp_path):
    # Back-compat: called without a counter (e.g. a direct unit test) -> no log.
    logs_dir = str(tmp_path / "logs")
    monkeypatch.setattr(av, "_create_anthropic_client",
                        lambda config: _Client([_Response([_Block("text", text="VERDICT: refuted")])]))
    av._run_agent_loop({"target": "example.com", "action": "x"}, set(), [], set(),
                       {"model": "claude-sonnet-4-6"}, "claude-sonnet-4-6",
                       logs_dir=logs_dir, egress_counter=None)
    assert not os.path.exists(os.path.join(logs_dir, "ai-interactions.log"))
