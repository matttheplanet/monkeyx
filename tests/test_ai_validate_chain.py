"""Chain-aware validation: attack_chains are walked as an ordered sequence.

A finding tagged `_category == "attack_chain"` gets the chain system prompt and a
seed that enumerates its steps in order (so the agent carries evidence forward
between steps). Any other finding keeps the single-finding prompt. The tool/scope
machinery is identical either way — this only checks the framing.
"""

import os
import sys
import types

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules import ai_validate as aiv


class _FakeStream:
    def __init__(self, msg):
        self._msg = msg

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def get_final_message(self):
        return self._msg


class _FakeMessages:
    def __init__(self, captured):
        self.captured = captured

    def stream(self, model, max_tokens, system, tools, messages):
        self.captured["system"] = system
        self.captured["messages"] = messages
        # Final turn: a text verdict, no tool calls — loop parses and returns.
        blk = types.SimpleNamespace(type="text",
                                    text='{"verdict":"unclear","evidence":"n/a"}')
        msg = types.SimpleNamespace(
            content=[blk],
            usage=types.SimpleNamespace(input_tokens=1, output_tokens=1))
        return _FakeStream(msg)


class _FakeClient:
    def __init__(self, captured):
        self.messages = _FakeMessages(captured)


def _run(finding, monkeypatch):
    captured = {}
    monkeypatch.setattr(aiv, "_create_anthropic_client", lambda cfg: _FakeClient(captured))
    aiv._run_agent_loop(finding, set(), [], set(), {}, "model-x", egress_counter=None)
    return captured


def test_attack_chain_uses_chain_prompt_and_enumerates_steps(monkeypatch):
    finding = {
        "_category": "attack_chain",
        "target": "1.2.3.4:8080 -> 1.2.3.5",
        "action": "Jenkins creds reused for RCE on build node",
        "confidence": "HIGH", "impact": "CRITICAL",
        "evidence": "default-login matched on H1",
        "commands": ["curl -s http://H1/whoAmI", "ssh with reused creds to H2",
                     "run id on H2"],
        "expected_result": "command execution on H2",
    }
    cap = _run(finding, monkeypatch)
    assert cap["system"] == aiv.SYSTEM_PROMPT_CHAIN
    seed = cap["messages"][0]["content"]
    assert "ATTACK CHAIN" in seed
    # Steps enumerated in order.
    assert "1. curl -s http://H1/whoAmI" in seed
    assert "2. ssh with reused creds to H2" in seed
    assert "3. run id on H2" in seed


def test_non_chain_uses_single_finding_prompt(monkeypatch):
    finding = {
        "_category": "quick_win",
        "target": "1.2.3.4:443",
        "action": "Expired TLS cert",
        "commands": ["openssl s_client -connect 1.2.3.4:443"],
        "evidence": "testssl flagged expiry",
    }
    cap = _run(finding, monkeypatch)
    assert cap["system"] == aiv.SYSTEM_PROMPT
    seed = cap["messages"][0]["content"]
    assert "Validate this suspected vulnerability" in seed
    assert "ATTACK CHAIN" not in seed


def test_render_chain_steps_shows_the_walk():
    lines = []
    r = {"steps": [
        {"step": 1, "status": "confirmed", "evidence": "default-login matched on H1"},
        {"step": 2, "status": "failed", "evidence": "reused creds refused on H2"},
    ]}
    aiv._render_chain_steps(lines, r)
    out = "\n".join(lines)
    assert "Attack Chain — step-by-step" in out
    assert "Step 1" in out and "confirmed" in out and "default-login matched on H1" in out
    assert "Step 2" in out and "failed" in out


def test_render_chain_steps_noop_without_steps():
    lines = []
    aiv._render_chain_steps(lines, {"verdict": "confirmed"})
    assert lines == []


def test_report_includes_chain_walk(tmp_path):
    results = [{
        "verdict": "confirmed", "severity": "critical",
        "evidence": "full chain demonstrated",
        "finding": {"action": "Jenkins creds -> RCE", "target": "H1 -> H2"},
        "steps": [{"step": 1, "status": "confirmed", "evidence": "creds matched"},
                  {"step": 2, "status": "confirmed", "evidence": "id ran on H2"}],
        "tool_history": [],
    }]
    out = tmp_path / "validation-report.md"
    aiv._render_report(results, str(out))
    txt = out.read_text()
    assert "Attack Chain — step-by-step" in txt
    assert "Step 1" in txt and "Step 2" in txt
