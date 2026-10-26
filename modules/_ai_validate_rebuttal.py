"""Adversarial rebuttal pass for ai_validate (independent second opinion).

The primary ai_validate agent (`_run_agent_loop`) is the *actor*: it tries to
confirm or refute a finding. This module is the *independent verifier*: for each
finding the actor ruled on, a SECOND agent starts from a FRESH context (it does
NOT inherit the actor's transcript — that's what lets it escape a wrong early
assumption) and is tasked with OVERTURNING the verdict:

  - a "confirmed" verdict is challenged as a possible false positive,
  - a "refuted" verdict is challenged as a possible missed real issue.

Reconciliation is conservative and mirrors ai_validate's `_guard_verdict`
principle — **a verdict only flips on evidence a command actually produced**:

  - rebuttal agrees               -> keep verdict, mark ``corroborated``
  - rebuttal overturns w/ a run   -> flip to the rebuttal's verdict (``flipped``)
  - rebuttal disagrees, no run    -> keep verdict, mark ``contested`` (a human
                                     sees the doubt; no speculative flip)

This is a helper (leading underscore => not auto-discovered as a module). It
reuses ai_validate's tool definitions, command builder, and scope/safety gates
unchanged, so the rebuttal respects the same authorization ceiling as the actor.
When ai_validate is split into a package this folds in alongside the agent loop.
"""

import json
import logging

from core.ai_provider import display_model_name, log_ai_interaction
from modules.ai_validate import (
    TOOLS,
    TOOL_NAMES,
    MAX_ATTEMPTS_PER_FINDING,
    _build_command,
    _is_safe_command,
    _execute_command,
    _shell_join,
    _create_anthropic_client,
    _egress_response_text,
    _parse_verdict,
    _guard_verdict,
    _category_playbook,
    _classify_finding,
    _get_protocol_hints,
)

logger = logging.getLogger("monkeyx.modules.ai_validate.rebuttal")

# Verdicts worth challenging: the "positive and negative" findings. unclear /
# error carry no confident claim to overturn, so they are skipped by default.
_REBUT_VERDICTS = frozenset({"confirmed", "refuted"})


REBUTTAL_SYSTEM_PROMPT = """You are a SECOND, independent penetration-test validation agent working during an authorized security assessment. A prior agent already investigated a finding and reached a verdict. Your job is ADVERSARIAL: try to OVERTURN that verdict with your own evidence.

- If the prior verdict is "confirmed": assume it may be a FALSE POSITIVE. Find the benign explanation — a CDN/WAF/proxy default or error page, a backported/patched build whose banner merely looks vulnerable, or a scanner "detect-only" match that proves the tech is present but not exploitable. Run the single read-only check that best distinguishes the real vulnerability from that benign cause.
- If the prior verdict is "refuted": assume the prior agent may have GIVEN UP TOO EARLY or run the wrong test. Find the decisive check it skipped that would actually prove exploitability, and run it.

Rules:
- Non-destructive / read-only ONLY — the same constraints as the prior agent. No writing data or state, no mail relay, no SET/write ops, no credential spraying, no persistence, no pivoting. If an intrusive step is not present in a provided checklist, do NOT perform or improvise it.
- Reach your OWN conclusion from evidence YOU gather. Do not defer to the prior verdict, and do not treat the prior agent's tool output as sufficient — re-test the decisive point yourself.
- A tool result beginning with "BLOCKED:" did NOT run (the scope/safety layer refused it) and is NOT evidence. If every check you attempt is blocked, return "unclear" — never confirm or refute without a command that actually ran.
- Prefer the single decisive test. Start with the cheapest check and escalate only if needed.
- Every tool call MUST include a `purpose`: one plain-language sentence saying what the step checks and why it moves your conclusion forward.

When you have enough evidence, respond with text (no more tool calls) containing your INDEPENDENT verdict as JSON:
{"verdict": "confirmed", "evidence": "what YOUR checks showed", "poc_command": "the single best command demonstrating it", "severity": "critical|high|medium|low"}
or
{"verdict": "refuted", "evidence": "why it is not exploitable, per your checks"}
or
{"verdict": "unclear", "evidence": "what you tried and why it is inconclusive"}"""


def _prior_steps_text(tool_history: list) -> str:
    """Render the actor's executed steps for the rebuttal seed message."""
    lines = []
    for step in tool_history or []:
        cmd = step.get("command", "")
        out = (step.get("output_preview") or "").strip()
        lines.append(f"$ {cmd}")
        lines.append(out if out else "(no output)")
    return "\n".join(lines) if lines else "(the prior agent ran no commands)"


def _build_rebuttal_message(finding: dict, result: dict, raw_evidence: list | None) -> str:
    """Seed message for the rebuttal agent: finding + the verdict to challenge."""
    orig = result.get("verdict", "unknown")
    msg = (
        "A prior validation agent assessed this finding and reached a verdict you "
        "must now independently challenge.\n\n"
        f"Target: {finding.get('target', 'unknown')}\n"
        f"Finding: {finding.get('action', 'unknown')}\n"
        f"AI-summarized evidence: {finding.get('evidence', '')}\n\n"
        "--- PRIOR AGENT VERDICT (challenge this) ---\n"
        f"Verdict: {orig}\n"
        f"Stated evidence: {result.get('evidence', '')}\n"
    )
    if result.get("poc_command"):
        msg += f"PoC command: {result['poc_command']}\n"
    msg += (
        "Steps the prior agent ran:\n"
        f"{_prior_steps_text(result.get('tool_history'))}\n"
        "---\n"
    )
    if raw_evidence:
        msg += (
            "\n--- Raw scanner evidence for this host (source of truth) ---\n"
            + json.dumps(raw_evidence, indent=1)
            + "\n---\n"
        )
    playbook = _category_playbook(finding)
    if playbook:
        msg += f"\n--- Validation playbook ({_classify_finding(finding)}) ---\n{playbook}\n---\n"
    protocol_hints = _get_protocol_hints(finding, allow_intrusive=False)
    if protocol_hints:
        msg += f"\n--- Protocol-specific checks ---\n{protocol_hints}\n---\n"
    msg += (
        "\nBegin. Independently confirm or overturn the prior verdict using the "
        "available tools. Start with the single most decisive read-only check."
    )
    return msg


def _run_rebuttal_loop(finding, result, scope_ips, scope_networks, scope_hosts,
                       config, model, allow_intrusive=False, raw_evidence=None,
                       host_scope=None, logs_dir=None, egress_counter=None,
                       max_attempts=MAX_ATTEMPTS_PER_FINDING) -> dict:
    """Run a fresh adversarial agent loop that tries to overturn `result`.

    Mirrors ai_validate._run_agent_loop's execution/scope/egress handling (the
    loop body is intentionally duplicated here rather than shared, to keep the
    primary validation path untouched; it merges when ai_validate is split into
    a package). Returns a verdict dict {verdict, evidence, poc_command?,
    severity?, tool_history, _usage}. Any confirmed/refuted verdict that rests on
    no executed command is downgraded to 'unclear' by _guard_verdict, so only an
    executed check can carry a flip.
    """
    client = _create_anthropic_client(config)
    log_model = display_model_name(model, config)

    def _log_egress(phase, system_prompt, content):
        if egress_counter is None:
            return
        if phase == "request":
            egress_counter[0] += 1
        log_ai_interaction(logs_dir, egress_counter[0], phase, "anthropic",
                           log_model, system_prompt=system_prompt, content=content)

    messages = [{"role": "user",
                 "content": _build_rebuttal_message(finding, result, raw_evidence)}]
    attempts = 0
    tool_history: list = []
    usage_input = 0
    usage_output = 0

    while attempts < max_attempts:
        last = messages[-1]["content"] if messages else ""
        _log_egress("request",
                    REBUTTAL_SYSTEM_PROMPT if attempts == 0 else None,
                    last if isinstance(last, str) else json.dumps(last, default=str))
        try:
            with client.messages.stream(
                model=model,
                max_tokens=2048,
                system=REBUTTAL_SYSTEM_PROMPT,
                tools=TOOLS,
                messages=messages,
            ) as _stream:
                response = _stream.get_final_message()
        except Exception as e:
            logger.error("Claude API error during rebuttal: %s", e)
            return {
                "verdict": "error",
                "evidence": f"API error: {e}",
                "tool_history": tool_history,
                "_usage": {"input_tokens": usage_input, "output_tokens": usage_output, "calls": attempts},
            }

        if hasattr(response, "usage"):
            usage_input += getattr(response.usage, "input_tokens", 0)
            usage_output += getattr(response.usage, "output_tokens", 0)

        _log_egress("response", None, _egress_response_text(response))

        tool_use_blocks = [b for b in response.content if b.type == "tool_use"]
        text_blocks = [b for b in response.content if b.type == "text"]

        if not tool_use_blocks:
            final_text = " ".join(b.text for b in text_blocks)
            verdict = _parse_verdict(final_text)
            # A rebuttal verdict must also rest on a command that ran; otherwise
            # it can only contest, never flip (enforced by downgrading to unclear).
            _guard_verdict(verdict, tool_history)
            verdict["tool_history"] = tool_history
            verdict["_usage"] = {"input_tokens": usage_input, "output_tokens": usage_output, "calls": attempts + 1}
            return verdict

        turn_reasoning = " ".join(b.text.strip() for b in text_blocks if b.text.strip()).strip()

        tool_results = []
        for block in tool_use_blocks:
            if block.name not in TOOL_NAMES:
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": f"Unknown tool: {block.name}",
                })
                continue

            argv, stdin = _build_command(block.name, block.input, allow_intrusive)
            cmd_display = _shell_join(argv)
            safe, reason = _is_safe_command(
                argv, scope_ips, scope_networks, scope_hosts,
                tool_name=block.name, host_scope=host_scope)

            if not safe:
                result_text = f"BLOCKED: {reason}"
                logger.warning("Rebuttal blocked command: %s (%s)", cmd_display, reason)
            else:
                logger.info("Rebuttal executing: %s", cmd_display)
                result_text = _execute_command(argv, stdin=stdin)

            purpose = ""
            if isinstance(block.input, dict):
                purpose = (block.input.get("purpose") or "").strip()

            tool_history.append({
                "tool": block.name,
                "input": block.input,
                "command": cmd_display,
                "blocked": not safe,
                "output_preview": result_text[:500],
                "purpose": purpose,
                "reasoning": turn_reasoning,
            })
            tool_results.append({
                "type": "tool_result",
                "tool_use_id": block.id,
                "content": result_text,
            })
            attempts += 1

        messages.append({"role": "assistant", "content": response.content})
        messages.append({"role": "user", "content": tool_results})

    return {
        "verdict": "unclear",
        "evidence": "max rebuttal attempts reached",
        "tool_history": tool_history,
        "_usage": {"input_tokens": usage_input, "output_tokens": usage_output, "calls": attempts},
    }


def reconcile(result: dict, rebuttal: dict) -> dict:
    """Fold a rebuttal verdict into `result` (mutated in place). Pure/testable.

    Rules (a flip requires the rebuttal to have run a command — enforced upstream
    by _guard_verdict, which downgrades an unsupported confirmed/refuted to
    'unclear' before we get here):

      - rebuttal verdict == original          -> corroborated (verdict kept)
      - rebuttal verdict in {confirmed,refuted} and != original
                                               -> flipped to the rebuttal verdict
      - rebuttal disagrees but is unclear/error (incl. a downgraded reasoning-only
        challenge)                             -> contested (verdict kept)
    """
    orig = result.get("verdict")
    reb_verdict = rebuttal.get("verdict")
    reb_history = rebuttal.get("tool_history") or []

    block = {
        "original_verdict": orig,
        "rebuttal_verdict": reb_verdict,
        "evidence": rebuttal.get("evidence"),
        "tool_history": reb_history,
        "flipped": False,
        "contested": False,
        "corroborated": False,
        "usage": rebuttal.get("_usage"),
    }

    if reb_verdict == orig:
        block["corroborated"] = True
    elif reb_verdict in _REBUT_VERDICTS:
        # An executed, opposing conclusion — overturn the original verdict.
        block["flipped"] = True
        result["verdict"] = reb_verdict
        result["evidence"] = (
            f"[overturned by rebuttal — was {orig}] "
            + (rebuttal.get("evidence") or "")
        ).strip()
        if reb_verdict == "confirmed":
            # The rebuttal now owns the proof; carry its PoC/severity.
            if rebuttal.get("poc_command"):
                result["poc_command"] = rebuttal["poc_command"]
            if rebuttal.get("severity"):
                result["severity"] = rebuttal["severity"]
        else:
            # confirmed -> refuted: the old PoC no longer demonstrates anything.
            result.pop("poc_command", None)
    elif reb_verdict and reb_verdict != "error":
        # Disagreement without executed proof (unclear / downgraded) — surface
        # the doubt but do not flip on speculation.
        block["contested"] = True

    result["rebuttal"] = block
    return result


def apply_rebuttal_phase(results: list, evidence_index: dict, scope_ips: set,
                         scope_networks: list, scope_hosts: set, config: dict,
                         model: str, allow_intrusive: bool = False,
                         host_scope: tuple | None = None, logs_dir=None,
                         egress_counter=None,
                         max_attempts=MAX_ATTEMPTS_PER_FINDING) -> dict:
    """Run the adversarial rebuttal over confirmed/refuted results (in place).

    Each rebuttal is an extra AI agent loop; its token usage is added to the
    matching result's `_usage` so run_ai_validate's totals include it. Returns a
    small summary {rebutted, flipped, contested, corroborated}.
    """
    # Imported here (not at module top) to avoid a load-time import cycle with
    # ai_validate, which imports this module lazily inside run_ai_validate.
    from modules.ai_validate import _evidence_for_finding

    summary = {"rebutted": 0, "flipped": 0, "contested": 0, "corroborated": 0}

    for result in results:
        if result.get("verdict") not in _REBUT_VERDICTS:
            continue
        finding = result.get("finding") or {}
        raw_evidence = _evidence_for_finding(finding, evidence_index)
        rebuttal = _run_rebuttal_loop(
            finding, result, scope_ips, scope_networks, scope_hosts, config, model,
            allow_intrusive=allow_intrusive, raw_evidence=raw_evidence,
            host_scope=host_scope, logs_dir=logs_dir, egress_counter=egress_counter,
            max_attempts=max_attempts)

        # Fold the rebuttal's token usage into the result so aggregate totals in
        # run_ai_validate (which sum r["_usage"]) account for the second pass.
        reb_usage = rebuttal.get("_usage") or {}
        usage = result.setdefault("_usage", {"input_tokens": 0, "output_tokens": 0, "calls": 0})
        usage["input_tokens"] = usage.get("input_tokens", 0) + reb_usage.get("input_tokens", 0)
        usage["output_tokens"] = usage.get("output_tokens", 0) + reb_usage.get("output_tokens", 0)
        usage["calls"] = usage.get("calls", 0) + reb_usage.get("calls", 0)

        reconcile(result, rebuttal)
        block = result.get("rebuttal") or {}
        summary["rebutted"] += 1
        if block.get("flipped"):
            summary["flipped"] += 1
        elif block.get("contested"):
            summary["contested"] += 1
        elif block.get("corroborated"):
            summary["corroborated"] += 1

    return summary
