"""AI-assisted analysis module for MonkeyX scan results.

Uses an AI provider to identify attack paths, research known vulnerabilities
for discovered services/versions, and produce prioritized recommendations.
Reads normalized JSONL from the normalize module and structured output from
the analyze module.
"""

import glob
import json
import logging
import os
import re
from collections import defaultdict
from datetime import datetime, timezone

from core.ai_provider import AIProvider, display_model_name
from core.anonymize import (
    anonymize_text as _anonymize_text,
    deanonymize_obj as _deanonymize_obj,
    extract_domains_from_text as _extract_domains_from_text,
)
from core.utils import version_output_path

logger = logging.getLogger('monkeyx.modules.ai_analyze')

REQUIRED_INPUTS = frozenset()

# --- Configurable limits with safe defaults ---
# These control how much data is sent to the AI to prevent excessive API costs.
# Override via workflow YAML step args or kwargs.

DEFAULT_LIMITS = {
    "quick": {
        "max_hosts": 20,
        "max_findings_per_host": 10,
        "max_web_dirs_per_host": 5,
        "max_ports_per_host": 30,
        "max_banner_len": 80,
        "max_tokens": 30000,
    },
    "standard": {
        "max_hosts": 50,
        "max_findings_per_host": 25,
        "max_web_dirs_per_host": 10,
        "max_ports_per_host": 50,
        "max_banner_len": 120,
        "max_tokens": 60000,
    },
    "balanced": {
        "max_hosts": 100,
        "max_findings_per_host": 30,
        "max_web_dirs_per_host": 15,
        "max_ports_per_host": 75,
        "max_banner_len": 150,
        "max_tokens": 80000,
    },
    "deep": {
        "max_hosts": 150,
        "max_findings_per_host": 50,
        "max_web_dirs_per_host": 25,
        "max_ports_per_host": 100,
        "max_banner_len": 200,
        "max_tokens": 120000,
    },
    "unlimited": {
        "max_hosts": None,
        "max_findings_per_host": None,
        "max_web_dirs_per_host": None,
        "max_ports_per_host": None,
        "max_banner_len": 300,
        "max_tokens": 200000,
    },
}


SYSTEM_PROMPT_RECOMMENDATIONS ="""You are a security auditor producing a prioritized exploitation plan. For each finding, provide the exact commands a security team would use to verify and exploit during a sanctioned assessment.

Rules — be strict about what is confirmed vs. detected:
- A nuclei "panel" or "detect" template means the service/page EXISTS — it does NOT confirm default credentials, auth bypass, or exploitability.
- A nuclei "default-login" template means credentials were actually tested and succeeded — this IS confirmed.
- An nmap version detection identifies the software version — it does NOT confirm a CVE is exploitable.
- nmap "amqp-info" returning capabilities does NOT prove default credentials. Only scripts that explicitly test auth (e.g. "ftp-anon: Anonymous FTP login allowed") confirm credential issues.
- Only state something is "confirmed" if the scan data explicitly shows successful exploitation (data extracted, auth bypassed, command executed, default-login matched).
- If nothing actionable was found, return empty lists. That is a valid and useful result.

Impact calibration — informational disclosures are LOW, not HIGH/CRITICAL:
- Internal/private (RFC1918) IP address disclosure, detailed version/banner disclosure, software fingerprinting, and server-header leakage are LOW impact ON THEIR OWN. They only matter as a stepping stone to a concrete exploit — rate the disclosure itself LOW, and if a specific version maps to an exploitable CVE, put THAT in cve_research (not a HIGH disclosure finding).
- Reserve HIGH/CRITICAL impact for findings that grant access, data, or code execution (auth bypass, RCE, SQLi/data extraction, credential compromise, SSRF reaching internal services) — backed by evidence.

For CONFIRMED findings (quick_wins and attack_chains):
- Every item MUST cite concrete scanner evidence proving exploitability (template ID, script name, exact output).
- Confidence HIGH = scanner explicitly confirmed it. MEDIUM = strong evidence but not tool-confirmed.
- Provide EXACT commands with host labels (H1, H2, etc.), ports, paths, and parameters from the scan data. Use the label verbatim as the address (e.g. `redis-cli -h H1 -p 6379`) — do NOT wrap it in angle brackets or add a suffix like `<H1_IP>`; it is the literal host, not a placeholder to fill in.
- Attack chains should show how findings connect logically — single-host or multi-host.

STEP DETAIL — the report merges every item into ONE ranked attack-path playbook, so make each one runnable top-to-bottom:
- Treat each entry in "commands" as ONE ordered step. Prefer a few meaningful steps (recon → gain access → confirm/loot) over a single opaque one-liner.
- When a step consumes the previous step's output (a token, path, SID, credential), say so inline as a comment on that step (e.g. `# use the session cookie from step 2`).
- "expected_result" must name the CONCRETE signal that proves it worked (a specific banner, an HTTP 200 + body marker, rows returned, a shell) — so both the operator and the downstream validator know success from failure.
- Put inter-step reasoning, prerequisites, pivots, and "if blocked, try X" in "notes" — NOT inside the shell block.

COMMAND REALISM — do NOT fabricate tools or exploits (critical):
- Commands may use ANY real, publicly-available tool or technique (e.g. curl, nmap, nuclei, ffuf, gobuster, hydra, sqlmap, medusa, testssl, openssl, dig, snmpwalk, smbclient, crackmapexec/nxc, enum4linux, wpscan, msfconsole, etc.). You are NOT limited to a fixed list — but every tool you name must actually exist.
- NEVER invent a script, binary, or PoC filename. Do not emit commands like `python3 exploit_CVE-2024-1234.py`, `./poc.sh`, `ruby cve.rb`, or a made-up path. These do not exist on the operator's machine and are dangerous noise.
- Do NOT invent Metasploit module paths (e.g. `exploit/linux/http/<madeup>`). Only reference an msf module if you are certain it exists; otherwise describe the approach in "notes".
- If exploiting a finding would require a public PoC or a tool that may not be installed, DO NOT write a fake command. Instead: put a real reconnaissance/verification command (using a standard tool) in "commands", and in "notes" name the CVE and state that a public PoC must be sourced/verified manually.
- If no real command can be constructed for an item, set "commands" to an empty list and explain the manual step in "notes". An empty commands list is acceptable and preferred over a fabricated one.
- Prefer commands that a validation agent could actually run (curl/nmap/nuclei/ffuf/testssl/dig/openssl/snmpwalk/smbclient/nc/whatweb/ssh-audit) so findings can be auto-verified downstream.

For UNCONFIRMED findings (requires_verification and cve_research):
- Clearly state in "evidence" that exploitability is UNTESTED.
- Include commands for initial verification only.

Group into these four categories:
1. Quick wins: confirmed exploitable, verifiable in < 15 minutes with one command
2. Attack chains: confirmed or high-confidence findings that need 2-5 steps, possibly spanning multiple hosts. Include confidence and impact ratings.
3. Requires verification: detected but NOT confirmed — default cred candidates, management panels, open services where auth was not tested
4. CVE research: version-matched CVE advisories needing PoC validation

Output valid JSON:
{
  "quick_wins": [
    {"target": "host:port", "action": "one-line description", "evidence": "what confirmed this (nuclei template, nmap script, etc.)", "commands": ["exact shell command"], "expected_result": "what success looks like"}
  ],
  "attack_chains": [
    {"target": "host:port or multiple hosts", "action": "one-line description", "confidence": "HIGH|MEDIUM", "impact": "CRITICAL|HIGH|MEDIUM", "evidence": "what confirmed this", "commands": ["step 1", "step 2", "..."], "expected_result": "what success looks like", "notes": "caveats, dependencies, or multi-host chain explanation"}
  ],
  "requires_verification": [
    {"target": "host:port", "action": "one-line description", "evidence": "what the scanner detected (NOT confirmed exploitable)", "commands": ["command to test"], "expected_result": "what success would look like if vulnerable", "notes": "why this is worth testing"}
  ],
  "cve_research": [
    {"target": "host:port", "action": "one-line description", "evidence": "CVE-YYYY-NNNNN matching exact version", "commands": ["command to validate"], "expected_result": "what success looks like", "notes": "advisory details, public PoC availability"}
  ]
}"""

SYSTEM_PROMPT_CORRELATION = """You are a network infrastructure analyst reviewing scan data from multiple tools. Your job is to find RELATIONSHIPS between hosts that would not be visible when reviewing each tool's output in isolation.

Look for:
1. **Infrastructure patterns**: Hosts sharing software stacks, DNS naming patterns suggesting same network segment or team, identical banners indicating shared management
2. **Combined findings**: Issues detected on different hosts by different scanners that together paint a larger picture of the environment's security posture
3. **Network relationships**: How hosts relate to each other based on shared services, similar configurations, or apparent trust relationships
4. **Outlier hosts**: Systems with unusual port combinations, outdated versions compared to peers, or services that don't match the surrounding environment
5. **Shared management indicators**: Same software versions + same non-default configurations across hosts suggesting centralized administration

Rules:
- Only report correlations backed by SPECIFIC data from the scan (cite the host labels, ports, banners, or findings that prove the relationship)
- Each correlation must involve 2+ hosts or 2+ different scanner outputs
- Do NOT report single-host findings (those are covered elsewhere)
- A host reached by both its IP and its hostname is ONE host, not a relationship — never infer a "shared deployment", "fleet", or "cluster" from the same service seen via IP and DNS name.
- Do NOT escalate a passive/OSINT reference (e.g. a public Docker Hub / GitHub / cloud-bucket URL found by bbot) into a causal claim like "the vulnerable image is baked into the deployment" or "supply-chain risk". State only what the data shows (a public reference exists) and, if worth noting, frame follow-up as an unverified lead — not a proven relationship.
- Ground every `implication` in the cited evidence. Do NOT speculate about architecture (load balancers, multi-tenancy, segmentation) that the scan data does not directly show.
- If no meaningful correlations exist, return an empty list. That is a valid result.

Output valid JSON:
{
  "correlations": [
    {
      "title": "short descriptive name",
      "type": "infrastructure_pattern|combined_finding|network_relationship|outlier_host|shared_management",
      "hosts": ["H1", "H2", ...],
      "evidence": "what specific scan data proves this relationship",
      "implication": "what this means — the security significance of this relationship",
      "commands": ["optional: command(s) to investigate further"]
    }
  ]
}"""


def _resolve_limits(depth: str, kwargs: dict) -> dict:
    """Resolve effective limits from depth preset + any explicit overrides."""
    base = dict(DEFAULT_LIMITS.get(depth, DEFAULT_LIMITS["standard"]))

    # Allow per-field override via kwargs
    for key in base:
        override = kwargs.get(f"ai_{key}")
        if override is not None:
            if override == "none" or override == "unlimited":
                base[key] = None
            else:
                base[key] = int(override)

    return base


def _build_host_alias_map(host_data: dict) -> tuple[dict, dict]:
    """Build bidirectional IP/domain <-> alias mappings.

    Returns (token_to_alias, alias_to_token) where:
    - IPs get aliases H1, H2, ... (sorted by finding+port count)
    - Domains get aliases D1, D2, ... (extracted from findings, URLs, subdomains)

    Both IPs and domains are anonymized so no client-identifying data reaches the AI.
    """
    sorted_hosts = sorted(
        host_data["hosts"].keys(),
        key=lambda ip: len(host_data["hosts"][ip]["findings"]) + len(host_data["hosts"][ip]["ports"]),
        reverse=True,
    )
    import re
    token_to_alias = {}
    alias_to_token = {}
    for i, ip in enumerate(sorted_hosts, 1):
        alias = f"H{i}"
        token_to_alias[ip] = alias
        alias_to_token[alias] = ip

    # Extract domains (and any IPs embedded in text) from findings, web_dirs,
    # subdomains, and banners.
    domains = set()
    text_ips = set()
    ipv4_re = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
    for host_ip, data in host_data["hosts"].items():
        for f in data.get("findings", []):
            detail = f.get("detail") or ""
            title = f.get("title") or ""
            _extract_domains_from_text(detail, domains)
            _extract_domains_from_text(title, domains)
            text_ips.update(ipv4_re.findall(detail))
            text_ips.update(ipv4_re.findall(title))
        for wd in data.get("web_dirs", []):
            _extract_domains_from_text(wd.get("url") or "", domains)
        for sub in data.get("subdomains", []):
            if sub:
                domains.add(sub.lower())
        for p in data.get("ports", []):
            banner = p.get("banner") or ""
            _extract_domains_from_text(banner, domains)
            text_ips.update(ipv4_re.findall(banner))

    # Client IPs that appear inside finding/banner TEXT but are not themselves
    # host keys (e.g. a resolved IP embedded in a testssl SWEET32 line) would
    # otherwise egress raw — the map only covered host keys + domains. Alias them
    # too, continuing the H* numbering after the host-key hosts.
    next_h = len(sorted_hosts) + 1
    for ip in sorted(text_ips):
        if ip not in token_to_alias:
            alias = f"H{next_h}"
            token_to_alias[ip] = alias
            alias_to_token[alias] = ip
            next_h += 1

    # Remove anything that looks like an IP (already handled above)
    ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    domains = {d for d in domains if not ip_pattern.match(d) and '.' in d and len(d) > 3}

    # Sort by length descending so longer subdomains are replaced before their parents
    for i, domain in enumerate(sorted(domains, key=len, reverse=True), 1):
        alias = f"D{i}"
        token_to_alias[domain] = alias
        alias_to_token[alias] = domain

    return token_to_alias, alias_to_token


# _extract_domains_from_text / _anonymize_text / _deanonymize_obj now live in
# core.anonymize (imported at the top under these same names) — the single,
# auditable home for AI-egress anonymization, shared with ai_analyze_gowitness.


# --- Map-reduce batching -------------------------------------------------- #
# Two clearly separated controls:
#   * ai_max_hosts (depth presets + "unlimited") — the TOTAL hosts analysed. The
#     coverage/cost ceiling, in the unit operators think in.
#   * how those hosts are split across AI calls — AUTOMATIC token-aware packing:
#     fill each call to ~CONTEXT_FRACTION of the model's context window, so a
#     sparse scope of 1000 lean hosts may go in ONE call while a dense one splits.
#     ai_hosts_per_call is an optional hard override (fixed count) for determinism.
# Multi-call runs are consolidated by a synthesis pass.

_REC_KEYS = ("quick_wins", "attack_chains", "requires_verification", "cve_research")

# Fraction of the context window we fill with host data — not 100%: leaves room
# for the system prompt, service inventory, KB text and the response, and avoids
# the "lost in the middle" fidelity drop on a brim-full prompt.
CONTEXT_FRACTION = 0.5
DEFAULT_CONTEXT_WINDOW = 1_000_000    # tokens — most Claude deployments
BEDROCK_CONTEXT_WINDOW = 200_000      # 1M is a gated beta on Bedrock; assume 200k
_CHARS_PER_TOKEN = 4                  # standard rough estimate

SYSTEM_PROMPT_SYNTHESIS = """You are a lead penetration tester consolidating the exploitation plans produced for separate batches of hosts from ONE engagement. You are given the merged recommendations as JSON. Produce a single, de-duplicated, prioritized plan in the SAME JSON schema.

Rules:
- Merge duplicates (same host+action, or the same finding) into one entry; keep the most complete commands and notes.
- Stitch attack chains that span hosts from different batches into unified chains where the evidence supports it (e.g. credentials/tokens found on one host that unlock another).
- Re-rank so the highest-likelihood, highest-impact items lead.
- Do NOT invent findings, hosts, or commands not present in the input. Consolidation must not drop coverage — only remove true duplicates.

Output JSON with keys: quick_wins, attack_chains, requires_verification, cve_research (each a list, same item shapes as the input)."""


def _chunk(seq: list, size: int) -> list:
    if size and size > 0:
        return [seq[i:i + size] for i in range(0, len(seq), size)]
    return [seq] if seq else []


def _context_window(ai: AIProvider, kwargs: dict) -> int:
    """Model context window in tokens. Resolution order (first wins):

    1. explicit ``ai_context_window`` kwarg (per-run override);
    2. ``context_window`` in the provider's credentials.yaml block — set this
       ONCE for a Bedrock account that HAS the 1M-context beta enabled, so it is
       no longer clamped every run;
    3. default 1M, dropped to 200k on Bedrock (where the 1M window is a gated
       beta and assuming it would otherwise error on accounts without it).
    """
    override = kwargs.get("ai_context_window")
    if override:
        try:
            return int(override)
        except (TypeError, ValueError):
            pass
    config = (getattr(ai, "config", {}) or {})
    cfg_window = config.get("context_window")
    if cfg_window:
        try:
            return int(cfg_window)
        except (TypeError, ValueError):
            pass
    is_bedrock = bool(config.get("aws_region"))
    return BEDROCK_CONTEXT_WINDOW if is_bedrock else DEFAULT_CONTEXT_WINDOW


def _host_data_char_budget(ai: AIProvider, kwargs: dict) -> int:
    """Chars of host data to pack per AI call = window * fraction * chars-per-token."""
    window = _context_window(ai, kwargs)
    frac = kwargs.get("ai_context_fraction", CONTEXT_FRACTION)
    try:
        frac = float(frac)
    except (TypeError, ValueError):
        frac = CONTEXT_FRACTION
    frac = min(max(frac, 0.05), 0.9)
    return int(window * frac * _CHARS_PER_TOKEN)


def _host_footprint_chars(data: dict) -> int:
    """Rough serialized size of one host's contribution to the prompt."""
    try:
        return len(json.dumps(data, default=str))
    except Exception:
        return 2000


def _pack_hosts(sorted_ips: list, host_data: dict, char_budget: int,
                hosts_per_call: int | None) -> list:
    """Group hosts into per-call batches.

    hosts_per_call set -> fixed-count chunks (manual override). Otherwise pack
    greedily by char budget: as many hosts as fit per call, always >=1 (a lone
    host bigger than the budget still gets its own call rather than being dropped).
    """
    if hosts_per_call and hosts_per_call > 0:
        return _chunk(sorted_ips, hosts_per_call)
    batches, cur, cur_chars = [], [], 0
    for ip in sorted_ips:
        c = _host_footprint_chars(host_data["hosts"].get(ip, {}))
        if cur and cur_chars + c > char_budget:
            batches.append(cur)
            cur, cur_chars = [], 0
        cur.append(ip)
        cur_chars += c
    if cur:
        batches.append(cur)
    return batches


def _subset_host_data(host_data: dict, host_ips: list) -> dict:
    """A host_data view containing only the given host IPs (totals recomputed)."""
    hosts = {ip: host_data["hosts"][ip] for ip in host_ips if ip in host_data["hosts"]}
    sub = dict(host_data)
    sub["hosts"] = hosts
    sub["total_ports"] = sum(len(d.get("ports", [])) for d in hosts.values())
    sub["total_findings"] = sum(len(d.get("findings", [])) for d in hosts.values())
    return sub


def _dedup_keep_first(items: list, key) -> list:
    seen, out = set(), []
    for it in items:
        try:
            k = key(it)
        except Exception:
            k = id(it)
        if k in seen:
            continue
        seen.add(k)
        out.append(it)
    return out


def _rec_item_key(item) -> str:
    if not isinstance(item, dict):
        return str(item)
    host = item.get("host") or item.get("target") or ""
    label = item.get("action") or item.get("title") or item.get("name") or ""
    return f"{host}|{label}".strip().lower()


def _merge_attack_paths(recs: dict) -> list[dict]:
    """Fold the four recommendation buckets into ONE likelihood-ranked, de-duped
    attack-path list for the report: high-confidence quick-win leads first, then
    high- then medium-confidence chains, then detected-but-unverified, then CVE
    leads. Nothing here is "exploited" — ai_analyze precedes ai_validate. Each
    item is tagged (`_status`/`_tier`/`_multi`) so the report shows its confidence
    without implying proof. The JSON buckets are left unchanged — ai_validate and
    focus still read quick_wins/attack_chains/requires_verification/cve_research.
    """
    impact_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    items: list[dict] = []

    def _tag(bucket, tier, status, multi=False):
        for r in (recs.get(bucket) or []):
            if isinstance(r, dict):
                items.append({**r, "_tier": tier, "_status": status, "_multi": multi})

    # NOTE: ai_analyze runs BEFORE any exploitation (ai_validate). quick_wins are
    # high-confidence scanner-detected leads the AI judged quickly exploitable —
    # NOT something we actually exploited. Label them honestly so the report never
    # implies proof we don't have ("not exploited"); ai_validate issues verdicts.
    _tag("quick_wins", 0, "high-confidence lead — not exploited")
    for r in (recs.get("attack_chains") or []):
        if not isinstance(r, dict):
            continue
        conf = str(r.get("confidence") or "").upper()
        items.append({**r, "_tier": 1 if conf == "HIGH" else 2,
                      "_status": f"attack chain — {conf.lower() or 'unrated'} confidence",
                      "_multi": True})
    _tag("requires_verification", 3, "detected — needs verification")
    _tag("cve_research", 4, "CVE lead — validate PoC")

    items.sort(key=lambda it: (it["_tier"],
                               impact_rank.get(str(it.get("impact") or "").upper(), 2)))
    # Dedup by host|action keeping the FIRST (highest-ranked after the sort), so a
    # finding that appears as both a quick-win and a chain step shows once, at its
    # most-confident framing.
    return _dedup_keep_first(items, _rec_item_key)


def _merge_recommendations(batch_results: list) -> dict:
    """Union the four recommendation lists across batches, deduping obvious repeats."""
    merged = {k: [] for k in _REC_KEYS}
    for r in batch_results:
        if not isinstance(r, dict):
            continue
        for k in _REC_KEYS:
            merged[k].extend(r.get(k) or [])
    for k in _REC_KEYS:
        merged[k] = _dedup_keep_first(merged[k], _rec_item_key)
    return merged


def _correlation_context(correlations: dict) -> str:
    """Compact, prompt-ready summary of the Pass-1 correlations.

    Correlations are produced with the SAME H1/D1 aliasing as the recommendations
    passes, so this text can be injected into those prompts verbatim (no re-alias).
    Fed to the chaining passes so multi-host attack_chains can build on real
    cross-host relationships instead of only what lands in a single batch.
    """
    corrs = (correlations or {}).get("correlations") or []
    if not corrs:
        return ""
    lines = ["## Infrastructure Relationships (use these to build multi-host attack_chains where the evidence supports it):"]
    for c in corrs[:25]:
        if not isinstance(c, dict):
            continue
        hosts = ", ".join(str(h) for h in (c.get("hosts") or [])[:8])
        title = c.get("title") or c.get("type") or "relationship"
        impl = (c.get("implication") or "").strip()
        ev = (c.get("evidence") or "").strip()
        line = f"- {title} [{hosts}]"
        if impl:
            line += f": {impl}"
        elif ev:
            line += f": {ev}"
        lines.append(line)
    return "\n".join(lines) + "\n\n"


def _synthesize_recommendations(ai: AIProvider, batch_results: list,
                                token_to_alias: dict, alias_to_token: dict,
                                max_tokens: int, correlation_context: str = "") -> dict:
    """Reduce step: merge per-batch recommendations, then (only when >1 batch) one
    AI pass to dedup, stitch cross-host chains, and re-rank. The payload is
    anonymized (same H1/D1 aliasing as the map passes) and de-anonymized after.
    Falls back to the plain merge on any failure — synthesis never loses data."""
    merged = _merge_recommendations(batch_results)
    real = [r for r in batch_results if isinstance(r, dict)]
    if len(real) <= 1 or not any(merged[k] for k in _REC_KEYS):
        return merged
    try:
        # correlation_context is already aliased; prepend it so the synthesis pass
        # can stitch cross-batch chains using the discovered relationships.
        payload = (correlation_context + _anonymize_text(json.dumps(merged), token_to_alias))[:600_000]
        result = ai.query_json(SYSTEM_PROMPT_SYNTHESIS, payload, max_tokens=max_tokens)
        if isinstance(result, dict) and any(result.get(k) for k in _REC_KEYS):
            result = _deanonymize_obj(result, alias_to_token)
            for k in _REC_KEYS:
                result.setdefault(k, [])
            _sanitize_targets(result)
            _cap_informational_impact(result)
            _flag_fabricated_commands(result)
            return result
        logger.warning("Synthesis returned no usable recommendations; using plain merge")
    except Exception as e:
        logger.error("Recommendation synthesis pass failed, using plain merge: %s", e)
    return merged


def run_ai_analyze(prefix, **kwargs):
    """Run AI-assisted analysis on scan results.

    Args:
        prefix: Output file prefix
        **kwargs:
            data_prefix: Where JSONL files live
            reports_prefix: Where to write reports
            ai_provider: Override provider name (optional)
            ai_depth: "quick" | "standard" | "deep" | "unlimited" (controls limits)
            ai_max_hosts: Override max hosts to analyze (int or "unlimited")
            ai_max_findings_per_host: Override max findings per host (int or "unlimited")
            ai_max_web_dirs_per_host: Override max web dirs per host (int or "unlimited")
            ai_max_tokens: Override max tokens per AI call (int)
            kb_max_tokens: Knowledge base token budget per injection (default: 4000)

    Returns:
        dict with module results
    """
    data_prefix = kwargs.get('data_prefix', prefix)
    reports_prefix = kwargs.get('reports_prefix', prefix)
    provider_name = kwargs.get('ai_provider', None)
    depth = kwargs.get('ai_depth', 'standard')

    logger.debug("ai_analyze kwargs keys: %s", [k for k in kwargs if k.startswith('ai_')])

    limits = _resolve_limits(depth, kwargs)

    logger.info("AI analysis starting: depth=%s provider=%s limits=%s",
                depth, provider_name or "default", limits)
    print(f"\n[*] AI Analysis Module (depth: {depth})")
    print(f"[*] Limits: max_hosts={limits['max_hosts'] or 'unlimited'}, "
          f"max_tokens={limits['max_tokens'] or 'unlimited'}")

    # Determine logs directory for AI interaction logging
    output_dir = os.path.dirname(os.path.dirname(data_prefix)) if data_prefix else None
    logs_dir = os.path.join(output_dir, "logs") if output_dir else None

    try:
        ai = AIProvider(provider_name, logs_dir=logs_dir)
    except ValueError as e:
        logger.error("Failed to initialize AI provider: %s", e)
        msg = f"AI provider initialization failed: {e}"
        print(f"\n{'!'*60}")
        print(f"[ERROR] {msg}")
        print(f"[ERROR] Configure a provider in ~/.monkeyx/credentials.yaml")
        print(f"[ERROR] Or set MONKEYX_AI_PROVIDER environment variable")
        print(f"{'!'*60}\n")
        raise RuntimeError(msg) from e

    print(f"[*] Using AI provider: {ai.name} (model: {ai.config.get('model', 'default')})")

    # Load scan data
    host_data = _load_scan_data(data_prefix)
    if not host_data["hosts"]:
        logger.error("No scan data found to analyze")
        msg = "No normalized scan data found. Ensure normalize has been run."
        print(f"\n{'!'*60}")
        print(f"[ERROR] {msg}")
        print(f"[ERROR] Add 'normalize' to your workflow/modules before 'ai_analyze'")
        print(f"[ERROR]   e.g.: -m normalize analyze ai_analyze")
        print(f"{'!'*60}\n")
        raise RuntimeError(msg)

    total_hosts = len(host_data["hosts"])
    total_web_services = sum(len(h.get("web_services", [])) for h in host_data["hosts"].values())
    print(f"[+] Loaded data: {total_hosts} hosts, "
          f"{host_data['total_ports']} open ports, "
          f"{host_data['total_findings']} findings (nuclei+nessus), "
          f"{total_web_services} httpx records")

    # Load existing static analysis if available (covers all hosts cheaply)
    analysis_path = f"{data_prefix}-analysis.json"
    static_analysis = None
    if os.path.exists(analysis_path):
        with open(analysis_path) as f:
            static_analysis = json.load(f)
        logger.info("Loaded existing static analysis from %s", analysis_path)
        print(f"[+] Static analysis loaded — full-scope context for all {total_hosts} hosts")

    # Track truncation for reporting
    truncation = {
        "hosts_truncated": False,
        "hosts_total": total_hosts,
        "hosts_analyzed": total_hosts,
        "services_total": 0,
        "services_analyzed": 0,
        "findings_truncated": False,
        "findings_truncated_hosts": [],
        "web_dirs_truncated": False,
        "web_dirs_truncated_hosts": [],
    }

    max_tokens = limits["max_tokens"] or 200000

    # Build anonymization map (H1/H2 for IPs, D1/D2 for domains) for safety-sensitive passes
    token_to_alias, alias_to_token = _build_host_alias_map(host_data)

    kb_max_tokens = int(kwargs.get('kb_max_tokens', 4000))
    char_budget = _host_data_char_budget(ai, kwargs)
    ctx_window = _context_window(ai, kwargs)
    ctx_explicit = bool(kwargs.get("ai_context_window"))
    _cfg = (getattr(ai, "config", {}) or {})
    ctx_from_cfg = bool(_cfg.get("context_window")) and not ctx_explicit
    ctx_is_bedrock = bool(_cfg.get("aws_region"))
    if ctx_explicit:
        ctx_note = "explicit ai_context_window"
    elif ctx_from_cfg:
        ctx_note = "credentials.yaml context_window"
    elif ctx_is_bedrock:
        ctx_note = ("Bedrock default — 1M is a gated beta; set context_window: 1000000 "
                    "in credentials.yaml (or ai_context_window=1000000) if your region/model supports it")
    else:
        ctx_note = "default"
    logger.info("Context window: %d tokens (%s); per-call host budget ~%d chars",
                ctx_window, ctx_note, char_budget)
    print(f"[*] Context window: {ctx_window:,} tokens ({ctx_note})")
    hpc = kwargs.get("ai_hosts_per_call")
    try:
        hosts_per_call = int(hpc) if hpc not in (None, "", "auto") else None
    except (TypeError, ValueError):
        hosts_per_call = None

    # Knowledge-base sources actually injected into the prompts this run —
    # accumulated across passes so the report can attribute them (distinct from
    # the CONFIGURED source list in metadata.knowledge_sources).
    kb_references_used: list = []

    # Service inventory — deterministic, no AI. The former LLM "service research"
    # pass recalled CVEs from version strings, which an LLM is unreliable at
    # (training-cutoff-bound hallucination); real CVE evidence now comes solely
    # from scanner findings surfaced in the per-host details. This is a plain
    # asset list (service/version/port/hosts) built straight from the scan data.
    print("[*] Building service inventory (deterministic)...")
    services = _deduplicate_services(host_data)
    service_inventory = {"services": services}
    inventory_count = len(services)
    truncation["services_total"] = inventory_count
    truncation["services_analyzed"] = inventory_count
    print(f"[+] Inventoried {inventory_count} unique service/version combination(s)")

    # Track which AI passes actually reached the provider. If ALL fail (e.g. a
    # provider auth/permission error), the module has produced no analysis and
    # must report failure — not a clean success with empty output.
    pass2_ok = pass3_ok = False

    # Pass 1: Infrastructure relationships — run BEFORE recommendations so the
    # cross-host relationships it finds can feed the chaining pass (attack_chains
    # that span hosts). Previously this ran last and its output was never fed
    # back into the plan, so chains couldn't build on it.
    print("[*] Pass 1/2: Infrastructure relationship analysis...")
    try:
        correlations = _correlate_findings(ai, host_data, static_analysis,
                                            token_to_alias, alias_to_token, max_tokens)
        pass2_ok = True
    except Exception as e:
        logger.error("Pass 1 (correlation) failed: %s", e, exc_info=True)
        print(f"[!] Pass 1 failed: {e}")
        correlations = {"correlations": []}
    correlation_count = len(correlations.get("correlations") or [])
    if "raw_response" in correlations and not correlations.get("correlations"):
        print("[!] Pass 2: AI returned non-JSON response — raw text saved to output")
    print(f"[+] Found {correlation_count} infrastructure relationships")
    # Compact, already-aliased summary threaded into the chaining passes below.
    correlation_context = _correlation_context(correlations)

    # Pass 2: recommendations. ai_max_hosts caps the TOTAL hosts analysed; those
    # hosts are packed into as few context-window-sized calls as fit (token-aware),
    # then a synthesis pass consolidates multi-call runs.
    print("[*] Pass 2/2: Identifying vulnerabilities and generating playbooks...")
    sorted_host_ips = [ip for ip, _ in sorted(
        host_data["hosts"].items(),
        key=lambda x: len(x[1]["findings"]) + len(x[1]["ports"]) + len(x[1].get("web_services", [])),
        reverse=True)]

    max_hosts = limits["max_hosts"]
    if max_hosts is not None and len(sorted_host_ips) > max_hosts:
        dropped = len(sorted_host_ips) - max_hosts
        sorted_host_ips = sorted_host_ips[:max_hosts]
        truncation["hosts_truncated"] = True
        print(f"[!] Host coverage: analysing top {max_hosts} of {total_hosts} hosts "
              f"(ai_max_hosts); {dropped} lowest-signal host(s) not sent. "
              f"Use ai_depth=deep/unlimited or ai_max_hosts to cover more.")
    truncation["hosts_analyzed"] = len(sorted_host_ips)

    host_batches = _pack_hosts(sorted_host_ips, host_data, char_budget, hosts_per_call)
    if len(host_batches) > 1:
        print(f"[*] {len(sorted_host_ips)} host(s) exceed one context window — analysing in "
              f"{len(host_batches)} call(s), then synthesising")
    else:
        print(f"[*] Analysing {len(sorted_host_ips)} host(s) in a single call")

    # Multi-pass (opt-in): run recommendations TWICE per batch — a "pure" pass
    # (scan + correlations, NO knowledge base) and a "KB-grounded" pass — then let
    # the existing synthesis step reconcile them (it merges/dedups/re-ranks any >1
    # result set). The pure pass catches leads a KB-anchored pass tunnels past; the
    # KB pass adds version/CVE specifics; reconciling cross-checks both. ~2x the
    # recommendations cost, so off by default.
    multipass = bool(kwargs.get("ai_multipass", False))
    # (pass-label, use_kb) legs run per batch.
    legs = [("recommendations:pure", False), ("recommendations:kb", True)] if multipass \
        else [("recommendations", True)]
    if multipass:
        print("[*] Multi-pass ON: a pure (no-KB) pass + a KB-grounded pass, reconciled")

    batch_limits = dict(limits)
    batch_limits["max_hosts"] = None  # per-call cap is the token budget, not a count
    batch_results = []
    for bi, batch_ips in enumerate(host_batches, 1):
        sub = _subset_host_data(host_data, batch_ips)
        sub_summary, sub_trunc = _build_host_summary(sub, batch_limits)
        if sub_trunc["findings_truncated"]:
            truncation["findings_truncated"] = True
            truncation["findings_truncated_hosts"].extend(sub_trunc["findings_truncated_hosts"])
        if sub_trunc["web_dirs_truncated"]:
            truncation["web_dirs_truncated"] = True
            truncation["web_dirs_truncated_hosts"].extend(sub_trunc["web_dirs_truncated_hosts"])
        for leg_label, use_kb in legs:
            try:
                r = _generate_recommendations(ai, service_inventory, sub, static_analysis,
                                              sub_summary, token_to_alias, alias_to_token,
                                              max_tokens, kb_max_tokens,
                                              kb_refs_out=kb_references_used,
                                              correlation_context=correlation_context,
                                              use_kb=use_kb, log_label=leg_label)
                pass3_ok = True
            except Exception as e:
                logger.error("Pass 2 call %d/%d (%s) failed: %s", bi, len(host_batches),
                             leg_label, e, exc_info=True)
                print(f"[!] Pass 2 call {bi} ({leg_label}) failed: {e}")
                r = {"quick_wins": [], "attack_chains": [], "requires_verification": [], "cve_research": []}
            batch_results.append(r)
            if len(host_batches) > 1 or multipass:
                print(f"[+] Call {bi}/{len(host_batches)} [{leg_label}]: "
                      f"{len(r.get('quick_wins') or [])} quick wins, "
                      f"{len(r.get('attack_chains') or [])} chains")

    if len(host_batches) > 1:
        print(f"[*] Synthesising {len(host_batches)} call analyses into one prioritized plan...")
    recommendations = _synthesize_recommendations(ai, batch_results, token_to_alias,
                                                   alias_to_token, max_tokens,
                                                   correlation_context=correlation_context)
    quick_wins = len(recommendations.get("quick_wins") or [])
    print(f"[+] Generated playbooks: {quick_wins} quick wins, "
          f"{len(recommendations.get('attack_chains') or [])} attack chains, "
          f"{len(recommendations.get('requires_verification') or [])} requires verification, "
          f"{len(recommendations.get('cve_research') or [])} cve research")

    # Assemble structured output
    any_truncated = (truncation["hosts_truncated"]
                     or truncation["findings_truncated"] or truncation["web_dirs_truncated"])

    ai_usage = ai.get_usage_summary()

    kb_sources_used = []
    try:
        from core.knowledge import load_config as kb_load_config
        kb_config = kb_load_config()
        if kb_config.get("sources"):
            kb_sources_used = [
                {"name": s.get("name"), "type": s.get("type"), "priority": s.get("priority", "community")}
                for s in kb_config["sources"]
            ]
    except Exception:
        pass

    # Deduplicate the references actually consulted this run (order-preserving).
    kb_references = []
    _seen_refs = set()
    for ref in kb_references_used:
        key = (ref.get("source"), ref.get("file_path"), ref.get("heading"))
        if key not in _seen_refs:
            _seen_refs.add(key)
            kb_references.append(ref)

    result_data = {
        "metadata": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "ai_provider": ai.name,
            # Client-safe label: a Bedrock ARN embeds our internal AWS account id,
            # so never persist the raw model value into the deliverable metadata.
            "ai_model": display_model_name(ai.config.get("model"), ai.config),
            "depth": depth,
            "hosts_analyzed": truncation["hosts_analyzed"],
            "hosts_total": truncation["hosts_total"],
            "total_ports": host_data["total_ports"],
            "total_findings": host_data["total_findings"],
            "services_analyzed": truncation["services_analyzed"],
            "services_total": truncation["services_total"],
            "limits_applied": limits,
            "data_truncated": any_truncated,
            "ai_usage": ai_usage,
            "knowledge_sources": kb_sources_used if kb_sources_used else None,
            "knowledge_references": kb_references if kb_references else None,
            # Explicit "did this run actually consult the knowledge base?" signal
            # (true iff KB references were injected into a prompt this run).
            "kb_references_used": bool(kb_references),
            # Multi-pass provenance: whether the pure + KB-grounded dual pass ran.
            "multipass": {
                "enabled": True,
                "passes": [leg_label for leg_label, _ in legs],
                "kb_references_used": bool(kb_references),
            } if multipass else None,
        },
        "truncation": truncation if any_truncated else None,
        "service_inventory": service_inventory.get("services") or [],
        "recommendations": recommendations,
        "correlations": correlations.get("correlations") or [],
    }

    # Write JSON output
    json_output = f"{data_prefix}-ai-analysis.json"
    version_output_path(json_output)
    with open(json_output, 'w') as f:
        json.dump(result_data, f, indent=2)
    logger.info("AI analysis JSON written to %s", json_output)

    # Write Markdown report
    md_output = f"{reports_prefix}-ai-analysis.md"
    version_output_path(md_output)
    _render_markdown(result_data, md_output)
    logger.info("AI analysis report written to %s", md_output)

    if ai_usage['total_cost_usd']:
        cost_str = f"${ai_usage['total_cost_usd']:.4f}"
        cost_str += " (estimated)" if ai_usage.get("cost_is_estimate") else ""
    elif ai_usage.get("cost_unknown"):
        cost_str = "unknown (no pricing for this model)"
    else:
        cost_str = "N/A"
    print(f"[+] AI analysis complete — {ai_usage['calls']} API calls, "
          f"{ai_usage['total_tokens']:,} tokens, cost: {cost_str}")
    if any_truncated:
        print(f"[!] WARNING: Data was truncated due to limits. Review reports for details.")
        print(f"    To analyze all data, use ai_depth=unlimited or override specific limits.")
    print(f"    JSON: {json_output}")
    print(f"    Report: {md_output}")

    # Total provider failure: every pass errored (e.g. auth/permission/quota), so
    # the output files contain scan data but no AI analysis. Report failure so the
    # run doesn't record a clean success for a module that produced nothing.
    if not (pass2_ok or pass3_ok):
        msg = ("ai_analyze: all AI provider calls failed (correlation and "
               "recommendations) — see errors.log. No AI analysis was produced.")
        print(f"[!] {msg}")
        return {
            'module': 'ai_analyze',
            'status': 'failed',
            'output_files': [json_output, md_output],
            'error': msg,
            'ai_usage': ai_usage,
        }

    return {
        'module': 'ai_analyze',
        'status': 'success',
        'output_files': [json_output, md_output],
        'inventoried_services': inventory_count,
        'quick_wins': quick_wins,
        'data_truncated': any_truncated,
        'ai_usage': ai_usage,
    }


_IPV4_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def _load_name_to_ip(data_prefix: str) -> dict:
    """hostname -> resolved in-scope IPv4, from the resolve-report ledger.

    Only in-scope resolutions are kept: a name that resolves to an excluded
    address (e.g. an internal 10.x VPN host) must NOT be folded onto that IP.
    """
    mapping: dict = {}
    for path in glob.glob(f"{data_prefix}*-resolve-report.jsonl"):
        for rec in _read_jsonl(path):
            name = (rec.get("hostname") or "").strip().lower().rstrip(".")
            ip = (rec.get("ip") or "").strip()
            if not name or not _IPV4_RE.match(ip):
                continue
            if rec.get("in_scope") is False:
                continue
            mapping.setdefault(name, ip)
    return mapping


def _dedup_dicts(items: list, keys: tuple) -> list:
    """Drop later dicts whose selected-key signature already appeared."""
    seen, out = set(), []
    for it in items:
        sig = tuple(it.get(k) for k in keys)
        if sig in seen:
            continue
        seen.add(sig)
        out.append(it)
    return out


def _consolidate_host_identities(hosts: dict, name_to_ip: dict) -> None:
    """Fold a hostname host-key into its resolved in-scope IP host-key, in place.

    The weburls dual-emit means the same asset is scanned as both `https://<ip>`
    and `https://<hostname>`, so `example.com` and `198.18.7.111` land as two
    separate hosts carrying the SAME findings. Left split, they inflate the host
    count and fool correlation into inventing a "shared deployment / fleet" from
    one machine. Merge the hostname's data into the IP (recording the name in the
    alias-covered `subdomains` list), then collapse the exact-duplicate findings/
    ports the dual-emit produced. A hostname whose IP is not itself a scanned host
    (e.g. a third-party reference) is left as its own entry.
    """
    for name in list(hosts.keys()):
        if _IPV4_RE.match(name):
            continue
        ip = name_to_ip.get(name.lower().rstrip("."))
        if not ip or ip == name or ip not in hosts:
            continue
        src = hosts.pop(name)
        dst = hosts[ip]
        for k in ("ports", "findings", "web_dirs", "web_services", "subdomains"):
            dst[k].extend(src.get(k, []))
        n = name.lower().rstrip(".")
        if n not in dst["subdomains"]:
            dst["subdomains"].append(n)
    for data in hosts.values():
        data["findings"] = _dedup_dicts(data["findings"], ("title", "severity", "detail"))
        data["ports"] = _dedup_dicts(data["ports"], ("port", "proto"))


def _load_scan_data(data_prefix: str) -> dict:
    """Load all normalized JSONL files into a structured summary."""
    hosts = defaultdict(lambda: {"ports": [], "findings": [], "web_dirs": [], "subdomains": [], "web_services": []})
    total_ports = 0
    total_findings = 0

    for path in glob.glob(f"{data_prefix}*-nmap-normalized.jsonl"):
        for record in _read_jsonl(path):
            host = record.get("host") or ""
            if not host:
                continue
            if record.get("type") == "open_port":
                hosts[host]["ports"].append({
                    "port": record.get("port"),
                    "proto": record.get("proto") or "tcp",
                    "service": record.get("title") or "",
                    "banner": record.get("detail") or "",
                })
                total_ports += 1
            elif record.get("type") == "vulnerability":
                # NSE vuln scripts that normalize's state-aware classifier rated
                # VULNERABLE/LIKELY (http-vuln-*, ssl-ccs-injection, ssl-dh-params,
                # ...). These are real findings and belong in the AI's context;
                # info script_output (ssl-cert, http-title) is intentionally
                # skipped as low-value context that would blow the token budget.
                hosts[host]["findings"].append({
                    "title": record.get("title") or "",
                    "severity": record.get("severity") or "info",
                    "detail": record.get("detail") or "",
                })
                total_findings += 1

    for path in glob.glob(f"{data_prefix}*-nuclei-normalized.jsonl"):
        for record in _read_jsonl(path):
            host = record.get("host") or ""
            if not host:
                continue
            hosts[host]["findings"].append({
                "title": record.get("title") or "",
                "severity": record.get("severity") or "info",
                "detail": record.get("detail") or "",
            })
            total_findings += 1

    # Nessus findings (already in normalized format from nessus_import module)
    for path in glob.glob(f"{data_prefix}*-nessus-normalized.jsonl"):
        for record in _read_jsonl(path):
            host = record.get("host") or ""
            if not host:
                continue
            severity = record.get("severity") or "info"
            title = record.get("title") or ""
            detail_parts = []
            if record.get("detail"):
                detail_parts.append(record["detail"])
            if record.get("cves"):
                detail_parts.append(f"CVEs: {', '.join(record['cves'])}")
            if record.get("exploit_available"):
                detail_parts.append("Exploit available: true")
            hosts[host]["findings"].append({
                "title": title,
                "severity": severity,
                "detail": " | ".join(detail_parts) if detail_parts else "",
            })
            total_findings += 1

    # httpx web service fingerprinting (raw httpx JSONL output)
    for path in glob.glob(f"{data_prefix}*-httpx.jsonl"):
        for record in _read_jsonl(path):
            host = record.get("host") or record.get("input") or ""
            url = record.get("url") or ""
            if not host and url:
                from urllib.parse import urlparse
                host = urlparse(url).hostname or ""
            if not host:
                continue
            tech = record.get("tech") or []
            if isinstance(tech, str):
                tech = [tech]
            hosts[host]["web_services"].append({
                "url": url,
                "status_code": record.get("status_code") or record.get("status-code"),
                "title": record.get("title") or "",
                "webserver": record.get("webserver") or "",
                "tech": tech,
                "content_type": record.get("content_type") or record.get("content-type") or "",
                "cdn": record.get("cdn") or False,
                "tls": record.get("tls") or {},
            })

    for path in glob.glob(f"{data_prefix}*-bbot-normalized.jsonl"):
        for record in _read_jsonl(path):
            host = record.get("host") or ""
            if not host or host == "unknown":
                continue
            rec_type = record.get("type", "")
            if rec_type == "finding":
                hosts[host]["findings"].append({
                    "title": record.get("title") or "",
                    "severity": record.get("severity") or "info",
                    "detail": record.get("detail") or "",
                })
                total_findings += 1
            elif rec_type == "open_port":
                port = record.get("port")
                if port:
                    hosts[host]["ports"].append({
                        "port": port,
                        "proto": record.get("proto") or "tcp",
                        "service": "",
                        "banner": "",
                    })
                    total_ports += 1
            elif rec_type == "technology":
                hosts[host]["web_services"].append({
                    "url": "",
                    "status_code": None,
                    "tech": [record.get("detail") or record.get("title") or ""],
                    "content_type": "",
                    "cdn": False,
                    "tls": {},
                })

    for tool in ("ffuf", "feroxbuster"):
        for path in glob.glob(f"{data_prefix}*-{tool}-normalized.jsonl"):
            for record in _read_jsonl(path):
                host = record.get("host") or ""
                if not host:
                    continue
                hosts[host]["web_dirs"].append({
                    "url": record.get("detail") or record.get("title") or "",
                    "status": record.get("port"),
                })

    # testssl / wafw00f / shodan / mantra / corsy / dalfox — normalize emits
    # finding-type records that carry host/port/severity/detail, so they load
    # like any other finding source.
    for tool in ("testssl", "wafw00f", "shodan", "mantra", "corsy", "dalfox",
                 "ssh-audit", "snmp-sweep", "smtp-security"):
        for path in glob.glob(f"{data_prefix}*-{tool}-normalized.jsonl"):
            for record in _read_jsonl(path):
                host = record.get("host") or ""
                if not host or host == "unknown":
                    continue
                if record.get("type") not in ("finding", "vulnerability"):
                    continue
                hosts[host]["findings"].append({
                    "title": record.get("title") or "",
                    "severity": record.get("severity") or "info",
                    "detail": record.get("detail") or "",
                })
                total_findings += 1

    for path in glob.glob(f"{data_prefix}*-subfinder-normalized.jsonl"):
        for record in _read_jsonl(path):
            host = record.get("host") or ""
            if host:
                hosts[host]["subdomains"].append(record.get("title") or "")

    for path in glob.glob(f"{data_prefix}*-dns-security.jsonl"):
        for record in _read_jsonl(path):
            # Keep ALL severities (like the nuclei/nmap/bbot loaders). Sub-high
            # DNS facts (weak SPF/DMARC, missing DNSSEC, CAA gaps) are exactly
            # the individually-minor signals that combine into real findings
            # during correlation — dropping them here blinds that analysis.
            severity = (record.get("severity") or "info").lower()
            if severity == "info":
                continue
            domain = record.get("domain") or ""
            if domain:
                hosts[domain]["findings"].append({
                    "title": record.get("check") or "dns_security",
                    "severity": severity,
                    "detail": record.get("detail") or "",
                    "evidence": record.get("evidence") or "",
                })
                total_findings += 1

    # Collapse hostname+IP duplicate identities into one asset (see
    # _consolidate_host_identities) BEFORE sorting/counting, so the host count
    # and correlation see real assets, not dual-emitted twins. Totals are
    # recomputed afterwards to reflect the deduplicated set.
    _consolidate_host_identities(hosts, _load_name_to_ip(data_prefix))
    total_findings = sum(len(d["findings"]) for d in hosts.values())
    total_ports = sum(len(d["ports"]) for d in hosts.values())

    _SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for data in hosts.values():
        data["findings"].sort(key=lambda f: _SEV_ORDER.get(f.get("severity", "info"), 5))

    return {
        "hosts": dict(hosts),
        "total_ports": total_ports,
        "total_findings": total_findings,
    }


def _deduplicate_services(host_data: dict) -> list[dict]:
    """Extract unique service+version combinations with host lists."""
    service_map = defaultdict(lambda: {"hosts": set(), "ports": set()})

    for host_ip, data in host_data["hosts"].items():
        for port_info in data["ports"]:
            service = (port_info.get("service") or "").strip()
            banner = (port_info.get("banner") or "").strip()
            port = port_info.get("port")

            if not service or not port:
                continue

            key = f"{service}|{banner}".lower()
            service_map[key]["hosts"].add(host_ip)
            service_map[key]["ports"].add(port)
            service_map[key]["service"] = service
            service_map[key]["version"] = banner

        # Include httpx webserver and tech detections as services
        for ws in data.get("web_services", []):
            webserver = (ws.get("webserver") or "").strip()
            if webserver:
                key = f"webserver|{webserver}".lower()
                service_map[key]["hosts"].add(host_ip)
                service_map[key]["ports"].add(443)
                service_map[key]["service"] = "webserver"
                service_map[key]["version"] = webserver
            for tech in (ws.get("tech") or []):
                tech = tech.strip()
                if tech:
                    key = f"tech|{tech}".lower()
                    service_map[key]["hosts"].add(host_ip)
                    service_map[key]["ports"].add(443)
                    service_map[key]["service"] = "technology"
                    service_map[key]["version"] = tech

    results = []
    for key, info in service_map.items():
        results.append({
            "service": info.get("service", ""),
            "version": info.get("version", ""),
            "port": min(info["ports"]) if info["ports"] else 0,
            "hosts": sorted(info["hosts"]),
            "host_count": len(info["hosts"]),
        })

    results.sort(key=lambda x: x["host_count"], reverse=True)
    return results


def _build_host_summary(host_data: dict, limits: dict) -> tuple[str, dict]:
    """Build a text summary of hosts for the AI prompt.

    Returns:
        Tuple of (summary_text, truncation_info_dict)
    """
    max_hosts = limits["max_hosts"]
    max_findings = limits["max_findings_per_host"]
    max_web_dirs = limits["max_web_dirs_per_host"]
    max_ports = limits.get("max_ports_per_host")
    max_banner = limits.get("max_banner_len", 120)

    truncation_info = {
        "findings_truncated": False,
        "findings_truncated_hosts": [],
        "web_dirs_truncated": False,
        "web_dirs_truncated_hosts": [],
    }

    lines = []
    sorted_hosts = sorted(
        host_data["hosts"].items(),
        key=lambda x: len(x[1]["findings"]) + len(x[1]["ports"]) + len(x[1].get("web_services", [])),
        reverse=True,
    )

    hosts_to_process = sorted_hosts if max_hosts is None else sorted_hosts[:max_hosts]

    for host_ip, data in hosts_to_process:
        lines.append(f"\n## Host: {host_ip}")

        if data["ports"]:
            ports_to_show = data["ports"] if max_ports is None else data["ports"][:max_ports]
            lines.append("Ports:")
            for p in ports_to_show:
                service_str = p.get("service") or ""
                banner_str = p.get("banner") or ""
                if max_banner and len(banner_str) > max_banner:
                    banner_str = banner_str[:max_banner] + "..."
                detail = f" ({banner_str})" if banner_str else ""
                lines.append(f"  - {p['port']}/{p['proto']} {service_str}{detail}")
            if max_ports is not None and len(data["ports"]) > max_ports:
                lines.append(f"  [{len(data['ports']) - max_ports} more ports omitted]")

        if data.get("web_services"):
            lines.append("Web Services (httpx):")
            for ws in data["web_services"][:10]:
                tech_str = f" [{', '.join(ws['tech'])}]" if ws.get("tech") else ""
                server_str = f" server={ws['webserver']}" if ws.get("webserver") else ""
                cdn_str = " [CDN]" if ws.get("cdn") else ""
                lines.append(f"  - {ws.get('url', '')} -> {ws.get('status_code', '?')} "
                             f"\"{ws.get('title', '')}\"{server_str}{tech_str}{cdn_str}")
            if len(data["web_services"]) > 10:
                lines.append(f"  [{len(data['web_services']) - 10} more web services omitted]")

        if data["findings"]:
            findings_to_show = data["findings"] if max_findings is None else data["findings"][:max_findings]
            lines.append("Findings:")
            for f in findings_to_show:
                lines.append(f"  - [{f['severity'].upper()}] {f['title']}")
                if f.get("detail"):
                    lines.append(f"    Detail: {f['detail'][:200]}")
            if max_findings is not None and len(data["findings"]) > max_findings:
                omitted = len(data["findings"]) - max_findings
                lines.append(f"  [TRUNCATED: {omitted} additional findings not sent to AI]")
                truncation_info["findings_truncated"] = True
                truncation_info["findings_truncated_hosts"].append(
                    {"host": host_ip, "shown": max_findings, "total": len(data["findings"])}
                )

        if data["web_dirs"]:
            dirs_to_show = data["web_dirs"] if max_web_dirs is None else data["web_dirs"][:max_web_dirs]
            lines.append(f"Web Discoveries ({len(data['web_dirs'])} total):")
            for wd in dirs_to_show:
                lines.append(f"  - {wd.get('url', '')}")
            if max_web_dirs is not None and len(data["web_dirs"]) > max_web_dirs:
                omitted = len(data["web_dirs"]) - max_web_dirs
                lines.append(f"  [TRUNCATED: {omitted} additional directories not sent to AI]")
                truncation_info["web_dirs_truncated"] = True
                truncation_info["web_dirs_truncated_hosts"].append(
                    {"host": host_ip, "shown": max_web_dirs, "total": len(data["web_dirs"])}
                )

    if max_hosts is not None and len(host_data["hosts"]) > max_hosts:
        omitted = len(host_data["hosts"]) - max_hosts
        lines.append(f"\n[TRUNCATED] {omitted} additional hosts were not analyzed by AI. "
                     f"Review source JSONL files for complete data.")

    return "\n".join(lines), truncation_info


def _build_static_analysis_context(static_analysis: dict) -> str:
    """Build a compact context string from the static analysis module output.

    This covers ALL hosts in far fewer tokens than raw per-host data by
    leveraging the pre-filtered, aggregated sections from the analyze module.
    """
    sections = []

    # SMB signing disabled (relay targets)
    smb = static_analysis.get("smb_signing_disabled", [])
    if smb:
        hosts = [f"{e['host']}:{e.get('port', 445)}" for e in smb]
        sections.append(f"## SMB Signing Disabled (relay targets)\n{', '.join(hosts)}")

    # Default creds / anonymous access
    creds = static_analysis.get("default_creds_anon_access", [])
    if creds:
        lines = ["## Default Credentials / Anonymous Access"]
        for e in creds[:30]:
            lines.append(f"- {e.get('host', '')}:{e.get('port', '')} ({e.get('script', '')}) — {(e.get('detail', ''))[:150]}")
        sections.append("\n".join(lines))

    # SSL/TLS issues
    ssl = static_analysis.get("ssl_tls_issues", [])
    if ssl:
        lines = ["## SSL/TLS Weaknesses"]
        for e in ssl[:20]:
            lines.append(f"- {e.get('host', '')}:{e.get('port', '')} — {', '.join(e.get('issues', []))}")
        sections.append("\n".join(lines))

    # Dangerous HTTP methods
    http_methods = static_analysis.get("http_methods", [])
    if http_methods:
        lines = ["## Dangerous HTTP Methods"]
        for e in http_methods[:20]:
            lines.append(f"- {e.get('host', '')}:{e.get('port', '')} — {', '.join(e.get('methods', []))}")
        sections.append("\n".join(lines))

    # Login panels (password spray targets)
    spray = static_analysis.get("password_spray", {})
    login_panels = spray.get("login_panels", [])
    if login_panels:
        lines = ["## Login Panels"]
        for p in login_panels[:20]:
            lines.append(f"- {p.get('url', '')} ({p.get('source', '')}): {p.get('title', '')}")
        sections.append("\n".join(lines))

    # Tech stack (helps identify attack surface)
    tech = static_analysis.get("tech_stack", {})
    if tech:
        lines = ["## Technology Stack"]
        for tech_name, hosts in list(tech.items())[:20]:
            lines.append(f"- {tech_name}: {len(hosts)} host(s) — {', '.join(hosts[:5])}")
        sections.append("\n".join(lines))

    # OS fingerprint
    os_fp = static_analysis.get("os_fingerprint", {})
    if os_fp:
        lines = ["## OS Fingerprinting"]
        for os_name, hosts in list(os_fp.items())[:10]:
            lines.append(f"- {os_name}: {len(hosts)} host(s)")
        sections.append("\n".join(lines))

    # Port/service stats summary
    pss = static_analysis.get("port_service_stats", {})
    port_counts = pss.get("port_counts", {})
    if port_counts:
        lines = ["## Port Distribution (all hosts)"]
        for port, count in list(port_counts.items())[:25]:
            lines.append(f"- {port}: {count} host(s)")
        sections.append("\n".join(lines))

    return "\n\n".join(sections)



def _generate_recommendations(ai: AIProvider, service_inventory: dict,
                              host_data: dict, static_analysis: dict | None,
                              summary: str, token_to_alias: dict,
                              alias_to_token: dict, max_tokens: int,
                              kb_max_tokens: int = 4000,
                              kb_refs_out: list | None = None,
                              correlation_context: str = "",
                              use_kb: bool = True,
                              log_label: str = "") -> dict:
    """Pass 2: Identify vulnerabilities and generate exploitation playbooks.

    Combines attack path identification and playbook generation into a single
    pass. Uses anonymized identifiers (H1, H2 for IPs; D1, D2 for domains)
    to avoid safety refusals, then substitutes real values back.

    If `kb_refs_out` is provided, the knowledge-base sources actually injected
    into this call's prompt are appended to it (deduplicated by the caller).
    """
    if not isinstance(service_inventory, dict):
        service_inventory = {"services": []}

    context = (
        "Analyze these scan results. Identify all confirmed vulnerabilities, attack chains, "
        "and unconfirmed findings worth testing. Provide exact commands for each. "
        "Hosts are labeled H1, H2, etc. Domains are labeled D1, D2, etc. "
        "Use these labels in all commands and targets.\n\n"
    )

    # Include static analysis overview if available
    if static_analysis:
        static_context = _build_static_analysis_context(static_analysis)
        if static_context:
            context += "## Scan Overview (all hosts)\n\n" + _anonymize_text(static_context, token_to_alias) + "\n\n"

    # Include the alias legend so the AI knows what each host is
    context += "## Host Legend:\n"
    # No host-count slice here — the caller passes a fits-in-context batch of
    # hosts (see _pack_hosts), so every host in the batch is described.
    for host_ip, data in sorted(
        host_data["hosts"].items(),
        key=lambda x: len(x[1]["findings"]) + len(x[1]["ports"]),
        reverse=True,
    ):
        alias = token_to_alias.get(host_ip, host_ip)
        port_summary = ", ".join(
            f"{p['port']}/{p.get('service') or '?'}" for p in data["ports"][:8]
        )
        context += f"- {alias}: ports [{port_summary}]\n"

    context += "\n## Service Inventory:\n"
    for svc in (service_inventory.get("services") or [])[:15]:
        if not isinstance(svc, dict):
            continue
        hosts = svc.get("hosts") or []
        aliased_hosts = [token_to_alias.get(h, h) for h in hosts[:10]]
        context += f"- {svc.get('service', '')} {svc.get('version', '')} port {svc.get('port', '')} on: {', '.join(aliased_hosts)}\n"

    # Cross-host relationships (Pass 1) — already aliased; steer the chaining bucket.
    if correlation_context:
        context += "\n" + correlation_context

    context += "\n## Per-Host Details (findings + ports):\n"
    # Batch is already bounded by the caller — describe every host in it.
    hosts_with_findings = sorted(
        host_data["hosts"].items(),
        key=lambda x: len(x[1]["findings"]) + len(x[1]["ports"]),
        reverse=True,
    )
    for host_ip, data in hosts_with_findings:
        if not data["findings"] and not data["ports"]:
            continue
        alias = token_to_alias.get(host_ip, host_ip)
        context += f"\n{alias}:\n"
        for f in data["findings"][:8]:
            detail = _anonymize_text((f.get("detail") or "")[:150], token_to_alias)
            context += f"  - [{f['severity'].upper()}] {f['title']}"
            if detail:
                context += f" | {detail}"
            context += "\n"
        for p in data["ports"][:12]:
            service_str = p.get("service") or ""
            banner_str = _anonymize_text((p.get("banner") or "")[:80], token_to_alias)
            if service_str or banner_str:
                context += f"  - {p['port']}/{p['proto']} {service_str} {banner_str}\n"

    # Include detailed host summary if available (covers hosts not in top-20 findings)
    if summary:
        context += "\n## Additional Host Data:\n\n" + _anonymize_text(summary, token_to_alias)

    # use_kb=False is the "pure" multi-pass leg — reason over the scan + the
    # correlations only, no external knowledge base (a KB can both ground AND
    # bias; the pure pass catches what a KB-anchored pass tunnels past). The
    # KB-grounded leg (use_kb=True) still injects references as before.
    if use_kb:
        try:
            from core.knowledge import retrieve_with_refs as kb_retrieve_with_refs
            kb_terms = set()
            for _, data in hosts_with_findings:
                for p in data.get("ports", []):
                    svc = (p.get("service") or "").split("/")[0].lower()
                    if svc:
                        kb_terms.add(svc)
            if kb_terms:
                kb_text, kb_refs = kb_retrieve_with_refs(query_terms=list(kb_terms)[:10], max_tokens=kb_max_tokens)
                if kb_text:
                    context += f"\n\n{kb_text}\n"
                    logger.info("Knowledge base: injected references for recommendations (%d chars)", len(kb_text))
                if kb_refs_out is not None:
                    kb_refs_out.extend(kb_refs)
        except Exception as e:
            logger.debug("Knowledge base retrieval skipped: %s", e)

    MAX_PROMPT_CHARS = 900_000
    if len(context) > MAX_PROMPT_CHARS:
        logger.warning("Prompt too large (%d chars), truncating to %d", len(context), MAX_PROMPT_CHARS)
        context = context[:MAX_PROMPT_CHARS] + "\n\n[TRUNCATED — prompt exceeded size limit]"

    result = ai.query_json(SYSTEM_PROMPT_RECOMMENDATIONS, context, max_tokens=max_tokens,
                           log_label=log_label or ("recommendations:kb" if use_kb else "recommendations:pure"))

    if not any(result.get(k) for k in ("quick_wins", "attack_chains", "requires_verification", "cve_research")):
        if "raw_response" not in result:
            result = {"quick_wins": [], "attack_chains": [], "requires_verification": [], "cve_research": []}

    # Substitute aliases back to real values
    result = _deanonymize_obj(result, alias_to_token)
    # Repair spuriously doubled ports (host:port:port) in targets/commands (#10).
    _sanitize_targets(result)
    # Clamp informational disclosures (internal-IP / version) to LOW impact.
    _cap_informational_impact(result)
    # Backstop against fabricated exploit scripts/binaries the prompt didn't catch.
    _flag_fabricated_commands(result)
    return result


# Known real security tools. Not exhaustive and NOT an allowlist — its only job
# is to recognize commands that clearly invoke a real tool so we don't flag them.
# Anything not here is only flagged if it ALSO looks like a local script/binary
# (see _flag_fabricated_commands), so novel-but-real tools pass through untouched.
_KNOWN_TOOLS = frozenset({
    "curl", "wget", "nmap", "ncat", "nc", "netcat", "nuclei", "ffuf", "gobuster",
    "feroxbuster", "dirb", "dirbuster", "hydra", "medusa", "sqlmap", "nikto",
    "testssl", "testssl.sh", "openssl", "dig", "nslookup", "host", "whatweb",
    "wpscan", "joomscan", "snmpwalk", "snmpget", "snmp-check", "smbclient",
    "rpcclient", "enum4linux", "enum4linux-ng", "crackmapexec", "nxc", "netexec",
    "ssh", "ssh-audit", "sshpass", "telnet", "ftp", "ldapsearch", "redis-cli",
    "mysql", "psql", "mongo", "msfconsole", "msfvenom", "responder", "impacket",
    "kerbrute", "evil-winrm", "onesixtyone", "showmount", "rpcinfo", "ike-scan",
    "amass", "subfinder", "httpx", "katana", "gau", "waybackurls", "python", "python3",
    "bash", "sh", "sudo", "echo", "cat", "grep", "awk", "sed", "base64", "printf",
})

# Signatures of a fabricated local artifact: script/binary filenames or relative
# invocations the model tends to invent (exploit_CVE-2024-1234.py, ./poc.sh, ...).
_SCRIPT_ARTIFACT_RE = re.compile(
    r"""(?xi)
    (?:^|[\s;|&])                                              # start or shell separator
    (?:
        \.?/?[\w./-]*\.(?:py|sh|rb|pl|ps1|exe|bin|jar|out)\b   # something.py / ./x.sh
      | \./[\w.-]+                                             # ./exploit
    )
    """
)


def _command_is_suspect(cmd: str) -> bool:
    """True if a command likely invokes a fabricated local exploit script/binary.

    Real CLI tools (even ones not in _KNOWN_TOOLS) are NOT flagged — only commands
    that reference a local script/binary artifact AND aren't clearly driven by a
    recognized interpreter/tool are treated as suspect.
    """
    import shlex
    if not isinstance(cmd, str) or not cmd.strip():
        return False
    if not _SCRIPT_ARTIFACT_RE.search(cmd):
        return False
    # A script artifact is present. Allow it only if a recognized interpreter/tool
    # is clearly driving it in a real way we can't second-guess... except that
    # `python3 exploit_CVE-*.py` is exactly the fabrication we want to catch, so a
    # bare interpreter + unknown script still counts as suspect.
    try:
        tokens = shlex.split(cmd)
    except ValueError:
        return True  # unparseable → suspicious
    interpreters = {"python", "python3", "ruby", "perl", "php", "pwsh", "powershell", "node", "bash", "sh"}
    for tok in tokens:
        base = tok.split("/")[-1].lower()
        # A recognized non-interpreter tool driving the line → trust it.
        if base in _KNOWN_TOOLS and base not in interpreters:
            return False
    return True


# A "<host>:<port>:<port>[:<port>…]" run the model sometimes emits (it treats a
# nuclei matched-at "host:port" as the host and re-appends a port). Host = a
# dotted hostname or IPv4 — never IPv6 (no dots), so a bare IPv6's colons are
# untouched. Collapses to "<host>:<port>" keeping the FIRST port (the real
# service port; the appended one is noise).
_DOUBLED_PORT_RE = re.compile(
    r"((?:[A-Za-z0-9-]+\.)+[A-Za-z0-9-]+|\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})(?::\d{1,5})+"
)


def _normalize_target(target):
    """Collapse a spuriously doubled port in a recommendation target.

    'host:6379:6379' / 'host:4280:443' -> 'host:port' (first port). URLs,
    bracketed '[ipv6]:port', bare IPs, and well-formed 'host:port' pass through.
    """
    if not isinstance(target, str):
        return target
    t = target.strip()
    if not t or "://" in t or t.startswith("["):
        return target
    return _DOUBLED_PORT_RE.sub(r"\1:\2", t)


def _sanitize_targets(result: dict) -> None:
    """Repair spuriously doubled ports in recommendation targets/commands (#10).

    A malformed 'host:port:port' target produced un-runnable PoC commands AND
    broke ai_validate's port/finding_id join (verdicts never wrote back to
    scan.db), so a later-refuted finding kept reading as confirmed. Normalize the
    target field and collapse the same triple-colon run inside command strings.
    Mutates `result` in place.
    """
    if not isinstance(result, dict):
        return
    for category in ("quick_wins", "attack_chains", "requires_verification", "cve_research"):
        for item in result.get(category) or []:
            if not isinstance(item, dict):
                continue
            if "target" in item:
                item["target"] = _normalize_target(item.get("target"))
            cmds = item.get("commands")
            if isinstance(cmds, list):
                item["commands"] = [
                    _DOUBLED_PORT_RE.sub(r"\1:\2", c) if isinstance(c, str) else c
                    for c in cmds
                ]


# Actions that are purely informational disclosure — NOT an exploit. The model
# tends to rate these CRITICAL/HIGH; they are low risk on their own (they only
# matter as a stepping stone, which is what a separate chain item would capture).
# Matched against the action text; narrow on purpose so we don't catch an actual
# exploit that merely mentions a version or an internal IP (e.g. "SSRF to
# internal IP" or "RCE via <software> <version>").
_INFO_DISCLOSURE_RES = [
    re.compile(r"\b(internal|private|rfc\s?1918)\s+ip(\s+address)?(es)?\b.*\b(disclos|expos|leak|reveal)", re.I),
    re.compile(r"\b(disclos|expos|leak|reveal)\w*\b.*\b(internal|private|rfc\s?1918)\s+ip", re.I),
    re.compile(r"\b(version|banner|software[-\s]?version|build[-\s]?number)\b.*\b(disclos|expos|leak|reveal|fingerprint)", re.I),
    re.compile(r"\b(detailed|verbose)\s+version\b", re.I),
    re.compile(r"\bserver\s+(header|banner)\s+(disclos|expos|leak|reveal)", re.I),
]


def _is_info_disclosure(item: dict) -> bool:
    """True if the item's action is a pure info-disclosure (internal-IP / version)."""
    action = str(item.get("action") or "")
    # If the action also names a concrete exploit outcome, it's NOT just
    # disclosure — leave the model's rating alone.
    if re.search(r"\b(rce|sqli|xss|ssrf|lfi|rfi|auth\w* bypass|takeover|command injection|"
                 r"deserializ|path traversal|exploit|shell|credential\w* (dump|extract))\b",
                 action, re.I):
        return False
    return any(rx.search(action) for rx in _INFO_DISCLOSURE_RES)


def _cap_informational_impact(result: dict) -> None:
    """Clamp internal-IP / version-disclosure recommendations to LOW impact.

    The model routinely over-rates informational disclosures as CRITICAL/HIGH.
    On their own they are low risk, so cap `impact` to LOW (and downgrade a
    HIGH-confidence chain to MEDIUM so it doesn't lead the ranked playbook).
    Buckets are left intact — ai_validate/focus still read them. Mutates in place.
    """
    if not isinstance(result, dict):
        return
    for category in ("quick_wins", "attack_chains", "requires_verification", "cve_research"):
        for item in result.get(category) or []:
            if not isinstance(item, dict) or not _is_info_disclosure(item):
                continue
            if str(item.get("impact") or "").upper() in ("CRITICAL", "HIGH", "MEDIUM"):
                item["impact"] = "LOW"
            if str(item.get("confidence") or "").upper() == "HIGH":
                item["confidence"] = "MEDIUM"


def _flag_fabricated_commands(result: dict) -> None:
    """Mark commands that appear to invoke non-existent exploit scripts/binaries.

    Prefixes suspect commands with a visible marker rather than deleting them, so
    the tester keeps the model's idea but is warned it is not a runnable artifact.
    Mutates `result` in place.
    """
    if not isinstance(result, dict):
        return
    marker = "[UNVERIFIED — no such tool/script on host; verify manually] "
    for category in ("quick_wins", "attack_chains", "requires_verification", "cve_research"):
        for item in result.get(category) or []:
            if not isinstance(item, dict):
                continue
            cmds = item.get("commands")
            if not isinstance(cmds, list):
                continue
            new_cmds = []
            for cmd in cmds:
                if _command_is_suspect(cmd) and not str(cmd).startswith(marker):
                    new_cmds.append(marker + str(cmd))
                else:
                    new_cmds.append(cmd)
            item["commands"] = new_cmds


def _correlate_findings(ai: AIProvider, host_data: dict,
                        static_analysis: dict | None,
                        token_to_alias: dict, alias_to_token: dict,
                        max_tokens: int) -> dict:
    """Pass 1: Infrastructure relationships — find non-obvious patterns across hosts/tools.

    Uses anonymized identifiers to avoid safety refusals.
    """
    context = (
        "Analyze these scan results for cross-host and cross-tool correlations. "
        "Hosts are labeled H1, H2, etc. Domains are labeled D1, D2, etc. "
        "Use these labels in all references.\n\n"
    )

    # Host legend
    context += "## Host Legend:\n"
    for host_ip in sorted(
        host_data["hosts"].keys(),
        key=lambda ip: len(host_data["hosts"][ip]["findings"]) + len(host_data["hosts"][ip]["ports"]),
        reverse=True,
    )[:40]:
        alias = token_to_alias.get(host_ip, host_ip)
        context += f"- {alias}\n"
    context += "\n"

    # Group hosts by shared services to make patterns visible
    service_to_hosts = defaultdict(list)
    for host_ip, data in host_data["hosts"].items():
        alias = token_to_alias.get(host_ip, host_ip)
        for p in data["ports"]:
            svc = (p.get("service") or "").strip()
            banner = (p.get("banner") or "").strip()
            if svc:
                key = f"{svc} {banner}" if banner else svc
                service_to_hosts[key].append(f"{alias}:{p['port']}")

    context += "## Service Distribution (hosts sharing services):\n"
    for svc_key, hosts in sorted(service_to_hosts.items(), key=lambda x: len(x[1]), reverse=True)[:30]:
        if len(hosts) > 1:
            context += f"- {_anonymize_text(svc_key, token_to_alias)}: {', '.join(hosts[:15])}\n"

    # Per-host summary with all tool outputs
    context += "\n## Per-Host Data (all tools combined):\n"
    sorted_hosts = sorted(
        host_data["hosts"].items(),
        key=lambda x: len(x[1]["findings"]) + len(x[1]["ports"]) + len(x[1]["web_dirs"]),
        reverse=True,
    )[:40]

    for host_ip, data in sorted_hosts:
        alias = token_to_alias.get(host_ip, host_ip)
        context += f"\n### {alias}\n"
        if data["ports"]:
            ports_summary = []
            for p in data["ports"][:20]:
                svc = p.get("service") or ""
                banner = _anonymize_text((p.get("banner") or "")[:60], token_to_alias)
                ports_summary.append(f"{p['port']}/{p['proto']} {svc} {banner}".strip())
            context += f"Ports: {'; '.join(ports_summary)}\n"
        if data["findings"]:
            context += "Findings:\n"
            for f in data["findings"][:8]:
                detail = _anonymize_text((f.get("detail") or "")[:100], token_to_alias)
                context += f"  - [{f['severity'].upper()}] {f['title']} {detail}\n"
        if data["web_dirs"]:
            context += f"Web paths ({len(data['web_dirs'])} total): "
            dirs = ", ".join(_anonymize_text(wd.get("url", ""), token_to_alias) for wd in data["web_dirs"][:5])
            context += dirs + "\n"
        if data["subdomains"]:
            anon_subs = [_anonymize_text(s, token_to_alias) for s in data["subdomains"][:5]]
            context += f"Subdomains: {', '.join(anon_subs)}\n"

    # Add static analysis for infrastructure-level patterns (anonymized)
    if static_analysis and isinstance(static_analysis, dict):
        os_fp = static_analysis.get("os_fingerprint") or {}
        if os_fp:
            context += "\n## OS Fingerprints:\n"
            for os_name, hosts in list(os_fp.items())[:10]:
                if not isinstance(hosts, list):
                    continue
                aliased = [token_to_alias.get(h, h) for h in hosts[:10]]
                context += f"- {os_name}: {', '.join(aliased)}\n"

        tech = static_analysis.get("tech_stack") or {}
        if tech:
            context += "\n## Shared Technology:\n"
            for tech_name, hosts in list(tech.items())[:15]:
                if not isinstance(hosts, list):
                    continue
                aliased = [token_to_alias.get(h, h) for h in hosts[:10]]
                context += f"- {tech_name}: {', '.join(aliased)}\n"

    MAX_PROMPT_CHARS = 900_000
    if len(context) > MAX_PROMPT_CHARS:
        context = context[:MAX_PROMPT_CHARS] + "\n\n[TRUNCATED]"

    result = ai.query_json(SYSTEM_PROMPT_CORRELATION, context, max_tokens=max_tokens)

    if not result.get("correlations") and "raw_response" not in result:
        result = {"correlations": []}

    result = _deanonymize_obj(result, alias_to_token)
    return result


def _render_markdown(data: dict, output_path: str) -> None:
    """Render the full AI analysis as a Markdown report."""
    lines = []
    meta = data["metadata"]

    lines.append("# AI-Assisted Penetration Test Analysis")
    lines.append("")
    lines.append(f"**Generated:** {meta['generated_at']}")
    lines.append(f"**AI Provider:** {meta['ai_provider']} ({meta['ai_model']})")
    lines.append(f"**Depth:** {meta['depth']}")
    if (meta.get("multipass") or {}).get("enabled"):
        lines.append("**Analysis mode:** multi-pass (a pure/no-KB pass + a "
                     "knowledge-base-grounded pass, reconciled)")
    # Always state whether the knowledge base actually contributed this run.
    lines.append(f"**Knowledge base references used:** {'yes' if meta.get('kb_references_used') else 'no'}")
    lines.append(f"**Hosts Analyzed:** {meta['hosts_analyzed']} of {meta['hosts_total']}")
    lines.append(f"**Services Inventoried:** {meta['services_total']}")
    lines.append(f"**Open Ports:** {meta['total_ports']}")
    # total_findings aggregates ALL finding sources fed to the AI (nuclei +
    # nessus + bbot + testssl/shodan/etc + dns_security), not nuclei alone —
    # labeling it "Nuclei Findings" was wrong (e.g. it reported "3" for 3
    # dns_security findings on a run where nuclei produced zero normalized rows).
    lines.append(f"**Findings Analyzed:** {meta['total_findings']}")
    lines.append("")

    kb_sources = meta.get("knowledge_sources")
    if kb_sources:
        lines.append(f"**Knowledge Base:** {', '.join(s['name'] for s in kb_sources)}")
        lines.append("")

    # References ACTUALLY consulted this run (the specific docs injected into the
    # prompts), distinct from the configured-sources line above.
    kb_references = meta.get("knowledge_references")
    if kb_references:
        lines.append("**Knowledge Base References (consulted this run):**")
        lines.append("")
        for ref in kb_references:
            cite = f"{ref.get('source', '?')}/{ref.get('file_path', '?')}"
            heading = (ref.get("heading") or "").strip()
            if heading:
                cite += f" > {heading}"
            lines.append(f"- {cite}")
        lines.append("")

    ai_usage = meta.get("ai_usage")
    if ai_usage and ai_usage.get("calls"):
        lines.append("### AI Usage")
        lines.append("")
        lines.append(f"| Metric | Value |")
        lines.append(f"|--------|-------|")
        lines.append(f"| API Calls | {ai_usage['calls']} |")
        lines.append(f"| Input Tokens | {ai_usage['input_tokens']:,} |")
        lines.append(f"| Output Tokens | {ai_usage['output_tokens']:,} |")
        lines.append(f"| Total Tokens | {ai_usage['total_tokens']:,} |")
        cost = ai_usage.get('total_cost_usd', 0)
        if cost:
            estimate = " (estimated)" if ai_usage.get("cost_is_estimate") else ""
            lines.append(f"| Cost | ${cost:.4f}{estimate} |")
        elif ai_usage.get("cost_unknown"):
            lines.append("| Cost | unknown (no pricing for this model) |")
        if ai_usage.get("total_duration_s"):
            lines.append(f"| Duration | {ai_usage['total_duration_s']:.1f}s |")
        lines.append("")

    # Truncation warning banner
    if meta.get("data_truncated"):
        lines.append("---")
        lines.append("")
        lines.append("> **WARNING: This analysis is based on a subset of the full scan data.**")
        lines.append(">")
        truncation = data.get("truncation", {})
        if truncation.get("hosts_truncated"):
            lines.append(f"> - **Hosts:** Only the top {meta['hosts_analyzed']} of "
                         f"{meta['hosts_total']} hosts were analyzed (prioritized by "
                         f"finding count + open ports).")
        if truncation.get("findings_truncated"):
            count = len(truncation.get("findings_truncated_hosts", []))
            lines.append(f"> - **Findings:** Nuclei findings were capped on {count} host(s). "
                         f"Some findings were not sent to the AI.")
        if truncation.get("web_dirs_truncated"):
            count = len(truncation.get("web_dirs_truncated_hosts", []))
            lines.append(f"> - **Web Directories:** Directory discoveries were capped on {count} host(s).")
        lines.append(">")
        lines.append("> **Action required:** Review the source JSONL files in `data/` for complete results.")
        lines.append("> To run a full analysis without limits, use `ai_depth=unlimited` "
                     "(note: this may incur significant API costs).")
        lines.append("")

    # Attack Paths — one ranked, de-duplicated playbook merging every actionable
    # lead (confirmed quick-wins, multi-step chains, detected-unverified, CVE
    # leads), most-likely/highest-impact first, each tagged with its confidence.
    # Replaces the former split "Priority Findings"/"Unconfirmed" sections so the
    # operator gets a single prioritized how-to-attack list.
    paths = _merge_attack_paths(data.get("recommendations", {}))
    lines.append("## Attack Paths")
    lines.append("")
    if paths:
        lines.append("> One prioritized, de-duplicated playbook — most likely / "
                     "highest-impact first; each item tagged with its confidence. "
                     "**AI-selected, not validated** — see **Validation Results** for "
                     "confirmed / refuted / unclear verdicts.")
        lines.append("")
        for idx, rec in enumerate(paths, 1):
            target = rec.get("target", "")
            action = rec.get("action", "")
            tags = [t for t in (rec.get("_status", ""),
                                f"impact: {rec['impact']}" if rec.get("impact") else "") if t]
            lines.append(f"### {idx}. {target} — {action}")
            if tags:
                lines.append(f"*{' · '.join(tags)}*")
            lines.append("")
            lines.append(f"Evidence: {rec.get('evidence', 'N/A')}")
            commands = rec.get("commands", [])
            if commands:
                lines.append("")
                lines.append("```bash")
                if rec.get("_multi") and len(commands) > 1:
                    for i, cmd in enumerate(commands, 1):
                        lines.append(f"# Step {i}")
                        lines.append(cmd)
                else:
                    for cmd in commands:
                        lines.append(cmd)
                lines.append("```")
            if rec.get("expected_result"):
                lines.append(f"Expected: {rec['expected_result']}")
            if rec.get("notes"):
                lines.append(f"Notes: {rec['notes']}")
            lines.append("")
    else:
        lines.append("*No actionable attack paths identified.*")
        lines.append("")

    # Infrastructure Relationships
    correlations = data.get("correlations", [])
    if correlations:
        lines.append("## Infrastructure Relationships")
        lines.append("")

        for i, corr in enumerate(correlations, 1):
            corr_type = (corr.get("type") or "").replace("_", " ").title()
            lines.append(f"### {i}. {corr.get('title', 'Unnamed')}")
            lines.append(f"**Type:** {corr_type} | **Hosts:** {', '.join(corr.get('hosts', []))}")
            lines.append("")
            if corr.get("evidence"):
                lines.append(f"**Evidence:** {corr['evidence']}")
                lines.append("")
            if corr.get("implication"):
                lines.append(f"**Implication:** {corr['implication']}")
                lines.append("")
            commands = corr.get("commands", [])
            if commands:
                lines.append("```bash")
                for cmd in commands:
                    lines.append(cmd)
                lines.append("```")
                lines.append("")

    # Service Inventory — a deterministic asset list (service/version/port/hosts)
    # built straight from scan data. CVE assessment is in the exploitation plan
    # above, grounded in actual scanner findings rather than LLM version recall.
    lines.append("---")
    lines.append("## Service Inventory")
    lines.append("")

    services = [
        s for s in data.get("service_inventory", [])
        if s.get("service") and s.get("version") and s.get("port")
    ]
    if services:
        any_hosts = any(svc.get("hosts") for svc in services)
        if any_hosts:
            lines.append("| Service | Version | Port | Hosts |")
            lines.append("|---------|---------|------|-------|")
            for svc in services:
                hosts = svc.get("hosts") or []
                host_count = str(len(hosts)) if hosts else "-"
                lines.append(
                    f"| {svc.get('service', '')} | {svc.get('version', '')} | "
                    f"{svc.get('port', '')} | {host_count} |"
                )
        else:
            lines.append("| Service | Version | Port |")
            lines.append("|---------|---------|------|")
            for svc in services:
                lines.append(
                    f"| {svc.get('service', '')} | {svc.get('version', '')} | "
                    f"{svc.get('port', '')} |"
                )
        lines.append("")
    else:
        lines.append("*No services identified.*")
        lines.append("")

    # Footer with limits info
    lines.append("---")
    lines.append("")
    lines.append("*Analysis generated by MonkeyX AI module.*")
    if meta.get("data_truncated"):
        lines.append("")
        lines.append(f"*Data limits applied (depth: {meta['depth']}). "
                     f"For complete coverage, re-run with `ai_depth=unlimited`. "
                     f"Review JSONL source files for data not included in this analysis.*")

    with open(output_path, 'w') as f:
        f.write("\n".join(lines))



def _read_jsonl(path: str) -> list[dict]:
    """Read a JSONL file and return list of dicts."""
    records = []
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
    except (OSError, IOError) as e:
        logger.warning("Could not read %s: %s", path, e)
    return records
