"""AI-assisted gowitness screenshot analysis module for MonkeyX.

Uses Claude vision to analyze web screenshots grouped by perceptual hash,
identifying login panels, admin interfaces, exposed services, and attack
surface from visual inspection of captured pages.
"""

import base64
import glob
import json
import logging
import os
import re
import sqlite3
from collections import defaultdict
from datetime import datetime, timezone
from urllib.parse import urlparse

from core import scan_db
from core.ai_provider import AIProvider, display_model_name
from core.anonymize import (
    anonymize_text,
    build_alias_map,
    deanonymize_obj,
    extract_domains_from_text,
)
from core.utils import version_output_path

logger = logging.getLogger('monkeyx.modules.ai_analyze_gowitness')

REQUIRED_INPUTS = frozenset()

_IP_RE = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')


def _build_screenshot_alias_map(groups):
    """Build IP/domain <-> alias maps from every URL/title/technology in the
    loaded gowitness data, so text metadata (URLs, titles, techs) can be aliased
    before it reaches the vision API and restored in the response.

    NOTE: this covers the TEXT channel only. The screenshot JPEG itself still
    egresses with identifying content (rendered hostnames, logos, page text) —
    a vision model cannot analyze an image we've scrubbed. See
    core/anonymize.py and docs/AI_DATA_HANDLING.md.
    """
    ips, domains, seen_ip = [], set(), set()
    for members in groups.values():
        for m in members:
            for field in (m.get("url"), m.get("final_url")):
                if not field:
                    continue
                parsed = urlparse(field if "://" in field else f"http://{field}")
                host = parsed.hostname or ""
                if _IP_RE.match(host):
                    if host not in seen_ip:
                        seen_ip.add(host)
                        ips.append(host)
                elif host:
                    domains.add(host.lower())
                extract_domains_from_text(field, domains)
            extract_domains_from_text(m.get("title") or "", domains)
            for tech in m.get("technologies", []):
                extract_domains_from_text(str(tech), domains)
    return build_alias_map(ips, domains)

DEFAULT_LIMITS = {
    "quick": {
        "max_groups": 10,
        "max_screenshots_per_group": 1,
        "max_singletons": 10,
        "max_image_size_kb": 200,
        "max_tokens": 30000,
    },
    "standard": {
        "max_groups": 23,
        "max_screenshots_per_group": 2,
        "max_singletons": 30,
        "max_image_size_kb": 300,
        "max_tokens": 60000,
    },
    "deep": {
        "max_groups": None,
        "max_screenshots_per_group": 3,
        "max_singletons": None,
        "max_image_size_kb": 500,
        "max_tokens": 120000,
    },
    "unlimited": {
        "max_groups": None,
        "max_screenshots_per_group": 5,
        "max_singletons": None,
        "max_image_size_kb": 800,
        "max_tokens": 200000,
    },
}

SYSTEM_PROMPT = """You are a security reconnaissance analyst reviewing web application screenshots captured during an external penetration test. Your job is to identify security-relevant findings from visual inspection.

For each screenshot, identify:

1. **Application type**: Login portal, admin panel, API documentation, default page, error page, monitoring dashboard, CI/CD interface, cloud management console, etc.
2. **Authentication state**: Login form present, ALREADY AUTHENTICATED (logged-in view visible), no auth required, SSO/OAuth flow
3. **Technology indicators**: Visible framework names, version numbers, server software, cloud providers
4. **Security observations**: Default-credential hints, verbose error messages, debug/stack traces, exposed internal paths/IPs, directory listings, exposed secrets/config, information disclosure

**Severity — anchor to what is EXPLOITABLE and VISIBLE in THIS screenshot, not to how valuable the target type sounds:**
- **CRITICAL**: Directly exploitable *right now* with no credentials, OR clear sensitive-data exposure — an already-authenticated session or admin/monitoring dashboard rendered without login, an open directory listing of sensitive files, exposed secrets/API keys/config, a debug/stack-trace page leaking source or credentials, or an unauthenticated privileged console (phpMyAdmin, Kibana, a Jenkins script console, a Kubernetes dashboard).
- **HIGH**: Likely exploitable or clearly risky — a strong, evidenced lead roughly one step from compromise: a product+version visible that maps to known CVEs, an exposed SETUP/installer/first-run page you could complete to take the app over (e.g. "WordPress Installation", an unconfigured setup wizard), an exposed non-production/staging/debug environment showing build/version internals, or a verbose error revealing internal IPs/paths/hostnames/connection strings.
- **MEDIUM**: A privileged/high-value login or admin panel (Jenkins, Grafana, GitLab, VPN, webmail, a cloud/hypervisor console, a router/IPMI/BMC) that ALSO shows a concrete extra signal short of direct exploitation — a visible internal hostname/username/path, a non-public environment label, or a partially-rendered authenticated element — OR standalone partial info disclosure (internal hostnames/usernames/internal paths/non-public structure visible but not directly usable). A **bare** privileged login with nothing else exposed is LOW, not MEDIUM; a mere product/version string is LOW (fingerprinting), not MEDIUM.
- **LOW**: Minor, low-value attack surface — ANY login/admin panel (generic OR privileged) where nothing beyond the panel itself is visible, a landing page that fingerprints a tech stack or shows a product/version string with no further exposure, or a minor informational page/redirect.
- **INFO**: Inventory only — no exposure and low intrinsic value: default framework/server landing pages ("It works!", nginx/Apache default), parked/blank/placeholder pages, or a bare login form with no identifying or high-value context.

Rules:
- Focus ONLY on what is VISIBLE. Do not speculate about weak auth, default creds, or "known vulns" you cannot actually see.
- Do NOT inflate severity because the target TYPE sounds valuable (VPN, webmail, a hostname like "pipeline"/"admin"/"dev"). A login page's severity comes from WHAT ELSE is visible, never the product name alone — a privileged/admin panel with nothing else exposed is LOW, exactly like a generic one.
- A plain login form is INFO (LOW if it fingerprints a product/version, INCLUDING a privileged-system login). It is MEDIUM only if the screenshot ALSO shows a concrete extra exposure (internal hostname/username/path, a non-public environment label, a partial authenticated element), and HIGH/CRITICAL only if it shows something directly exploitable (default-cred banner, exposed data behind it, a version tied to a CVE, debug output, or an already-authenticated view).
- Note any visible hostnames, paths, or version strings exactly as shown, in the `evidence` field.
- The `evidence` field must cite the specific visible detail that justifies the severity. If you cannot name a concrete visible detail, the severity is INFO or LOW.

Output valid JSON:
{
  "findings": [
    {
      "url": "the URL that was screenshotted",
      "title": "page title if visible",
      "category": "login_panel|admin_interface|api_docs|monitoring|cicd|cloud_console|default_page|error_page|application|other",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "description": "what you observe in the screenshot",
      "technologies": ["tech1", "tech2"],
      "attack_notes": "specific attack vectors or next steps for a pentester",
      "evidence": "what in the screenshot supports this finding"
    }
  ],
  "summary": {
    "total_analyzed": 0,
    "critical_count": 0,
    "high_count": 0,
    "interesting_targets": ["url1", "url2"]
  }
}"""

SYSTEM_PROMPT_GROUP = """You are a security reconnaissance analyst. You are reviewing a GROUP of web screenshots that share the same visual appearance (same perceptual hash group). I'll show you one or two representative screenshots from this group, plus metadata about all URLs in the group.

Your job: determine if this group is security-relevant or just noise (error pages, CDN blocks, etc.), and if relevant, describe what the group represents.

**Severity — anchor to what is EXPLOITABLE and VISIBLE in the screenshots, not to how valuable the target type sounds:**
- **CRITICAL**: exploitable now with no creds, or clear sensitive-data exposure — already-authenticated/admin dashboard, open directory listing, exposed secrets/config, debug/stack-trace leaking source or credentials, an unauthenticated privileged console (phpMyAdmin/Kibana/Jenkins script console/K8s dashboard).
- **HIGH**: likely exploitable / clearly risky — a product+version tied to known CVEs, an exposed setup/installer page you could complete to take over, an exposed non-prod/staging/debug environment showing internals, or a verbose error leaking internal IPs/paths.
- **MEDIUM**: a privileged/high-value login or admin panel (Jenkins/Grafana/GitLab/VPN/webmail/cloud console/IPMI/BMC) that ALSO shows a concrete extra signal (internal hostname/username/path, a non-public env label, a partial authed element), OR standalone partial info disclosure. A bare privileged login with nothing else exposed is LOW. Mark `interesting` only for genuine MEDIUM+.
- **LOW**: minor/low-value surface — ANY login/admin panel (generic OR privileged) with nothing beyond the panel visible, a landing page that fingerprints a stack or shows a version string, a minor informational page.
- **INFO**: inventory only — default framework/server landing pages, parked/blank pages, or a bare login form with no identifying context.

Classify generic CDN/WAF error pages and default/parked pages as `noise`. Do NOT inflate severity because the target type sounds valuable: a wall of login panels — generic OR privileged — is INFO/LOW; a privileged login is MEDIUM only with a visible extra exposure, and nothing is HIGH/CRITICAL without visible exploitable exposure.

Output valid JSON:
{
  "group_assessment": "interesting|noise",
  "category": "login_panel|admin_interface|api_docs|monitoring|cicd|cloud_console|default_page|error_page|application|other",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "description": "what this group of pages represents",
  "technologies": ["tech1", "tech2"],
  "notable_urls": ["any URLs from the group metadata that stand out as particularly interesting"],
  "attack_notes": "attack vectors if interesting, or 'N/A' if noise"
}"""


# --- Coverage + synthesis -------------------------------------------------- #
# Vision analysis is per-item (one call per perceptual-hash group; groups of
# _SINGLETON_BATCH singletons per call). ai_max_groups / ai_max_singletons (depth
# presets + "unlimited") cap the TOTAL items analysed — the coverage ceiling. Any
# items beyond the cap are REPORTED (not silently dropped), and a synthesis pass
# consolidates the findings into one prioritized, de-duplicated set.

_SINGLETON_BATCH = 5
_SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

SYSTEM_PROMPT_SYNTH = """You are consolidating web-screenshot findings from an external penetration test into ONE prioritized list, CLUSTERED BY THEME. You are given findings as JSON (each was produced from a single screenshot or a group of similar screenshots).

Cluster aggressively, don't just dedup:
- Merge findings that represent the SAME thing across hosts into ONE clustered entry, clustered by application family + category — e.g. all "AtlasNet non-prod portals", all Kentico instances, all Cloudflare error pages. A recurring login panel across 8 hosts is ONE finding, not 8 — and this holds for PRIVILEGED-system logins too: 30 Grafana logins across 30 hosts is ONE entry with member_count 30, never 30 findings.
- Default to collapsing. Only break an instance out of its family cluster if THAT instance shows a DISTINCT higher-value exposure (info disclosure, exposed non-prod internals, an already-authenticated view) the rest of the cluster does not — otherwise it stays in the cluster.
- For a clustered entry: put 1-3 representative URLs in `url`, list EVERY host/URL it covers in `hosts` (an array), and set `member_count`. Keep the most complete description/attack_notes; note in the description how many hosts and what distinguishes them (e.g. "8 non-prod environments np01-np06 plus npd/npq").

Severity (re-apply, evidence-based — do NOT inflate by target type):
- CRITICAL: exploitable now / sensitive-data exposure (authed view, open dir listing, exposed secrets, debug/stack trace, unauth privileged console).
- HIGH: a version tied to known CVEs, an exposed setup/installer page, exposed non-prod internals, or a verbose error leaking internals.
- MEDIUM: a privileged/high-value login/admin panel that ALSO shows a concrete extra signal (internal hostname/username/path, a non-public env label, a partial authed element), OR standalone partial info disclosure. A bare privileged login is NOT MEDIUM.
- LOW: ANY login/admin panel (generic OR privileged) with nothing else exposed, a standard landing page or visible version string, minor info.
- INFO: default/parked pages, or bare login forms with no identifying context.
Re-rank so evidenced CRITICAL/HIGH lead, then MEDIUM, then LOW, then INFO. A recurring login cluster — generic OR privileged — is LOW (INFO if bare/featureless); it is MEDIUM only when the cluster itself carries a concrete extra exposure.

Do NOT invent findings, URLs, technologies, or hosts not present in the input. Clustering must not drop coverage — every input host must appear in some entry's `url` or `hosts`.

Output valid JSON: {"findings": [ { ...item shape as input, plus "hosts": ["url1","url2"], "member_count": 0 } ], "summary": {"total": 0, "critical_count": 0, "high_count": 0}}"""


def _dedup_findings(findings):
    """De-dup by (url, category), keeping the highest-severity variant; order-stable."""
    best, order = {}, []
    for f in findings:
        if not isinstance(f, dict):
            continue
        key = (str(f.get("url", "")).lower(), f.get("category", ""))
        if key not in best:
            best[key] = f
            order.append(key)
        elif _SEV_RANK.get(f.get("severity"), 0) > _SEV_RANK.get(best[key].get("severity"), 0):
            best[key] = f
    return [best[k] for k in order]


def _synthesize_gowitness_findings(ai, findings, max_tokens,
                                   token_to_alias=None, alias_to_token=None):
    """Reduce step: dedup, then (when there's enough to consolidate) one text-only
    AI pass to merge/re-rank. Falls back to the deduped merge — never loses data.

    The findings passed in are already de-aliased (real URLs), so the payload is
    re-aliased before this egress and the response de-aliased again.
    """
    token_to_alias = token_to_alias or {}
    alias_to_token = alias_to_token or {}
    deduped = _dedup_findings(findings)
    if len(deduped) < 2:
        return deduped
    try:
        payload = anonymize_text(json.dumps({"findings": deduped}), token_to_alias)[:400_000]
        result = ai.query_json(SYSTEM_PROMPT_SYNTH, payload, max_tokens=min(max_tokens, 8192))
        result = deanonymize_obj(result, alias_to_token)
        if isinstance(result, dict) and result.get("findings"):
            return result["findings"]
        logger.warning("gowitness synthesis returned no findings; using deduped merge")
    except Exception as e:
        logger.error("gowitness synthesis pass failed, using deduped merge: %s", e)
    return deduped


def _resolve_limits(depth, kwargs):
    base = dict(DEFAULT_LIMITS.get(depth, DEFAULT_LIMITS["standard"]))
    for key in base:
        override = kwargs.get(f"ai_{key}")
        if override is not None:
            if override == "none" or override == "unlimited":
                base[key] = None
            else:
                base[key] = int(override)
    return base


def _find_gowitness_db(data_prefix, reports_prefix, kwargs):
    """Locate the gowitness SQLite database."""
    explicit = kwargs.get("gowitness_db")
    if explicit and os.path.isfile(explicit):
        return explicit

    search_dirs = []
    if reports_prefix:
        reports_dir = os.path.dirname(reports_prefix)
        search_dirs.append(reports_dir)
    if data_prefix:
        data_dir = os.path.dirname(data_prefix)
        search_dirs.append(data_dir)
        output_dir = os.path.dirname(data_dir)
        reports_from_output = os.path.join(output_dir, "reports")
        search_dirs.append(reports_from_output)

    for search_dir in search_dirs:
        if not os.path.isdir(search_dir):
            continue
        for dirpath, dirnames, filenames in os.walk(search_dir):
            if "gowitness.sqlite3" in filenames:
                return os.path.join(dirpath, "gowitness.sqlite3")
            for f in filenames:
                if f.endswith(".sqlite3") and "gowitness" in dirpath.lower():
                    return os.path.join(dirpath, f)

    return None


def _load_gowitness_data(db_path):
    """Load screenshot data from gowitness SQLite DB, grouped by perceptual hash."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    results = conn.execute("""
        SELECT r.id, r.url, r.title, r.response_code, r.final_url,
               r.perception_hash_group_id, r.filename, r.content_length
        FROM results r
        WHERE r.failed = 0
        ORDER BY r.perception_hash_group_id, r.id
    """).fetchall()

    tech_map = defaultdict(list)
    for row in conn.execute("SELECT result_id, value FROM technologies"):
        tech_map[row["result_id"]].append(row["value"])

    conn.close()

    groups = defaultdict(list)
    for row in results:
        entry = {
            "id": row["id"],
            "url": row["url"],
            "title": row["title"] or "",
            "response_code": row["response_code"],
            "final_url": row["final_url"] or "",
            "filename": row["filename"] or "",
            "content_length": row["content_length"] or 0,
            "technologies": tech_map.get(row["id"], []),
        }
        groups[row["perception_hash_group_id"]].append(entry)

    return dict(groups)


def _is_likely_noise_group(members):
    """Heuristic: if a large group is mostly 4xx/5xx error pages, it's noise."""
    if len(members) < 5:
        return False
    error_count = sum(1 for m in members if (m["response_code"] or 0) >= 400)
    error_ratio = error_count / len(members)
    noise_titles = {"403 forbidden", "404 not found", "access denied",
                    "bad request", "invalid url", "error", "service unavailable",
                    "503 service temporarily unavailable", "400 the plain http request was sent to https port",
                    "400 no required ssl certificate was sent"}
    noise_title_count = sum(
        1 for m in members
        if m["title"].lower().strip() in noise_titles or not m["title"].strip()
    )
    noise_title_ratio = noise_title_count / len(members)
    return error_ratio > 0.7 and noise_title_ratio > 0.5


def _select_representative(members):
    """Pick the most interesting member of a group as representative."""
    scored = []
    for m in members:
        score = 0
        if m["title"] and m["title"].lower() not in {"", "403 forbidden", "404 not found",
                                                      "access denied", "bad request", "invalid url"}:
            score += 2
        if m["response_code"] == 200:
            score += 2
        if m["technologies"]:
            score += len(m["technologies"])
        if m["content_length"] > 1000:
            score += 1
        scored.append((score, m))
    scored.sort(key=lambda x: x[0], reverse=True)
    return scored[0][1] if scored else members[0]


def _load_screenshot_base64(db_dir, filename, max_size_kb):
    """Load a JPEG screenshot and return base64 encoded data."""
    filepath = os.path.join(db_dir, filename)
    if not os.path.isfile(filepath):
        return None

    file_size = os.path.getsize(filepath)
    if max_size_kb and file_size > max_size_kb * 1024:
        logger.debug("Screenshot %s too large (%d KB), skipping", filename, file_size // 1024)
        return None

    with open(filepath, "rb") as f:
        return base64.b64encode(f.read()).decode("ascii")


def _query_vision_anthropic(ai, system_prompt, user_text, images, max_tokens):
    """Send a vision query with images directly to Anthropic API."""
    client = ai._create_anthropic_client()
    model = ai.config.get("model", "claude-opus-4-6")

    content = []
    for img_data, img_label in images:
        content.append({
            "type": "image",
            "source": {
                "type": "base64",
                "media_type": "image/jpeg",
                "data": img_data,
            },
        })
        content.append({
            "type": "text",
            "text": f"[Screenshot: {img_label}]",
        })

    content.append({"type": "text", "text": user_text})

    logger.info("Vision request (stream): model=%s images=%d max_tokens=%d", model, len(images), max_tokens)
    with client.messages.stream(
        model=model,
        max_tokens=max_tokens,
        system=system_prompt,
        messages=[{"role": "user", "content": content}],
    ) as stream:
        response = stream.get_final_message()

    if hasattr(response, "usage"):
        ai.usage["input_tokens"] += getattr(response.usage, "input_tokens", 0)
        ai.usage["output_tokens"] += getattr(response.usage, "output_tokens", 0)
    ai.usage["calls"] += 1

    text = ai._extract_anthropic_text(response)
    return ai._parse_json_response(text)


def _analyze_group(ai, group_id, members, db_dir, limits,
                   token_to_alias=None, alias_to_token=None):
    """Analyze a perceptual hash group by sending representative screenshots.

    Text metadata (URLs, titles, technologies) is aliased before egress and the
    response de-aliased. The screenshot image itself is unaltered — it can't be
    (see _build_screenshot_alias_map).
    """
    token_to_alias = token_to_alias or {}
    alias_to_token = alias_to_token or {}
    representative = _select_representative(members)
    max_size_kb = limits.get("max_image_size_kb", 300)

    img_data = _load_screenshot_base64(db_dir, representative["filename"], max_size_kb)
    if not img_data:
        return None

    images = [(img_data, anonymize_text(representative["url"], token_to_alias))]

    max_per_group = limits.get("max_screenshots_per_group", 2)
    if max_per_group > 1 and len(members) > 1:
        others = [m for m in members if m["id"] != representative["id"]]
        for other in others[:max_per_group - 1]:
            other_data = _load_screenshot_base64(db_dir, other["filename"], max_size_kb)
            if other_data:
                images.append((other_data, anonymize_text(other["url"], token_to_alias)))

    group_metadata = f"""Group #{group_id} contains {len(members)} URLs with visually similar screenshots.

URLs in this group:
"""
    for m in members[:30]:
        techs = f" [{', '.join(m['technologies'])}]" if m["technologies"] else ""
        group_metadata += f"- {m['url']} (HTTP {m['response_code']}, title: \"{m['title']}\"){techs}\n"
    if len(members) > 30:
        group_metadata += f"... and {len(members) - 30} more URLs\n"

    group_metadata += "\nAnalyze the representative screenshot(s) and assess this group."
    group_metadata += "\n\nIMPORTANT: Respond with ONLY valid JSON. No markdown, no explanation, no code fences."

    group_metadata = anonymize_text(group_metadata, token_to_alias)

    result = _query_vision_anthropic(ai, SYSTEM_PROMPT_GROUP, group_metadata, images, 4096)
    return deanonymize_obj(result, alias_to_token)


def _analyze_singletons(ai, entries, db_dir, limits,
                        token_to_alias=None, alias_to_token=None):
    """Analyze individual interesting screenshots in batches.

    Text metadata (URLs, titles, technologies) is aliased before egress and each
    returned finding de-aliased. The screenshot images are unaltered.
    """
    token_to_alias = token_to_alias or {}
    alias_to_token = alias_to_token or {}
    max_size_kb = limits.get("max_image_size_kb", 300)
    max_tokens = limits.get("max_tokens", 60000)

    batch_size = _SINGLETON_BATCH
    all_findings = []

    for i in range(0, len(entries), batch_size):
        batch = entries[i:i + batch_size]
        images = []
        metadata_lines = []

        for entry in batch:
            img_data = _load_screenshot_base64(db_dir, entry["filename"], max_size_kb)
            if not img_data:
                continue
            images.append((img_data, anonymize_text(entry["url"], token_to_alias)))
            techs = f" [{', '.join(entry['technologies'])}]" if entry["technologies"] else ""
            metadata_lines.append(
                f"- URL: {entry['url']} | HTTP {entry['response_code']} | "
                f"Title: \"{entry['title']}\"{techs}"
            )

        if not images:
            continue

        user_text = f"Analyze these {len(images)} screenshots from unique pages:\n\n"
        user_text += "\n".join(metadata_lines)
        user_text += "\n\nFor each screenshot, provide a finding entry."
        user_text += "\n\nIMPORTANT: Respond with ONLY valid JSON. No markdown, no explanation, no code fences."

        user_text = anonymize_text(user_text, token_to_alias)

        result = _query_vision_anthropic(ai, SYSTEM_PROMPT, user_text, images,
                                         min(max_tokens, 8192))
        result = deanonymize_obj(result, alias_to_token)
        if result and "findings" in result:
            all_findings.extend(result["findings"])

    return all_findings


def _finding_report_lines(f, idx, detailed=True):
    """Render one finding as markdown lines, cluster-aware."""
    lines = [f"{idx}. **{f.get('url', 'Unknown URL')}**"]
    hosts = [h for h in (f.get("hosts") or []) if h]
    count = f.get("member_count") or (len(hosts) if hosts else 0)
    if count and count > 1:
        lines.append(f"   - Cluster: {count} hosts")
        shown = hosts[:10]
        if shown and shown != [f.get("url")]:
            for h in shown:
                lines.append(f"     - {h}")
            if len(hosts) > 10:
                lines.append(f"     - ... and {len(hosts) - 10} more")
    lines.append(f"   - Category: {f.get('category', 'unknown')}")
    lines.append(f"   - Description: {f.get('description', '')}")
    if detailed:
        if f.get("evidence"):
            lines.append(f"   - Evidence: {f['evidence']}")
        if f.get("technologies"):
            lines.append(f"   - Technologies: {', '.join(f['technologies'])}")
        if f.get("attack_notes"):
            lines.append(f"   - Attack Notes: {f['attack_notes']}")
    lines.append("")
    return lines


def _generate_report(findings, group_assessments, meta, output_path):
    """Generate markdown report from analysis results."""
    lines = [
        "# Gowitness Screenshot AI Analysis",
        "",
        f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        f"**Provider:** {meta['provider']} (model: {meta['model']})",
        f"**Total screenshots:** {meta['total_screenshots']}",
        f"**Perceptual hash groups:** {meta['total_groups']}",
        f"**Groups analyzed:** {meta['groups_analyzed']}",
        f"**Individual screenshots analyzed:** {meta['singletons_analyzed']}",
        "",
    ]

    critical = [f for f in findings if f.get("severity") == "CRITICAL"]
    high = [f for f in findings if f.get("severity") == "HIGH"]
    medium = [f for f in findings if f.get("severity") == "MEDIUM"]
    low = [f for f in findings if f.get("severity") == "LOW"]
    info = [f for f in findings if f.get("severity") == "INFO"]

    lines.append("## Executive Summary")
    lines.append("")
    lines.append(f"- **CRITICAL findings:** {len(critical)}")
    lines.append(f"- **HIGH findings:** {len(high)}")
    lines.append(f"- **MEDIUM findings:** {len(medium)}")
    lines.append(f"- **LOW findings:** {len(low)}")
    lines.append(f"- **INFO (attack-surface inventory):** {len(info)}")
    lines.append(f"- **Total findings:** {len(findings)}")
    lines.append("")

    if critical:
        lines.append("## Critical Findings")
        lines.append("")
        for idx, f in enumerate(critical, 1):
            lines.extend(_finding_report_lines(f, idx, detailed=True))

    if high:
        lines.append("## High Findings")
        lines.append("")
        for idx, f in enumerate(high, 1):
            lines.extend(_finding_report_lines(f, idx, detailed=True))

    if medium:
        lines.append("## Medium Findings")
        lines.append("")
        for idx, f in enumerate(medium, 1):
            lines.extend(_finding_report_lines(f, idx, detailed=False))

    # Low/Info: catalogued attack surface (generic logins, standard apps, default
    # pages) — compact, non-detailed, so they're visible but don't drown signal.
    if low or info:
        lines.append("## Low / Informational (attack-surface inventory)")
        lines.append("")
        for f in low + info:
            sev = f.get("severity", "INFO")
            cat = f.get("category", "other")
            url = f.get("url") or ", ".join((f.get("hosts") or [])[:1]) or "?"
            title = f.get("title") or f.get("description") or cat
            lines.append(f"- **[{sev}]** {url} — {cat}: {title}")
        lines.append("")

    interesting_groups = [g for g in group_assessments if g.get("group_assessment") == "interesting"]
    if interesting_groups:
        lines.append("## Interesting Groups (by visual similarity)")
        lines.append("")
        lines.append("_A visual-clustering index of what was captured. Severity and "
                     "prioritization live in the Findings sections above — this "
                     "list intentionally omits severity to avoid restating a "
                     "per-group guess that the consolidated findings re-ranked._")
        lines.append("")
        for idx, g in enumerate(interesting_groups, 1):
            lines.append(f"{idx}. **{g.get('description', 'Unknown')}**")
            lines.append(f"   - Category: {g.get('category', '?')}")
            if g.get("notable_urls"):
                lines.append("   - Notable URLs:")
                for url in g["notable_urls"][:10]:
                    lines.append(f"     - {url}")
            if g.get("attack_notes") and g["attack_notes"] != "N/A":
                lines.append(f"   - Attack Notes: {g['attack_notes']}")
            lines.append("")

    noise_groups = [g for g in group_assessments if g.get("group_assessment") == "noise"]
    if noise_groups:
        lines.append("## Noise Groups (skipped)")
        lines.append("")
        lines.append(f"*{len(noise_groups)} groups classified as noise (error pages, CDN blocks, etc.)*")
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("*Analysis generated by MonkeyX AI Gowitness module.*")

    with open(output_path, 'w') as f:
        f.write("\n".join(lines))


_SEV_MAP = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium",
            "LOW": "low", "INFO": "info"}


def _mint_gowitness_findings(findings, output_dir, now):
    """Mint AI visual findings into scan.db so they flow into the focus list,
    report.html, and the web view alongside scanner findings.

    Each finding is keyed by (host, port, proto=tcp, claim) where claim is
    ``gowitness:<category>`` — the visual-analysis discriminator, distinct from
    nuclei/nmap claims so it never collides. All severities down to INFO are
    minted (ranked by severity, so low-value items sit at the bottom rather than
    being dropped) — pure noise (CDN/WAF/default/parked) is already filtered
    upstream at the interesting-vs-noise gate and never reaches here. Only an
    unmappable/absent severity is skipped. Best-effort, non-fatal; returns count.
    """
    db = scan_db.open_db(output_dir) if output_dir else None
    if db is None:
        return 0
    minted = 0
    minted_ids: set[str] = set()   # every finding_id written this run
    try:
        for f in findings:
            sev = _SEV_MAP.get(str(f.get("severity", "")).upper())
            if sev is None:
                continue  # unmappable/absent severity — can't rank it, skip
            category = f.get("category", "other")
            claim = f"gowitness:{category}"
            title = (f.get("title") or f.get("description") or category)[:500]
            base_detail = [f.get("description", "")]
            if f.get("evidence"):
                base_detail.append(f"Evidence: {f['evidence']}")
            if f.get("attack_notes"):
                base_detail.append(f"Attack notes: {f['attack_notes']}")
            tech_tags = [t for t in (f.get("technologies") or []) if t]

            # A finding can cover many hosts: its primary url(s) were the pages
            # actually cited/analyzed; every other host in `hosts` shares the same
            # perceptual-hash group / cluster. Mint one row per host so all
            # similar hosts surface — the non-primary ones tagged inferred
            # (visual similarity), at the SAME severity, with a provenance note.
            primary_urls = [u.strip() for u in (f.get("url") or "").split(",") if u.strip()]
            host_urls = [h for h in (f.get("hosts") or []) if h]
            # Primary first, then covered hosts; order-stable dedup.
            all_urls = list(dict.fromkeys(primary_urls + host_urls))
            primary_set = set(primary_urls)
            rep_label = primary_urls[0] if primary_urls else None

            for one_url in all_urls:
                if " " in one_url:
                    continue  # skip a non-URL primary (e.g. "Group #5")
                parsed = urlparse(one_url if "://" in one_url else f"http://{one_url}")
                host = parsed.hostname
                if not host:
                    continue
                port = parsed.port or (443 if parsed.scheme == "https" else 80)
                inferred = one_url not in primary_set
                fid = scan_db.finding_id(host, port, "tcp", claim)
                detail_parts = list(base_detail)
                if inferred and rep_label:
                    detail_parts.append(
                        f"Inferred: assessed by visual similarity to {rep_label} "
                        f"(same perceptual-hash group of {f.get('member_count') or len(all_urls)} "
                        f"pages); this host was not individually vision-analyzed.")
                tags = tech_tags + (["inferred-visual-similarity"] if inferred else [])
                try:
                    db.upsert_finding(
                        finding_id=fid, host=host, port=port, proto="tcp",
                        claim=claim, tool="gowitness", type="finding",
                        severity=sev, title=title,
                        detail="\n".join(p for p in detail_parts if p),
                        matched_at=one_url,
                        tags=",".join(tags) or None,
                        source_file="ai-gowitness-analysis.json", now=now)
                    minted += 1
                    minted_ids.add(fid)
                except Exception as exc:  # pragma: no cover - defensive
                    logger.warning("gowitness finding mint failed for %s: %s", one_url, exc)
        # Idempotent re-run guard: drop any prior gowitness findings NOT re-minted
        # this run (recategorized or no-longer-produced), so `--continue -m
        # ai_analyze_gowitness` refreshes in place instead of accumulating stale
        # duplicates. Scoped to this module's source_file, so scanner findings are
        # untouched; upsert already preserved triage on the rows we kept.
        try:
            pruned = db.prune_findings_by_source("ai-gowitness-analysis.json", minted_ids)
            if pruned:
                logger.info("Pruned %d stale gowitness finding(s) from scan.db", pruned)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("gowitness finding prune failed: %s", exc)
    finally:
        db.close(checkpoint=False)
    return minted


def run_ai_analyze_gowitness(prefix, **kwargs):
    """Run AI-assisted visual analysis of gowitness screenshots.

    Args:
        prefix: Output file prefix
        **kwargs:
            data_prefix: Where data files live
            reports_prefix: Where to write reports
            gowitness_db: Explicit path to gowitness.sqlite3 (optional, auto-detected)
            ai_provider: Override provider name
            ai_depth: "quick" | "standard" | "deep" | "unlimited"
            ai_max_groups: Override max groups to analyze
            ai_max_screenshots_per_group: Override screenshots per group
            ai_max_singletons: Override max individual screenshots
            ai_max_tokens: Override max tokens per call

    Returns:
        dict with module results
    """
    data_prefix = kwargs.get('data_prefix', prefix)
    reports_prefix = kwargs.get('reports_prefix', prefix)
    provider_name = kwargs.get('ai_provider', None)
    depth = kwargs.get('ai_depth', 'standard')

    limits = _resolve_limits(depth, kwargs)

    logger.info("AI gowitness analysis starting: depth=%s provider=%s", depth, provider_name or "default")
    print(f"\n[*] AI Gowitness Screenshot Analysis (depth: {depth})")

    output_dir = os.path.dirname(os.path.dirname(data_prefix)) if data_prefix else None
    logs_dir = os.path.join(output_dir, "logs") if output_dir else None

    # Detect gowitness output BEFORE touching the AI provider. If no screenshot
    # DB exists — typically because ax_gowitness was skipped on a run with no URLs
    # ("missing inputs: urls") — there is nothing to analyze. Skip gracefully
    # instead of hard-failing the run (and before enforcing the Anthropic-provider
    # requirement, which is moot with no screenshots). Mirrors ax_gowitness's own
    # "nothing to scan" skip so a URL-less deep run doesn't read as errored.
    db_path = _find_gowitness_db(data_prefix, reports_prefix, kwargs)
    if not db_path:
        msg = ("No gowitness.sqlite3 database found — gowitness produced no "
               "screenshots (typically because the run had no URLs); nothing to "
               "analyze, skipping.")
        logger.info(msg)
        print(f"[*] {msg}")
        return {
            "module": "ai_analyze_gowitness",
            "status": "skipped",
            "output_files": [],
            "warning": msg,
        }
    db_dir = os.path.dirname(db_path)
    print(f"[+] Found gowitness DB: {db_path}")

    try:
        ai = AIProvider(provider_name, logs_dir=logs_dir)
    except ValueError as e:
        logger.error("Failed to initialize AI provider: %s", e)
        msg = f"AI provider initialization failed: {e}"
        print(f"[!] {msg}")
        raise RuntimeError(msg) from e

    if ai.name not in ("anthropic",):
        msg = (f"ai_analyze_gowitness requires Anthropic provider (needs vision API). "
               f"Current provider: {ai.name}")
        logger.error(msg)
        print(f"[!] {msg}")
        print(f"[!] Set provider to 'anthropic' with aws_region for Bedrock or api_key for direct API.")
        raise RuntimeError(msg)

    print(f"[*] Using AI provider: {ai.name} (model: {ai.config.get('model', 'default')})")

    groups = _load_gowitness_data(db_path)
    total_screenshots = sum(len(members) for members in groups.values())
    print(f"[+] Loaded: {total_screenshots} screenshots in {len(groups)} perceptual hash groups")

    # Alias IPs/domains in the text metadata (URLs, titles, technologies) before
    # it leaves the host; the response is de-aliased before anything is written.
    # NOTE: the screenshot IMAGES themselves are sent unaltered and still carry
    # identifying content — see _build_screenshot_alias_map / docs/AI_DATA_HANDLING.md.
    token_to_alias, alias_to_token = _build_screenshot_alias_map(groups)
    if token_to_alias:
        print(f"[+] Anonymizing {len(token_to_alias)} host/domain token(s) in text "
              f"metadata (screenshot images are sent unaltered)")

    sorted_groups = sorted(groups.items(), key=lambda x: len(x[1]), reverse=True)

    # ai_max_groups caps the TOTAL non-noise groups analysed (depth preset +
    # unlimited). Groups beyond the cap are reported, not silently dropped.
    max_groups = limits.get("max_groups")

    # Phase 1: Analyze large groups (send representative screenshot)
    print(f"[*] Phase 1: Analyzing {len(sorted_groups)} perceptual hash groups...")
    group_assessments = []
    interesting_from_groups = []
    groups_analyzed = 0
    noise_skipped_heuristic = 0
    groups_dropped = 0

    for group_id, members in sorted_groups:
        if _is_likely_noise_group(members):
            noise_skipped_heuristic += 1
            group_assessments.append({
                "group_id": group_id,
                "group_assessment": "noise",
                "category": "error_page",
                "severity": "LOW",
                "description": f"Error/block pages ({len(members)} URLs, mostly 4xx/5xx)",
                "member_count": len(members),
                "skipped_reason": "heuristic",
            })
            continue

        if max_groups is not None and groups_analyzed >= max_groups:
            groups_dropped += 1
            continue

        try:
            result = _analyze_group(ai, group_id, members, db_dir, limits,
                                    token_to_alias, alias_to_token)
        except Exception as e:
            logger.warning("Failed to analyze group %s: %s", group_id, e)
            continue

        if not result:
            continue

        groups_analyzed += 1
        result["group_id"] = group_id
        result["member_count"] = len(members)
        # Every member of a perceptual-hash group is, by definition, the same
        # page visually. Carry all member URLs so a vulnerable group's verdict
        # can be propagated to every host in it (only the representative was
        # actually vision-analyzed — the rest are minted as inferred, same sev).
        result["member_urls"] = [m["url"] for m in members if m.get("url")]
        group_assessments.append(result)

        if result.get("group_assessment") == "interesting":
            notable = result.get("notable_urls", [])
            for m in members:
                if m["url"] in notable or len(members) <= 5:
                    interesting_from_groups.append(m)

        print(f"    Group #{group_id} ({len(members)} URLs): "
              f"{result.get('group_assessment', '?')} - {result.get('category', '?')} "
              f"[{result.get('severity', '?')}]")

    print(f"[+] Groups: {groups_analyzed} analyzed via AI, {noise_skipped_heuristic} skipped (noise heuristic)")
    if groups_dropped:
        print(f"[!] Group coverage: {groups_dropped} group(s) beyond ai_max_groups "
              f"({max_groups}) not analyzed. Use ai_depth=deep/unlimited or ai_max_groups.")

    # Phase 2: Analyze individual interesting screenshots from small/unique groups
    singletons = []
    for group_id, members in sorted(groups.items(), key=lambda x: len(x[1])):
        if len(members) <= 3:
            for m in members:
                if m["response_code"] == 200 or m["title"].strip():
                    singletons.append(m)

    # Highest-value first, then bound by the cost ceiling (batches of
    # _SINGLETON_BATCH per AI call) instead of a silent hard cap.
    singletons.sort(key=lambda m: (
        len(m["technologies"]),
        1 if m["response_code"] == 200 else 0,
        m["content_length"]
    ), reverse=True)
    singletons_dropped = 0
    max_singletons = limits.get("max_singletons")
    if max_singletons is not None and len(singletons) > max_singletons:
        singletons_dropped = len(singletons) - max_singletons
        singletons = singletons[:max_singletons]

    findings = []
    singletons_analyzed = 0
    if singletons:
        print(f"[*] Phase 2: Analyzing {len(singletons)} individual interesting screenshots...")
        findings = _analyze_singletons(ai, singletons, db_dir, limits,
                                       token_to_alias, alias_to_token)
        singletons_analyzed = len(singletons)
        print(f"[+] Individual analysis: {len(findings)} findings from {singletons_analyzed} screenshots")
    else:
        print(f"[*] Phase 2: No individual screenshots to analyze")
    if singletons_dropped:
        print(f"[!] Screenshot coverage: {singletons_dropped} individual screenshot(s) beyond "
              f"ai_max_singletons ({max_singletons}) not analyzed. Use ai_depth=deep/unlimited.")

    # Combine group findings into the findings list
    for ga in group_assessments:
        if ga.get("group_assessment") == "interesting":
            notable = [u for u in (ga.get("notable_urls") or [])[:3] if u]
            member_urls = ga.get("member_urls") or []
            # Primary = the notable/analyzed URL(s); fall back to a real member
            # URL so the finding never carries a synthetic "Group #N" as its url.
            primary = notable or member_urls[:1]
            findings.append({
                "url": ", ".join(primary) or f"Group #{ga.get('group_id')}",
                "title": ga.get("description", ""),
                "category": ga.get("category", "other"),
                "severity": ga.get("severity", "MEDIUM"),
                "description": ga.get("description", ""),
                "technologies": ga.get("technologies", []),
                "attack_notes": ga.get("attack_notes", ""),
                "evidence": f"Perceptual hash group with {ga.get('member_count', 0)} similar pages",
                # All members carried so the verdict propagates to every host in
                # the group (see _mint_gowitness_findings — non-primary hosts are
                # tagged inferred-visual-similarity).
                "hosts": member_urls,
                "member_count": ga.get("member_count", len(member_urls)),
            })

    # Reduce step: consolidate the many per-group/per-singleton findings into one
    # de-duplicated, prioritized set.
    if findings:
        print(f"[*] Synthesising {len(findings)} visual finding(s) into a prioritized set...")
        findings = _synthesize_gowitness_findings(ai, findings, limits.get("max_tokens", 60000),
                                                  token_to_alias, alias_to_token)
        print(f"[+] Consolidated to {len(findings)} finding(s)")

    # Output results
    meta = {
        "provider": ai.name,
        # Client-safe label — never persist a Bedrock ARN (embeds our AWS acct id).
        "model": display_model_name(ai.config.get("model"), ai.config),
        "depth": depth,
        "total_screenshots": total_screenshots,
        "total_groups": len(groups),
        "groups_analyzed": groups_analyzed,
        "groups_dropped": groups_dropped,
        "noise_skipped": noise_skipped_heuristic,
        "singletons_analyzed": singletons_analyzed,
        "singletons_dropped": singletons_dropped,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

    output_data = {
        "meta": meta,
        "findings": findings,
        "group_assessments": group_assessments,
        "usage": ai.get_usage_summary(),
    }

    json_path = version_output_path(f"{data_prefix}-ai-gowitness-analysis.json")
    with open(json_path, 'w') as f:
        json.dump(output_data, f, indent=2)
    print(f"[+] JSON output: {json_path}")

    # Mint into scan.db so visual findings surface in focus/report/web view.
    minted = _mint_gowitness_findings(findings, output_dir, meta["generated_at"])
    if minted:
        print(f"[+] Minted {minted} visual finding(s) into scan.db")

    report_path = version_output_path(f"{reports_prefix}-ai-gowitness-analysis.md")
    _generate_report(findings, group_assessments, meta, report_path)
    print(f"[+] Report: {report_path}")

    # Summary
    critical_count = len([f for f in findings if f.get("severity") == "CRITICAL"])
    high_count = len([f for f in findings if f.get("severity") == "HIGH"])
    usage = ai.get_usage_summary()

    print(f"\n[*] AI Gowitness Analysis Complete")
    print(f"    Findings: {len(findings)} total ({critical_count} critical, {high_count} high)")
    print(f"    API calls: {usage['calls']} | Tokens: {usage['total_tokens']:,}")
    if usage.get("total_cost_usd"):
        print(f"    Estimated cost: ${usage['total_cost_usd']:.4f}")
    elif usage.get("cost_unknown"):
        print("    Estimated cost: unknown (no pricing for this model)")

    return {
        "module": "ai_analyze_gowitness",
        "status": "success",
        "findings_count": len(findings),
        "critical_count": critical_count,
        "high_count": high_count,
        "json_output": json_path,
        "report_output": report_path,
    }
