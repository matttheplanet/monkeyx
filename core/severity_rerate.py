"""MonkeyX severity re-rating.

Some tools (notably nuclei) rate genuinely serious exposures as info/low because
the *template* only "detects" a condition — e.g. `credentials-disclosure` (an
API key visible in a response) ships as info. Passed through unchanged, those
findings get buried and a severity-sorted consumer (or the API
`/findings?severity=high`) misses them entirely; on the Hyatt run they only
reached the deliverable because the AI pass happened to rescue them.

This module re-rates a curated ALLOWLIST of under-rated claims to a severity
floor, ELEVATE-ONLY (never lowers a tool that already rated it higher). The
original tool rating is always preserved separately (see scan.db
`original_severity`), and every elevation carries a reason, so the change is
transparent and auditable — a reviewer can always see what the tool said.

Keyed on the finding's ``claim`` (for nuclei that is the template-id; for bbot a
short event slug; for NSE the script id), so it works across tools. The list is
deliberately small and high-confidence — this is not a blanket inflator.
"""

from __future__ import annotations

_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


# claim (lowercased) -> (severity_floor, reason). Only add entries where the tool
# systematically UNDER-rates a real, actionable exposure.
_RULES: dict[str, tuple[str, str]] = {
    # --- credential / secret exposure (nuclei ships these as info) ---
    "credentials-disclosure": ("high", "Credential/API key exposed in response"),
    "aem-userinfo-servlet": ("high", "AEM UserInfo servlet exposes credentials"),
    "exposed-service-account": ("high", "Service-account credential exposed"),
    # --- access-control bypass ---
    "xff-403-bypass": ("medium", "X-Forwarded-For header bypasses a 403 (access control)"),
    "403-bypass": ("medium", "403 access-control bypass"),
    # --- unauthenticated state-changing / cache abuse ---
    "unauthenticated-varnish-cache-purge": ("medium", "Unauthenticated Varnish cache purge"),
    # --- exposed source control / backups (often info/low templates) ---
    "git-config": ("high", "Exposed .git config — source code / secrets disclosure"),
    "git-exposure": ("high", "Exposed .git repository — source code disclosure"),
    # --- subdomain takeover (bbot/baddns dangling records) ---
    "baddns": ("high", "Dangling DNS record — possible subdomain takeover"),
    "baddns_direct": ("high", "Dangling DNS record — possible subdomain takeover"),
    "baddns_zone": ("high", "Dangling DNS zone — possible takeover"),
    "subdomain-takeover": ("high", "Possible subdomain takeover"),
}


def rerate(claim: str | None, tool_severity: str | None):
    """Return (effective_severity, source, reason).

    ``source`` is ``"monkeyx_rule"`` and ``reason`` is set only when a rule
    ELEVATES the rating above the tool's; otherwise ``("<tool_severity>", "tool",
    None)``. Never downgrades — a tool that already rated it higher wins.
    """
    tool = (tool_severity or "info").lower()
    rule = _RULES.get((claim or "").strip().lower())
    if not rule:
        return tool, "tool", None
    floor, reason = rule
    if _SEV_RANK.get(floor, 0) > _SEV_RANK.get(tool, 0):
        return floor, "monkeyx_rule", reason
    return tool, "tool", None
