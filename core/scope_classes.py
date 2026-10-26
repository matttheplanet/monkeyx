"""Module scope classification — the authorization ceiling each module needs.

This is the single, auditable source of truth for the input-channel scope model
(see docs). Every module is classified by WHAT IT ACTUALLY TOUCHES on the wire,
not by which target string it is handed:

  - HOST  — probes an address (IP:port). Ports, service sweeps, and any
            name-blind protocol (SSH, SNMP, raw SMTP, masscan/nmap/naabu).
            On a shared IP this reaches co-tenants, so a HOST module may only
            run against fully-authorized targets: the operator's `-t` assets and
            derived assets whose resolved IP falls inside a `-t` range.
  - NAME  — addresses a named service that the protocol routes by name (HTTP
            Host header, HTTPS/TLS SNI). On a shared IP the request still lands
            on the client's tenant, so a NAME module is safe against `-d`/`-url`
            names even on shared infrastructure. WEB-ONLY: a module is NAME only
            if the name travels to the server on every connection.
  - PASSIVE — no target contact (OSINT via third parties, local analysis,
            reporting). Always allowed.

Fail-safe default: a module NOT listed here (and with no module-level
SCOPE_CLASS override) is treated as HOST — the dangerous class — so a newly
added scanning module can never silently gain name-safe privileges.

`ENUM_MODULES` is an ORTHOGONAL tag (not a fourth class): a subdomain-discovery
module is still NAME-class for scope gating, but is additionally suppressible
via `--no-subdomain-enum`.
"""

SCOPE_HOST = "host"
SCOPE_NAME = "name"
SCOPE_PASSIVE = "passive"

_VALID_CLASSES = (SCOPE_HOST, SCOPE_NAME, SCOPE_PASSIVE)

# --- HOST: touches an address; requires -t authorization -------------------
# Port scanners / sweeps and name-blind service probes. On shared infra these
# reach whatever else lives on the IP, so they are confined to -t (and derived
# assets that resolve into a -t range).
_HOST_MODULES = frozenset({
    "ax_nmap_tcp", "ax_nmap_udp", "ax_nmap_quick_web",
    "ax_masscan", "ax_naabu",
    "ax_live_host_discovery",
    "dns_resolve",          # reads the target file as IPs/hosts to resolve
    # Name-blind service audits: they open a socket to the resolved IP:port.
    # A hostname argument does NOT make these name-safe (no Host/SNI routing).
    "ssh_audit_scan",
    "snmp_sweep",
    "smtp_security",
    # ax_nuclei scans web URLs (name-safe) AND raw IP:port service endpoints
    # (name-blind). The IP:port surface makes it HOST; its url_file is never
    # remapped (not a _HOST_SCOPED_FILES key), so web coverage stays full while
    # the engine restricts its open_ports_file to -t-authorized IPs.
    "ax_nuclei",
    # Bare-IP enrichment / lookups keyed on the resolved address.
    "shodan_enrich",
})

# --- NAME: web-only, routed to the tenant by Host/SNI ----------------------
_NAME_MODULES = frozenset({
    # HTTP(S) probing / crawling / screenshots — all addressed by URL/host.
    "ax_httpx", "ax_gowitness", "ax_katana",
    "ax_ffuf", "ax_feroxbuster",
    "ax_testssl", "ax_wafw00f",         # TLS/WAF fingerprint via SNI on the vhost
    "ax_gau", "ax_subjs", "ax_linkfinder", "ax_arjun",
    "ax_wpscan", "ax_corsy", "ax_mantra",
    # DNS / subdomain discovery — operate on names, never sweep an address.
    "dnsx_resolve", "dns_security",
    "subfinder", "ax_subfinder", "ax_amass", "ax_puredns_bruteforce",
    # bbot name/domain-scoped pipelines.
    "bbot_passive", "bbot_code", "bbot_cloud", "bbot_takeover",
    "bbot_recon",
    # Invasive web modules — NAME-class for scope gating (they address by
    # name/URL over HTTP), but INVASIVE_MODULES additionally requires the
    # caller to gate them behind an explicit opt-in.
    "ax_dalfox", "bbot_dast",
})

# --- PASSIVE: no target contact --------------------------------------------
_PASSIVE_MODULES = frozenset({
    "normalize", "analyze", "ai_analyze", "ai_analyze_gowitness",
    "focus", "jsonl_to_csv", "nmap_converter",
    "html_report", "summary", "nessus_import",
})

# --- INVASIVE: active exploitation; explicit opt-in regardless of channel ---
# These are NAME-addressed but perform state-changing/exploitation actions, so
# being in -d is NOT sufficient to run them; they require an explicit opt-in
# (handled by the caller). Listed here so callers can identify them.
INVASIVE_MODULES = frozenset({
    "ax_dalfox",     # active XSS
    "bbot_dast",     # SQLi/XSS/SSRF/SSTI/CMDi fuzzing
})

# --- ENUM: subdomain discovery; suppressible via --no-subdomain-enum -------
# Orthogonal tag. These remain NAME-class for scope gating.
ENUM_MODULES = frozenset({
    "subfinder", "ax_subfinder", "ax_amass", "ax_puredns_bruteforce",
    "bbot_passive",   # passive subdomain discovery via CT/OSINT sources
})

# ai_validate spawns an agent that runs multiple tools per finding, so its real
# ceiling is enforced per-command inside the agent (see modules/ai_validate.py
# _is_safe_command). For whole-module gating it is deliberately HOST (fail-safe):
# it can invoke nmap/netcat/etc., so it must never be treated as name-safe.
_HOST_AGENT_MODULES = frozenset({"ai_validate"})

# Import-time helper functions that _discover_modules re-registers as phantom
# "modules" because they are imported (not defined) into real module files
# (run_ax_module in _ax_common, run_bbot_flags/run_bbot_modules in
# _bbot_common). They are never independently selectable; excluded from the
# classification-coverage assertion. Not a scope decision.
_DISCOVERY_HELPER_PHANTOMS = frozenset({
    "ax_module", "bbot_flags", "bbot_modules",
})


def scope_class(module_name: str, module_obj=None) -> str:
    """Return the scope class for a module.

    Resolution order:
      1. A module-level ``SCOPE_CLASS`` attribute override, if valid.
      2. The registry above.
      3. Fail-safe default: HOST.
    """
    if module_obj is not None:
        override = getattr(module_obj, "SCOPE_CLASS", None)
        if override in _VALID_CLASSES:
            return override
    if module_name in _PASSIVE_MODULES:
        return SCOPE_PASSIVE
    if module_name in _NAME_MODULES:
        return SCOPE_NAME
    if module_name in _HOST_MODULES or module_name in _HOST_AGENT_MODULES:
        return SCOPE_HOST
    return SCOPE_HOST


def is_enum_module(module_name: str) -> bool:
    """True if the module performs subdomain enumeration (suppressible)."""
    return module_name in ENUM_MODULES


def is_invasive_module(module_name: str) -> bool:
    """True if the module performs active exploitation (explicit opt-in only)."""
    return module_name in INVASIVE_MODULES
