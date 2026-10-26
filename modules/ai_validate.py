"""AI-driven validation of findings from ai_analyze.

⚠️ EXPERIMENTAL — opt-in only (never in a built-in workflow; run via
`-m ai_validate` or `--rebuttal`). The agentic validation loop is unreliable:
verdicts can be wrong in either direction, so treat them as leads to review, not
ground truth. Not recommended for unattended use. This is why it is NOT part of
the default `standard`/`deep`/`fast` pipelines.

Uses Claude API tool_use to run an agentic loop: for each finding from the
exploitation playbooks, an AI agent picks validation commands, observes their
output, and issues a verdict (confirmed/refuted/unclear).

Inputs:  {prefix}-ai-analysis.json (from ai_analyze)
Outputs: {prefix}-validated-findings.json
         {prefix}-validation-report.md
"""

import json
import logging
import os
import re
import time
from ipaddress import ip_address

from core.credentials import get_ai_provider
from core.ai_provider import resolve_cost_rates, display_model_name, log_ai_interaction
from core.utils import version_output_path
from core import scan_db, tool_runners, attack_policy
from modules.normalize import _claim_for

logger = logging.getLogger("monkeyx.modules.ai_validate")

REQUIRED_INPUTS = frozenset()

# Claim tokens as they appear in ai_analyze's prose: a leading/inline
# [template-id] bracket (e.g. "[phpmyadmin-panel]") or a bare CVE id.
_BRACKET_TOKEN = re.compile(r"\[([A-Za-z0-9][\w.\-]*)\]")
_CVE_TOKEN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

# ---------------------------------------------------------------------------
# Tool definitions (Claude API tool_use schema)
# ---------------------------------------------------------------------------

TOOLS = [
    {
        "name": "curl_request",
        "description": "Make an HTTP/HTTPS request. Use for checking web services, default creds, response inspection.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Full URL to request"},
                "method": {"type": "string", "enum": ["GET", "HEAD", "POST", "PUT", "OPTIONS"], "description": "HTTP method"},
                "headers": {"type": "object", "description": "Key-value headers to send", "additionalProperties": {"type": "string"}},
                "data": {"type": "string", "description": "Request body (for POST/PUT)"},
                "follow_redirects": {"type": "boolean", "description": "Ignored — redirects are never auto-followed; the response shows any 3xx Location, request that URL separately (it will be scope-checked)."},
            },
            "required": ["url"],
        },
    },
    {
        "name": "nmap_scan",
        "description": "Run nmap against a specific target. Use for service detection, script scanning, version checks.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "IP or hostname to scan"},
                "ports": {"type": "string", "description": "Port specification (e.g. '80,443' or '1-1000')"},
                "scripts": {"type": "string", "description": "NSE scripts to run (e.g. 'http-title,ssl-cert')"},
                "flags": {"type": "string", "description": "Additional nmap flags (e.g. '-sV -sC')"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "nuclei_scan",
        "description": "Run nuclei templates against a target URL. Use for CVE validation, misconfig detection.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "URL or host to scan"},
                "templates": {"type": "string", "description": "Template IDs (e.g. 'CVE-2022-0543') or template file/dir paths, comma-separated. IDs are matched with -id, paths with -t."},
                "tags": {"type": "string", "description": "Template tags to filter (e.g. 'cve,misconfig')"},
                "severity": {"type": "string", "description": "Severity filter (e.g. 'critical,high')"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "testssl_check",
        "description": "Run testssl.sh against a TLS service. Use for SSL/TLS misconfiguration validation.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "host:port to check"},
                "checks": {"type": "string", "description": "Specific checks (e.g. '--vulnerable --protocols')"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "dig_lookup",
        "description": "DNS lookup. Use for zone transfer attempts, record enumeration.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Domain or IP to query"},
                "record_type": {"type": "string", "description": "Record type (A, AAAA, MX, TXT, AXFR, NS, SOA)"},
                "server": {"type": "string", "description": "DNS server to query (@server)"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "openssl_connect",
        "description": "Connect to a TLS service and inspect the certificate/handshake.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "host:port to connect to"},
                "command": {"type": "string", "description": "openssl subcommand (s_client, x509, etc.)"},
                "flags": {"type": "string", "description": "Additional flags"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "ssh_audit",
        "description": "Audit SSH configuration. Use for weak algorithms, old versions.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "host or host:port"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "netcat_banner",
        "description": "Grab a service banner via netcat. Use for raw protocol inspection.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "host"},
                "port": {"type": "integer", "description": "port number"},
                "send_data": {"type": "string", "description": "Data to send after connecting (optional)"},
            },
            "required": ["target", "port"],
        },
    },
    {
        "name": "whatweb_scan",
        "description": "Fingerprint web technologies on a target URL.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "URL to fingerprint"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "ffuf_fuzz",
        "description": "Fuzz a URL for directory/file discovery. Use for finding hidden endpoints.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "URL with FUZZ keyword (e.g. http://host/FUZZ)"},
                "wordlist": {"type": "string", "description": "Path to wordlist"},
                "filter_codes": {"type": "string", "description": "Status codes to filter out (e.g. '404,403')"},
                "extensions": {"type": "string", "description": "File extensions to try (e.g. 'php,html,txt')"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "snmp_check",
        "description": "Check SNMP access with common community strings.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "IP to check"},
                "community": {"type": "string", "description": "Community string to try (default: public)"},
                "version": {"type": "string", "enum": ["1", "2c", "3"], "description": "SNMP version"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "smb_check",
        "description": "Check SMB configuration (signing, null session, shares).",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "IP to check"},
                "check_type": {"type": "string", "enum": ["signing", "shares", "null_session", "version"], "description": "What to check"},
            },
            "required": ["target"],
        },
    },
]

# Every tool takes an optional `purpose`: a one-sentence, plain-language
# explanation of what THIS step checks and why, so the validation report can
# explain each step rather than just listing the command. Injected uniformly
# here (DRY) rather than repeated in every schema. `_build_command` reads its
# argv via explicit `.get()` of known keys, so this extra field never reaches
# the shell.
for _t in TOOLS:
    _t["input_schema"]["properties"]["purpose"] = {
        "type": "string",
        "description": (
            "One sentence, plain language: what this step checks and why it "
            "moves the verdict forward. Always include it."
        ),
    }
del _t

# Tool names for quick lookup
TOOL_NAMES = {t["name"] for t in TOOLS}

# Per-tool scope class (input-channel model — see core/scope_classes.py).
# HOST-touching tools open a socket to the resolved IP:port (name-blind), so on
# shared infra they reach co-tenants — allowed ONLY against -t-authorized
# targets. NAME-safe tools address the service by hostname (HTTP Host / TLS SNI)
# or query DNS, so they are safe against -d/-url names on shared infra.
# Anything unlisted defaults to HOST (fail-safe).
_HOST_TOUCHING_TOOLS = frozenset({
    "nmap_scan", "netcat_banner", "snmp_check", "smb_check",
    "ssh_audit", "openssl_connect", "testssl_check",
})
_NAME_SAFE_TOOLS = frozenset({
    "curl_request", "nuclei_scan", "dig_lookup", "whatweb_scan", "ffuf_fuzz",
})


def _tool_is_host_touching(tool_name: str) -> bool:
    """True if the tool probes an address (name-blind) — gate to -t only.

    Fail-safe: a tool not explicitly listed as name-safe is treated as
    host-touching, so a newly added tool can't silently gain name-safe reach.
    """
    return tool_name not in _NAME_SAFE_TOOLS

# ---------------------------------------------------------------------------
# Safety layer
# ---------------------------------------------------------------------------

# The destructive/exfil/persistence/reverse-shell/cred-spray denylist ("bad
# attacks library") lives in core.attack_policy so it is a single, categorized,
# operator-extensible source shared with future AI-driven components (and the
# complementary proxy-container network layer). _is_safe_command delegates the
# command-content check to attack_policy.check_command().

MAX_RUNTIME_PER_CMD = 45
MAX_ATTEMPTS_PER_FINDING = 6          # per-finding tool-call budget (default)
# "unlimited" maps to this finite ceiling: each command is already bounded by
# MAX_RUNTIME_PER_CMD, but a truly unbounded loop would burn unlimited time/
# tokens on a single finding, so cap it.
_ATTEMPTS_UNLIMITED = 40
MAX_FINDINGS_TO_VALIDATE = 25


def _resolve_max_attempts(value) -> int:
    """Resolve the per-finding attempt budget. An explicit positive int is
    honored as-is (it's the operator's cost); 'unlimited'/'none'/0/negative map
    to the finite _ATTEMPTS_UNLIMITED ceiling; anything unparseable -> default 6."""
    if isinstance(value, str) and value.strip().lower() in ("unlimited", "none", "0"):
        return _ATTEMPTS_UNLIMITED
    try:
        n = int(value)
    except (TypeError, ValueError):
        return MAX_ATTEMPTS_PER_FINDING
    return _ATTEMPTS_UNLIMITED if n <= 0 else n

# ffuf's wordlist is a file path the model can set. Restrict it to known
# wordlist roots so a prompt-injected agent can't point it at /etc/passwd,
# ~/.ssh/id_rsa, ~/.aws/credentials, etc. and exfiltrate the file's contents
# as fuzz values to an in-scope (possibly attacker-controlled) target.
_DEFAULT_WORDLIST = "/usr/share/seclists/Discovery/Web-Content/common.txt"
_ALLOWED_WORDLIST_ROOTS = ("/usr/share/seclists", "/home/op/lists", "/usr/share/wordlists")


def _safe_wordlist(path: str | None) -> str:
    """Return an allowlisted wordlist path, or the safe default.

    Rejects any path (after resolving symlinks/`..`) not under an allowed root,
    preventing the model from reading arbitrary local files via ffuf -w.
    """
    if not path:
        return _DEFAULT_WORDLIST
    try:
        resolved = os.path.realpath(path)
    except OSError:
        return _DEFAULT_WORDLIST
    for root in _ALLOWED_WORDLIST_ROOTS:
        root_real = os.path.realpath(root)
        if resolved == root_real or resolved.startswith(root_real + os.sep):
            return path
    logger.warning("ffuf wordlist %r outside allowed roots — using default", path)
    return _DEFAULT_WORDLIST


# Model-controlled free-text option fields (nmap flags/scripts, testssl checks,
# openssl flags) are split into argv. shell=False stops shell metacharacters
# from mattering, but the OPTIONS themselves are still dangerous: an output
# flag (nmap -oN, testssl --logfile) writes tool output to an arbitrary path
# the process can write (a shell profile -> RCE, or clobbering files), and NSE
# script categories like exploit/dos/brute are actively destructive — both
# contradict the module's read-only, non-destructive contract. These reach the
# agent from untrusted scan data, so they must be constrained here.
#
# A command containing a disallowed option is rejected wholesale (fail closed)
# rather than silently stripped, so the attempt is visible to the operator.

# Sentinel argv[0] that _is_safe_command always rejects (same fail-closed idiom
# as the \x00 host sentinels in _extract_targets_from_argv). The second element
# carries the human-readable reason for logging.
_BLOCKED_OPTION_SENTINEL = "\x00blocked-option"

# NSE script names / categories that are state-changing or actively abusive.
# Gated behind allow_intrusive (operator opt-in), matching the protocol-hint tiers.
_INTRUSIVE_NSE = frozenset({
    "dos", "exploit", "brute", "intrusive", "malware", "vuln-exploit",
})

# Intrusive/abusive substrings that appear in NSE *script names* whose category
# isn't visible from the name's leading segment (e.g. "http-slowloris" splits to
# "http", "smb-flood" to "smb"). Matched anywhere in the script name.
_INTRUSIVE_NSE_NAME_KEYWORDS = (
    "slowloris", "flood", "dos", "brute", "exploit", "malware", "backdoor",
)


def _option_is_unsafe(token: str) -> bool:
    """True if an option token can write files, escape scope, or bypass a gate.

    Denies (case-insensitive):
    - any nmap output flag: -oN/-oX/-oG/-oA/-oS and the -o* family
    - long flags whose name ends in 'file' or 'log' (testssl --logfile,
      --jsonfile, --htmlfile, --csvfile; --outfile; --excludefile;
      --script-args-file; generic --*file)
    - shell redirections that survived tokenization (>, >>)
    - nmap target-source flags -iL / -iR: these add scan targets the module
      never scope-checked. -iL <file> reads targets (and any file) from disk;
      -iR <n> scans random INTERNET hosts. Either escapes the engagement scope
      even when an in-scope target is also present, so _is_safe_command's
      per-target check can't catch them.
    - nmap --script* in a free-text flags string: the dedicated `scripts` field
      is the only path that runs through the intrusive-NSE gate
      (_safe_nse_scripts + allow_intrusive). Smuggling `--script exploit` via
      `flags` would run destructive categories with the operator gate bypassed,
      so --script (and --script-args / --script-help) are rejected here — the
      model must use the gated `scripts` field.

    nmap has no benign '-o*' the validation agent needs, so blocking the whole
    family is safe and avoids an incomplete per-flag denylist. These flags are
    likewise meaningless to the testssl/openssl callers, so blocking them across
    every _safe_option_tokens caller is safe.
    """
    t = token.strip().lower()
    if not t:
        return False
    if t.startswith("-o"):
        return True
    if t.startswith(">"):
        return True
    if t.startswith("-il") or t.startswith("-ir"):
        return True
    if t.startswith("--script"):
        return True
    if t.startswith("--"):
        name = t[2:].split("=", 1)[0]
        if name.endswith("file") or name.endswith("log"):
            return True
    return False


def _safe_option_tokens(tokens: list) -> tuple[list, str | None]:
    """Validate a split, model-controlled option string. Returns (tokens, reason).

    reason is None when every token is safe; otherwise it names the offending
    token and the caller must reject the whole command.

    Besides the file-write / scope-escape flags blocked by _option_is_unsafe,
    this rejects a STANDALONE bare positional (a token not starting with '-' and
    not following an option flag): nmap et al. treat positional args as scan
    targets, so `flags="internalhost"` would scan an unlisted host that the
    per-target scope check misses (single-label tokens aren't extracted as
    targets). Option VALUES stay allowed because they follow a flag
    (`-starttls smtp`, `-p 80`, `--dns-servers 8.8.8.8`, `--exclude host.com`) —
    and any IP / multi-label host among them is still extracted and
    scope-checked downstream by _is_safe_command. Residual (documented): a bare
    single-label token right after a value-less boolean flag (`-sV internalhost`)
    still passes — targets belong in the scope-checked `target` field.
    """
    toks = [str(t) for t in tokens]
    for i, tok in enumerate(toks):
        if _option_is_unsafe(tok):
            return toks, f"unsafe option: {tok}"
        if not tok.startswith("-"):
            prev = toks[i - 1] if i > 0 else ""
            if not prev.startswith("-"):
                return toks, f"unexpected positional token in flags: {tok}"
    return toks, None


def _safe_nse_scripts(scripts: str, allow_intrusive: bool) -> tuple[str, str | None]:
    """Validate an nmap --script value. Returns (scripts, reason).

    Rejects intrusive/destructive NSE categories (exploit, dos, brute, ...)
    unless the operator opted in via allow_intrusive. reason is None when safe.
    """
    for part in scripts.split(","):
        name = part.strip().lower()
        if not name:
            continue
        # Match a bare category token or a category used anywhere in a
        # glob/hyphenated name ("exploit*", "dos-*", "ftp-brute"), AND flag
        # named intrusive scripts whose category isn't in the leading segment
        # ("http-slowloris" -> "http", "smb-flood" -> "smb").
        segments = re.split(r"[*\-]", name)
        if not allow_intrusive and (
            name in _INTRUSIVE_NSE
            or any(seg in _INTRUSIVE_NSE for seg in segments)
            or any(kw in name for kw in _INTRUSIVE_NSE_NAME_KEYWORDS)
        ):
            return scripts, f"intrusive NSE script/category: {part.strip()}"
    return scripts, None


def _split_nuclei_selectors(value: str) -> tuple[list[str], list[str]]:
    """Split a comma-separated nuclei template selector into (paths, ids).

    nuclei's ``-t`` takes a template FILE/DIR/URL **path**; a bare template id
    like ``CVE-2022-0543`` is not a path, so ``-t CVE-2022-0543`` makes nuclei
    abort with ``[FTL] no templates provided`` (this silently failed 4/6
    validation calls and flipped a real Redis RCE to "unclear"). The agent
    naturally passes ids, so route path-like tokens (containing a separator or a
    ``.yaml``/``.yml`` suffix) to ``-t`` and everything else to ``-id``.
    """
    paths: list[str] = []
    ids: list[str] = []
    for tok in value.split(","):
        tok = tok.strip()
        if not tok:
            continue
        if "/" in tok or "\\" in tok or tok.lower().endswith((".yaml", ".yml")):
            paths.append(tok)
        else:
            ids.append(tok)
    return paths, ids


def _extract_targets_from_argv(argv: list) -> list[str]:
    """Extract candidate IP/hostname targets from an argv list for scope checking.

    Only argv tokens that actually look like a network target are returned — the
    binary name, option flags (leading '-'), and non-target values (OIDs, ports,
    template names) are skipped. Targets may be bare IPs, hostnames, or embedded
    in a URL (https://host:port/path) or a dig @server argument.
    """
    from urllib.parse import urlparse

    targets: list[str] = []
    for tok in argv[1:]:  # skip argv[0] (the binary name)
        s = str(tok)
        if s.startswith('-'):
            continue  # option flag

        # URL token: use urlparse to get the real host, which correctly discards
        # userinfo. A hand-rolled strip missed `user@host`, so
        # https://x@127.0.0.1/ parsed to no recognizable host and slipped the
        # scope check entirely. Fail closed: if a URL has no parseable host,
        # emit a sentinel so the scope check rejects the command.
        if "://" in s:
            try:
                host = urlparse(s).hostname
            except ValueError:
                host = None
            if not host:
                targets.append("\x00invalid-url-host")  # never in scope -> blocks
                continue
            targets.append(host.rstrip('.'))
            continue

        # dig @server form.
        s = s.lstrip('@')
        # Bare host or host:port (not a URL). Reject an embedded userinfo '@'.
        if '@' in s:
            targets.append("\x00invalid-host")  # userinfo on a bare token -> block
            continue
        # SMB UNC form (smbclient -L //host): strip leading slashes so the host
        # is extracted and scope-checked. Without this it split to "" and was
        # skipped — an unchecked target.
        s = s.lstrip('/')
        s = s.split('/', 1)[0]
        if not s:
            continue
        # Drop a trailing :port from host:port / ip:port (IPv6 literals have >1 colon).
        host = s
        if host.count(':') == 1:
            host = host.split(':')[0]
        # Classify: valid IP, or a hostname whose last label is non-numeric
        # (filters out OIDs like 1.3.6.1.2.1.1 and bare numbers).
        try:
            ip_address(host)
            targets.append(host)
            continue
        except ValueError:
            pass
        labels = host.rstrip('.').split('.')
        if len(labels) >= 2 and re.search(r'[A-Za-z]', labels[-1]) and \
                re.fullmatch(r'[A-Za-z0-9\-.]+', host):
            targets.append(host)
    # NOTE: bare single-label tokens (e.g. `internalhost`, or an option VALUE
    # like a SNMP community) are deliberately NOT emitted as targets here —
    # doing so would misclassify option values and falsely block legitimate
    # commands. The fail-closed guard in _is_safe_command handles the bare
    # single-label *host* attack instead: a network command that extracts NO
    # recognizable target is blocked outright.
    return targets


def _is_in_scope(target_str: str, scope_ips: set, scope_networks: list,
                 scope_hosts: set) -> bool:
    """Check if a target IP or hostname is within scope.

    IPs must match an explicit scope IP or network. Hostnames must appear in the
    ledger-derived in-scope hostname set — hostnames are NOT allowed by default.
    """
    try:
        addr = ip_address(target_str)
    except ValueError:
        # Hostname: only allow if the ledger says it's in scope.
        return target_str.lower().rstrip('.') in scope_hosts
    if str(addr) in scope_ips:
        return True
    for net in scope_networks:
        if addr in net:
            return True
    return False


def _is_safe_command(argv: list, scope_ips: set, scope_networks: list,
                     scope_hosts: set, tool_name: str | None = None,
                     host_scope: tuple | None = None) -> tuple[bool, str]:
    """Validate an argv command against blocklist and scope. Returns (safe, reason).

    Two-tier scope: every command's target must be in the full in-scope set
    (scope_ips/networks/hosts). Additionally, when `tool_name` is host-touching
    (name-blind — nmap/nc/snmp/…), its target must also be -t-authorized, given
    by `host_scope` = (host_ips, host_networks, host_hosts). This blocks a
    host-level probe against a -d/-url-only name on shared infra while still
    allowing name-safe tools (curl/nuclei) to validate that same name.
    """
    # A rejected model-controlled option (see _build_command) produces this
    # sentinel argv; block it and surface the reason.
    if argv and str(argv[0]) == _BLOCKED_OPTION_SENTINEL:
        return False, argv[1] if len(argv) > 1 else "unsafe option"

    # Command-content denylist ("bad attacks library") — destructive / exfil /
    # persistence / reverse-shell / cred-spray patterns, categorized and
    # operator-extensible, in core.attack_policy.
    policy_ok, policy_reason = attack_policy.check_command(argv)
    if not policy_ok:
        return False, policy_reason

    targets = _extract_targets_from_argv(argv)

    # Fail closed: a network tool with no recognizable target slips the scope
    # check entirely (e.g. a bare single-label host, or an option-smuggled
    # `-iL /etc/passwd` with no target token). Require at least one target so
    # the scope check below actually runs. `echo` is the unknown-tool fallback
    # in _build_command and contacts nothing, so it's exempt.
    binary = str(argv[0]) if argv else ""
    if not targets and binary != "echo":
        return False, "no verifiable in-scope target"

    for t in targets:
        if not _is_in_scope(t, scope_ips, scope_networks, scope_hosts):
            return False, f"out of scope: {t}"

    # Channel ceiling: a host-touching tool may only hit -t-authorized targets.
    if tool_name is not None and _tool_is_host_touching(tool_name):
        h_ips, h_nets, h_hosts = host_scope or (set(), [], set())
        for t in targets:
            if not _is_in_scope(t, h_ips, h_nets, h_hosts):
                return False, (f"host-scope: {tool_name} is a host-level probe; "
                               f"{t} is name-safe (-d/-url) only, not -t-authorized")

    return True, ""


# ---------------------------------------------------------------------------
# Tool execution — maps tool_use calls to subprocess commands
# ---------------------------------------------------------------------------

def _build_command(tool_name: str, tool_input: dict,
                   allow_intrusive: bool = False) -> tuple[list, str | None]:
    """Map a Claude tool_use call to an (argv, stdin) pair.

    Returns a command as an argv *list* (never a shell string) plus an optional
    stdin payload. Execution is done with shell=False, so tool inputs are never
    interpreted by a shell. Beyond that, model-controlled option strings are
    allowlisted: output/file-writing flags (nmap -oN, testssl --logfile) and
    intrusive NSE categories (exploit/dos/brute, unless allow_intrusive) are
    rejected. A rejected option yields the _BLOCKED_OPTION_SENTINEL argv, which
    _is_safe_command fails closed on — so untrusted scan data driving the agent
    cannot smuggle a file write or a destructive scan.
    """

    if tool_name == "curl_request":
        method = str(tool_input.get("method", "GET"))
        url = tool_input["url"]
        headers = tool_input.get("headers") or {}
        # Reject CR/LF/NUL in the model-controlled method + header strings: with
        # shell=False they can't reach a shell, but a newline in -X <method> or
        # -H "<k>: <v>" injects extra request lines/headers (request
        # splitting/smuggling) against the in-scope service.
        _ctl = lambda s: any(c in s for c in ("\r", "\n", "\x00"))
        if _ctl(method) or any(_ctl(str(k)) or _ctl(str(v)) for k, v in headers.items()):
            return [_BLOCKED_OPTION_SENTINEL,
                    "CR/LF/NUL not allowed in curl method or headers"], None
        # Never auto-follow redirects. Only the initial URL is scope-checked;
        # curl -L would follow a 3xx to ANY host (e.g. an in-scope target
        # redirecting to http://169.254.169.254/ or http://127.0.0.1/), an SSRF
        # / scope-escape. The agent sees the 3xx + Location and can choose to
        # probe the (scope-checked) destination as a separate request.
        # Restrict to HTTP(S): curl otherwise speaks dict/gopher/file/ldap/…,
        # which reach in-scope services in ways HTTP validation doesn't model.
        argv = ["curl", "-sk", "--proto", "=http,https", "--max-time", "20", "-X", method]
        for k, v in headers.items():
            argv.extend(["-H", f"{k}: {v}"])
        if tool_input.get("data"):
            data = str(tool_input["data"])
            # curl reads a `-d @file` value from the local filesystem — block it
            # (allowlist, not denylist): the model must never turn a request body
            # into an arbitrary local-file read/exfil (e.g. @~/.monkeyx/credentials.yaml,
            # @/proc/self/environ). --data-raw would be needed for a literal '@'.
            if data.lstrip().startswith("@"):
                return [_BLOCKED_OPTION_SENTINEL,
                        "curl -d @<file> (local file read) is not allowed"], None
            argv.extend(["-d", data])
        argv.append(url)
        return argv, None

    elif tool_name == "nmap_scan":
        target = tool_input["target"]
        argv = ["nmap", "--open", "-T4", "--max-retries", "2"]
        if tool_input.get("flags"):
            flag_tokens, reason = _safe_option_tokens(tool_input["flags"].split())
            if reason:
                return [_BLOCKED_OPTION_SENTINEL, reason], None
            argv.extend(flag_tokens)
        else:
            argv.append("-sV")
        if tool_input.get("ports"):
            argv.extend(["-p", tool_input["ports"]])
        if tool_input.get("scripts"):
            scripts, reason = _safe_nse_scripts(tool_input["scripts"], allow_intrusive)
            if reason:
                return [_BLOCKED_OPTION_SENTINEL, reason], None
            argv.extend(["--script", scripts])
        argv.append(target)
        return argv, None

    elif tool_name == "nuclei_scan":
        target = tool_input["target"]
        argv = ["nuclei", "-u", target, "-silent", "-no-color"]
        if tool_input.get("templates"):
            # Route template IDs to -id and paths to -t: nuclei's -t wants a
            # path, so a bare id (CVE-2022-0543) under -t aborts the scan.
            paths, ids = _split_nuclei_selectors(tool_input["templates"])
            if paths:
                argv.extend(["-t", ",".join(paths)])
            if ids:
                argv.extend(["-id", ",".join(ids)])
        if tool_input.get("tags"):
            argv.extend(["-tags", tool_input["tags"]])
        if tool_input.get("severity"):
            argv.extend(["-severity", tool_input["severity"]])
        return argv, None

    elif tool_name == "testssl_check":
        target = tool_input["target"]
        argv = ["testssl", "--quiet", "--color", "0"]
        if tool_input.get("checks"):
            check_tokens, reason = _safe_option_tokens(tool_input["checks"].split())
            if reason:
                return [_BLOCKED_OPTION_SENTINEL, reason], None
            argv.extend(check_tokens)
        argv.append(target)
        return argv, None

    elif tool_name == "dig_lookup":
        target = tool_input["target"]
        argv = ["dig"]
        if tool_input.get("server"):
            argv.append(f"@{tool_input['server']}")
        argv.append(target)
        if tool_input.get("record_type"):
            argv.append(tool_input["record_type"])
        argv.append("+short")
        return argv, None

    elif tool_name == "openssl_connect":
        target = tool_input["target"]
        subcmd = tool_input.get("command", "s_client")
        # Allowlist the subcommand: this tool is "connect to a TLS service and
        # read the cert/ciphers", not arbitrary openssl (enc/req/rsautl/dgst
        # can read or write local files).
        if subcmd not in ("s_client", "x509", "ciphers", "s_time"):
            return [_BLOCKED_OPTION_SENTINEL,
                    f"openssl subcommand not allowed: {subcmd}"], None
        argv = ["openssl", subcmd, "-connect", target]
        if tool_input.get("flags"):
            flag_tokens, reason = _safe_option_tokens(tool_input["flags"].split())
            if reason:
                return [_BLOCKED_OPTION_SENTINEL, reason], None
            argv.extend(flag_tokens)
        if subcmd == "s_client":
            # Auto-terminate after handshake by closing stdin immediately.
            return argv, ""
        return argv, None

    elif tool_name == "ssh_audit":
        target = tool_input["target"]
        return ["ssh-audit", target], None

    elif tool_name == "netcat_banner":
        target = tool_input["target"]
        port = tool_input["port"]
        send = tool_input.get("send_data", "")
        # send_data is passed via stdin (input=), never interpolated into a shell.
        return ["nc", "-w", "5", str(target), str(port)], (send if send else "")

    elif tool_name == "whatweb_scan":
        target = tool_input["target"]
        return ["whatweb", "--color=never", "-q", target], None

    elif tool_name == "ffuf_fuzz":
        url = tool_input["url"]
        # Allowlist the wordlist path — the model must not read arbitrary files.
        wordlist = _safe_wordlist(tool_input.get("wordlist"))
        argv = ["ffuf", "-u", url, "-w", wordlist, "-mc", "all", "-t", "10", "-timeout", "10"]
        if tool_input.get("filter_codes"):
            argv.extend(["-fc", tool_input["filter_codes"]])
        else:
            argv.extend(["-fc", "404"])
        if tool_input.get("extensions"):
            argv.extend(["-e", tool_input["extensions"]])
        return argv, None

    elif tool_name == "snmp_check":
        target = tool_input["target"]
        community = tool_input.get("community", "public")
        version = tool_input.get("version", "2c")
        return ["snmpwalk", f"-v{version}", "-c", community, target, "1.3.6.1.2.1.1"], None

    elif tool_name == "smb_check":
        target = tool_input["target"]
        check = tool_input.get("check_type", "signing")
        if check == "shares":
            return ["smbclient", "-N", "-L", f"//{target}"], None
        elif check == "null_session":
            return ["rpcclient", "-U", "", "-N", target, "-c", "enumdomusers"], None
        elif check == "version":
            return ["nmap", "--script", "smb-protocols", "-p", "445", target], None
        # signing (default)
        return ["nmap", "--script", "smb2-security-mode", "-p", "445", target], None

    return ["echo", f"Unknown tool: {tool_name}"], None


def _shell_join(parts: list) -> str:
    """Render an argv list as a human-readable, safely-quoted string (display/logging only)."""
    import shlex
    return " ".join(shlex.quote(str(p)) for p in parts)


def _execute_command(argv: list, timeout: int = MAX_RUNTIME_PER_CMD, stdin: str | None = None) -> str:
    """Execute a command (argv list, shell=False) with timeout and capture output.

    Thin wrapper over the shared core.tool_runners.run_argv so execution lives in
    one place (also used by the standalone service-audit modules). Behaviour is
    identical — guarded by tests/test_ai_validate_toolrunner_parity.py.
    """
    return tool_runners.run_argv(argv, timeout=timeout, stdin=stdin)


# ---------------------------------------------------------------------------
# Agent loop
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """You are a penetration test validation agent working during an authorized security assessment. You have access to tools that execute on the tester's machine. Your job is to confirm or refute suspected vulnerabilities by running non-destructive verification commands.

For each finding, you will:
1. Review the suspected vulnerability and suggested exploitation steps
2. Choose a tool to validate it (start simple: banner grab, version check, curl)
3. Observe the output
4. Either issue a verdict or try another approach

Rules:
- Non-destructive only. Prove exploitability WITHOUT modifying data or state on the
  target: no writing files, no sending/relaying mail, no SET/write operations, no
  credential spraying. Read-only observation only. If a checklist explicitly labels a
  step "intrusive"/"operator-approved", it will only appear when the operator opted in;
  if it is not present, do NOT perform it or improvise it.
- Never attempt to maintain persistence or pivot to other hosts.
- Goal is PROOF of exploitability — the exact command and output that demonstrates the issue.
- Start with the cheapest/fastest check. Escalate only if needed.
- Before confirming, FALSIFY: ask what benign thing (CDN, WAF, proxy, default page,
  login panel, banner backport) could produce the same evidence, and whether the
  response is from the real origin. Pick the single test that best distinguishes the
  vulnerability from that benign explanation. Do not confirm on a banner/version match
  or a page merely existing.
- If the first check conclusively proves or disproves the finding, stop immediately.
- A tool result beginning with "BLOCKED:" means the command was NOT executed (the
  scope/safety layer refused it) and produced NO evidence. Never treat a blocked step
  as a result or infer its outcome. If EVERY check you attempt is blocked, return an
  "unclear" verdict explaining the target could not be tested within scope — do NOT
  return "confirmed" or "refuted" without at least one command that actually ran.
- Every tool call MUST include a `purpose`: one plain-language sentence saying what
  that step checks and why it moves the verdict forward. This is shown to a human in
  the validation report, so make it self-explanatory (e.g. "Grab the SMTP banner to
  confirm the service and version before testing for open relay").

When you have enough evidence, respond with text (no more tool calls) containing your verdict as JSON:
{"verdict": "confirmed", "evidence": "what proves it", "poc_command": "the single best command that demonstrates the vuln", "severity": "critical|high|medium|low"}
or
{"verdict": "refuted", "evidence": "why it's not exploitable"}
or
{"verdict": "unclear", "evidence": "what you tried and why it's inconclusive"}"""


SYSTEM_PROMPT_CHAIN = """You are a penetration test validation agent working during an authorized security assessment. You have access to tools that execute on the tester's machine. Your job is to validate a suspected ATTACK CHAIN — an ordered sequence of steps, possibly spanning multiple hosts — by walking it step by step with non-destructive verification commands.

A chain is only real if the WHOLE sequence holds. Walk it in order:
1. Verify each step with a tool before moving to the next.
2. Carry forward what you actually confirm — a credential, token, path, or reachable service observed in an earlier step is what unlocks a later one. Use only real observed values, never assumed ones.
3. If an EARLY step cannot be confirmed, the chain is BROKEN downstream — report it refuted/unclear and name the step that failed. Do NOT fabricate or assume success of later steps once a prerequisite fails.

Rules:
- Non-destructive only. Prove reachability/exploitability WITHOUT modifying data or state: no writing files, no sending/relaying mail, no SET/write operations, no credential spraying, no persistence. Read-only observation only. If a checklist labels a step "intrusive"/"operator-approved" and it is not present, do NOT perform or improvise it.
- Never pivot to hosts outside the chain's stated targets.
- Before confirming any step, FALSIFY: what benign thing (CDN, WAF, proxy, default page, banner backport) could produce the same evidence? Pick the test that distinguishes real from benign. Do not confirm on a banner/version match or a page merely existing.
- A tool result beginning with "BLOCKED:" means the command was NOT executed (the scope/safety layer refused it) and produced NO evidence. Never treat a blocked step as a result. If every check you attempt is blocked, return "unclear".
- Every tool call MUST include a `purpose`: one plain-language sentence saying what that step checks and why it moves the chain forward.
- The chain is "confirmed" ONLY if the full sequence is demonstrated with commands that actually ran. If only the first N steps hold, report "refuted" or "unclear" and say how far it got.

When done, respond with text (no more tool calls) containing your verdict as JSON:
{"verdict": "confirmed|refuted|unclear", "evidence": "how far the chain got and what proves/breaks it", "steps": [{"step": 1, "status": "confirmed|failed|skipped", "evidence": "what you observed"}], "poc_command": "the single most decisive command", "severity": "critical|high|medium|low"}"""


def _classify_finding(finding: dict) -> str:
    """Classify a finding into a validator category based on content."""
    action = (finding.get("action") or "").lower()
    target = (finding.get("target") or "").lower()
    commands = " ".join(finding.get("commands") or []).lower()
    combined = f"{action} {target} {commands}"

    if any(k in combined for k in ("ssl", "tls", "cert", "cipher", "testssl")):
        return "crypto"
    if any(k in combined for k in ("smb", "445", "netbios", "rdp", "ldap", "kerberos", "snmp")):
        return "network"
    if any(k in combined for k in ("http", "https", "curl", "web", "api", "nuclei", "nikto", "sqli", "xss")):
        return "web"
    return "web"


# Per-category validation playbooks — the preferred tools and what actually
# constitutes proof for each finding class. Keeps the agent from confirming on
# weak signals (a page existing, a version string) and points it at the check
# that distinguishes real exploitability. Read-only guidance.
_CATEGORY_PLAYBOOKS = {
    "web": (
        "Web validation guidance:\n"
        "- Prefer curl_request (GET/HEAD) to inspect status, headers, redirects, body.\n"
        "- A 200 or a login/panel page EXISTING is not proof — confirm the actual\n"
        "  weakness (auth bypass returns protected data; default creds return an\n"
        "  authenticated response; a template 'detect' only means the tech is present).\n"
        "- Distinguish origin vs CDN/WAF/error pages before concluding."
    ),
    "crypto": (
        "TLS/crypto validation guidance:\n"
        "- Use testssl_check or openssl_connect (read-only handshake) — do not send\n"
        "  application data.\n"
        "- Proof is the negotiated protocol/cipher/cert fact itself (e.g. TLS1.0\n"
        "  offered, expired/self-signed cert, weak cipher accepted), not a scanner label."
    ),
    "network": (
        "Network-service validation guidance:\n"
        "- Confirm the service responds and its security-relevant property directly\n"
        "  (SMB signing not required; anonymous/null session returns data; SNMP read\n"
        "  with a default community returns the tree).\n"
        "- An open port alone is not a finding. Do NOT perform write/state-changing\n"
        "  actions unless an intrusive checklist was explicitly provided."
    ),
}


def _category_playbook(finding: dict) -> str:
    """Return the validation playbook text for a finding's category."""
    return _CATEGORY_PLAYBOOKS.get(_classify_finding(finding), "")


# Protocol validation hints, split by test-safety tier:
#   "safe"      — Tier 0/1: passive / read-only observation (banner, EHLO
#                 capabilities, anonymous LIST, default-community read walk,
#                 SPF/DMARC lookups). Always allowed.
#   "intrusive" — Tier 2/3: state-changing or actively-abusive tests (open-relay
#                 RCPT TO an external recipient = actually relaying mail; SNMP
#                 write with 'private'; FTP STOR = writing a file). These
#                 contradict "non-destructive" and are only included when the
#                 operator opts in (--allow-intrusive-validation).
_PROTOCOL_HINTS = {
    "smtp": {
        "safe": (
            "SMTP validation checklist (read-only):\n"
            "1. Connect and grab banner (netcat port 25/465/587)\n"
            "2. Issue EHLO and check supported extensions (STARTTLS, AUTH, VRFY, EXPN, SIZE)\n"
            "3. Check SPF/DMARC: dig TXT <domain> for v=spf1, dig TXT _dmarc.<domain>\n"
            "4. STARTTLS: check whether STARTTLS is advertised (observe only)\n"
            "Do NOT attempt an open-relay test or send mail — advertised extensions "
            "plus SPF/DMARC posture are enough to flag a likely issue for manual review."
        ),
        "intrusive": (
            "SMTP intrusive checks (operator-approved):\n"
            "- Open relay test: MAIL FROM:<test@attacker.com> then RCPT TO:<test@external-domain.com>; "
            "250 OK on an external RCPT TO indicates an open relay (CRITICAL). NOTE: this actually "
            "relays mail — state-changing.\n"
            "- VRFY/EXPN user enumeration: VRFY root, VRFY admin, EXPN postmaster."
        ),
    },
    "snmp": {
        "safe": (
            "SNMP validation checklist (read-only):\n"
            "1. Try default community strings for READ: public, community\n"
            "2. If accessible, walk the tree to confirm data exposure (system info, interfaces, routes)\n"
            "3. Note the SNMP version — v1/v2c community strings are cleartext\n"
            "Do NOT attempt write access."
        ),
        "intrusive": (
            "SNMP intrusive check (operator-approved):\n"
            "- Test WRITE access with the 'private' community (SET) — state-changing on the device."
        ),
    },
    "ftp": {
        "safe": (
            "FTP validation checklist (read-only):\n"
            "1. Connect and grab banner for version\n"
            "2. Test anonymous login: USER anonymous, PASS anonymous@\n"
            "3. If anonymous succeeds, LIST to check readable content"
        ),
        "intrusive": (
            "FTP intrusive check (operator-approved):\n"
            "- STOR test (upload a file) to distinguish read-only from read-write — "
            "this WRITES to the server, state-changing."
        ),
    },
}


def _get_protocol_hints(finding: dict, allow_intrusive: bool = False) -> str:
    """Return protocol validation guidance for a finding.

    By default only the safe (read-only) checklist is included. Intrusive,
    state-changing steps (open relay, SNMP write, FTP upload) are appended only
    when allow_intrusive is set (operator opt-in via --allow-intrusive-validation).
    """
    action = (finding.get("action") or "").lower()
    target = (finding.get("target") or "").lower()
    commands = " ".join(finding.get("commands") or []).lower()
    combined = f"{action} {target} {commands}"

    matched: list[str] = []

    def _match(proto: str):
        if proto not in matched:
            matched.append(proto)

    for protocol in _PROTOCOL_HINTS:
        if protocol in combined:
            _match(protocol)
    if any(p in combined for p in (":25", ":465", ":587", "port 25", "port 465", "port 587")):
        _match("smtp")
    if any(p in combined for p in (":161", ":162", "port 161")):
        _match("snmp")
    if any(p in combined for p in (":21 ", ":21/", "port 21")):
        _match("ftp")

    hints = []
    for proto in matched:
        entry = _PROTOCOL_HINTS[proto]
        hints.append(entry["safe"])
        if allow_intrusive:
            hints.append(entry["intrusive"])
    return "\n\n".join(hints)


def _extract_host(target: str) -> str | None:
    """Pull the bare host (IP or hostname) from a finding target.

    Handles 'host', 'host:port', and full URLs. Lowercased, no trailing dot.
    """
    from urllib.parse import urlparse
    if not target:
        return None
    t = str(target).strip()
    # The AI sometimes annotates a recommendation target with a trailing
    # parenthetical type hint, e.g. "referral.example.com (domain)" or
    # "1.2.3.4 (ip)". Strip it so the bare host resolves — otherwise the
    # host lookup misses and the validation's finding_id is orphaned.
    t = re.sub(r"\s*\([^)]*\)\s*$", "", t).strip()
    if "://" in t:
        try:
            h = urlparse(t).hostname
            return h.lower().rstrip(".") if h else None
        except ValueError:
            return None
    # host or host:port (IPv6 in [..]:port handled by rsplit on last ':')
    if t.startswith("["):  # [ipv6]:port
        return t[1:].split("]")[0].lower()
    # A bare IP (v4 or v6, no port) IS the host — return it whole so a bare
    # IPv6's own colons aren't mistaken for a port separator.
    try:
        ip_address(t)
        return t.lower()
    except ValueError:
        pass
    # hostname/IPv4 optionally followed by ':port' — or a malformed
    # 'host:port:port' the AI sometimes emits (matched-at treated as host, port
    # re-appended). Host is the first label; the extra ports are noise.
    if ":" in t:
        t = t.split(":", 1)[0]
    return t.lower().rstrip(".") or None


def _extract_port(target: str) -> int | None:
    """Pull the port from a 'host:port' or URL target, if present."""
    from urllib.parse import urlparse
    if not target:
        return None
    t = str(target).strip()
    try:
        if "://" in t:
            p = urlparse(t).port
            return int(p) if p else None
        if t.startswith("[") and "]:" in t:
            return int(t.split("]:")[1].split("/")[0])
        if ":" in t:
            # Bare IPv6 (many colons, no port component) has no port.
            try:
                ip_address(t)
                return None
            except ValueError:
                pass
            # 'host:port' or a malformed 'host:port:port' — the FIRST port after
            # the host is the real service port (the appended one is AI noise).
            return int(t.split(":", 2)[1].split("/")[0])
    except (ValueError, TypeError):
        return None
    return None


def _load_evidence_index(data_prefix: str) -> dict:
    """Build {host: [raw normalized record, ...]} from *-normalized.jsonl.

    This is the ORIGINAL scanner evidence (nuclei template-id/matched-at, nmap
    script output, banners), so validation can reason over source data rather
    than only ai_analyze's prose summary of it.
    """
    import glob
    index: dict[str, list[dict]] = {}
    if not data_prefix:
        return index
    for path in glob.glob(f"{data_prefix}*-normalized.jsonl"):
        try:
            with open(path, encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    host = (rec.get("host") or rec.get("hostname") or "")
                    if isinstance(host, str) and host:
                        index.setdefault(host.lower().rstrip("."), []).append(rec)
        except OSError:
            continue
    return index


def _evidence_for_finding(finding: dict, index: dict, max_records: int = 12) -> list[dict]:
    """Return compact raw scanner records matching a finding's host.

    Prefers records on the finding's port (when the target names one), then
    fills with other host records. Each record is trimmed to the fields useful
    for validation reasoning.
    """
    if not index:
        return []
    host = _extract_host(finding.get("target", ""))
    if not host or host not in index:
        return []
    port = _extract_port(finding.get("target", ""))
    records = index[host]
    if port is not None:
        same_port = [r for r in records if r.get("port") == port]
        other = [r for r in records if r.get("port") != port]
        ordered = same_port + other
    else:
        ordered = list(records)

    compact = []
    for r in ordered[:max_records]:
        c = {
            "tool": r.get("tool"),
            "type": r.get("type"),
            "severity": r.get("severity"),
            "port": r.get("port"),
            "title": r.get("title"),
        }
        detail = r.get("detail")
        if detail:
            c["detail"] = str(detail)[:500]
        for k in ("template-id", "matched-at", "template", "cves"):
            if r.get(k):
                c[k] = r[k]
        compact.append({k: v for k, v in c.items() if v is not None})
    return compact


def _finding_claim_tokens(finding: dict) -> set[str]:
    """Claim tokens the recommendation mentions: [bracketed] ids + CVE ids.

    ai_analyze reliably echoes the source template id in brackets and CVE ids
    inline (e.g. "Nuclei template [CVE-2019-9874] matched", "[phpmyadmin-panel]
    detected"). We scan action + evidence + commands. Lowercased for matching.
    """
    text_parts = [str(finding.get("action") or ""), str(finding.get("evidence") or "")]
    cmds = finding.get("commands")
    if isinstance(cmds, list):
        text_parts.extend(str(c) for c in cmds)
    elif cmds:
        text_parts.append(str(cmds))
    text = "\n".join(text_parts)
    tokens = {m.group(1).lower() for m in _BRACKET_TOKEN.finditer(text)}
    tokens |= {m.group(0).lower() for m in _CVE_TOKEN.finditer(text)}
    return tokens


def _match_finding_ids(finding: dict, index: dict) -> list[str]:
    """Resolve a validated recommendation to concrete finding_id(s).

    The exact join: recompute finding_id from the SAME raw normalized record
    normalize minted from, so identical inputs -> identical hash -> the exact
    findings row. Resolution order:
      1. Claim token in the recommendation matches a raw record's claim/cve on
         the finding's (host, port) -> those records' ids (may be several).
      2. No token, but exactly one raw finding-type record on (host, port) -> it.
      3. Otherwise -> [] (ambiguous; caller records a NULL-join validation).
    """
    host = _extract_host(finding.get("target", ""))
    if not host or host not in index:
        return []
    port = _extract_port(finding.get("target", ""))
    records = index[host]
    # Restrict to the finding's port when named; findings-type records only.
    scoped = [r for r in records if r.get("type") in scan_db.FINDING_TYPES
              and (port is None or r.get("port") == port)]
    if not scoped:
        return []

    def _fid(rec):
        return scan_db.finding_id(
            rec.get("host") or rec.get("hostname"), rec.get("port"),
            rec.get("proto"), _claim_for(rec))

    tokens = _finding_claim_tokens(finding)
    if tokens:
        matched = []
        for rec in scoped:
            claim = (_claim_for(rec) or "").lower()
            cve = (rec.get("cve_id") or "").lower()
            if (claim and claim in tokens) or (cve and cve in tokens):
                fid = _fid(rec)
                if fid not in matched:
                    matched.append(fid)
        if matched:
            return matched

    # No token match: only trust an unambiguous single record.
    if len(scoped) == 1:
        return [_fid(scoped[0])]
    return []


def _prioritize_findings(recommendations: dict) -> list[dict]:
    """Flatten and prioritize findings from ai_analyze recommendations."""
    findings = []

    for item in (recommendations.get("quick_wins") or []):
        if isinstance(item, dict):
            item["_priority"] = 1
            item["_category"] = "quick_win"
            findings.append(item)

    for item in (recommendations.get("attack_chains") or []):
        if isinstance(item, dict):
            item["_priority"] = 2
            item["_category"] = "attack_chain"
            findings.append(item)

    for item in (recommendations.get("requires_verification") or []):
        if isinstance(item, dict):
            item["_priority"] = 3
            item["_category"] = "requires_verification"
            findings.append(item)

    for item in (recommendations.get("cve_research") or []):
        if isinstance(item, dict):
            item["_priority"] = 4
            item["_category"] = "cve_research"
            findings.append(item)

    return findings


def _create_anthropic_client(config: dict):
    """Create the appropriate Anthropic client (direct API or Bedrock)."""
    import anthropic

    aws_region = config.get("aws_region")
    if aws_region:
        return anthropic.AnthropicBedrock(aws_region=aws_region)

    api_key = config.get("api_key")
    if not api_key:
        raise ValueError("Anthropic API key not configured (set api_key or aws_region for Bedrock)")
    return anthropic.Anthropic(api_key=api_key)


def _egress_response_text(response) -> str:
    """A readable render of an agent turn's response for the egress log."""
    parts = []
    for block in getattr(response, "content", []) or []:
        btype = getattr(block, "type", None)
        if btype == "text":
            parts.append(getattr(block, "text", ""))
        elif btype == "tool_use":
            parts.append(f"[tool_use {getattr(block, 'name', '?')}] "
                         f"{json.dumps(getattr(block, 'input', {}), default=str)}")
    return "\n".join(parts)


def _run_agent_loop(finding: dict, scope_ips: set, scope_networks: list,
                    scope_hosts: set, config: dict, model: str,
                    kb_max_tokens: int = 2000, allow_intrusive: bool = False,
                    raw_evidence: list | None = None,
                    host_scope: tuple | None = None,
                    logs_dir: str | None = None,
                    egress_counter: list | None = None,
                    max_attempts: int = MAX_ATTEMPTS_PER_FINDING) -> dict:
    """Run the Claude tool_use agent loop for one finding.

    `host_scope` = (ips, networks, hosts) of -t-authorized targets; host-touching
    tools are gated to it (see _is_safe_command). None => empty (host tools
    blocked entirely, fail-safe).

    Every turn is an external AI call; `logs_dir`/`egress_counter` (a shared
    mutable [int]) record each one in logs/ai-interactions.log so the shipped
    egress log accounts for ai_validate's calls, not just ai_analyze's.
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

    target = finding.get("target", "unknown")
    action = finding.get("action", "unknown")
    commands = finding.get("commands") or []
    expected = finding.get("expected_result", "")
    evidence = finding.get("evidence", "")
    notes = finding.get("notes", "")

    # Attack chains are validated as an ORDERED SEQUENCE in one agent context so
    # evidence confirmed at step 1 (a cred/token/reachable service) carries into
    # step 2 — instead of each step being a disconnected single-finding check.
    # The tool-execution/scope/verdict machinery below is identical either way;
    # only the framing prompt + seed differ.
    is_chain = (finding.get("_category") == "attack_chain")
    system_prompt = SYSTEM_PROMPT_CHAIN if is_chain else SYSTEM_PROMPT

    if is_chain:
        steps_text = "\n".join(f"  {i}. {c}" for i, c in enumerate(commands, 1)) \
            or "  (no explicit steps listed — infer the sequence from the description)"
        user_msg = (
            f"Validate this ATTACK CHAIN by walking its steps IN ORDER:\n\n"
            f"Target(s): {target}\n"
            f"Chain: {action}\n"
            f"Confidence / impact: {finding.get('confidence', '?')} / {finding.get('impact', '?')}\n"
            f"AI-summarized evidence: {evidence}\n"
            f"Chain steps (in order):\n{steps_text}\n"
            f"Expected end state if the chain holds: {expected}\n"
        )
    else:
        user_msg = (
            f"Validate this suspected vulnerability:\n\n"
            f"Target: {target}\n"
            f"Finding: {action}\n"
            f"AI-summarized evidence: {evidence}\n"
            f"Suggested commands: {json.dumps(commands)}\n"
            f"Expected result if vulnerable: {expected}\n"
        )
    if notes:
        user_msg += f"Notes: {notes}\n"

    # Original scanner records for this host — the underlying evidence the
    # ai_analyze summary above was derived from. Reason over THIS, not just the
    # summary; if the raw records don't support the claim, lean toward refuting.
    if raw_evidence:
        user_msg += (
            "\n--- Raw scanner evidence for this host (source of truth) ---\n"
            + json.dumps(raw_evidence, indent=1)
            + "\n---\n"
        )

    playbook = _category_playbook(finding)
    if playbook:
        user_msg += f"\n--- Validation playbook ({_classify_finding(finding)}) ---\n{playbook}\n---\n"

    protocol_hints = _get_protocol_hints(finding, allow_intrusive=allow_intrusive)
    if protocol_hints:
        user_msg += f"\n--- Protocol-specific checks ---\n{protocol_hints}\n---\n"

    kb_references: list[dict] = []
    try:
        from core.knowledge import retrieve_with_refs as kb_retrieve_with_refs
        kb_terms = [t for t in [
            action.split()[0].lower() if action else None,
            finding.get("service"),
            finding.get("protocol"),
        ] if t]
        kb_port = None
        import re as _re
        port_match = _re.search(r"(?:\]:|\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:)(\d+)", target)
        if not port_match:
            port_match = _re.search(r":(\d{2,5})(?:/|$|\s)", target)
        if port_match:
            kb_port = int(port_match.group(1))
        kb_text, kb_references = kb_retrieve_with_refs(
            query_terms=kb_terms, port=kb_port, max_tokens=kb_max_tokens)
        if kb_text:
            user_msg += f"\n{kb_text}\n"
    except Exception as e:
        logger.debug("Knowledge base retrieval skipped: %s", e)

    if is_chain:
        user_msg += (
            "\nBegin. Verify each step in order with a tool, carrying forward what you "
            "confirm. If an early step can't be confirmed, the chain is broken — say which "
            "step failed and stop. Start with step 1's cheapest check."
        )
    else:
        user_msg += (
            f"\nBegin validation. Use the available tools to confirm or refute this finding. "
            f"Start with the simplest check."
        )

    messages = [{"role": "user", "content": user_msg}]
    attempts = 0
    tool_history = []
    usage_input = 0
    usage_output = 0

    while attempts < max_attempts:
        # Record the egress BEFORE the call — the full conversation is re-sent
        # each turn; the last message is the new content this turn adds.
        last = messages[-1]["content"] if messages else ""
        _log_egress("request",
                    system_prompt if attempts == 0 else None,
                    last if isinstance(last, str) else json.dumps(last, default=str))
        try:
            with client.messages.stream(
                model=model,
                max_tokens=2048,
                system=system_prompt,
                tools=TOOLS,
                messages=messages,
            ) as _stream:
                response = _stream.get_final_message()
        except Exception as e:
            logger.error("Claude API error during validation: %s", e)
            return {
                "verdict": "error",
                "evidence": f"API error: {e}",
                "finding": finding,
                "tool_history": tool_history,
                "kb_references": kb_references,
                "_usage": {"input_tokens": usage_input, "output_tokens": usage_output, "calls": attempts},
            }

        if hasattr(response, "usage"):
            usage_input += getattr(response.usage, "input_tokens", 0)
            usage_output += getattr(response.usage, "output_tokens", 0)

        _log_egress("response", None, _egress_response_text(response))

        tool_use_blocks = [b for b in response.content if b.type == "tool_use"]
        text_blocks = [b for b in response.content if b.type == "text"]

        if not tool_use_blocks:
            # Final answer — parse verdict from text
            final_text = " ".join(b.text for b in text_blocks)
            verdict = _parse_verdict(final_text)
            # A confirmed/refuted verdict must rest on a command that actually
            # ran; if every step was blocked (or none ran), downgrade to unclear.
            _guard_verdict(verdict, tool_history)
            verdict["finding"] = finding
            verdict["tool_history"] = tool_history
            verdict["kb_references"] = kb_references
            verdict["_usage"] = {"input_tokens": usage_input, "output_tokens": usage_output, "calls": attempts + 1}
            return verdict

        # The model's free-text reasoning for THIS turn precedes its tool calls;
        # capture it so the report can explain why each step was run, not just
        # show the command.
        turn_reasoning = " ".join(b.text.strip() for b in text_blocks if b.text.strip()).strip()

        # Execute each tool call
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
                logger.warning("Blocked command: %s (%s)", cmd_display, reason)
            else:
                logger.info("Executing: %s", cmd_display)
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
                # Why this step was run: the model's stated per-call purpose,
                # falling back to its reasoning text for the turn.
                "purpose": purpose,
                "reasoning": turn_reasoning,
            })

            tool_results.append({
                "type": "tool_result",
                "tool_use_id": block.id,
                "content": result_text,
            })
            attempts += 1

        # Append to conversation
        messages.append({"role": "assistant", "content": response.content})
        messages.append({"role": "user", "content": tool_results})

    # Exhausted attempts
    return {
        "verdict": "unclear",
        "evidence": "max validation attempts reached",
        "finding": finding,
        "tool_history": tool_history,
        "kb_references": kb_references,
        "_usage": {"input_tokens": usage_input, "output_tokens": usage_output, "calls": attempts},
    }


def _extract_balanced_json(text: str) -> list[str]:
    """Return all balanced top-level {...} blocks in text (handles nested braces/strings)."""
    blocks = []
    depth = 0
    start = -1
    in_str = False
    escape = False
    for i, ch in enumerate(text):
        if in_str:
            if escape:
                escape = False
            elif ch == '\\':
                escape = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == '{':
            if depth == 0:
                start = i
            depth += 1
        elif ch == '}':
            if depth > 0:
                depth -= 1
                if depth == 0 and start != -1:
                    blocks.append(text[start:i + 1])
                    start = -1
    return blocks


def _verdict_has_executed_evidence(tool_history: list) -> bool:
    """True if at least one validation step actually RAN (was not blocked).

    A BLOCKED step never reached the network — the scope/safety layer refused it,
    so it produced no observation. A verdict of confirmed/refuted must rest on a
    step that executed; this reports whether any did.
    """
    return any(not s.get("blocked") for s in (tool_history or []))


def _guard_verdict(verdict: dict, tool_history: list) -> None:
    """Downgrade an unsupported confirmed/refuted verdict to 'unclear', in place.

    A finding can only be confirmed or refuted from evidence the agent actually
    gathered. When EVERY validation step was blocked (out of scope / unsafe) — or
    no command was run at all — there is no observation to stand on, so the
    verdict is forced to 'unclear' with the reason recorded and any (unverified)
    poc_command dropped. This stops a finding being reported as confirmed when
    its only "proof" is a BLOCKED message.
    """
    orig = verdict.get("verdict")
    if orig not in ("confirmed", "refuted"):
        return
    if _verdict_has_executed_evidence(tool_history):
        return
    n = len(tool_history or [])
    reason = ("all {} attempt(s) were blocked (out of scope / unsafe)".format(n)
              if n else "the agent ran no validation checks")
    prior = (verdict.get("evidence") or "").strip()
    verdict["verdict"] = "unclear"
    verdict["evidence"] = (
        f"[auto-downgraded from {orig}] No validation command executed — {reason}; "
        f"cannot mark {orig}." + (f" Model note: {prior}" if prior else ""))
    verdict.pop("poc_command", None)
    logger.warning("ai_validate: downgraded %s -> unclear (%s)", orig, reason)


def _parse_verdict(text: str) -> dict:
    """Extract JSON verdict from agent's final text response."""
    # Prefer the last balanced JSON object that actually carries a "verdict" key.
    # (A naive [^{}]* regex fails whenever evidence/poc fields contain nested JSON.)
    for block in reversed(_extract_balanced_json(text)):
        if '"verdict"' not in block:
            continue
        try:
            parsed = json.loads(block)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict) and "verdict" in parsed:
            return parsed

    # Fallback: look for verdict keyword. Check "refuted" first so prose that
    # merely mentions "confirmed" doesn't override an explicit refutation.
    text_lower = text.lower()
    if "refuted" in text_lower:
        return {"verdict": "refuted", "evidence": text[:500]}
    elif "confirmed" in text_lower:
        return {"verdict": "confirmed", "evidence": text[:500]}
    return {"verdict": "unclear", "evidence": text[:500]}


# ---------------------------------------------------------------------------
# Scope parsing
# ---------------------------------------------------------------------------

def _parse_scope(target_file: str, data_prefix: str = None) -> tuple[set, list, set]:
    """Parse target file and discovery ledger into scope IPs, networks, and hostnames.

    Delegates to the shared core.tool_runners.load_scope so scope parsing lives
    in exactly one place (also used by the standalone ssh_audit_scan / snmp_sweep
    / smtp_security modules). Behaviour is identical — guarded by
    tests/test_ai_validate_toolrunner_parity.py. The tuple shape is preserved so
    _is_safe_command's signature is untouched.
    """
    scope = tool_runners.load_scope(target_file, data_prefix)
    return scope.ips, scope.networks, scope.hosts


def _parse_host_scope(data_prefix: str = None) -> tuple[set, list, set]:
    """Parse the -t-authorized (host-scoped) exported files into a scope tuple.

    The engine writes ledger-targets.host.txt (and siblings) containing ONLY
    assets a host-class module may scan (channel==t or promoted into a -t range).
    Host-touching ai_validate tools are gated against this. If the .host files
    are absent (older run, or ai_validate invoked standalone), returns empty —
    fail-safe: host-touching tools are then blocked entirely rather than falling
    back to the full name-safe surface.
    """
    if not data_prefix:
        return set(), [], set()
    data_dir = os.path.dirname(data_prefix)
    ips: set = set()
    networks: list = []
    hosts: set = set()
    from core.tool_runners import _add_scope_line
    from core.output_layout import ledger_file
    for name in ("ledger-targets.host.txt", "ledger-target-ips.host.txt"):
        path = ledger_file(data_dir, name)
        if not os.path.exists(path):
            continue
        try:
            with open(path, encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    # target-ips.host.txt rows may be "ip\thost1,host2" — take the IP.
                    line = line.split("\t", 1)[0]
                    _add_scope_line(line, ips, networks, hosts)
        except OSError:
            pass
    return ips, networks, hosts


# ---------------------------------------------------------------------------
# Report rendering
# ---------------------------------------------------------------------------

# Severity ordering for confirmed vulnerabilities (highest criticality first).
# Unknown/missing severity sorts last. Matches modules/focus.py:_SEVERITY_RANK.
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _severity_rank(result: dict) -> int:
    """Rank a result by its severity (critical=0 … lower = higher priority)."""
    return _SEVERITY_RANK.get((result.get("severity") or "").strip().lower(), 5)


_CHAIN_STEP_MARK = {"confirmed": "✅", "failed": "❌", "skipped": "⏭️"}


def _render_chain_steps(lines: list, r: dict) -> None:
    """Append the per-step walk for a validated attack chain, if present.

    A chain result carries a `steps[]` array (step / status / evidence) from the
    chain-aware agent loop. Rendering it shows how far the chain got — the "here
    is the confirmed kill chain" view — rather than just an overall verdict.
    """
    steps = r.get("steps")
    if not isinstance(steps, list) or not steps:
        return
    lines.append("**Attack Chain — step-by-step:**")
    lines.append("")
    for s in steps:
        if not isinstance(s, dict):
            continue
        num = s.get("step", "?")
        status = str(s.get("status") or "").strip().lower()
        mark = _CHAIN_STEP_MARK.get(status, "•")
        ev = (s.get("evidence") or "").strip()
        line = f"{mark} **Step {num}** ({status or 'unknown'})"
        if ev:
            line += f" — {ev}"
        lines.append(f"- {line}")
    lines.append("")


def _render_validation_steps(lines: list, r: dict) -> None:
    """Append the per-finding 'Validation Steps' block to `lines`.

    Each step is prefaced with a plain-language explanation of what it checks
    and why (from the model's `purpose`, falling back to its turn reasoning),
    so the report explains the steps rather than just listing commands.
    """
    if not r.get("tool_history"):
        return
    lines.append("**Validation Steps:**")
    lines.append("")
    last_reasoning = ""
    for step in r["tool_history"]:
        # Explanation: prefer the per-call purpose; else the turn's reasoning
        # (shown once, not repeated for every tool call in the same turn).
        explanation = (step.get("purpose") or "").strip()
        if not explanation:
            reasoning = (step.get("reasoning") or "").strip()
            if reasoning and reasoning != last_reasoning:
                explanation = reasoning
                last_reasoning = reasoning
        else:
            last_reasoning = (step.get("reasoning") or "").strip()
        if explanation:
            lines.append(f"- _{explanation}_")
        lines.append("```")
        lines.append(f"$ {step['command']}")
        if step.get("blocked"):
            # output_preview holds "BLOCKED: <specific reason>" (out-of-scope
            # host, blocked pattern, host-scope ceiling, no verifiable target).
            # Surface the real reason so it's clear WHY a step was blocked, not
            # just that it was.
            lines.append(step.get("output_preview") or "BLOCKED: out of scope or unsafe")
        else:
            lines.append(step.get("output_preview") or "(no output)")
        lines.append("```")
        lines.append("")


def _render_kb_references(lines: list, r: dict) -> None:
    """Append a 'Knowledge Base References' call-out if any KB source was used."""
    refs = r.get("kb_references")
    if not refs:
        return
    lines.append("**Knowledge Base References:**")
    for ref in refs:
        cite = f"{ref.get('source', '?')}/{ref.get('file_path', '?')}"
        heading = (ref.get("heading") or "").strip()
        if heading:
            cite += f" > {heading}"
        lines.append(f"- {cite}")
    lines.append("")


def _render_rebuttal(lines: list, r: dict) -> None:
    """Append the rebuttal (independent second-opinion) note for a finding.

    Shows whether an adversarial second agent corroborated, contested, or
    overturned the verdict, and renders the rebuttal's own validation steps.
    """
    reb = r.get("rebuttal")
    if not reb:
        return
    lines.append("**Rebuttal (independent second opinion):**")
    ev = (reb.get("evidence") or "").strip()
    if reb.get("flipped"):
        lines.append(f"- ⚖️ Overturned the initial *{reb.get('original_verdict')}* "
                     f"verdict → **{reb.get('rebuttal_verdict')}**." + (f" {ev}" if ev else ""))
    elif reb.get("contested"):
        lines.append(f"- ⚠️ Contested: the second agent could not corroborate the "
                     f"*{reb.get('original_verdict')}* verdict (reached "
                     f"*{reb.get('rebuttal_verdict')}*)." + (f" {ev}" if ev else ""))
    elif reb.get("corroborated"):
        lines.append(f"- ✅ Independently corroborated the "
                     f"*{reb.get('original_verdict')}* verdict." + (f" {ev}" if ev else ""))
    lines.append("")
    # The rebuttal's own steps, rendered with the same formatter.
    _render_validation_steps(lines, {"tool_history": reb.get("tool_history")})


def _render_report(results: list, output_path: str) -> None:
    """Write a markdown validation report."""
    confirmed = [r for r in results if r.get("verdict") == "confirmed"]
    refuted = [r for r in results if r.get("verdict") == "refuted"]
    unclear = [r for r in results if r.get("verdict") == "unclear"]
    errors = [r for r in results if r.get("verdict") == "error"]

    # Confirmed vulnerabilities are the operator's action list — order them by
    # severity, highest criticality first (stable, so same-severity items keep
    # their discovery order).
    confirmed.sort(key=_severity_rank)

    lines = [
        "# Vulnerability Validation Report",
        "",
        f"**Validated:** {len(results)} findings | "
        f"**Confirmed:** {len(confirmed)} | "
        f"**Refuted:** {len(refuted)} | "
        f"**Unclear:** {len(unclear)} | "
        f"**Errors:** {len(errors)}",
        "",
        "---",
        "",
    ]

    if confirmed:
        lines.append("## Confirmed Vulnerabilities")
        lines.append("")
        for i, r in enumerate(confirmed, 1):
            finding = r.get("finding", {})
            lines.append(f"### {i}. {finding.get('action', 'Unknown')} — {finding.get('target', '?')}")
            lines.append("")
            if r.get("severity"):
                lines.append(f"**Severity:** {r['severity']}")
                lines.append("")
            if r.get("evidence"):
                lines.append(f"**Evidence:** {r['evidence']}")
                lines.append("")
            if r.get("poc_command"):
                lines.append(f"**PoC Command:**")
                lines.append(f"```bash")
                lines.append(r["poc_command"])
                lines.append(f"```")
                lines.append("")
            _render_chain_steps(lines, r)
            _render_validation_steps(lines, r)
            _render_kb_references(lines, r)
            _render_rebuttal(lines, r)

    if refuted:
        lines.append("## Refuted (False Positives)")
        lines.append("")
        for i, r in enumerate(refuted, 1):
            finding = r.get("finding", {})
            lines.append(f"### {i}. {finding.get('action', 'Unknown')} — {finding.get('target', '?')}")
            lines.append("")
            lines.append(f"**Reason:** {r.get('evidence', 'N/A')}")
            lines.append("")
            _render_chain_steps(lines, r)
            _render_validation_steps(lines, r)
            _render_kb_references(lines, r)
            _render_rebuttal(lines, r)

    if unclear:
        lines.append("## Unclear (Needs Manual Review)")
        lines.append("")
        for i, r in enumerate(unclear, 1):
            finding = r.get("finding", {})
            lines.append(f"### {i}. {finding.get('action', 'Unknown')} — {finding.get('target', '?')}")
            lines.append("")
            lines.append(f"**Notes:** {r.get('evidence', 'inconclusive')}")
            lines.append("")
            _render_chain_steps(lines, r)
            _render_validation_steps(lines, r)
            _render_kb_references(lines, r)
            _render_rebuttal(lines, r)

    if errors:
        lines.append("## Errors")
        lines.append("")
        for r in errors:
            finding = r.get("finding", {})
            lines.append(f"- **{finding.get('action', 'Unknown')}** ({finding.get('target', '?')}) — {r.get('evidence', 'error')}")
        lines.append("")

    with open(output_path, "w") as f:
        f.write("\n".join(lines))


# ---------------------------------------------------------------------------
# Module entry point
# ---------------------------------------------------------------------------

def run_ai_validate(prefix=None, target=None, fleet=None, **kwargs):
    """Agentic validation of findings from ai_analyze.

    Reads the ai-analysis.json output and runs an AI agent loop to
    confirm or refute each exploitation playbook finding.

    Kwargs:
        max_validate: Max findings to validate per run (default: 25)
        kb_max_tokens: Knowledge base token budget per finding (default: 2000)
    """
    print("[!] ai_validate is EXPERIMENTAL — the agentic validation loop is "
          "unreliable; treat its verdicts as leads to review, not ground truth.")
    data_prefix = kwargs.get("data_prefix", prefix)
    reports_prefix = kwargs.get("reports_prefix", prefix)
    max_findings = int(kwargs.get("max_validate", MAX_FINDINGS_TO_VALIDATE))
    # Per-finding tool-call budget. "max validation attempts reached" = this was
    # exhausted on a finding. Configurable via max_attempts (int or "unlimited").
    max_attempts = _resolve_max_attempts(kwargs.get("max_attempts", MAX_ATTEMPTS_PER_FINDING))
    # Intrusive (Tier 2/3, state-changing) protocol checks are opt-in only.
    allow_intrusive = bool(kwargs.get("allow_intrusive", False))
    # Adversarial rebuttal pass (independent second opinion) — opt-in; roughly
    # doubles cost, so off by default. See modules/_ai_validate_rebuttal.py.
    rebuttal = bool(kwargs.get("rebuttal", False))

    print("[*] Running ai_validate: agentic finding validation"
          + (" (intrusive checks ENABLED)" if allow_intrusive else "")
          + (" (rebuttal pass ENABLED)" if rebuttal else ""))

    # Load AI provider config
    ai_config = get_ai_provider()
    if ai_config["name"] != "anthropic":
        print("[!] ai_validate requires Anthropic provider (needs tool_use API)")
        return {"module": "ai_validate", "status": "skipped",
                "reason": "requires anthropic provider"}

    api_key = ai_config.get("api_key")
    aws_region = ai_config.get("aws_region")
    if not api_key and not aws_region:
        print("[!] ai_validate: no API key or AWS region configured")
        return {"module": "ai_validate", "status": "failed",
                "error": "no api_key or aws_region"}

    model = ai_config.get("model", "claude-opus-4-6")

    # Load ai_analyze results
    analysis_path = f"{data_prefix}-ai-analysis.json"
    if not os.path.exists(analysis_path):
        print(f"[!] ai_validate: no ai_analyze output found at {analysis_path}")
        return {"module": "ai_validate", "status": "skipped",
                "reason": "no ai-analysis.json found"}

    with open(analysis_path) as f:
        analysis = json.load(f)

    recommendations = analysis.get("recommendations") or {}
    if not any(recommendations.get(k) for k in ("quick_wins", "attack_chains", "requires_verification", "cve_research")):
        print("[!] ai_validate: no exploitation playbooks to validate")
        return {"module": "ai_validate", "status": "skipped",
                "reason": "no recommendations to validate"}

    # Parse scope
    target_file = target or kwargs.get("target")
    scope_ips, scope_networks, scope_hosts = _parse_scope(target_file, data_prefix)
    if not scope_ips and not scope_networks and not scope_hosts:
        logger.warning("No scope parsed from target file/ledger — all commands will be "
                       "blocked as out-of-scope. Ensure the target file or discovery "
                       "ledger is available to ai_validate.")

    # -t-authorized (host-scoped) subset — host-touching tools (nmap/nc/snmp/…)
    # are gated to this so they never probe a -d/-url name on shared infra.
    host_scope = _parse_host_scope(data_prefix)
    if not any(host_scope):
        logger.info("ai_validate: no -t host scope found (.host files absent) — "
                    "host-touching tools will be blocked; name-safe tools unaffected.")

    # Index the original normalized scanner records so validation reasons over
    # source evidence, not only ai_analyze's prose summary (#9).
    evidence_index = _load_evidence_index(data_prefix)
    if evidence_index:
        logger.info("ai_validate: loaded raw evidence for %d hosts", len(evidence_index))

    # Prioritize findings
    findings = _prioritize_findings(recommendations)
    to_validate = findings[:max_findings]

    print(f"[*] ai_validate: {len(to_validate)} findings to validate "
          f"(of {len(findings)} total, capped at {max_findings}); "
          f"up to {max_attempts} probe attempt(s) per finding")

    # Egress logging: every agent turn is an external AI call. Record them in the
    # same logs/ai-interactions.log ai_analyze writes, via a shared call counter,
    # so the shipped egress log accounts for ai_validate's calls too (#7).
    _logs_output_dir = os.path.dirname(os.path.dirname(data_prefix)) if data_prefix else None
    egress_logs_dir = os.path.join(_logs_output_dir, "logs") if _logs_output_dir else None
    egress_counter = [0]

    # Run validation loop
    results = []
    confirmed_count = 0
    refuted_count = 0

    for i, finding in enumerate(to_validate, 1):
        target_str = finding.get("target", "?")
        action_str = finding.get("action", "?")
        category = finding.get("_category", "?")
        print(f"[*] Validating ({i}/{len(to_validate)}) [{category}]: {action_str} @ {target_str}")

        raw_evidence = _evidence_for_finding(finding, evidence_index)
        result = _run_agent_loop(finding, scope_ips, scope_networks, scope_hosts,
                                 ai_config, model,
                                 kb_max_tokens=kwargs.get('kb_max_tokens', 2000),
                                 allow_intrusive=allow_intrusive,
                                 raw_evidence=raw_evidence,
                                 host_scope=host_scope,
                                 logs_dir=egress_logs_dir,
                                 egress_counter=egress_counter,
                                 max_attempts=max_attempts)
        results.append(result)

        verdict = result.get("verdict", "unclear")
        if verdict == "confirmed":
            confirmed_count += 1
            print(f"[+] CONFIRMED: {action_str}")
        elif verdict == "refuted":
            refuted_count += 1
            print(f"[-] Refuted: {action_str}")
        elif verdict == "error":
            print(f"[!] Error: {action_str} — {result.get('evidence', '')[:100]}")
        else:
            print(f"[?] Unclear: {action_str}")

    # Adversarial rebuttal pass: an independent second agent tries to overturn
    # each confirmed/refuted verdict from a fresh context. Reconciliation flips a
    # verdict only on evidence a rebuttal command actually produced; otherwise it
    # annotates (corroborated / contested). Mutates `results` in place, so the
    # reconciled verdicts flow into scan.db + JSON + report below unchanged.
    if rebuttal:
        from modules._ai_validate_rebuttal import apply_rebuttal_phase
        print(f"[*] ai_validate: running rebuttal pass over confirmed/refuted findings")
        reb_summary = apply_rebuttal_phase(
            results, evidence_index, scope_ips, scope_networks, scope_hosts,
            ai_config, model, allow_intrusive=allow_intrusive, host_scope=host_scope,
            logs_dir=egress_logs_dir, egress_counter=egress_counter,
            max_attempts=max_attempts)
        print(f"[*] Rebuttal complete: {reb_summary['rebutted']} challenged — "
              f"{reb_summary['flipped']} overturned, {reb_summary['contested']} contested, "
              f"{reb_summary['corroborated']} corroborated")

    # Write outputs. Recompute all verdict counts from `results` (not the inline
    # tallies) so a rebuttal flip is reflected in the summary and returned dict.
    confirmed_count = len([r for r in results if r.get("verdict") == "confirmed"])
    refuted_count = len([r for r in results if r.get("verdict") == "refuted"])
    unclear_count = len([r for r in results if r.get("verdict") == "unclear"])
    error_count = len([r for r in results if r.get("verdict") == "error"])

    # Aggregate AI usage
    total_input_tokens = sum(r.get("_usage", {}).get("input_tokens", 0) for r in results)
    total_output_tokens = sum(r.get("_usage", {}).get("output_tokens", 0) for r in results)
    total_api_calls = sum(r.get("_usage", {}).get("calls", 0) for r in results)
    ai_usage = {
        "provider": "anthropic",
        # Client-safe label — never persist a Bedrock ARN (embeds our AWS acct id).
        # The raw `model` is still used above for the API call and below for cost.
        "model": display_model_name(model, ai_config),
        "calls": total_api_calls,
        "input_tokens": total_input_tokens,
        "output_tokens": total_output_tokens,
        "total_tokens": total_input_tokens + total_output_tokens,
    }
    # Price the aggregated tokens. resolve_cost_rates handles a named model,
    # a model-name-bearing inference-profile ARN, or an operator override
    # (input_price_per_1m/output_price_per_1m or model_family in credentials.yaml)
    # — the last is the only way to price an opaque application-inference-profile
    # ARN. If the model can't be priced, cost stays None (tokens still reported).
    rates = resolve_cost_rates(model, ai_config)
    if rates:
        ai_usage["total_cost_usd"] = (
            (total_input_tokens / 1000) * rates["input"]
            + (total_output_tokens / 1000) * rates["output"]
        )
        ai_usage["cost_is_estimate"] = True
    elif total_input_tokens or total_output_tokens:
        ai_usage["cost_unknown"] = True

    print(f"\n[+] Validation complete: {confirmed_count} confirmed, "
          f"{refuted_count} refuted, {unclear_count} unclear, {error_count} errors")
    cost = ai_usage.get("total_cost_usd")
    if cost:
        cost_str = f", cost: ${cost:.4f} (estimated)"
    elif ai_usage.get("cost_unknown"):
        cost_str = ", cost: unknown (no pricing for this model)"
    else:
        cost_str = ""
    print(f"    AI usage: {total_api_calls} API calls, {ai_usage['total_tokens']:,} tokens{cost_str}")

    # Exact join back to the findings minted at normalize time + verdict write.
    # scan.db lives at output_dir/ (data_prefix is output_dir/data/<name>).
    output_dir = os.path.dirname(os.path.dirname(data_prefix)) if data_prefix else None
    db = scan_db.open_db(output_dir) if output_dir else None

    # JSON output
    json_output = f"{data_prefix}-validated-findings.json"
    version_output_path(json_output)
    # Strip internal fields before writing; annotate with the joined finding_id(s).
    clean_results = []
    for r in results:
        clean = dict(r)
        clean.pop("_usage", None)
        finding = clean.get("finding") or {}
        if "finding" in clean:
            f = dict(finding)
            f.pop("_priority", None)
            f.pop("_category", None)
            clean["finding"] = f

        # Recompute the shared id from the raw evidence and record the verdict.
        fids = _match_finding_ids(finding, evidence_index)
        verdict = clean.get("verdict") or "unclear"
        host = _extract_host(finding.get("target", ""))
        port = _extract_port(finding.get("target", ""))
        clean["finding_id"] = fids[0] if fids else None
        clean["finding_ids"] = fids
        # ai_validate assesses port/service-scoped recommendations, so the
        # verdict's natural home is the port. proto isn't carried on the
        # recommendation target (host:port); nmap findings are overwhelmingly
        # tcp and the ports PK needs a proto, so default to tcp.
        proto = "tcp"
        clean["port_proto"] = proto
        if db is not None:
            try:
                # One validation row. finding_id is set only on an exact join
                # (token / single real finding); it stays traceable via
                # host/port/proto regardless. The verdict lands on the port (so
                # it surfaces like findings.verdict) AND on any exactly-joined
                # finding.
                db.record_validation(
                    finding_id=fids[0] if fids else None, host=host, port=port,
                    proto=proto, verdict=verdict, evidence=clean.get("evidence"),
                    poc_command=clean.get("poc_command"), severity=clean.get("severity"),
                    action=finding.get("action"),
                    tool_history=json.dumps(clean.get("tool_history"))
                    if clean.get("tool_history") is not None else None)
                for fid in fids:
                    db.set_verdict(fid, verdict)
                port_hit = 0
                if port is not None:
                    port_hit = db.set_port_verdict(
                        host=host, port=port, proto=proto, verdict=verdict,
                        evidence=(clean.get("evidence") or "")[:2000] or None)
                if not fids:
                    logger.info("ai_validate: no exact finding_id join for %s:%s "
                                "(%s) — verdict on port (%d row) + validations row",
                                host, port, finding.get("action", "")[:60], port_hit)
            except Exception as exc:  # pragma: no cover - defensive, DB never aborts
                logger.warning("scan.db validation write failed: %s", exc)
        clean_results.append(clean)

    if db is not None:
        # Short-lived secondary handle: run_modules' long-lived ledger/tracker
        # connections are still open on this WAL, so the final ledger.close() is
        # the sole checkpointer. Match normalize/focus/ai_analyze_gowitness.
        db.close(checkpoint=False)

    with open(json_output, "w") as f:
        json.dump(clean_results, f, indent=2)
    logger.info("Validated findings JSON: %s", json_output)

    # Markdown report
    md_output = f"{reports_prefix}-validation-report.md"
    version_output_path(md_output)
    _render_report(results, md_output)
    logger.info("Validation report: %s", md_output)
    print(f"[+] Report written: {md_output}")

    return {
        "module": "ai_validate",
        "status": "completed",
        "output_files": [json_output, md_output],
        "confirmed": confirmed_count,
        "refuted": refuted_count,
        "unclear": unclear_count,
        "errors": error_count,
        "total_validated": len(results),
        "ai_usage": ai_usage,
    }
