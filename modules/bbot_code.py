"""BBOT code enumeration — discover repos, scan for secrets.

Runs bbot with the 'code-enum' flag. The recursive pipeline discovers
code repositories (GitHub org/codesearch, GitLab, Postman, Docker Hub),
clones them, and runs trufflehog for secret scanning automatically.

Only runs against apex/root domains (not subdomains) since code searching
for sub.sub.example.com is redundant — searching example.com covers all of them.

Inputs:  domainlist (domains/org names to search for)
Outputs: {prefix}-bbot-code.jsonl
"""

import logging
import os

from modules._bbot_common import collect_bbot_targets, run_bbot_flags

logger = logging.getLogger('monkeyx.modules.bbot_code')

REQUIRED_INPUTS = frozenset()

BBOT_FLAGS = ['code-enum']


def _extract_apex_domains(targets):
    """Filter target list to likely apex domains only.

    Skips anything that isn't a bare hostname — URLs (contain '/' or '://'),
    host:port entries (contain ':'), and IPs — because the naive last-two-labels
    collapse below mangles them into invalid "domains" (e.g.
    'https://api.example.com/v1' -> 'example.com/v1', '1.2.3.4' -> '3.4').
    """
    apex = set()
    for t in targets:
        t = t.lower().strip()
        if not t or ":" in t or "/" in t:
            continue  # URL or host:port — not a bare hostname
        parts = t.split(".")
        if all(p.isdigit() for p in parts):
            continue  # IPv4 address, not a domain
        if len(parts) <= 2:
            apex.add(t)
        elif len(parts) == 3 and parts[0] == "www":
            apex.add(".".join(parts[1:]))
        else:
            apex.add(".".join(parts[-2:]))
    return sorted(apex)


def run_bbot_code(domainlist=None, prefix=None, **kwargs):
    """Discover code repos and scan for secrets via bbot.

    Primarily uses domains/org names for code search. IPs and URLs from
    other input types are passed through but typically won't produce code
    search results — domains are the valuable input here.

    Args:
        domainlist: File containing domains/org names to search
        prefix: Output file prefix
        **kwargs:
            bbot_timeout: Max seconds (default: 3600)
            data_prefix: Override for output prefix
            url_file: Path to ledger-urls.txt
            open_ports_file: Path to ledger-open-ports.txt
    """
    prefix = kwargs.get('data_prefix', prefix)

    # code-enum searches code hosts (GitHub/GitLab/Postman/DockerHub) by
    # org/domain name, then collapses to apex domains. Feed the domain list
    # only — URLs/IPs/host:port aren't valid code-search terms (and the apex
    # collapse can't sanely reduce them anyway).
    all_targets = collect_bbot_targets(domainlist=domainlist)

    if not all_targets:
        print('[!] bbot_code: no targets provided')
        return {'module': 'bbot_code', 'status': 'failed', 'output_files': [], 'error': 'No targets'}

    targets = _extract_apex_domains(all_targets)
    # ~60s per domain for code-enum (cloning, trufflehog), minimum 3600s
    # Cap the auto-computed timeout: len(targets)*60 was unbounded (1000 apexes
    # -> 16h). Override via bbot_timeout for a huge authorized scan.
    timeout = kwargs.get('bbot_timeout', min(max(3600, len(targets) * 60), 14400))

    if len(all_targets) != len(targets):
        print(f'[*] Filtered {len(all_targets)} entries to {len(targets)} apex domains for code search')
    print(f'[*] Running bbot code enumeration against {len(targets)} targets (timeout: {timeout}s)')

    output_file = f"{prefix}-bbot-code.jsonl"
    scan_name = f"monkeyx-code-{os.getpid()}"

    try:
        result = run_bbot_flags(
            targets, BBOT_FLAGS, scan_name, output_file,
            timeout=timeout,
        )
        print(f'[*] bbot_code complete — {result["events"]} events, {result["findings"]} findings')
        return {
            'module': 'bbot_code',
            'status': 'success',
            'output_files': [output_file],
        }
    except Exception as e:
        print(f'[!] bbot_code failed: {e}')
        return {'module': 'bbot_code', 'status': 'failed', 'output_files': [], 'error': str(e)}
