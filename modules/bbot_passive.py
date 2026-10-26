"""BBOT passive intelligence — enrichment without touching targets.

Runs bbot with the 'passive' flag to gather intel from third-party APIs:
Shodan InternetDB, Wayback Machine, viewdns reverse whois, ipneighbor,
certificate transparency, DNS records, etc.

No packets are sent to target systems.

Inputs:  domainlist (domains) and/or target (IPs)
Outputs: {prefix}-bbot-passive.jsonl
"""

import logging
import os

from modules._bbot_common import collect_bbot_targets, run_bbot_flags

logger = logging.getLogger('monkeyx.modules.bbot_passive')

REQUIRED_INPUTS = frozenset()

BBOT_FLAGS = ['passive', 'safe']

EXCLUDE_MODULES = [
    'bucket_amazon',
    'bucket_google',
    'bucket_microsoft',
    'bucket_digitalocean',
    'bucket_firebase',
    'bucket_file_enum',
    'azure_tenant',
]


def run_bbot_passive(domainlist=None, target=None, prefix=None, **kwargs):
    """Gather passive intelligence via bbot without touching targets.

    Accepts all monkeyx input types (domains, IPs/CIDRs, URLs). bbot's
    passive modules use these as seeds for API lookups (Shodan InternetDB,
    Wayback, CT logs, ipneighbor, etc.) — no packets sent to targets.

    Args:
        domainlist: File containing domains to enrich
        target: Optional file containing IPs/CIDRs (for shodan_idb, ipneighbor)
        prefix: Output file prefix
        **kwargs:
            bbot_timeout: Max seconds (default: 3600)
            data_prefix: Override for output prefix
            url_file: Path to ledger-urls.txt
            open_ports_file: Path to ledger-open-ports.txt
    """
    prefix = kwargs.get('data_prefix', prefix)

    # Passive sources (CT logs, Wayback, passive DNS, InternetDB, ipneighbor)
    # key off DNS_NAME / IP_ADDRESS only. Feeding URLs/open-ports adds nothing
    # but inflates the target count (and the count-scaled timeout below).
    targets = collect_bbot_targets(domainlist=domainlist, target=target)

    if not targets:
        print('[!] bbot_passive: no targets provided')
        return {'module': 'bbot_passive', 'status': 'failed', 'output_files': [], 'error': 'No targets'}

    # ~2s per target for passive API lookups, minimum 3600s
    # Cap the auto-computed timeout (see bbot_recon). Override via bbot_timeout.
    timeout = kwargs.get('bbot_timeout', min(max(3600, len(targets) * 2), 7200))
    print(f'[*] Running bbot passive intel against {len(targets)} targets (timeout: {timeout}s)')

    output_file = f"{prefix}-bbot-passive.jsonl"
    scan_name = f"monkeyx-passive-{os.getpid()}"

    try:
        result = run_bbot_flags(
            targets, BBOT_FLAGS, scan_name, output_file,
            timeout=timeout, exclude_modules=EXCLUDE_MODULES,
            require_flags=True,
        )
        print(f'[*] bbot_passive complete — {result["events"]} events, {result["findings"]} findings')
        return {
            'module': 'bbot_passive',
            'status': 'success',
            'output_files': [output_file],
        }
    except Exception as e:
        print(f'[!] bbot_passive failed: {e}')
        return {'module': 'bbot_passive', 'status': 'failed', 'output_files': [], 'error': str(e)}
