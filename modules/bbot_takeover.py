"""BBOT DNS takeover detection — baddns suite."""

import logging
import os

from modules._bbot_common import collect_bbot_targets, run_bbot_modules

logger = logging.getLogger('monkeyx.modules.bbot_takeover')

REQUIRED_INPUTS = frozenset()

BBOT_MODULES = [
    'baddns',
    'baddns_direct',
    'baddns_zone',
]


def run_bbot_takeover(domainlist=None, prefix=None, **kwargs):
    """Detect dangling DNS records and subdomain takeover opportunities via bbot CLI.

    Accepts all monkeyx input types. Domains are the primary input for DNS
    takeover checks, but bbot will also check IPs for zone transfer/NSEC.

    Args:
        domainlist: File containing domains/subdomains to check
        prefix: Output file prefix
        **kwargs:
            bbot_timeout: Max seconds before killing bbot (default: 1800)
            data_prefix: Override for output prefix
            url_file: Path to ledger-urls.txt
            open_ports_file: Path to ledger-open-ports.txt
    """
    prefix = kwargs.get('data_prefix', prefix)

    # baddns takeover checks are per-hostname (DNS_NAME). URLs/IPs/host:port are
    # redundant (bbot would just re-derive the host already in the domain list),
    # so feed the domain/subdomain list only.
    targets = collect_bbot_targets(domainlist=domainlist)

    if not targets:
        print('[!] bbot_takeover: no targets provided')
        return {'module': 'bbot_takeover', 'status': 'failed', 'output_files': [], 'error': 'No targets'}

    # ~3s per target for baddns checks, minimum 1800s
    timeout = kwargs.get('bbot_timeout', max(1800, len(targets) * 3))

    print(f'[*] Running bbot DNS takeover detection against {len(targets)} targets (timeout: {timeout}s)')

    output_file = f"{prefix}-bbot-takeover.jsonl"
    scan_name = f"monkeyx-takeover-{os.getpid()}"

    try:
        result = run_bbot_modules(targets, BBOT_MODULES, scan_name, output_file, timeout=timeout)
        print(f'[*] bbot_takeover complete — {result["events"]} events, {result["findings"]} findings')
        return {
            'module': 'bbot_takeover',
            'status': 'success',
            'output_files': [output_file],
        }
    except Exception as e:
        print(f'[!] bbot_takeover failed: {e}')
        return {'module': 'bbot_takeover', 'status': 'failed', 'output_files': [], 'error': str(e)}
