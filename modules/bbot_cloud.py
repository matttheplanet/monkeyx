"""BBOT cloud discovery — buckets (S3, GCS, Azure, DO, Firebase) + Azure tenant/realm."""

import logging
import os

from modules._bbot_common import collect_bbot_targets, run_bbot_modules

logger = logging.getLogger('monkeyx.modules.bbot_cloud')

REQUIRED_INPUTS = frozenset()

BBOT_MODULES = [
    'bucket_amazon',
    'bucket_google',
    'bucket_microsoft',
    'bucket_digitalocean',
    'bucket_firebase',
    'bucket_file_enum',
    'azure_tenant',
]


def run_bbot_cloud(domainlist=None, prefix=None, **kwargs):
    """Discover exposed cloud storage buckets via bbot CLI.

    Accepts all monkeyx input types. Domains are most useful here (bucket
    names derive from domain/org names), but bbot will also attempt discovery
    from IPs/URLs if that's all that's available.

    Args:
        domainlist: File containing domains/subdomains to scan
        prefix: Output file prefix
        **kwargs:
            bbot_timeout: Max seconds before killing bbot (default: 1800)
            data_prefix: Override for output prefix
            url_file: Path to ledger-urls.txt
            open_ports_file: Path to ledger-open-ports.txt
    """
    prefix = kwargs.get('data_prefix', prefix)
    timeout = kwargs.get('bbot_timeout', 1800)

    # Bucket (S3/GCS/Azure/DO/Firebase) and azure_tenant discovery derive
    # candidates from org/domain names — IPs, URLs and host:port are pure noise
    # to these modules, so feed names only.
    targets = collect_bbot_targets(domainlist=domainlist)

    if not targets:
        print('[!] bbot_cloud: no targets provided')
        return {'module': 'bbot_cloud', 'status': 'failed', 'output_files': [], 'error': 'No targets'}

    print(f'[*] Running bbot cloud bucket discovery against {len(targets)} targets')

    output_file = f"{prefix}-bbot-cloud.jsonl"
    scan_name = f"monkeyx-cloud-{os.getpid()}"

    try:
        result = run_bbot_modules(targets, BBOT_MODULES, scan_name, output_file, timeout=timeout)
        print(f'[*] bbot_cloud complete — {result["events"]} events, {result["findings"]} findings')
        return {
            'module': 'bbot_cloud',
            'status': 'success',
            'output_files': [output_file],
        }
    except Exception as e:
        print(f'[!] bbot_cloud failed: {e}')
        return {'module': 'bbot_cloud', 'status': 'failed', 'output_files': [], 'error': str(e)}
