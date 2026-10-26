"""BBOT consolidated recon — web + cloud + takeover in one scan.

Runs a single bbot scan with web scanning, cloud bucket enumeration, and
takeover detection all active. This lets bbot's recursive event pipeline
chain discoveries: subdomains get HTTP-probed → crawled → tech detected →
cloud buckets checked → takeover tested — all within one event loop.

The `web`/`web-heavy` presets are web-only (verified via
`bbot -p web web-heavy --current-preset`: no bucket_* / baddns), so the cloud
bucket + baddns takeover modules are added EXPLICITLY via EXTRA_MODULES. This is
why bbot_recon in standard/deep covers cloud + takeover without a separate
scan; the standalone bbot_cloud / bbot_takeover modules remain for focused
`-m` runs.

Does NOT include passive modules (shodan, wayback, etc.) because the
'passive' preset conflicts with active web scanning in bbot 3.0.
Use bbot_passive separately for passive API lookups.

Should run AFTER subfinder/puredns + dnsx_resolve so it starts with maximum
seed targets.

Inputs:  domainlist (domains/subdomains), optionally target (IPs) and url_file
Outputs: {prefix}-bbot-recon.jsonl
"""

import logging
import os

from modules._bbot_common import collect_bbot_targets, run_bbot_flags

logger = logging.getLogger('monkeyx.modules.bbot_recon')

REQUIRED_INPUTS = frozenset()

BBOT_FLAGS = ['web', 'web-heavy']

EXCLUDE_MODULES = [
    'nuclei',
    'dnsbrute',
    'dnsbrute_mutations',
    'portscan',
    'lightfuzz',
    'generic_ssrf',
]

# The web presets don't include these, so add them so recon genuinely does
# "cloud + takeover" (see module docstring). Mirrors bbot_cloud + bbot_takeover.
EXTRA_MODULES = [
    'baddns', 'baddns_direct', 'baddns_zone',            # DNS/subdomain takeover
    'bucket_amazon', 'bucket_google', 'bucket_microsoft',
    'bucket_digitalocean', 'bucket_firebase', 'bucket_file_enum',
    'azure_tenant',                                       # cloud bucket / tenant enum
]


def run_bbot_recon(domainlist=None, target=None, prefix=None, **kwargs):
    """Run consolidated bbot recon: web + cloud + takeover.

    Combines what was previously 3 separate bbot invocations into one scan
    so bbot's recursive event pipeline can chain discoveries internally.

    Accepts all monkeyx input types (domains, IPs/CIDRs, URLs, open ports)
    and passes them to bbot which handles DNS_NAME, IP_ADDRESS, IP_RANGE,
    URL, and OPEN_TCP_PORT natively.

    Args:
        domainlist: File containing domains/subdomains to scan
        target: Optional file containing IPs/CIDRs
        prefix: Output file prefix
        **kwargs:
            bbot_timeout: Max seconds (default: 7200)
            data_prefix: Override for output prefix
            url_file: Path to ledger-urls.txt (seed known URLs)
            open_ports_file: Path to ledger-open-ports.txt (host<tab>ports)
    """
    prefix = kwargs.get('data_prefix', prefix)

    targets = collect_bbot_targets(
        domainlist=domainlist, target=target,
        url_file=kwargs.get('url_file'),
        open_ports_file=kwargs.get('open_ports_file'),
    )

    if not targets:
        print('[!] bbot_recon: no targets provided')
        return {'module': 'bbot_recon', 'status': 'failed', 'output_files': [], 'error': 'No targets'}

    # Cap the auto-computed timeout: bbot discovers far beyond the seed count, so
    # scaling on len(targets) alone can explode. Operator can override via
    # bbot_timeout (config/YAML) for a genuinely huge authorized scan.
    timeout = kwargs.get('bbot_timeout', min(max(7200, len(targets) * 5), 14400))
    print(f'[*] Running bbot consolidated recon against {len(targets)} targets (timeout: {timeout}s)')

    output_file = f"{prefix}-bbot-recon.jsonl"
    scan_name = f"monkeyx-recon-{os.getpid()}"

    try:
        result = run_bbot_flags(
            targets, BBOT_FLAGS, scan_name, output_file,
            timeout=timeout, exclude_modules=EXCLUDE_MODULES,
            extra_modules=EXTRA_MODULES,
        )
        print(f'[*] bbot_recon complete — {result["events"]} events, {result["findings"]} findings')
        return {
            'module': 'bbot_recon',
            'status': 'success',
            'output_files': [output_file],
        }
    except Exception as e:
        print(f'[!] bbot_recon failed: {e}')
        return {'module': 'bbot_recon', 'status': 'failed', 'output_files': [], 'error': str(e)}
