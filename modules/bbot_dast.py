"""BBOT DAST — dynamic application security testing (bbot 3.x).

Runs bbot's `lightfuzz` preset with its full pipeline: HTTP crawling,
parameter extraction (excavate), then fuzzing for SQLi, XSS, SSRF,
SSTI, command injection, path traversal, deserialization, and ESI.
Adds `generic_ssrf` (common SSRF params via OOB) as an extra module.

This is invasive — it sends payloads. Run only against targets where
you have explicit authorization.

Why a PRESET, not require-flags: a previous version passed
`-rf active loud` (require-flags). bbot require-flags are AND-matched —
a module runs only if it has EVERY listed flag — so (a) on bbot < 3.0
`loud` isn't a flag at all and the filter dropped EVERY module (the scan
did nothing, silently), and (b) even on 3.0 it dropped `generic_ssrf`
(no `loud` flag) and the passive extraction chain (excavate is `passive`),
starving the fuzzer of parameters. The `lightfuzz` preset enables the
fuzz submodules AND their httpx/excavate dependencies the correct way;
`generic_ssrf` is added explicitly with `-m`. Mirrors bbot_recon's
preset-based invocation.

Inputs:  domainlist (domains/subdomains with web services)
Outputs: {prefix}-bbot-dast.jsonl
"""

import logging
import os

from modules._bbot_common import collect_bbot_targets, run_bbot_flags

logger = logging.getLogger('modules.bbot_dast')

REQUIRED_INPUTS = frozenset()

# bbot 3.x preset: enables the lightfuzz submodules (sqli/xss/ssrf/ssti/cmdi/
# path/serial/esi/crypto) + companions (badsecrets, hunt, reflected_parameters)
# and the http/excavate extraction chain. It sets NO flags and pulls in NO
# dnsbrute/portscan, so there is nothing scope-expanding to exclude here.
BBOT_PRESETS = ['lightfuzz']

# Added explicitly — generic_ssrf is not in the lightfuzz preset.
EXTRA_MODULES = ['generic_ssrf']

# The lightfuzz preset itself warns the web spider should be enabled — without
# it, lightfuzz only fuzzes params on the exact URLs fed (no crawl). Enable a
# bounded spider so it crawls the live endpoints and fuzzes what it finds.
# Overridable via spider_distance / spider_depth kwargs; 0 disables crawling.
DEFAULT_SPIDER_DISTANCE = 2
DEFAULT_SPIDER_DEPTH = 4


def _clamp_int(value, lo, hi, default):
    try:
        return max(lo, min(hi, int(value)))
    except (TypeError, ValueError):
        return default


def run_bbot_dast(domainlist=None, prefix=None, **kwargs):
    """Run DAST fuzzing via bbot's lightfuzz + generic_ssrf.

    Accepts all monkeyx input types. URLs and open ports are particularly
    valuable here — bbot skips redundant HTTP probing and goes straight to
    fuzzing known-live endpoints.

    Args:
        domainlist: File containing domains/subdomains to fuzz
        prefix: Output file prefix
        **kwargs:
            bbot_timeout: Max seconds (default: 7200)
            data_prefix: Override for output prefix
            url_file: Path to ledger-urls.txt
            open_ports_file: Path to ledger-open-ports.txt
            spider_distance: web.spider_distance (default: 2; 0 = no crawl)
            spider_depth: web.spider_depth (default: 4)
    """
    prefix = kwargs.get('data_prefix', prefix)

    # This is the loud/invasive fuzzer — every extra target multiplies real
    # attack traffic. Fuzz known-live endpoints only: the URL list (remapped to
    # the httpx-live subset via _LIVE_URL_SCANNERS under --url-prune) plus open
    # ports. Deliberately NOT fed domainlist/target, which would make bbot
    # re-crawl from scratch and fuzz dead/derived hosts.
    targets = collect_bbot_targets(
        url_file=kwargs.get('url_file'),
        open_ports_file=kwargs.get('open_ports_file'),
    )

    if not targets:
        print('[!] bbot_dast: no targets provided')
        return {'module': 'bbot_dast', 'status': 'failed', 'output_files': [], 'error': 'No targets'}

    # ~10s per target for fuzzing, minimum 7200s
    # Cap the auto-computed timeout (see bbot_recon). Override via bbot_timeout.
    timeout = kwargs.get('bbot_timeout', min(max(7200, len(targets) * 10), 14400))
    print(f'[*] Running bbot DAST against {len(targets)} targets (timeout: {timeout}s)')

    output_file = f"{prefix}-bbot-dast.jsonl"
    scan_name = f"monkeyx-dast-{os.getpid()}"

    # Bounded web spider so lightfuzz crawls the live endpoints (int-validated
    # so these never carry shell metachars into the bbot -c args).
    distance = _clamp_int(kwargs.get('spider_distance', DEFAULT_SPIDER_DISTANCE),
                          0, 10, DEFAULT_SPIDER_DISTANCE)
    depth = _clamp_int(kwargs.get('spider_depth', DEFAULT_SPIDER_DEPTH),
                       0, 20, DEFAULT_SPIDER_DEPTH)
    spider_config = [f"web.spider_distance={distance}", f"web.spider_depth={depth}"]

    try:
        result = run_bbot_flags(
            targets, BBOT_PRESETS, scan_name, output_file,
            timeout=timeout, extra_modules=EXTRA_MODULES,
            require_flags=False, config=spider_config,
        )
        print(f'[*] bbot_dast complete — {result["events"]} events, {result["findings"]} findings')
        return {
            'module': 'bbot_dast',
            'status': 'success',
            'output_files': [output_file],
        }
    except Exception as e:
        print(f'[!] bbot_dast failed: {e}')
        return {'module': 'bbot_dast', 'status': 'failed', 'output_files': [], 'error': str(e)}
