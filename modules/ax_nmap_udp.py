"""UDP port scan module.

Configurable port selection: top-N or explicit list.
Replaces the former ax_nmap_udptop200 module.

Outputs:
    {prefix}-udpscan.xml         merged nmap XML
    {prefix}-udp-weburls.txt     discovered web URLs (if any)
"""

import os

from core.utils import bash_command, validate_port_spec
from core.scanning import merge_nmap_folder, uncovered_ip_targets
from modules.ax_nmap_tcp import _validate_int, _validate_timeout, _validate_timing

REQUIRED_INPUTS = frozenset({"target"})
PRODUCES = {"nmap_xml": "{prefix}-udpscan.xml"}

DEFAULT_PORTS = "top-200"
# UDP runtime is dominated by retransmission of unanswered probes, so a low
# --max-retries is the single biggest speed lever (even lower than TCP's 3).
DEFAULT_MAX_RETRIES = 2
DEFAULT_HOST_TIMEOUT = "60m"  # match TCP; UDP rarely hits it with low retries
DEFAULT_TIMING = "T4"


def run_ax_nmap_udp(target, prefix, fleet, **kwargs):
    """Run UDP port scan with configurable port selection.

    Args:
        target:    Target file containing hosts/IPs
        prefix:    Output file prefix
        fleet:     Axiom fleet name
        **kwargs:
            data_prefix: Override for output prefix
            ports:       Port selection — "top-N" for --top-ports N,
                         or comma-separated list (default: top-200)
            max_retries: nmap --max-retries (default: 2 — UDP retransmits
                         dominate runtime, so keep this low)
            min_rate:    nmap --min-rate packets/sec (default: unset/adaptive)
            timing:      nmap timing template T0-T5 (default: T4)
            host_timeout: nmap --host-timeout, e.g. 30m/600s (default: 30m)
    """
    prefix = kwargs.get('data_prefix', prefix)
    ports = validate_port_spec(kwargs.get('ports', DEFAULT_PORTS))

    if ports.startswith('top-'):
        n = ports.split('-', 1)[1]
        port_flag = f'--top-ports {n}'
        print(f'[*] Running UDP scan (top {n} ports)')
    else:
        port_flag = f'-p {ports}'
        print(f'[*] Running UDP scan (ports: {ports})')

    # Tuning knobs (validated before shell interpolation, same as ax_nmap_tcp).
    max_retries = _validate_int(
        kwargs.get('max_retries', DEFAULT_MAX_RETRIES), 0, 10, 'max_retries')
    host_timeout = _validate_timeout(kwargs.get('host_timeout', DEFAULT_HOST_TIMEOUT))
    timing = _validate_timing(kwargs.get('timing', DEFAULT_TIMING))
    timing_flags = [f'-{timing} --open --defeat-rst-ratelimit',
                    f'--max-retries {max_retries}',
                    f'--host-timeout {host_timeout}']
    min_rate = kwargs.get('min_rate')
    if min_rate not in (None, '', 0, '0'):
        timing_flags.append(f'--min-rate {_validate_int(min_rate, 1, 100000, "min_rate")}')

    cmd = (
        f"ax scan '{target}' --fleet '{fleet}' --expand-cidr "
        f"-oA '{prefix}-udpscan' -m nmapx "
        f"-Pn -sU {port_flag} {' '.join(timing_flags)}"
    )

    # ax scan can exit non-zero from a cosmetic cleanup step (e.g. `tput init`
    # failing in a non-TTY subprocess) even when the scan fully succeeded. Don't
    # discard results on exit code alone — merge what landed and judge on output.
    scan_error = None
    try:
        bash_command(cmd)
    except Exception as e:
        scan_error = str(e)
        print(f'[!] UDP scan command returned an error (verifying output anyway): {e}')

    print('[*] Merging nmap UDP results')
    merged_xml = f"{prefix}-udpscan.xml"
    try:
        merge_info = merge_nmap_folder(prefix, "udpscan", "UDP Scan")
    except Exception as merge_error:
        merge_info = {}
        print(f'[!] UDP merge step errored: {merge_error}')

    if scan_error and not (os.path.exists(merged_xml) and os.path.getsize(merged_xml) > 0):
        print('[!] UDP scan failed: command errored and produced no output')
        return {
            'module': 'ax_nmap_udp',
            'status': 'failed',
            'output_files': [],
            'error': scan_error,
        }

    uncovered = uncovered_ip_targets(target, merged_xml, f"{prefix}-udpscan")

    try:
        from core.nmap_service_parse import nmap_to_udphosts
        nmap_to_udphosts(f"{prefix}-udpscan.xml", prefix, "udp")
        result = {
            'module': 'ax_nmap_udp',
            'status': 'success',
            'output_files': [f"{prefix}-udpscan.xml"],
            'parsed_urls': f"{prefix}-udp-weburls.txt",
        }
        if uncovered:
            dropped = set((merge_info or {}).get('dropped_hosts') or [])
            cause = (" (some were lost in the nmap merge)"
                     if any(ip in dropped for ip in uncovered) else "")
            result['status'] = 'warning'
            result['warning'] = (
                f"ax_nmap_udp: {len(uncovered)} in-scope target(s) produced no results "
                f"and may not have been scanned/collected{cause}: {', '.join(uncovered)}. "
                f"Their UDP ports are NOT in the ledger — verify before assuming clean."
            )
            result['uncovered_targets'] = uncovered
        elif scan_error:
            # Results present despite a non-zero exit — kept, not discarded.
            result['status'] = 'warning'
            result['warning'] = (
                "ax_nmap_udp: the ax scan command exited non-zero but results were "
                f"collected, so they were kept (not discarded): {scan_error}")
        return result
    except Exception as parse_error:
        print(f"[!] UDP parsing failed: {parse_error}")
        return {
            'module': 'ax_nmap_udp',
            'status': 'success',
            'output_files': [f"{prefix}-udpscan.xml"],
            'warning': f'Parsing failed: {parse_error}',
        }
