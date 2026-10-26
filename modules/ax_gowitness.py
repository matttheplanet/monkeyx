"""Gowitness web screenshot module."""

from core.utils import bash_command
from modules._ax_common import _count_lines, _resolve_timeout
from modules.ax_nmap_tcp import _validate_int
import os

REQUIRED_INPUTS = frozenset({"url_file"})
CONSUMES_URLS = True

# Wall-clock backstop so a hung headless-Chromium node can't block the pipeline
# forever (this module shells out directly, so it's otherwise invisible to
# fleet.ax_timeout). Overridable via modules.ax_gowitness.timeout / fleet.ax_timeout.
DEFAULT_TIMEOUT = 3600
# Cap concurrent headless Chromium. gowitness defaults to ~6; on 2GB fleet nodes
# that OOMs. Forwarded to gowitness as `--threads N` (ax forwards tool flags,
# same as the nmap module). Overridable via modules.ax_gowitness.threads.
DEFAULT_THREADS = 2


def run_ax_gowitness(prefix, fleet, url_file='./parsed-weburls.txt', **kwargs):
    """Run Gowitness to capture screenshots of web services.
    
    Args:
        prefix: Output file prefix
        fleet: Name of the Axiom fleet
        url_file: File containing URLs to screenshot (default: ./parsed-weburls.txt)
        **kwargs: Additional arguments
        
    Returns:
        dict: Results of the Gowitness scan
    """
    prefix = kwargs.get('reports_prefix', prefix)
    if not os.path.exists(url_file):
        msg = (f"Gowitness requires a URL file but '{url_file}' does not exist. "
               f"Provide one with -url/--url-list or run a scanning module first.")
        print(f'[!] {msg}')
        return {
            'module': 'ax_gowitness',
            'status': 'failed',
            'output_files': [],
            'error': msg
        }
    if _count_lines(url_file) == 0:
        # Present-but-empty URL file → ax hands interlace an empty target list,
        # which aborts before the fleet is reached (ax still exits 0). Skip
        # honestly rather than log a false success.
        msg = f"Gowitness URL file '{url_file}' is empty — nothing to scan, skipping."
        print(f'[*] {msg}')
        return {
            'module': 'ax_gowitness',
            'status': 'skipped',
            'output_files': [],
            'warning': msg
        }

    print('[*] Running Gowitness screenshot module')
    
    threads = _validate_int(kwargs.get('threads', DEFAULT_THREADS), 1, 16, 'threads')
    gowitness_cmd = (f"ax scan '{url_file}' --fleet '{fleet}' --expand-cidr "
                     f"-m gowitness --threads {threads} -o '{prefix}-gowitness'")
    timeout = _resolve_timeout('ax_gowitness', kwargs.get('timeout')) or DEFAULT_TIMEOUT

    try:
        bash_command(gowitness_cmd, timeout=timeout)
        return {
            'module': 'ax_gowitness',
            'status': 'success',
            'output_files': [f"{prefix}-gowitness"]  # Directory
        }
    except Exception as e:
        print(f'[!] Gowitness scan failed: {e}')
        return {
            'module': 'ax_gowitness',
            'status': 'failed',
            'output_files': [],
            'error': str(e)
        }
