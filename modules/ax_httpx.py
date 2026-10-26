"""httpx web probing module — fingerprints live web services for filtering and intelligence."""

from core.utils import ax_local_config, bash_command
from modules._ax_common import _count_lines
import os

REQUIRED_INPUTS = frozenset({"url_file"})
CONSUMES_URLS = True


def run_ax_httpx(prefix, fleet, url_file='./parsed-weburls.txt', **kwargs):
    """Run httpx against discovered web services for fingerprinting and filtering.

    Args:
        prefix: Output file prefix
        fleet: Name of the Axiom fleet
        url_file: File containing URLs to probe (default: ./parsed-weburls.txt)
        **kwargs: Additional arguments

    Returns:
        dict: Results of the httpx probe
    """
    prefix = kwargs.get('data_prefix', prefix)
    if not os.path.exists(url_file):
        msg = (f"httpx requires a URL file but '{url_file}' does not exist. "
               f"Provide one with -url/--url-list or run a scanning module first.")
        print(f'[!] {msg}')
        return {
            'module': 'ax_httpx',
            'status': 'failed',
            'output_files': [],
            'error': msg
        }
    if _count_lines(url_file) == 0:
        # Present-but-empty URL file → ax hands interlace an empty target list,
        # which aborts before the fleet is reached (ax still exits 0). Skip
        # honestly rather than log a false success.
        msg = f"httpx URL file '{url_file}' is empty — nothing to probe, skipping."
        print(f'[*] {msg}')
        return {
            'module': 'ax_httpx',
            'status': 'skipped',
            'output_files': [],
            'warning': msg
        }

    print('[*] Running httpx web probing module')

    httpx_flags = (
        '-status-code -title -tech-detect -web-server -content-length '
        '-hash md5 -cdn -tls-grab -favicon -location -follow-redirects '
        '-content-type -j'
    )

    httpx_cmd = (
        f"ax scan '{url_file}' --fleet '{fleet}' "
        f"-oJ '{prefix}-httpx.jsonl' "
        f"-m httpx {httpx_flags}"
        f"{ax_local_config('httpx')}"
    )

    try:
        bash_command(httpx_cmd)
        return {
            'module': 'ax_httpx',
            'status': 'success',
            'output_files': [f"{prefix}-httpx.jsonl"],
        }
    except Exception as e:
        print(f'[!] httpx probe failed: {e}')
        return {
            'module': 'ax_httpx',
            'status': 'failed',
            'output_files': [],
            'error': str(e)
        }
