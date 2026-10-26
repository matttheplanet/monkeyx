"""Ffuf directory and file fuzzing module."""

from core.utils import bash_command, shell_safe_str
from modules._ax_common import _count_lines, _resolve_timeout
import os

REQUIRED_INPUTS = frozenset({"url_file"})
CONSUMES_URLS = True

# Wall-clock backstop (this module shells out directly, so it's otherwise
# invisible to fleet.ax_timeout). Override via modules.ax_ffuf.timeout.
DEFAULT_TIMEOUT = 3600


def run_ax_ffuf(prefix, fleet, url_file='./parsed-weburls.txt', wordlist='/home/op/lists/seclists/Discovery/Web-Content/common.txt', **kwargs):
    """Run Ffuf directory and file fuzzing on discovered web services.
    
    Args:
        prefix: Output file prefix
        fleet: Name of the Axiom fleet
        url_file: File containing URLs to scan (default: ./parsed-weburls.txt)
        wordlist: Path to wordlist file (default: common.txt from SecLists)
        **kwargs: Additional arguments
        
    Returns:
        dict: Results of the Ffuf scan
    """
    prefix = kwargs.get('data_prefix', prefix)
    # wordlist is single-quote-wrapped into the ax command but can arrive from
    # monkeyx.config / workflow YAML args unsanitized — reject shell-breaking chars.
    shell_safe_str(wordlist)
    if not os.path.exists(url_file):
        msg = (f"Ffuf requires a URL file but '{url_file}' does not exist. "
               f"Provide one with -url/--url-list or run a scanning module first.")
        print(f'[!] {msg}')
        return {
            'module': 'ax_ffuf',
            'status': 'failed',
            'output_files': [],
            'error': msg
        }
    if _count_lines(url_file) == 0:
        # Present-but-empty URL file → ax hands interlace an empty target list,
        # which aborts before the fleet is reached (ax still exits 0). Skip
        # honestly rather than log a false success.
        msg = f"Ffuf URL file '{url_file}' is empty — nothing to scan, skipping."
        print(f'[*] {msg}')
        return {
            'module': 'ax_ffuf',
            'status': 'skipped',
            'output_files': [],
            'warning': msg
        }

    print('[*] Running Ffuf directory and file fuzzing module')
    print(f'[*] Using wordlist: {wordlist} (on remote Axiom fleet)')
    
    ffuf_cmd = f"ax scan '{url_file}' --fleet '{fleet}' -m ffuf -w '{wordlist}' -oJ '{prefix}-ffuf.jsonl'"
    timeout = _resolve_timeout('ax_ffuf', kwargs.get('timeout')) or DEFAULT_TIMEOUT

    try:
        bash_command(ffuf_cmd, timeout=timeout)
        return {
            'module': 'ax_ffuf',
            'status': 'success',
            'output_files': [f"{prefix}-ffuf.jsonl"],
            'wordlist': wordlist
        }
    except Exception as e:
        print(f'[!] Ffuf scan failed: {e}')
        return {
            'module': 'ax_ffuf',
            'status': 'failed',
            'output_files': [],
            'error': str(e)
        }