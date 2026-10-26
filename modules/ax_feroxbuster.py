"""Feroxbuster directory brute force module."""

from core.utils import bash_command, shell_safe_str
from modules._ax_common import _count_lines, _resolve_timeout
import os
import re

# Wall-clock backstop for the whole ax fan-out (the tool-side --time-limit below
# only bounds a single scan, not the orchestration). Override via
# modules.ax_feroxbuster.timeout.
DEFAULT_TIMEOUT = 3600

REQUIRED_INPUTS = frozenset({"url_file"})
CONSUMES_URLS = True

# feroxbuster recurses by default — on a wildcard/soft-404 host or a deep tree it
# can run effectively forever (the "freezing" you see). These conservative
# defaults bound it: cap recursion depth, hard-stop after a while, and bail on a
# target that floods errors. All are tunable / disable-able via monkeyx.config
# (modules.ax_feroxbuster). They are passed as feroxbuster flags on the ax
# command; if your ax build does NOT forward tool flags, set `tuning: false` to
# fall back to the plain invocation (and instead bake the limits into the ax
# feroxbuster module template).
_DEFAULT_DEPTH = 2          # recursion depth cap (feroxbuster default is 4)
_DEFAULT_TIME_LIMIT = "15m"  # hard stop per scan
_TIME_LIMIT_RE = re.compile(r"^\d+[smhd]?$")   # e.g. 30s, 15m, 2h


def _ferox_flags(kwargs) -> str:
    """Build the (validated, shell-safe) feroxbuster tuning flag string.

    All numeric knobs are cast to int (so no shell metacharacters survive) and
    time_limit is format-checked; anything invalid falls back to the default or
    is dropped. Returns "" (no extra flags) when tuning is disabled."""
    if not kwargs.get("tuning", True):
        return ""
    flags = []

    def _int(name, default=0):
        try:
            return int(kwargs.get(name, default))
        except (TypeError, ValueError):
            return default

    depth = _int("depth", _DEFAULT_DEPTH)
    if depth and depth > 0:
        flags.append(f"--depth {depth}")

    tl = str(kwargs.get("time_limit", _DEFAULT_TIME_LIMIT)).strip()
    if tl and _TIME_LIMIT_RE.match(tl):
        flags.append(f"--time-limit {tl}")

    if kwargs.get("auto_bail", True):
        flags.append("--auto-bail")

    for knob, flag in (("scan_limit", "--scan-limit"),
                       ("threads", "--threads"),
                       ("rate_limit", "--rate-limit")):
        v = _int(knob, 0)
        if v > 0:
            flags.append(f"{flag} {v}")

    return (" " + " ".join(flags)) if flags else ""


def run_ax_feroxbuster(prefix, fleet, url_file='./parsed-weburls.txt', wordlist='/home/op/lists/seclists/Discovery/Web-Content/common.txt', **kwargs):
    """Run Feroxbuster directory brute forcing on discovered web services.

    Args:
        prefix: Output file prefix
        fleet: Name of the Axiom fleet
        url_file: File containing URLs to scan (default: ./parsed-weburls.txt)
        wordlist: Path to wordlist file (default: common.txt from SecLists)
        **kwargs: tuning knobs (depth, time_limit, auto_bail, scan_limit,
                  threads, rate_limit, tuning) — see _ferox_flags.

    Returns:
        dict: Results of the Feroxbuster scan
    """
    if not os.path.exists(url_file):
        msg = (f"Feroxbuster requires a URL file but '{url_file}' does not exist. "
               f"Provide one with -url/--url-list or run a scanning module first.")
        print(f'[!] {msg}')
        return {
            'module': 'ax_feroxbuster',
            'status': 'failed',
            'output_files': [],
            'error': msg
        }
    if _count_lines(url_file) == 0:
        # Present-but-empty URL file → ax hands interlace an empty target list,
        # which aborts before the fleet is reached (ax still exits 0). Skip
        # honestly rather than log a false success.
        msg = f"Feroxbuster URL file '{url_file}' is empty — nothing to scan, skipping."
        print(f'[*] {msg}')
        return {
            'module': 'ax_feroxbuster',
            'status': 'skipped',
            'output_files': [],
            'warning': msg
        }

    prefix = kwargs.get('data_prefix', prefix)
    # wordlist is single-quote-wrapped into the ax command but can arrive from
    # monkeyx.config / workflow YAML args unsanitized — reject shell-breaking chars.
    shell_safe_str(wordlist)
    flags = _ferox_flags(kwargs)
    print('[*] Running Feroxbuster directory brute force module')
    print(f'[*] Using wordlist: {wordlist} (on remote Axiom fleet)')
    if flags:
        print(f'[*] Recursion/runtime limits:{flags}')

    feroxbuster_cmd = (
        f"ax scan '{url_file}' --fleet '{fleet}' -m feroxbuster -w '{wordlist}'"
        f"{flags} -o '{prefix}-feroxbuster.txt'")
    timeout = _resolve_timeout('ax_feroxbuster', kwargs.get('timeout')) or DEFAULT_TIMEOUT

    try:
        bash_command(feroxbuster_cmd, timeout=timeout)
        return {
            'module': 'ax_feroxbuster',
            'status': 'success',
            'output_files': [f"{prefix}-feroxbuster.txt"],
            'wordlist': wordlist
        }
    except Exception as e:
        print(f'[!] Feroxbuster scan failed: {e}')
        return {
            'module': 'ax_feroxbuster',
            'status': 'failed',
            'output_files': [],
            'error': str(e)
        }
