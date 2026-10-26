"""Nuclei vulnerability scanning — web URLs AND network service endpoints.

Single nuclei pass: it scans the discovered web URLs (HTTP Host/SNI routes the
request to the client's tenant) together with the -t-authorized IP:port service
endpoints (SSH/SMTP/DBs and other name-blind protocols), so nuclei's HTTP and
network/service templates all fire from one module.

Because it points nuclei at raw IP:port on shared infrastructure (which can reach
co-tenants), this module is HOST-class (see core/scope_classes.py): the engine
remaps its open_ports_file to the -t-authorized-only host variant
(ledger-open-ports.host.txt) via _host_scoped_kwargs. The URL list (url_file) is
NAME-safe by nature (addressed by Host/SNI) and is never remapped, so full web
coverage is preserved while the IP:port surface stays -t-only.

Output: {prefix}-nuclei.jsonl (normalize's `*-nuclei.jsonl` glob picks it up).
"""

from core.utils import ax_local_config, bash_command
from modules._ax_common import _count_lines
import logging
import os

logger = logging.getLogger("monkeyx.modules.ax_nuclei")

# Empty: runs whenever the pipeline provides either URLs or open ports. A
# user-provided URL is not required (a -t-only run with open service ports still
# has network endpoints to scan).
REQUIRED_INPUTS = frozenset()
CONSUMES_URLS = True


def _iter_endpoints(open_ports_file):
    """Yield 'host:port' strings from the ledger open-ports file.

    ledger-open-ports(.host).txt format: 'host\\tport1,port2,...' — already
    scope-filtered (and, for the host variant this module receives, restricted
    to -t-authorized IPs) by the ledger export.
    """
    if not open_ports_file or not os.path.exists(open_ports_file):
        return
    try:
        with open(open_ports_file, encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line or "\t" not in line:
                    continue
                host, ports = line.split("\t", 1)
                host = host.strip()
                for p in ports.split(","):
                    p = p.strip()
                    if p.isdigit():
                        yield f"{host}:{p}"
    except OSError:
        pass


def run_ax_nuclei(prefix, fleet, url_file='./parsed-weburls.txt', **kwargs):
    """Run Nuclei against discovered web URLs and -t-authorized IP:port endpoints.

    Args:
        prefix: Output file prefix
        fleet: Name of the Axiom fleet
        url_file: File of URLs to scan (default: ./parsed-weburls.txt)
        **kwargs: reads open_ports_file (the -t-authorized host variant) for the
            network/service endpoints

    Returns:
        dict: Results of the Nuclei scan
    """
    prefix = kwargs.get('data_prefix', prefix)
    open_ports_file = kwargs.get('open_ports_file')

    # Collect targets from both sources, dedup while preserving discovery order.
    seen: set[str] = set()
    targets: list[str] = []

    if url_file and os.path.exists(url_file) and _count_lines(url_file) > 0:
        try:
            with open(url_file, encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    u = line.strip()
                    if u and u not in seen:
                        seen.add(u)
                        targets.append(u)
        except OSError as e:
            logger.warning("ax_nuclei could not read URL file '%s': %s", url_file, e)

    for ep in _iter_endpoints(open_ports_file):
        if ep not in seen:
            seen.add(ep)
            targets.append(ep)

    if not targets:
        # No URLs and no in-scope open ports: nothing to scan. An empty target
        # list makes `ax scan` hand interlace an empty file and exit 0, which
        # would otherwise log as a false success — skip honestly instead.
        msg = ("ax_nuclei: no URLs or in-scope open ports to scan — skipping. "
               "Provide -url/--url-list or run a scanning module first.")
        print(f'[*] {msg}')
        return {
            'module': 'ax_nuclei',
            'status': 'skipped',
            'output_files': [],
            'warning': msg
        }

    targets_file = f"{prefix}-nuclei-targets.txt"
    try:
        with open(targets_file, "w", encoding="utf-8") as fh:
            fh.write("\n".join(targets) + "\n")
    except OSError as e:
        msg = f"ax_nuclei could not write target list '{targets_file}': {e}"
        print(f'[!] {msg}')
        return {
            'module': 'ax_nuclei',
            'status': 'failed',
            'output_files': [],
            'error': msg
        }

    print(f'[*] Running Nuclei vulnerability scan on {len(targets)} targets (web URLs + IP:port)')

    out = f"{prefix}-nuclei.jsonl"
    nuclei_cmd = (f"ax scan '{targets_file}' --fleet '{fleet}' --expand-cidr "
                  f"-m nuclei -oJ '{out}'{ax_local_config('nuclei')}")

    try:
        bash_command(nuclei_cmd)
    except Exception as e:
        print(f'[!] Nuclei scan failed: {e}')
        return {
            'module': 'ax_nuclei',
            'status': 'failed',
            'output_files': [],
            'error': str(e)
        }

    # A missing/empty -oJ file is downgraded success->warning centrally in
    # workflows.run_module, so it isn't re-checked here.
    return {
        'module': 'ax_nuclei',
        'status': 'success',
        'output_files': [out]
    }
