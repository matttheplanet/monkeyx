"""Fleet-distributed subfinder subdomain enumeration.

Runs subfinder across the ax fleet for faster enumeration of large domain
lists. Uses -oJ for JSONL output compatible with downstream modules
(normalize, dnsx_resolve).

Inputs:  domainlist (file of root domains)
Outputs: {prefix}-subfinder-output.jsonl (one JSON line per subdomain)
"""

import logging
import os

from core.utils import ax_local_config, bash_command

logger = logging.getLogger("monkeyx.modules.ax_subfinder")

REQUIRED_INPUTS = frozenset({"domainlist"})


def run_ax_subfinder(domainlist=None, prefix=None, fleet=None, **kwargs):
    """Run subfinder across the ax fleet for subdomain enumeration."""
    prefix = kwargs.get("data_prefix", prefix)

    if not domainlist or not os.path.exists(domainlist):
        print("[!] ax_subfinder: no domainlist provided")
        return {
            "module": "ax_subfinder",
            "status": "failed",
            "output_files": [],
            "error": "No domainlist file",
        }

    if not fleet:
        print("[!] ax_subfinder: no fleet specified")
        return {
            "module": "ax_subfinder",
            "status": "failed",
            "output_files": [],
            "error": "No fleet specified",
        }

    with open(domainlist) as f:
        domain_count = sum(1 for line in f if line.strip() and not line.startswith("#"))

    print(f"[*] Running ax_subfinder: {domain_count} domains across fleet '{fleet}'")

    output_file = f"{prefix}-subfinder-output.jsonl"
    cmd = (
        f"ax scan '{domainlist}' --fleet '{fleet}' -m subfinder "
        f"-o '{output_file}' --extra-args '-oJ'"
        f"{ax_local_config('subfinder')}"
    )
    try:
        bash_command(cmd)
    except Exception as e:
        logger.error("ax_subfinder failed: %s", e)
        print(f"[!] ax_subfinder failed: {e}")
        return {
            "module": "ax_subfinder",
            "status": "failed",
            "output_files": [],
            "error": str(e),
        }

    if not os.path.exists(output_file):
        print("[!] ax_subfinder: no output file produced")
        return {
            "module": "ax_subfinder",
            "status": "failed",
            "output_files": [],
            "error": "No output file produced",
        }

    line_count = 0
    try:
        with open(output_file) as f:
            line_count = sum(1 for line in f if line.strip())
    except OSError:
        pass

    print(f"[+] ax_subfinder complete: {line_count} subdomains discovered")
    logger.info("ax_subfinder: %d subdomains from %d domains", line_count, domain_count)

    return {
        "module": "ax_subfinder",
        "status": "success",
        "output_files": [output_file],
    }
