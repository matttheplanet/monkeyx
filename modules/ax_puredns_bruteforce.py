"""DNS subdomain bruteforce via puredns running across the ax fleet.

Distributed across the fleet via the built-in `puredns-bruteforce` ax module.
The wordlist is passed with `-w` (configurable via the `wordlist` kwarg /
monkeyx.config); resolvers are configured on the fleet nodes and not passed.

Inputs:
    domainlist (required) — file with one domain per line. Each domain is
    bruteforced independently against the wordlist.

Outputs:
    {prefix}-puredns-bruteforce.txt   raw puredns output (one subdomain per line)
"""

import logging
import os
import subprocess

from core.utils import bash_command, shell_safe_str

logger = logging.getLogger("monkeyx.modules.ax_puredns_bruteforce")

REQUIRED_INPUTS = frozenset({"domainlist"})

DEFAULT_WORDLIST = "/home/op/lists/seclists/Discovery/DNS/subdomains-top1million-110000.txt"

# Bound the puredns run so a resolver stall (dead/rate-limited resolvers, the
# common "stuck for hours" cause) fails cleanly instead of hanging the whole
# scan. puredns is pure DNS resolution — minutes, not hours — so: 30 min floor,
# +60s per base domain being bruteforced, capped at 2 h. Override with the
# `puredns_timeout` kwarg (seconds; 0/blank/invalid => no timeout).
_PUREDNS_TIMEOUT_FLOOR = 1800      # 30 min
_PUREDNS_TIMEOUT_PER_DOMAIN = 60   # +1 min per base domain
_PUREDNS_TIMEOUT_CAP = 7200        # 2 h


def _puredns_timeout(n_domains, override=None):
    """Resolve the subprocess timeout (seconds) — scaled by base-domain count."""
    if override is not None:
        try:
            val = int(override)
        except (TypeError, ValueError):
            val = None
        else:
            return val if val > 0 else None   # 0 => no timeout
    return min(max(_PUREDNS_TIMEOUT_FLOOR, n_domains * _PUREDNS_TIMEOUT_PER_DOMAIN),
               _PUREDNS_TIMEOUT_CAP)


def run_ax_puredns_bruteforce(domainlist, prefix, fleet, **kwargs):
    """Bruteforce subdomains for each domain via puredns on the fleet.

    Args:
        domainlist: Path to a file with one domain per line
        prefix:     Output file prefix
        fleet:      Axiom fleet name
        **kwargs:
            data_prefix: Override for output prefix
            wordlist:    Path to wordlist file (default: seclists DNS top 110k)
            puredns_timeout: Max seconds before the run is killed (default scales
                with base-domain count: 30 min floor, +60s/domain, 2 h cap;
                0 = no timeout).
    """
    prefix = kwargs.get("data_prefix", prefix)
    wordlist = kwargs.get("wordlist", DEFAULT_WORDLIST)
    # wordlist is single-quote-wrapped into the ax command but can arrive from
    # monkeyx.config / workflow YAML args unsanitized — reject shell-breaking chars.
    shell_safe_str(wordlist)
    print("[*] Running ax_puredns_bruteforce module")

    if not os.path.exists(domainlist):
        msg = f"Domainlist '{domainlist}' does not exist"
        print(f"[!] {msg}")
        return {
            "module": "ax_puredns_bruteforce",
            "status": "failed",
            "output_files": [],
            "error": msg,
        }

    output_file = f"{prefix}-puredns-bruteforce.txt"

    try:
        with open(domainlist, encoding="utf-8", errors="ignore") as fh:
            n_domains = sum(1 for line in fh if line.strip())
    except OSError:
        n_domains = 0
    timeout = _puredns_timeout(n_domains, kwargs.get("puredns_timeout"))
    if timeout:
        print(f"[*] ax_puredns_bruteforce: {n_domains} base domain(s), timeout {timeout}s")

    cmd = f"ax scan '{domainlist}' --fleet '{fleet}' -m puredns-bruteforce -w '{wordlist}' -o '{output_file}'"

    try:
        bash_command(cmd, timeout=timeout)
    except subprocess.TimeoutExpired:
        # Almost always dead/rate-limited resolvers or a wildcard-heavy domain —
        # NOT a clean "no subdomains". Fail honestly with the remedy rather than
        # hang the run; raise puredns_timeout or refresh the fleet's resolver list.
        msg = (f"puredns bruteforce exceeded its {timeout}s timeout and was killed "
               f"({n_domains} base domain(s)) — usually dead/rate-limited resolvers "
               f"or a wildcard-heavy domain. Refresh the fleet's resolver list, or "
               f"raise it via the puredns_timeout arg (0 = no timeout).")
        logger.error("ax_puredns_bruteforce timed out after %ss", timeout)
        print(f"[!] {msg}")
        return {
            "module": "ax_puredns_bruteforce",
            "status": "failed",
            "output_files": [],
            "error": msg,
        }
    except Exception as e:
        logger.error("ax_puredns_bruteforce scan failed: %s", e)
        print(f"[!] ax_puredns_bruteforce scan failed: {e}")
        return {
            "module": "ax_puredns_bruteforce",
            "status": "failed",
            "output_files": [],
            "error": str(e),
        }

    if not os.path.exists(output_file):
        print("[!] ax_puredns_bruteforce: no output file produced")
        return {
            "module": "ax_puredns_bruteforce",
            "status": "failed",
            "output_files": [],
            "error": "No output file produced",
        }

    # Extract discovered subdomains
    hosts = set()
    try:
        with open(output_file) as f:
            for line in f:
                host = line.strip()
                if host:
                    hosts.add(host)
    except Exception as e:
        logger.warning("Could not parse puredns output: %s", e)

    hosts_file = f"{prefix}-puredns-bruteforce-sorted.txt"
    with open(hosts_file, "w") as f:
        for h in sorted(hosts):
            f.write(h + "\n")

    print(f"[+] ax_puredns_bruteforce: discovered {len(hosts)} subdomains")

    return {
        "module": "ax_puredns_bruteforce",
        "status": "success",
        "output_files": [output_file, hosts_file],
        "discovered_hosts_file": hosts_file,
        "discovered_count": len(hosts),
    }
