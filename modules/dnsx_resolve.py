"""DNS resolution via locally installed dnsx.

Runs dnsx directly (locally) rather than distributing via ax scan. Use when the
fleet is unreliable or unnecessary.

Inputs (target file): mixed IPs, CIDRs, hostnames. Hostnames go to dnsx for
resolution; IPs/CIDRs are passed through. Subdomains discovered earlier
(subfinder, ax_puredns_bruteforce) are picked up from the data dir automatically.

After forward resolution, runs PTR (reverse DNS) on all IPs (passthrough +
resolved) to discover hostnames associated with each IP.

Outputs:
  {prefix}-dnsx-resolve.txt          raw dnsx JSONL (one line per hostname)
  {prefix}-dnsx-ptr.txt              raw dnsx PTR JSONL (one line per IP)
  {prefix}-resolve-report.jsonl      normalized report
  {prefix}-resolved-targets.txt      flat list of resolved IPs (name-safe:
                                     in-scope by the name that resolved to them;
                                     only port-scanned if a -t range owns the IP)
"""

import logging
import os

from core.dns_helpers import (
    load_puredns_bruteforce_output,
    load_subfinder_output,
    parse_dnsx_jsonl,
    parse_ptr_output,
    parse_target_file,
    snapshot_actual_input,
    write_resolve_outputs,
)
from core.utils import bash_command

logger = logging.getLogger("monkeyx.modules.dnsx_resolve")

REQUIRED_INPUTS = frozenset()


def _hostnames_from_url_file(url_file):
    """Extract resolvable hostnames from a URL list (one URL/host per line).

    Returns the set of DNS names appearing as URL hosts. Bare IP-literal hosts
    are skipped (there's nothing to resolve). Used so a URL-only (-url) run still
    resolves the names behind its web surface.
    """
    from ipaddress import ip_address
    from urllib.parse import urlparse

    hosts = set()
    if not url_file or not os.path.exists(url_file):
        return hosts
    with open(url_file) as f:
        for line in f:
            u = line.strip()
            if not u or u.startswith("#"):
                continue
            if "://" in u:
                host = urlparse(u).hostname
            else:
                # bare host or host:port/path
                host = u.split("/", 1)[0].split(":", 1)[0]
            if not host:
                continue
            host = host.rstrip(".")
            try:
                ip_address(host)
                continue  # IP literal — nothing to resolve
            except ValueError:
                pass
            hosts.add(host)
    return hosts


def run_dnsx_resolve(target=None, prefix=None, **kwargs):
    """Resolve hostnames to IPs via locally installed dnsx."""
    prefix = kwargs.get("data_prefix", prefix)
    scope_filter = kwargs.get("scope_filter", "strict")

    print(f"[*] Running dnsx_resolve (local, scope_filter={scope_filter})")
    logger.info("dnsx_resolve: scope_filter=%s", scope_filter)

    if target and os.path.exists(target):
        scope_networks, hostnames, passthrough_ips = parse_target_file(target)
    else:
        scope_networks, hostnames, passthrough_ips = [], set(), set()
    logger.info("Parsed targets: %d networks, %d hostnames, %d passthrough IPs",
                len(scope_networks), len(hostnames), len(passthrough_ips))

    subfinder_hosts = load_subfinder_output(prefix)
    bruteforce_hosts = load_puredns_bruteforce_output(prefix)
    all_hostnames = hostnames | subfinder_hosts | bruteforce_hosts

    domainlist = kwargs.get("domainlist")
    if domainlist and os.path.exists(domainlist):
        with open(domainlist) as f:
            for line in f:
                d = line.strip()
                if d and not d.startswith("#"):
                    all_hostnames.add(d)

    # URL-only runs (-url) carry their hostnames inside the URL strings, not in a
    # target/domain file — without this, dnsx_resolve resolved nothing and
    # resolved-targets.txt shipped empty. Extract each URL's host (name-safe:
    # resolving a name never touches an out-of-scope IP) so the IPs behind the
    # in-scope web surface land in the ledger. IP-literal hosts are skipped
    # (nothing to resolve).
    url_hosts = _hostnames_from_url_file(kwargs.get("url_file"))
    if url_hosts:
        logger.info("dnsx_resolve: %d hostname(s) extracted from url_file", len(url_hosts))
    all_hostnames |= url_hosts

    logger.info("Total hostnames to resolve: %d (subfinder=%d, bruteforce=%d)",
                len(all_hostnames), len(subfinder_hosts), len(bruteforce_hosts))

    if not all_hostnames:
        ptr_map = {}
        if passthrough_ips:
            ptr_map = _run_ptr_lookups(passthrough_ips, prefix)
        return write_resolve_outputs(
            prefix, "dnsx_resolve", passthrough_ips, [], scope_networks,
            scope_filter, ptr_map=ptr_map,
        )

    input_file = f"{prefix}-dnsx-resolve-input.txt"
    with open(input_file, "w") as f:
        for h in sorted(all_hostnames):
            f.write(h + "\n")
    print(f"[*] dnsx_resolve: resolving {len(all_hostnames)} hostnames")
    snapshot_actual_input(input_file, prefix, "dnsx_resolve")

    output_file = f"{prefix}-dnsx-resolve.txt"
    cmd = f"dnsx -l '{input_file}' -j -o '{output_file}' -a -aaaa -cname -mx -txt -soa"

    try:
        bash_command(cmd)
    except Exception as e:
        logger.error("dnsx_resolve failed: %s", e)
        print(f"[!] dnsx_resolve failed: {e}")
        return {
            "module": "dnsx_resolve",
            "status": "failed",
            "output_files": [],
            "error": str(e),
        }

    if not os.path.exists(output_file):
        print("[!] dnsx_resolve: no output file produced")
        return {
            "module": "dnsx_resolve",
            "status": "failed",
            "output_files": [],
            "error": "No output file produced",
        }

    dnsx_records = parse_dnsx_jsonl(output_file)
    logger.info("dnsx returned %d records", len(dnsx_records))

    all_ips_for_ptr = set(passthrough_ips)
    for rec in dnsx_records:
        for ip in (rec.get("a") or []):
            all_ips_for_ptr.add(ip)

    ptr_map = {}
    if all_ips_for_ptr:
        ptr_map = _run_ptr_lookups(all_ips_for_ptr, prefix)

    return write_resolve_outputs(
        prefix, "dnsx_resolve", passthrough_ips, dnsx_records, scope_networks,
        scope_filter, raw_output=output_file, ptr_map=ptr_map,
    )


def _run_ptr_lookups(ips: set, prefix: str) -> dict[str, list[str]]:
    """Run dnsx -ptr locally on a set of IPs. Returns {ip: [hostname, ...]}."""
    if not ips:
        return {}

    ptr_input = f"{prefix}-dnsx-ptr-input.txt"
    ptr_output = f"{prefix}-dnsx-ptr.txt"

    with open(ptr_input, "w") as f:
        for ip in sorted(ips):
            f.write(ip + "\n")

    print(f"[*] dnsx_resolve: running PTR lookups on {len(ips)} IPs")
    logger.info("PTR lookup on %d IPs", len(ips))

    cmd = f"dnsx -l '{ptr_input}' -ptr -j -o '{ptr_output}'"

    try:
        bash_command(cmd)
    except Exception as e:
        logger.warning("PTR lookup failed: %s", e)
        print(f"[!] dnsx_resolve PTR failed (non-fatal): {e}")
        return {}

    ptr_map = parse_ptr_output(ptr_output)
    ptr_count = sum(len(v) for v in ptr_map.values())
    print(f"[+] PTR lookups: {ptr_count} hostnames for {len(ptr_map)} IPs")
    logger.info("PTR results: %d hostnames for %d IPs", ptr_count, len(ptr_map))

    snapshot_actual_input(ptr_input, prefix, "dnsx_resolve_ptr")
    return ptr_map
