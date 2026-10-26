"""DNS resolution module with scope filtering and wildcard detection."""

import concurrent.futures
import ipaddress
import logging
import json
import os
import random
import string
from datetime import datetime, timezone

from core.utils import version_output_path

logger = logging.getLogger('monkeyx.modules.dns_resolve')

REQUIRED_INPUTS = frozenset({"target"})

NAMESERVERS = ["8.8.8.8", "1.1.1.1", "9.9.9.9", "8.8.4.4", "1.0.0.1"]
RESOLVE_TIMEOUT = 5
MAX_WORKERS = 50
WILDCARD_TEST_COUNT = 3


def run_dns_resolve(target, prefix, **kwargs):
    """Resolve hostnames to IPs, filter by scope, detect wildcards.

    Args:
        target: Path to target file (IPs, CIDRs, hostnames mixed)
        prefix: Output file prefix
        **kwargs:
            scope_filter: "none", "warn", or "strict" (default: "warn")
            domainlist: Path to domain list file (for wildcard detection)
            data_prefix: Override for output prefix

    Returns:
        dict: Results with resolved target file for downstream modules
    """
    import dns.resolver
    import dns.exception

    prefix = kwargs.get('data_prefix', prefix)
    scope_filter = kwargs.get('scope_filter', 'strict')

    print(f'[*] Running dns_resolve module (scope_filter={scope_filter})')
    logger.info(f"dns_resolve: scope_filter={scope_filter}")

    # Parse target file into IPs/CIDRs and hostnames
    scope_networks, hostnames, passthrough_ips = _parse_target_file(target)
    logger.info(f"Parsed targets: {len(scope_networks)} networks, "
                f"{len(hostnames)} hostnames, {len(passthrough_ips)} IPs")

    # Also grab subdomains from subfinder output if available
    subfinder_hosts = _load_subfinder_output(prefix)
    all_hostnames = hostnames | subfinder_hosts

    # Load domains/subdomains from domainlist (ledger-exported or user-provided)
    domains = set()
    domainlist = kwargs.get('domainlist')
    if domainlist and os.path.exists(domainlist):
        with open(domainlist) as f:
            for line in f:
                d = line.strip()
                if d and not d.startswith('#'):
                    domains.add(d)
                    all_hostnames.add(d)

    logger.info(f"Total hostnames to resolve: {len(all_hostnames)} "
                f"({len(subfinder_hosts)} from subfinder, {len(domains)} from domainlist)")

    # Infer parent domains from hostnames
    for h in all_hostnames:
        parts = h.split('.')
        if len(parts) >= 2:
            domains.add('.'.join(parts[-2:]))

    wildcard_domains = _detect_wildcards(domains, dns, NAMESERVERS)
    if wildcard_domains:
        print(f'[!] Wildcard DNS detected for: {", ".join(sorted(wildcard_domains))}')
        logger.warning(f"Wildcard domains detected: {wildcard_domains}")

    # Resolve all hostnames concurrently
    print(f'[*] Resolving {len(all_hostnames)} hostnames...')
    resolution_results = _resolve_all(all_hostnames, dns, NAMESERVERS)

    # Build results
    resolved_targets = set(passthrough_ips)
    report_entries = []
    in_scope_count = 0
    out_of_scope_count = 0
    no_resolve_count = 0
    wildcard_filtered_count = 0

    for hostname, result in resolution_results.items():
        if result['status'] == 'resolved':
            for ip in result['ips']:
                is_wildcard = _is_wildcard_result(hostname, ip, wildcard_domains)
                if is_wildcard:
                    wildcard_filtered_count += 1
                    report_entries.append({
                        'hostname': hostname,
                        'ip': ip,
                        'status': 'wildcard_filtered',
                        'in_scope': False,
                        'wildcard_domain': _get_parent_domain(hostname, wildcard_domains),
                    })
                    continue

                in_scope = _ip_in_scope(ip, scope_networks)

                if in_scope:
                    resolved_targets.add(ip)
                    in_scope_count += 1
                elif scope_filter == 'none':
                    resolved_targets.add(ip)
                    in_scope_count += 1
                elif scope_filter == 'warn':
                    resolved_targets.add(ip)
                    out_of_scope_count += 1
                else:  # strict
                    out_of_scope_count += 1

                report_entries.append({
                    'hostname': hostname,
                    'ip': ip,
                    'status': 'resolved',
                    'in_scope': in_scope,
                    'scope_action': 'included' if ip in resolved_targets else 'excluded',
                })
        else:
            no_resolve_count += 1
            report_entries.append({
                'hostname': hostname,
                'ip': None,
                'status': result['status'],
                'in_scope': False,
                'error': result.get('error'),
            })

    # Write outputs
    resolved_target_file = f"{prefix}-resolved-targets.txt"
    report_file = f"{prefix}-resolve-report.jsonl"

    version_output_path(resolved_target_file)
    with open(resolved_target_file, 'w') as f:
        for ip in sorted(resolved_targets):
            f.write(ip + '\n')

    version_output_path(report_file)
    now = datetime.now(timezone.utc).isoformat()
    with open(report_file, 'w') as f:
        for entry in report_entries:
            entry['resolved_at'] = now
            entry['scope_filter_mode'] = scope_filter
            f.write(json.dumps(entry) + '\n')

    # Summary
    print(f'[+] Resolution complete:')
    print(f'    Resolved IPs: {len(resolved_targets)} (passthrough: {len(passthrough_ips)})')
    print(f'    In-scope: {in_scope_count}, Out-of-scope: {out_of_scope_count}')
    print(f'    No resolution: {no_resolve_count}')
    print(f'    Wildcard filtered: {wildcard_filtered_count}')
    if scope_filter == 'warn' and out_of_scope_count > 0:
        print(f'[!] WARNING: {out_of_scope_count} IPs are outside provided scope (included anyway)')
    elif scope_filter == 'strict' and out_of_scope_count > 0:
        print(f'[!] STRICT: {out_of_scope_count} IPs excluded (outside provided scope)')

    logger.info(f"dns_resolve complete: {len(resolved_targets)} targets, "
                f"in_scope={in_scope_count}, out_of_scope={out_of_scope_count}, "
                f"no_resolve={no_resolve_count}, wildcard={wildcard_filtered_count}")

    return {
        'module': 'dns_resolve',
        'status': 'success',
        'output_files': [resolved_target_file, report_file],
        'resolved_target_file': resolved_target_file,
        'target_count': len(resolved_targets),
        'in_scope_count': in_scope_count,
        'out_of_scope_count': out_of_scope_count,
        'no_resolve_count': no_resolve_count,
        'wildcard_filtered_count': wildcard_filtered_count,
        'wildcard_domains': sorted(wildcard_domains),
    }


def _parse_target_file(target_path):
    """Split target file into scope networks, hostnames, and passthrough IPs."""
    scope_networks = []
    hostnames = set()
    passthrough_ips = set()

    with open(target_path) as f:
        for line in f:
            entry = line.strip()
            if not entry or entry.startswith('#'):
                continue

            if '/' in entry:
                try:
                    net = ipaddress.ip_network(entry, strict=False)
                    scope_networks.append(net)
                    # Don't add CIDRs to passthrough — they define scope, not scan targets individually
                except ValueError:
                    hostnames.add(entry)
            elif _is_ip(entry):
                passthrough_ips.add(entry)
                # Single IPs also define scope
                try:
                    scope_networks.append(ipaddress.ip_network(entry + '/32', strict=False))
                except ValueError:
                    pass
            else:
                hostnames.add(entry)

    return scope_networks, hostnames, passthrough_ips


def _is_ip(value):
    """Check if a string is a valid IP address."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _ip_in_scope(ip_str, scope_networks):
    """Check if an IP falls within any of the scope networks."""
    if not scope_networks:
        return True
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in scope_networks)
    except ValueError:
        return False


def _load_subfinder_output(prefix):
    """Load subdomains from subfinder output if it exists."""
    hosts = set()
    prefix_dir = os.path.dirname(prefix) if os.path.dirname(prefix) else '.'

    # Check for subfinder JSONL output
    for name in os.listdir(prefix_dir) if os.path.isdir(prefix_dir) else []:
        if 'subfinder' in name and name.endswith('.jsonl'):
            path = os.path.join(prefix_dir, name)
            try:
                with open(path) as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        if line.startswith('{'):
                            try:
                                record = json.loads(line)
                                host = record.get('host', '')
                                if host:
                                    hosts.add(host)
                            except json.JSONDecodeError:
                                pass
                        else:
                            hosts.add(line)
            except Exception as e:
                logger.warning(f"Failed to read subfinder output {path}: {e}")

    # Also check plain text subfinder output
    for name in os.listdir(prefix_dir) if os.path.isdir(prefix_dir) else []:
        if 'subfinder' in name and name.endswith('.txt'):
            path = os.path.join(prefix_dir, name)
            try:
                with open(path) as f:
                    for line in f:
                        h = line.strip()
                        if h and not h.startswith('#'):
                            hosts.add(h)
            except Exception as e:
                logger.warning(f"Failed to read subfinder output {path}: {e}")

    return hosts


def _detect_wildcards(domains, dns_module, nameservers):
    """Detect wildcard DNS for a set of domains."""
    wildcard_domains = set()

    for domain in domains:
        wildcard_ips = set()
        detected = True

        for _ in range(WILDCARD_TEST_COUNT):
            random_sub = ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
            test_host = f"{random_sub}.{domain}"
            ips = _resolve_single(test_host, dns_module, nameservers)
            if ips is None:
                detected = False
                break
            wildcard_ips.update(ips)

        if detected and wildcard_ips:
            wildcard_domains.add(domain)
            logger.info(f"Wildcard detected for {domain}: resolves to {wildcard_ips}")

    return wildcard_domains


def _is_wildcard_result(hostname, ip, wildcard_domains):
    """Check if a resolution is likely a wildcard response."""
    for wd in wildcard_domains:
        if hostname.endswith('.' + wd) or hostname == wd:
            return True
    return False


def _get_parent_domain(hostname, wildcard_domains):
    """Get the wildcard domain a hostname falls under."""
    for wd in wildcard_domains:
        if hostname.endswith('.' + wd) or hostname == wd:
            return wd
    return None


def _resolve_single(hostname, dns_module, nameservers):
    """Resolve a single hostname. Returns set of IPs or None on failure."""
    resolver = dns_module.resolver.Resolver()
    resolver.nameservers = nameservers
    resolver.timeout = RESOLVE_TIMEOUT
    resolver.lifetime = RESOLVE_TIMEOUT

    try:
        answers = resolver.resolve(hostname, 'A')
        return {rdata.address for rdata in answers}
    except (dns_module.resolver.NXDOMAIN, dns_module.resolver.NoAnswer,
            dns_module.resolver.NoNameservers, dns_module.exception.Timeout):
        return None
    except Exception:
        return None


def _resolve_all(hostnames, dns_module, nameservers):
    """Resolve all hostnames concurrently. Returns dict of hostname -> result."""
    results = {}

    def _do_resolve(hostname):
        resolver = dns_module.resolver.Resolver()
        resolver.nameservers = list(nameservers)
        random.shuffle(resolver.nameservers)
        resolver.timeout = RESOLVE_TIMEOUT
        resolver.lifetime = RESOLVE_TIMEOUT

        try:
            answers = resolver.resolve(hostname, 'A')
            ips = [rdata.address for rdata in answers]
            return hostname, {'status': 'resolved', 'ips': ips}
        except dns_module.resolver.NXDOMAIN:
            return hostname, {'status': 'nxdomain', 'ips': [], 'error': 'NXDOMAIN'}
        except dns_module.resolver.NoAnswer:
            return hostname, {'status': 'no_answer', 'ips': [], 'error': 'No A record'}
        except dns_module.resolver.NoNameservers:
            return hostname, {'status': 'servfail', 'ips': [], 'error': 'SERVFAIL'}
        except dns_module.exception.Timeout:
            return hostname, {'status': 'timeout', 'ips': [], 'error': 'Timeout'}
        except Exception as e:
            return hostname, {'status': 'error', 'ips': [], 'error': str(e)}

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(_do_resolve, h) for h in hostnames]
        for future in concurrent.futures.as_completed(futures):
            hostname, result = future.result()
            results[hostname] = result

    return results
