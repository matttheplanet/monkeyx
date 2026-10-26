"""Dry-run synthetic output generators for MonkeyX modules.

Produces minimal but format-correct output files so the full orchestration
pipeline (ledger, discovery extraction, URL aggregation, normalize, analyze)
exercises real code paths without running actual scanning tools.
"""

import json
import os
import time

SYNTHETIC_HOSTS = [
    ("10.0.0.1", "web.example.com"),
    ("10.0.0.2", "api.example.com"),
    ("10.0.0.3", "mail.example.com"),
]

SYNTHETIC_SUBDOMAINS = [
    ("dev.example.com", "example.com"),
    ("staging.example.com", "example.com"),
    ("admin.example.com", "example.com"),
]

SYNTHETIC_PORTS = [
    (80, "http", "nginx/1.25.3"),
    (443, "https", "nginx/1.25.3"),
    (22, "ssh", "OpenSSH 8.9p1"),
    (8080, "http-proxy", ""),
    (3389, "ms-wbt-server", ""),
]

PASSTHROUGH_MODULES = frozenset({"normalize", "analyze", "jsonl_to_csv", "nmap_converter"})


def generate_synthetic_output(module_name: str, **kwargs) -> dict:
    """Dispatch to the appropriate fixture generator for a module."""
    time.sleep(0.05)

    generators = {
        "ax_nmap_tcp": _gen_nmap,
        "ax_nmap_udp": _gen_nmap_udp,
        "ax_live_host_discovery": _gen_live_hosts,
        "ax_naabu": _gen_naabu,
        "subfinder": _gen_subfinder,
        "dns_resolve": _gen_dns_resolve,
        "dnsx_resolve": _gen_dnsx_resolve,
        "ax_puredns_bruteforce": _gen_puredns_bruteforce,
        "ax_nuclei": _gen_nuclei,
        "ax_gowitness": _gen_gowitness,
        "ax_ffuf": _gen_ffuf,
        "ax_feroxbuster": _gen_feroxbuster,
    }

    gen = generators.get(module_name, _gen_generic)
    return gen(module_name, **kwargs)


def _prefix(kwargs):
    return kwargs.get('data_prefix', kwargs.get('prefix', './dryrun'))


def _reports_prefix(kwargs):
    return kwargs.get('reports_prefix', kwargs.get('prefix', './dryrun'))


def _read_targets(kwargs):
    """Read current targets from the target file if available."""
    target_file = kwargs.get('target')
    if target_file and os.path.exists(target_file):
        with open(target_file) as f:
            return [l.strip() for l in f if l.strip() and not l.startswith('#')]
    return [h[0] for h in SYNTHETIC_HOSTS]


def _read_urls(kwargs):
    """Read current URLs from url_file if available."""
    url_file = kwargs.get('url_file')
    if url_file and os.path.exists(url_file):
        with open(url_file) as f:
            return [l.strip() for l in f if l.strip() and not l.startswith('#')]
    return [f"http://{h[0]}" for h in SYNTHETIC_HOSTS]


_NMAP_MODULE_IDS = {
    "ax_nmap_tcp": "tcpscan",
}


def _gen_nmap(module_name: str, **kwargs) -> dict:
    prefix = _prefix(kwargs)
    module_id = _NMAP_MODULE_IDS.get(module_name, "scan")

    hosts_xml = ""
    alive = []
    urls = []
    for ip, hostname in SYNTHETIC_HOSTS:
        ports_xml = ""
        for port, svc, product in SYNTHETIC_PORTS[:3]:
            tunnel = ' tunnel="ssl"' if svc == "https" else ""
            product_attr = f' product="{product}"' if product else ""
            ports_xml += (
                f'      <port protocol="tcp" portid="{port}">'
                f'<state state="open"/>'
                f'<service name="{svc}"{tunnel}{product_attr}/>'
                f'</port>\n'
            )
            if svc in ("http", "http-proxy"):
                urls.append(f"http://{ip}:{port}" if port != 80 else f"http://{ip}")
            elif svc == "https":
                urls.append(f"https://{ip}:{port}" if port != 443 else f"https://{ip}")
        hosts_xml += (
            f'  <host><status state="up" reason="syn-ack"/>\n'
            f'    <address addr="{ip}" addrtype="ipv4"/>\n'
            f'    <hostnames><hostname name="{hostname}" type="PTR"/></hostnames>\n'
            f'    <ports>\n{ports_xml}    </ports>\n'
            f'  </host>\n'
        )
        alive.append(ip)

    xml_content = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE nmaprun>\n'
        '<nmaprun scanner="nmap" args="nmap -sS --dry-run" start="1700000000" version="7.94">\n'
        f'{hosts_xml}'
        '</nmaprun>\n'
    )

    xml_path = f"{prefix}-{module_id}.xml"
    os.makedirs(os.path.dirname(xml_path) or '.', exist_ok=True)
    with open(xml_path, 'w') as f:
        f.write(xml_content)

    alive_path = f"{prefix}-{module_id}-alive-hosts.txt"
    with open(alive_path, 'w') as f:
        for ip in alive:
            f.write(ip + "\n")

    url_path = f"{prefix}-{module_id}-weburls.txt"
    with open(url_path, 'w') as f:
        for u in urls:
            f.write(u + "\n")

    print(f"  [DRY-RUN] Generated synthetic nmap output ({len(alive)} hosts, {len(urls)} URLs)")
    return {
        'module': module_name,
        'status': 'success',
        'output_files': [xml_path, alive_path, url_path],
        'parsed_urls': url_path,
    }


def _gen_nmap_udp(module_name: str, **kwargs) -> dict:
    prefix = _prefix(kwargs)

    hosts_xml = ""
    alive = []
    for ip, hostname in SYNTHETIC_HOSTS[:2]:
        hosts_xml += (
            f'  <host><status state="up" reason="udp-response"/>\n'
            f'    <address addr="{ip}" addrtype="ipv4"/>\n'
            f'    <hostnames><hostname name="{hostname}" type="PTR"/></hostnames>\n'
            f'    <ports>\n'
            f'      <port protocol="udp" portid="53"><state state="open"/>'
            f'<service name="domain"/></port>\n'
            f'      <port protocol="udp" portid="161"><state state="open"/>'
            f'<service name="snmp"/></port>\n'
            f'    </ports>\n'
            f'  </host>\n'
        )
        alive.append(ip)

    xml_content = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE nmaprun>\n'
        '<nmaprun scanner="nmap" args="nmap -sU --dry-run" start="1700000000" version="7.94">\n'
        f'{hosts_xml}'
        '</nmaprun>\n'
    )

    xml_path = f"{prefix}-udp.xml"
    os.makedirs(os.path.dirname(xml_path) or '.', exist_ok=True)
    with open(xml_path, 'w') as f:
        f.write(xml_content)

    alive_path = f"{prefix}-udp-alive-hosts.txt"
    with open(alive_path, 'w') as f:
        for ip in alive:
            f.write(ip + "\n")

    print(f"  [DRY-RUN] Generated synthetic UDP nmap output ({len(alive)} hosts)")
    return {
        'module': module_name,
        'status': 'success',
        'output_files': [xml_path, alive_path],
    }


def _gen_live_hosts(module_name: str, **kwargs) -> dict:
    prefix = _prefix(kwargs)
    targets = _read_targets(kwargs)

    alive_path = f"{prefix}-live-hosts.txt"
    os.makedirs(os.path.dirname(alive_path) or '.', exist_ok=True)
    with open(alive_path, 'w') as f:
        for t in targets:
            f.write(t + "\n")

    print(f"  [DRY-RUN] Generated {len(targets)} live hosts")
    return {
        'module': module_name,
        'status': 'success',
        'output_files': [alive_path],
        'live_hosts': alive_path,
    }


def _gen_naabu(module_name: str, **kwargs) -> dict:
    prefix = _prefix(kwargs)
    targets = _read_targets(kwargs)

    lines = []
    for t in targets[:3]:
        for port, _, _ in SYNTHETIC_PORTS[:3]:
            lines.append(f"{t}:{port}")

    naabu_path = f"{prefix}-naabu.txt"
    os.makedirs(os.path.dirname(naabu_path) or '.', exist_ok=True)
    with open(naabu_path, 'w') as f:
        for line in lines:
            f.write(line + "\n")

    alive_path = f"{prefix}-naabu-live-hosts.txt"
    with open(alive_path, 'w') as f:
        for t in targets[:3]:
            f.write(t + "\n")

    print(f"  [DRY-RUN] Generated naabu output ({len(lines)} host:port pairs)")
    return {
        'module': module_name,
        'status': 'success',
        'output_files': [naabu_path, alive_path],
        'live_hosts': alive_path,
    }


def _gen_subfinder(module_name: str, **kwargs) -> dict:
    prefix = _prefix(kwargs)

    records = []
    for subdomain, parent in SYNTHETIC_SUBDOMAINS:
        records.append({"host": subdomain, "input": parent, "source": "crtsh"})

    jsonl_path = f"{prefix}-subfinder.jsonl"
    os.makedirs(os.path.dirname(jsonl_path) or '.', exist_ok=True)
    with open(jsonl_path, 'w') as f:
        for rec in records:
            f.write(json.dumps(rec) + "\n")

    print(f"  [DRY-RUN] Generated {len(records)} subfinder discoveries")
    return {
        'module': module_name,
        'status': 'success',
        'output_files': [jsonl_path],
    }


def _gen_dns_resolve(module_name: str, **kwargs) -> dict:
    prefix = _prefix(kwargs)

    resolved_ips = []
    report_records = []
    for subdomain, _ in SYNTHETIC_SUBDOMAINS:
        ip = f"10.0.1.{len(resolved_ips) + 1}"
        resolved_ips.append(ip)
        report_records.append({
            "hostname": subdomain,
            "ip": ip,
            "status": "resolved",
            "in_scope": True,
        })

    for ip, hostname in SYNTHETIC_HOSTS:
        report_records.append({
            "hostname": hostname,
            "ip": ip,
            "status": "resolved",
            "in_scope": True,
        })

    resolved_path = f"{prefix}-resolved-targets.txt"
    os.makedirs(os.path.dirname(resolved_path) or '.', exist_ok=True)
    with open(resolved_path, 'w') as f:
        for ip, _ in SYNTHETIC_HOSTS:
            f.write(ip + "\n")
        for ip in resolved_ips:
            f.write(ip + "\n")

    report_path = f"{prefix}-resolve-report.jsonl"
    with open(report_path, 'w') as f:
        for rec in report_records:
            f.write(json.dumps(rec) + "\n")

    print(f"  [DRY-RUN] Generated dns_resolve output ({len(report_records)} resolutions)")
    return {
        'module': module_name,
        'status': 'success',
        'output_files': [resolved_path, report_path],
        'resolved_target_file': resolved_path,
    }


def _gen_dnsx_resolve(module_name: str, **kwargs) -> dict:
    """Synthesize dnsx -recon -j JSONL output + the same resolve-report shape
    the live dnsx_resolve module produces.
    """
    prefix = _prefix(kwargs)
    os.makedirs(os.path.dirname(prefix) or '.', exist_ok=True)

    raw_path = f"{prefix}-dnsx-resolve.txt"
    resolved_path = f"{prefix}-resolved-targets.txt"
    report_path = f"{prefix}-resolve-report.jsonl"

    raw_records = []
    report_records = []
    resolved_ips = set()
    counter = 0

    for subdomain, _ in SYNTHETIC_SUBDOMAINS:
        counter += 1
        ip = f"10.0.1.{counter}"
        cname = f"origin-{counter}.cdn.example.com"
        raw_records.append({
            "host": subdomain,
            "a": [ip],
            "cname": [cname],
            "ns": ["ns1.example.com", "ns2.example.com"],
            "asn": {"as-number": "AS13335", "as-name": "CLOUDFLARENET",
                    "as-country": "US"},
            "wildcard": False,
        })
        report_records.append({
            "hostname": subdomain,
            "ip": ip,
            "status": "resolved",
            "in_scope": True,
            "scope_action": "included",
            "a": [ip],
            "cname": [cname],
            "asn": {"as-number": "AS13335", "as-name": "CLOUDFLARENET",
                    "as-country": "US"},
            "wildcard": False,
        })
        resolved_ips.add(ip)

    for ip, hostname in SYNTHETIC_HOSTS:
        raw_records.append({
            "host": hostname,
            "a": [ip],
            "wildcard": False,
        })
        report_records.append({
            "hostname": hostname,
            "ip": ip,
            "status": "resolved",
            "in_scope": True,
            "scope_action": "included",
            "a": [ip],
        })
        resolved_ips.add(ip)

    with open(raw_path, 'w') as f:
        for rec in raw_records:
            f.write(json.dumps(rec) + "\n")

    with open(resolved_path, 'w') as f:
        for ip in sorted(resolved_ips):
            f.write(ip + "\n")

    with open(report_path, 'w') as f:
        for rec in report_records:
            f.write(json.dumps(rec) + "\n")

    print(f"  [DRY-RUN] Generated dnsx_resolve output "
          f"({len(report_records)} resolutions, {len(resolved_ips)} IPs)")
    return {
        'module': module_name,
        'status': 'success',
        'output_files': [resolved_path, report_path, raw_path],
        'resolved_target_file': resolved_path,
        'target_count': len(resolved_ips),
        'in_scope_count': len(report_records),
    }


def _gen_puredns_bruteforce(module_name: str, **kwargs) -> dict:
    """Synthesize puredns bruteforce output — discovered subdomains (one per line)."""
    prefix = _prefix(kwargs)
    os.makedirs(os.path.dirname(prefix) or '.', exist_ok=True)

    raw_path = f"{prefix}-puredns-bruteforce.txt"
    hosts_path = f"{prefix}-puredns-bruteforce-hosts.txt"

    fake_subs = ["api", "admin", "dev", "staging", "vpn", "mail"]
    discovered = set()

    domainlist = kwargs.get('domainlist')
    domains = []
    if domainlist and os.path.exists(domainlist):
        with open(domainlist) as f:
            for line in f:
                d = line.strip()
                if d and not d.startswith("#"):
                    domains.append(d)
    if not domains:
        domains = ["example.com"]

    for domain in domains[:3]:
        for sub in fake_subs:
            discovered.add(f"{sub}.{domain}")

    with open(raw_path, 'w') as f:
        for h in sorted(discovered):
            f.write(h + "\n")

    with open(hosts_path, 'w') as f:
        for h in sorted(discovered):
            f.write(h + "\n")

    print(f"  [DRY-RUN] Generated ax_puredns_bruteforce output "
          f"({len(discovered)} subdomains)")
    return {
        'module': module_name,
        'status': 'success',
        'output_files': [raw_path, hosts_path],
        'discovered_hosts_file': hosts_path,
        'discovered_count': len(discovered),
    }


def _gen_nuclei(module_name: str, **kwargs) -> dict:
    prefix = _prefix(kwargs)
    urls = _read_urls(kwargs)

    findings = [
        {"template-id": "cve-2024-1234", "info": {"name": "Example RCE", "severity": "critical"},
         "matched-at": urls[0] if urls else "http://10.0.0.1", "host": "10.0.0.1", "type": "http"},
        {"template-id": "misconfig-cors", "info": {"name": "CORS Misconfiguration", "severity": "medium"},
         "matched-at": urls[1] if len(urls) > 1 else "http://10.0.0.2", "host": "10.0.0.2", "type": "http"},
        {"template-id": "tech-detect-nginx", "info": {"name": "Nginx Detected", "severity": "info"},
         "matched-at": urls[0] if urls else "http://10.0.0.1", "host": "10.0.0.1", "type": "http"},
    ]

    jsonl_path = f"{prefix}-nuclei.jsonl"
    os.makedirs(os.path.dirname(jsonl_path) or '.', exist_ok=True)
    with open(jsonl_path, 'w') as f:
        for finding in findings:
            f.write(json.dumps(finding) + "\n")

    print(f"  [DRY-RUN] Generated {len(findings)} nuclei findings")
    return {
        'module': module_name,
        'status': 'success',
        'output_files': [jsonl_path],
    }


def _gen_gowitness(module_name: str, **kwargs) -> dict:
    prefix = _reports_prefix(kwargs)

    out_dir = f"{prefix}-gowitness"
    os.makedirs(out_dir, exist_ok=True)

    db_path = os.path.join(out_dir, "gowitness.sqlite3")
    with open(db_path, 'w') as f:
        f.write("")

    print(f"  [DRY-RUN] Generated gowitness output directory")
    return {
        'module': module_name,
        'status': 'success',
        'output_files': [out_dir],
    }


def _gen_ffuf(module_name: str, **kwargs) -> dict:
    prefix = _prefix(kwargs)
    urls = _read_urls(kwargs)
    base_url = urls[0] if urls else "http://10.0.0.1"

    findings = [
        {"input": {"FUZZ": "admin"}, "url": f"{base_url}/admin", "status": 200, "length": 4521, "words": 312},
        {"input": {"FUZZ": "login"}, "url": f"{base_url}/login", "status": 200, "length": 2103, "words": 156},
        {"input": {"FUZZ": ".env"}, "url": f"{base_url}/.env", "status": 200, "length": 89, "words": 12},
    ]

    jsonl_path = f"{prefix}-ffuf.jsonl"
    os.makedirs(os.path.dirname(jsonl_path) or '.', exist_ok=True)
    with open(jsonl_path, 'w') as f:
        for finding in findings:
            f.write(json.dumps(finding) + "\n")

    print(f"  [DRY-RUN] Generated {len(findings)} ffuf discoveries")
    return {
        'module': module_name,
        'status': 'success',
        'output_files': [jsonl_path],
    }


def _gen_feroxbuster(module_name: str, **kwargs) -> dict:
    prefix = _prefix(kwargs)
    urls = _read_urls(kwargs)
    base_url = urls[0] if urls else "http://10.0.0.1"

    lines = [
        f"200      GET      312l      1024w     15234c {base_url}/api/v1",
        f"200      GET       45l       200w      3456c {base_url}/robots.txt",
        f"301      GET        0l         0w         0c {base_url}/static => {base_url}/static/",
    ]

    txt_path = f"{prefix}-feroxbuster.txt"
    os.makedirs(os.path.dirname(txt_path) or '.', exist_ok=True)
    with open(txt_path, 'w') as f:
        for line in lines:
            f.write(line + "\n")

    print(f"  [DRY-RUN] Generated {len(lines)} feroxbuster discoveries")
    return {
        'module': module_name,
        'status': 'success',
        'output_files': [txt_path],
    }


def _gen_generic(module_name: str, **kwargs) -> dict:
    """Fallback for unknown modules — return success with no output files."""
    print(f"  [DRY-RUN] No fixture for '{module_name}', returning empty success")
    return {
        'module': module_name,
        'status': 'success',
        'output_files': [],
    }
