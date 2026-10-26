"""Programmatic analysis module for MonkeyX scan results.

Consumes the JSONL files produced by the normalize module and generates
a structured analysis report (JSON) with service categorization,
scan comparison, and severity roll-ups.

Outlier ports (ports open on very few hosts — potential dev/forgotten services)
are surfaced by `_find_outlier_ports`, which ignores services nmap labels
`tcpwrapped`: that state means the TCP handshake completed but no service banner
was returned (commonly a firewall/wrapper closing the connection), so it is not a
reliable service signal and would otherwise generate false-positive outliers.
"""

import glob
import json
import logging
import os
import re
from collections import defaultdict
from datetime import datetime, timezone

from core.utils import version_output_path
from modules.normalize import dedup_findings

logger = logging.getLogger('monkeyx.modules.analyze')

REQUIRED_INPUTS = frozenset()


def _read_jsonl(path):
    """Read a JSONL file and return list of dicts."""
    records = []
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
    except OSError:
        pass
    return records




def _compare_baseline_vs_full(nmap_records):
    """Detect ports present in baseline scan but missing from full scan.

    This indicates possible blocking/rate-limiting during the longer full scan.
    """
    baseline_ports = defaultdict(set)
    full_ports = defaultdict(set)

    for rec in nmap_records:
        if rec.get('type') != 'open_port':
            continue
        src = (rec.get('source_file') or '').lower()
        host = rec.get('host', '')
        port = rec.get('port')
        if not host or port is None:
            continue

        if 'baseline' in src:
            baseline_ports[host].add(port)
        elif 'full' in src or 'tcpfull' in src:
            full_ports[host].add(port)

    if not baseline_ports or not full_ports:
        return []

    disappeared = []
    for host, b_ports in baseline_ports.items():
        f_ports = full_ports.get(host, set())
        missing = b_ports - f_ports
        if missing:
            disappeared.append({
                'host': host,
                'ports_in_baseline_not_in_full': sorted(missing),
            })

    return disappeared


def _find_mx_domains(data_prefix):
    """Find domains with MX records.

    Prefers the ledger-exported file (ledger-mx-domains.txt + ledger JSONL for
    MX host details). Falls back to reading raw dnsx JSONL directly.
    """
    mx_domains = {}

    # Try ledger JSONL first — has mx_domain entries with mx_hosts field
    data_dir = os.path.dirname(data_prefix)
    ledger_path = os.path.join(data_dir, '..', 'discovery-ledger.jsonl')
    if not os.path.exists(ledger_path):
        ledger_path = os.path.join(data_dir, 'discovery-ledger.jsonl')
    if os.path.exists(ledger_path):
        try:
            with open(ledger_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if entry.get('type') == 'mx_domain':
                        domain = entry.get('target', '')
                        mx_hosts = entry.get('mx_hosts', [])
                        if domain and mx_hosts:
                            mx_domains[domain] = mx_hosts
        except OSError:
            pass

    if mx_domains:
        return mx_domains

    # Fallback: read raw dnsx JSONL output directly
    dnsx_files = glob.glob(f"{data_prefix}*-dnsx-resolve.txt")
    for path in dnsx_files:
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line or not line.startswith('{'):
                        continue
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    mx_records = rec.get('mx') or []
                    if mx_records and rec.get('host'):
                        mx_domains[rec['host']] = [
                            mx if isinstance(mx, str) else mx.get('host', str(mx))
                            for mx in mx_records
                        ]
        except OSError:
            continue
    return mx_domains


_LOGIN_KEYWORDS = re.compile(
    r'login|sign.?in|auth|password|credential|sso|cas|adfs|okta|keycloak|saml',
    re.IGNORECASE,
)

_LOGIN_NUCLEI_TAGS = {'login', 'panel', 'default-login', 'default-credentials',
                      'auth', 'oauth', 'sso'}

_LOGIN_NMAP_SCRIPTS = {'http-auth', 'http-auth-finder', 'http-default-accounts'}


def _find_login_panels(nmap_records, nuclei_records):
    """Identify login pages and authentication endpoints.

    Sources:
    - Nuclei findings tagged with login/panel/default-login
    - Nuclei template IDs containing login/panel/auth keywords
    - Nmap script output from http-auth, http-title with login keywords
    """
    logins = []
    seen = set()

    # Nuclei login findings
    for rec in nuclei_records:
        template_id = (rec.get('template_id') or '').lower()
        tags = (rec.get('tags') or '').lower()
        title = (rec.get('title') or '').lower()
        matched_at = rec.get('matched_at', '')

        tag_set = {t.strip() for t in tags.split(',') if t.strip()}
        is_login = (
            tag_set & _LOGIN_NUCLEI_TAGS
            or _LOGIN_KEYWORDS.search(template_id)
            or _LOGIN_KEYWORDS.search(title)
        )

        if is_login and matched_at:
            key = ('nuclei', matched_at, template_id)
            if key not in seen:
                seen.add(key)
                logins.append({
                    'url': matched_at,
                    'source': 'nuclei',
                    'template_id': rec.get('template_id', ''),
                    'title': rec.get('title', ''),
                    'severity': rec.get('severity', 'info'),
                    'host': rec.get('host', ''),
                })

    # Nmap script output (http-auth, http-title with login keywords)
    for rec in nmap_records:
        if rec.get('type') != 'script_output':
            continue

        method = (rec.get('method') or '').lower()
        detail = (rec.get('detail') or '')
        host = rec.get('host', '')
        port = rec.get('port')

        is_login_script = method in _LOGIN_NMAP_SCRIPTS
        is_login_title = method == 'http-title' and _LOGIN_KEYWORDS.search(detail)

        if is_login_script or is_login_title:
            key = ('nmap', host, port, method)
            if key not in seen:
                seen.add(key)
                logins.append({
                    'url': f"{host}:{port}" if port else host,
                    'source': 'nmap',
                    'template_id': method,
                    'title': detail[:200],
                    'severity': 'info',
                    'host': host,
                })

    return logins


def _build_password_spray_section(data_prefix, nmap_records, nuclei_records, bbot_records=None):
    """Build the password spraying intelligence section."""
    mx_domains = _find_mx_domains(data_prefix)
    login_panels = _find_login_panels(nmap_records, nuclei_records)

    emails = []
    for rec in (bbot_records or []):
        if rec.get("type") == "email":
            email = rec.get("detail", "")
            if email and email not in emails:
                emails.append(email)

    return {
        'mx_domains': mx_domains,
        'login_panels': login_panels,
        'emails': emails,
    }


def _nuclei_severity_stats(nuclei_records):
    """Count nuclei findings by severity."""
    counts = defaultdict(int)
    for rec in nuclei_records:
        sev = (rec.get('severity') or 'unknown').lower()
        counts[sev] += 1
    return dict(counts)



def _build_port_service_stats(nmap_records):
    """Build port and service frequency counts from nmap records."""
    port_counts = defaultdict(int)
    service_counts = defaultdict(int)
    sv_counts = defaultdict(int)

    for rec in nmap_records:
        if rec.get('type') != 'open_port':
            continue
        port = rec.get('port')
        proto = rec.get('proto', 'tcp')
        service = rec.get('service') or ''
        product = rec.get('product') or ''
        version = rec.get('version') or ''

        if port is not None:
            port_counts[f"{port}/{proto}"] += 1
        if service:
            service_counts[service] += 1
        if service and product and version:
            sv_counts[(service, product, version)] += 1

    service_version_list = [
        {"service": s, "product": p, "version": v, "count": c}
        for (s, p, v), c in sorted(sv_counts.items(), key=lambda x: x[1], reverse=True)
    ]

    return {
        'port_counts': dict(sorted(port_counts.items(), key=lambda x: x[1], reverse=True)),
        'service_counts': dict(sorted(service_counts.items(), key=lambda x: x[1], reverse=True)),
        'service_version_counts': service_version_list,
    }


def _build_os_fingerprint(nmap_records):
    """Group hosts by detected operating system from banners/service info."""
    _OS_PATTERNS = [
        (re.compile(r'windows|win32|win64|microsoft|ms-wbt', re.I), 'Windows'),
        (re.compile(r'linux|ubuntu|debian|centos|red\s?hat|fedora|suse|arch|alpine|gentoo', re.I), 'Linux'),
        (re.compile(r'freebsd|openbsd|netbsd', re.I), 'BSD'),
        (re.compile(r'cisco|ios|nx-?os|asa', re.I), 'Cisco'),
        (re.compile(r'fortinet|fortios|fortigate', re.I), 'Fortinet'),
        (re.compile(r'juniper|junos', re.I), 'Juniper'),
        (re.compile(r'palo.?alto|pan-?os', re.I), 'Palo Alto'),
        (re.compile(r'vmware|esxi|vcenter', re.I), 'VMware'),
        (re.compile(r'hp-ux|hpux|procurve|aruba', re.I), 'HP'),
        (re.compile(r'solaris|sunos', re.I), 'Solaris'),
        (re.compile(r'macos|darwin|apple', re.I), 'macOS'),
        (re.compile(r'android', re.I), 'Android'),
        (re.compile(r'mikrotik|routeros', re.I), 'MikroTik'),
        (re.compile(r'ubiquiti|unifi', re.I), 'Ubiquiti'),
    ]

    os_to_hosts = defaultdict(set)

    for rec in nmap_records:
        if rec.get('type') != 'open_port':
            continue
        host = rec.get('host', '')
        banner = (rec.get('detail') or '') + ' ' + (rec.get('service') or '')

        for pattern, os_name in _OS_PATTERNS:
            if pattern.search(banner):
                os_to_hosts[os_name].add(host)

    return {os_name: sorted(hosts) for os_name, hosts in
            sorted(os_to_hosts.items(), key=lambda x: len(x[1]), reverse=True)}


def _find_http_methods(nmap_records):
    """Identify dangerous HTTP methods from nmap http-methods script output."""
    _DANGEROUS_METHODS = {'PUT', 'DELETE', 'TRACE', 'MOVE', 'COPY', 'PROPFIND',
                          'PROPPATCH', 'MKCOL', 'LOCK', 'UNLOCK'}

    findings = []
    seen = set()
    for rec in nmap_records:
        if rec.get('type') != 'script_output':
            continue
        method = (rec.get('method') or '').lower()
        if method != 'http-methods':
            continue

        detail = rec.get('detail') or ''
        host = rec.get('host', '')
        port = rec.get('port')

        found_methods = set()
        for m in _DANGEROUS_METHODS:
            if m in detail.upper():
                found_methods.add(m)

        if found_methods:
            key = (host, port)
            if key not in seen:
                seen.add(key)
                findings.append({
                    'host': host,
                    'port': port,
                    'methods': sorted(found_methods),
                    'detail': detail[:300],
                })

    return findings


def _find_default_creds_and_anon_access(nmap_records):
    """Identify services with default credentials or anonymous/unauthenticated access."""
    _ANON_SCRIPTS = {
        'ftp-anon', 'smb-enum-shares', 'http-default-accounts',
        'mongodb-databases', 'redis-info', 'memcached-info',
        'couchdb-databases', 'cassandra-info',
    }
    _ANON_KEYWORDS = re.compile(
        r'anonymous|guest\s*access|no\s*auth|no\s*password|default\s*(password|cred)|'
        r'unauthenticated|login\s*not\s*required|access\s*allowed|world.readable',
        re.IGNORECASE,
    )

    findings = []
    seen = set()
    for rec in nmap_records:
        if rec.get('type') != 'script_output':
            continue
        method = (rec.get('method') or '').lower()
        detail = rec.get('detail') or ''
        host = rec.get('host', '')
        port = rec.get('port')

        is_anon_script = method in _ANON_SCRIPTS
        has_anon_keyword = _ANON_KEYWORDS.search(detail)

        if is_anon_script or has_anon_keyword:
            key = (host, port, method)
            if key not in seen:
                seen.add(key)
                findings.append({
                    'host': host,
                    'port': port,
                    'script': method,
                    'detail': detail[:500],
                })

    return findings


def _find_ssl_tls_issues(nmap_records):
    """Identify SSL/TLS weaknesses from nmap script output."""
    # Scripts we look at at all. The weak-cipher/protocol check ONLY applies to
    # ssl-enum-ciphers; cert-hygiene checks apply to ssl-cert / ssl-date.
    _SSL_SCRIPTS = {'ssl-cert', 'ssl-enum-ciphers', 'ssl-date'}
    _CIPHER_SCRIPTS = {'ssl-enum-ciphers'}
    # MD5 is deliberately NOT in this list. Running a case-insensitive 'MD5'
    # against ssl-cert output previously matched the 'MD5:' fingerprint label
    # (and 'md5' base64 fragments) in the certificate body and produced a bogus
    # "weak cipher on N hosts" finding — a real false-positive that shipped into
    # the AI recon report. Cipher suites that use an MD5 MAC also carry
    # RC4/DES/EXPORT/NULL, so dropping MD5 loses no real detection. No word
    # boundaries: ssl-enum-ciphers joins cipher names with underscores
    # (TLS_RSA_WITH_RC4_128_SHA), where \bRC4\b would not match. This regex is
    # only ever run against ssl-enum-ciphers output (see _CIPHER_SCRIPTS gate),
    # so plain substrings can't hit certificate/PEM text.
    _WEAK_CIPHERS = re.compile(
        r'RC4|DES-CBC|3DES|_DES_|EXPORT|NULL|SSLv2|SSLv3|TLSv1\.0|TLSv1\.1',
    )
    _CERT_ISSUES = re.compile(
        r'expired|self.signed|not valid|wildcard|sha1|weak|untrusted|mismatch',
        re.IGNORECASE,
    )

    findings = []
    seen = set()
    for rec in nmap_records:
        if rec.get('type') != 'script_output':
            continue
        method = (rec.get('method') or '').lower()
        if method not in _SSL_SCRIPTS:
            continue

        detail = rec.get('detail') or ''
        host = rec.get('host', '')
        port = rec.get('port')
        issues = []

        # Weak cipher/protocol only from the cipher-enumeration script — never
        # from ssl-cert (its PEM body base64 trips substring matches).
        if method in _CIPHER_SCRIPTS and _WEAK_CIPHERS.search(detail):
            issues.append('weak cipher/protocol')
        if _CERT_ISSUES.search(detail):
            issues.append('certificate issue')
        if 'expired' in detail.lower():
            issues.append('expired certificate')
        if 'self-signed' in detail.lower() or 'self signed' in detail.lower():
            issues.append('self-signed certificate')

        if issues:
            key = (host, port, tuple(issues))
            if key not in seen:
                seen.add(key)
                findings.append({
                    'host': host,
                    'port': port,
                    'issues': issues,
                    'detail': detail[:500],
                })

    return findings


def _find_smb_signing_disabled(nmap_records):
    """Identify hosts with SMB signing not required (relay attack target)."""
    findings = []
    for rec in nmap_records:
        if rec.get('type') != 'script_output':
            continue
        method = (rec.get('method') or '').lower()
        detail = (rec.get('detail') or '').lower()

        if method in ('smb2-security-mode', 'smb-security-mode'):
            if 'signing enabled but not required' in detail or 'message signing disabled' in detail:
                findings.append({
                    # smb2-security-mode is a HOST-level NSE script, so the
                    # normalized record carries no port — default to SMB's 445
                    # (rather than rendering "host:None").
                    'host': rec.get('host', ''),
                    'port': rec.get('port') or 445,
                    'detail': rec.get('detail', '')[:300],
                })

    return findings


def _find_sensitive_paths(dir_records):
    """Identify sensitive paths from directory brute-force results."""
    _SENSITIVE_PATTERNS = re.compile(
        r'/\.git|/\.env|/\.svn|/\.hg|/\.DS_Store|'
        r'/admin|/backup|/config|/debug|/console|/manager|'
        r'/phpmyadmin|/phpinfo|/server-status|/server-info|'
        r'/wp-admin|/wp-login|/xmlrpc\.php|'
        r'/actuator|/swagger|/api-docs|/graphql|'
        r'/jenkins|/solr|/kibana|/grafana|'
        r'/\.aws|/\.ssh|/id_rsa|/credentials|/secrets|'
        r'/dump|/database|/db\b|/sql|'
        r'/shell|/cmd|/exec|/eval|'
        r'/test|/staging|/dev\b|/internal',
        re.IGNORECASE,
    )

    findings = []
    seen = set()
    for rec in dir_records:
        url = rec.get('url') or rec.get('matched_at') or ''
        status = rec.get('status') or rec.get('status_code')
        if not url:
            continue
        if _SENSITIVE_PATTERNS.search(url):
            if url not in seen:
                seen.add(url)
                findings.append({
                    'url': url,
                    'status': status,
                    'host': rec.get('host', ''),
                })

    return findings


_NUCLEI_MISCONFIG_TAGS = {
    'misconfig', 'cors', 'crlf', 'directory-listing', 'exposure',
    'unauth', 'disclosure', 'misconfiguration',
}

_NUCLEI_MISCONFIG_TEMPLATES = re.compile(
    r'cors-misconfig|directory-listing|open-redirect|'
    r'missing-(?:x-frame|csp|hsts|x-content)|'
    r'exposed-|bucket-|swagger-|graphql-|'
    r'phpinfo|server-status|debug|actuator|'
    r'unauth|security-txt|robots-txt',
    re.IGNORECASE,
)

_NUCLEI_PANEL_TEMPLATES = re.compile(
    r'panel|dashboard|console|webui|interface|manage|portal|'
    r'grafana|kibana|prometheus|jenkins|solr|couchdb|'
    r'phpmyadmin|adminer|pgadmin|mongo-express|'
    r'traefik|portainer|rancher|argocd|airflow|'
    r'webmin|glpi|zabbix|nagios|splunk',
    re.IGNORECASE,
)

_NUCLEI_TECH_TEMPLATES = re.compile(
    r'tech-detect|waf-detect|cms-detect|fingerprint|detect$|'
    r'version-detect|wordpress|drupal|joomla|'
    r'^wappalyzer|^whatweb|^builtwith',
    re.IGNORECASE,
)


def _extract_nuclei_intel(nuclei_records):
    """Extract actionable intelligence from low/info nuclei findings.

    Categorizes findings into:
    - misconfigs: CORS, directory listing, exposed endpoints, missing headers
    - exposed_panels: admin dashboards, management consoles, monitoring UIs
    - tech_detections: technology/WAF/CMS fingerprints with version info
    """
    misconfigs = []
    exposed_panels = []
    tech_detections = defaultdict(set)
    seen_misconfig = set()
    seen_panel = set()

    for rec in nuclei_records:
        severity = (rec.get('severity') or 'info').lower()
        if severity not in ('info', 'low'):
            continue

        template_id = (rec.get('template_id') or '').lower()
        tags = (rec.get('tags') or '').lower()
        title = rec.get('title') or ''
        matched_at = rec.get('matched_at') or ''
        host = rec.get('host') or ''
        detail = rec.get('detail') or ''

        tag_set = {t.strip() for t in tags.split(',') if t.strip()}

        is_misconfig = (
            tag_set & _NUCLEI_MISCONFIG_TAGS
            or _NUCLEI_MISCONFIG_TEMPLATES.search(template_id)
        )
        is_panel = (
            _NUCLEI_PANEL_TEMPLATES.search(template_id)
            or _NUCLEI_PANEL_TEMPLATES.search(title.lower())
        )
        is_login = (
            tag_set & _LOGIN_NUCLEI_TAGS
            or _LOGIN_KEYWORDS.search(template_id)
            or _LOGIN_KEYWORDS.search(title)
        )
        is_tech = (
            _NUCLEI_TECH_TEMPLATES.search(template_id)
            or 'tech' in tag_set
        )

        if is_misconfig:
            key = (host, template_id)
            if key not in seen_misconfig:
                seen_misconfig.add(key)
                misconfigs.append({
                    'host': host,
                    'matched_at': matched_at,
                    'template_id': rec.get('template_id', ''),
                    'title': title,
                    'severity': severity,
                    'detail': detail[:200] if detail else '',
                })
        elif is_panel and not is_login:
            key = (host, template_id)
            if key not in seen_panel:
                seen_panel.add(key)
                exposed_panels.append({
                    'host': host,
                    'matched_at': matched_at,
                    'template_id': rec.get('template_id', ''),
                    'title': title,
                })
        elif is_tech:
            tech_label = title.split(']')[-1].strip() if ']' in title else title
            version = detail.strip() if detail else ''
            entry = f"{tech_label}: {version}" if version else tech_label
            tech_detections[host].add(entry)

    tech_list = {host: sorted(techs) for host, techs in
                 sorted(tech_detections.items(), key=lambda x: len(x[1]), reverse=True)}

    return {
        'misconfigs': misconfigs,
        'exposed_panels': exposed_panels,
        'tech_detections': tech_list,
    }


def _build_tech_stack(nmap_records):
    """Group hosts by detected technology stack from banners/service info."""
    _TECH_PATTERNS = [
        (re.compile(r'apache', re.I), 'Apache'),
        (re.compile(r'nginx', re.I), 'nginx'),
        (re.compile(r'microsoft.iis|iis/', re.I), 'IIS'),
        (re.compile(r'tomcat', re.I), 'Tomcat'),
        (re.compile(r'node\.?js|express', re.I), 'Node.js'),
        (re.compile(r'php', re.I), 'PHP'),
        (re.compile(r'asp\.net|aspnet', re.I), 'ASP.NET'),
        (re.compile(r'java|servlet|jsp', re.I), 'Java'),
        (re.compile(r'python|django|flask|gunicorn|uvicorn|werkzeug', re.I), 'Python'),
        (re.compile(r'ruby|rails|passenger|puma', re.I), 'Ruby'),
        (re.compile(r'go|golang', re.I), 'Go'),
        (re.compile(r'openssl', re.I), 'OpenSSL'),
        (re.compile(r'openssh', re.I), 'OpenSSH'),
        (re.compile(r'microsoft.sql|mssql', re.I), 'MSSQL'),
        (re.compile(r'mysql|mariadb', re.I), 'MySQL'),
        (re.compile(r'postgres', re.I), 'PostgreSQL'),
        (re.compile(r'oracle', re.I), 'Oracle'),
        (re.compile(r'redis', re.I), 'Redis'),
        (re.compile(r'mongodb|mongod', re.I), 'MongoDB'),
        (re.compile(r'elasticsearch', re.I), 'Elasticsearch'),
        (re.compile(r'vmware|esxi|vcenter', re.I), 'VMware'),
        (re.compile(r'cisco', re.I), 'Cisco'),
        (re.compile(r'fortinet|fortigate|fortios', re.I), 'Fortinet'),
        (re.compile(r'palo.?alto', re.I), 'Palo Alto'),
        (re.compile(r'f5|big.?ip', re.I), 'F5 BIG-IP'),
        (re.compile(r'wordpress', re.I), 'WordPress'),
        (re.compile(r'drupal', re.I), 'Drupal'),
        (re.compile(r'joomla', re.I), 'Joomla'),
    ]

    tech_to_hosts = defaultdict(set)

    for rec in nmap_records:
        if rec.get('type') != 'open_port':
            continue
        host = rec.get('host', '')
        banner = (rec.get('detail') or '') + ' ' + (rec.get('service') or '')

        for pattern, tech in _TECH_PATTERNS:
            if pattern.search(banner):
                tech_to_hosts[tech].add(host)

    return {tech: sorted(hosts) for tech, hosts in
            sorted(tech_to_hosts.items(), key=lambda x: len(x[1]), reverse=True)}


def _find_outlier_ports(nmap_records, threshold=2):
    """Find ports open on very few hosts (potential dev/forgotten services)."""
    port_hosts = defaultdict(set)
    port_service_info = {}

    for rec in nmap_records:
        if rec.get('type') != 'open_port':
            continue
        service = (rec.get('service') or '').strip()
        # tcpwrapped = nmap completed the TCP handshake but got no service banner
        # back (commonly a firewall/wrapper closing the connection). It's not a
        # reliable indicator of a real service, so ignore it entirely — it should
        # neither become an outlier nor pull a host into another port's set.
        if service.lower() == 'tcpwrapped':
            continue
        host = rec.get('host', '')
        port = rec.get('port')
        proto = rec.get('proto', 'tcp')
        if host and port is not None:
            key = f"{port}/{proto}"
            port_hosts[key].add(host)
            product = (rec.get('product') or '').strip()
            version = (rec.get('version') or '').strip()
            if service or product or version:
                port_service_info[key] = {
                    'service': service,
                    'product': product,
                    'version': version,
                }

    outliers = []
    for port, hosts in sorted(port_hosts.items()):
        if len(hosts) <= threshold:
            entry = {
                'port': port,
                'hosts': sorted(hosts),
                'count': len(hosts),
            }
            if port in port_service_info:
                entry.update(port_service_info[port])
            outliers.append(entry)

    return outliers


def _normalize_url(url):
    """Normalize a URL/host:port for dedup — strip a single trailing slash.

    Two nuclei rows for `https://host/x` and `https://host/x/` are the same
    endpoint; treat them as one. Root `/` and bare `host:port` are left intact
    (stripping the lone slash from `https://host/` would still collapse with
    `https://host`, which is what we want).
    """
    u = (url or '').strip()
    if len(u) > 1 and u.endswith('/'):
        u = u[:-1]
    return u


def _group_login_panels(login_panels):
    """Collapse login-panel rows that describe the same panel.

    The scan fires many overlapping detections at CDN/shared-hosting estates:
    two templates on the same URL (plesk-onyx + plesk-obsidian), the same panel
    per-port (keycloak on 2053/2083/2087/...), and trailing-slash duplicates.
    We key on (normalized-url, source) and merge the template/title of the
    collapsed rows so no detection is silently dropped.
    """
    grouped = {}
    order = []
    for panel in login_panels:
        norm = _normalize_url(panel.get('url', ''))
        key = (norm, panel.get('source', ''))
        if key not in grouped:
            grouped[key] = {
                'url': norm or panel.get('url', ''),
                'source': panel.get('source', ''),
                'templates': [],
                'titles': [],
            }
            order.append(key)
        g = grouped[key]
        tmpl = (panel.get('template_id') or '').strip()
        title = (panel.get('title') or '').strip()
        if tmpl and tmpl not in g['templates']:
            g['templates'].append(tmpl)
        if title and title not in g['titles']:
            g['titles'].append(title)
    return [grouped[k] for k in order]


def _group_shared_host_ports(entries, host_key='host', min_group=5):
    """Group same-service rows that share a /24 (IPv4) or /48 (IPv6) prefix.

    A single CDN/hosting range (e.g. a /24 of Cloudflare edge IPs all exposing
    8443) produces dozens of identical rows. When >= min_group hosts in one
    prefix carry the same (port, service, notes), collapse them into one row
    with a host count; hosts that don't cluster are returned individually.

    Returns (grouped_rows, singles) where grouped_rows carry a 'hosts' list and
    'count', and singles are the original entries left ungrouped.
    """
    buckets = defaultdict(list)
    for e in entries:
        host = e.get(host_key, '')
        prefix = _network_prefix(host)
        sig = (prefix, e.get('port'), e.get('service', ''), e.get('reason', e.get('notes', '')))
        buckets[sig].append(e)

    grouped_rows = []
    singles = []
    for (prefix, port, service, notes), members in buckets.items():
        if prefix and len(members) >= min_group:
            grouped_rows.append({
                'prefix': prefix,
                'port': port,
                'service': service,
                'reason': notes,
                'hosts': sorted(m.get(host_key, '') for m in members),
                'count': len(members),
            })
        else:
            singles.extend(members)
    grouped_rows.sort(key=lambda g: g['count'], reverse=True)
    return grouped_rows, singles


def _network_prefix(host):
    """Return a grouping prefix (/24 for IPv4, /48 for IPv6) or '' for names."""
    import ipaddress
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return ''
    if ip.version == 4:
        return str(ipaddress.ip_network(f"{host}/24", strict=False))
    return str(ipaddress.ip_network(f"{host}/48", strict=False))


def _parse_explicit_host_port(matched_at):
    """Pull (host, port) from a nuclei matched_at ONLY when a port is explicit.

    Returns (host, port:int) for 'host:6379' or 'scheme://host:6379/...'; returns
    (None, None) for bare hosts/URLs with no explicit port (e.g. 'http://host') so
    we never infer a default web port — we only reconcile services that a scanner
    actually reached on a stated port.
    """
    m = (matched_at or '').strip()
    if not m:
        return (None, None)
    if '://' in m:
        m = m.split('://', 1)[1]
    netloc = m.split('/', 1)[0]
    if netloc.startswith('['):            # bracketed IPv6 — skip (rare here)
        return (None, None)
    if ':' not in netloc:
        return (None, None)
    host, _, port = netloc.rpartition(':')
    if host and port.isdigit():
        return (host, int(port))
    return (None, None)


def _services_outside_portscan(nuclei_records, conn, sdb):
    """Reconcile nuclei-discovered services against the TCP port scan.

    A scanner (nuclei) that reaches a service on host:port the port scan never
    reported is strong evidence the port scan is INCOMPLETE for that host —
    typically a SYN-filtering / rate-limiting target where nmap sees nothing but a
    gentler full-connect probe gets through (variably, so findings swing run to
    run). Only host-full (`-t`, channel 't') in-scope IPs are considered — a
    name-only host is intentionally not port-scanned (handled elsewhere).

    Returns {ip: sorted([ports])} for ports found by nuclei but absent from the
    ports table (any proto), or {} when nothing qualifies.
    """
    try:
        host_to_ip, _ = sdb.host_ip_maps_from_parents(conn)
    except Exception:
        host_to_ip = {}
    # Ports the scan DID report, as (host, port) across any protocol.
    scanned = set()
    for host, port in conn.execute("SELECT host, port FROM ports").fetchall():
        if host and port is not None:
            scanned.add((host, int(port)))
    # IPs that were supposed to be port-scanned.
    host_full = {r[0] for r in conn.execute(
        "SELECT target FROM targets WHERE target_type='ip' "
        "AND in_scope=1 AND channel='t'").fetchall()}
    if not host_full:
        return {}

    missed = defaultdict(set)
    for rec in nuclei_records:
        host, port = _parse_explicit_host_port(
            rec.get('matched_at') or rec.get('matched-at') or '')
        if not host or port is None:
            continue
        ip = host_to_ip.get(host, host)      # hostname -> IP; IPs pass through
        if ip not in host_full:
            continue
        if (ip, port) in scanned:
            continue
        missed[ip].add(port)
    return {ip: sorted(ports) for ip, ports in missed.items()}


# Coarse service hint from a nuclei template-id, for scanner-sourced port rows.
_NUCLEI_PORT_SERVICE = (
    ("openssh", "ssh"), ("ssh", "ssh"), ("redis", "redis"), ("ftp", "ftp"),
    ("smtp", "smtp"), ("smb", "smb"), ("mysql", "mysql"), ("mssql", "mssql"),
    ("postgres", "postgresql"), ("mongodb", "mongodb"), ("rdp", "rdp"),
    ("vnc", "vnc"), ("telnet", "telnet"), ("snmp", "snmp"), ("rpc", "rpcbind"),
    ("nfs", "nfs"), ("ldap", "ldap"), ("elasticsearch", "elasticsearch"),
)


def _service_from_template(template_id):
    t = (template_id or "").lower()
    for key, svc in _NUCLEI_PORT_SERVICE:
        if key in t:
            return svc
    return None


def _record_scanner_ports(nuclei_records, db, sdb):
    """Record ports a scanner (nuclei/httpx) reached but the port scan never
    reported, so the ports inventory (scan.db / API / report) is complete even
    where nmap under-covered a host.

    Evidence-based only: an explicit `host:port` a nuclei template actually
    matched, or a live httpx web endpoint. Mapped hostnames -> IPs and gated to
    in-scope IP targets. Tagged `source='nuclei'|'httpx'` so they're auditable
    and, since upsert_port is last-write-wins on non-empty fields only, never
    clobber real nmap service detail. Returns the number of new ports recorded.
    """
    conn = db._conn
    try:
        host_to_ip, _ = sdb.host_ip_maps_from_parents(conn)
    except Exception:
        host_to_ip = {}
    scanned = set()
    for host, port in conn.execute("SELECT host, port FROM ports").fetchall():
        if host and port is not None:
            scanned.add((host, int(port)))
    in_scope = {r[0] for r in conn.execute(
        "SELECT target FROM targets WHERE target_type='ip' AND in_scope=1"
    ).fetchall()}
    web_rows = conn.execute(
        "SELECT host, port, scheme FROM web_endpoints WHERE port IS NOT NULL"
    ).fetchall()

    added = 0

    def _add(host, port, service, source):
        nonlocal added
        ip = host_to_ip.get(host, host)
        if ip not in in_scope or (ip, int(port)) in scanned:
            return
        db.upsert_port(host=ip, port=int(port), proto="tcp", state="open",
                       service=service, source=source)
        scanned.add((ip, int(port)))
        added += 1

    for rec in nuclei_records:
        host, port = _parse_explicit_host_port(
            rec.get('matched_at') or rec.get('matched-at') or '')
        if host and port is not None:
            _add(host, port, _service_from_template(rec.get('template_id')), "nuclei")
    for host, port, scheme in web_rows:
        if host and port is not None:
            _add(host, port, (scheme or "").lower() or None, "httpx")
    return added


def _render_markdown(analysis: dict, output_path: str):
    """Render analysis dict as a human-readable Markdown report."""
    lines = []
    meta = analysis['metadata']
    summary = analysis['summary']

    lines.append("# Programmatic Analysis")
    lines.append("")
    lines.append(f"Generated: {meta['generated_at']}")
    lines.append("")

    # Loud, unmissable banner when the port scan looks degraded — otherwise the
    # near-zero port/service counts below read as a clean, closed network when the
    # scan actually failed to collect.
    if meta.get('port_scan_warning'):
        lines.append("> ## ⚠️ PORT SCAN LIKELY INCOMPLETE — RESULTS UNRELIABLE")
        lines.append(">")
        lines.append(f"> {meta['port_scan_warning']}")
        lines.append(">")
        lines.append("> **Do NOT treat the port/service counts below as a closed "
                     "attack surface.** Verify the fleet's nmap (raw-socket "
                     "privilege / libblas) and re-run the TCP scan before relying "
                     "on these results. Service-posture modules (ssh/smtp/snmp) "
                     "were likely skipped for the same reason.")
        lines.append("")

    # Calmer note (not a failure): no port scan ran because scope is name-only.
    elif meta.get('port_scan_scope_note'):
        lines.append("> ## ℹ️ No port scan — name-only scope")
        lines.append(">")
        lines.append(f"> {meta['port_scan_scope_note']}")
        lines.append("")

    # Additive, host-specific: scanners reached ports the scan never reported, so
    # the port scan is incomplete for those hosts. Independent of the banners above
    # (the overall scan can be healthy while one host filters), so render it too.
    if meta.get('port_scan_incomplete_note'):
        lines.append("> ## ⚠️ Port-scan coverage gap — results may vary between runs")
        lines.append(">")
        lines.append(f"> {meta['port_scan_incomplete_note']}")
        lines.append("")

    # NOTE: the host/port/service/OS overview (Summary metrics, Port Statistics,
    # Service/Version Inventory, OS Fingerprinting) now lives in the scan debrief
    # (reports/…-summary.md), which reads them from this module's analysis.json —
    # they were duplicated with the debrief and fit the debrief's "what's out
    # there" framing better than this analytical report. This report keeps the
    # analytical sections (blocking, password-spray, login panels, nuclei intel).
    # The data is still emitted to analysis.json (below) for the debrief + machines.

    # Scan comparison (possible blocking) — an analytical signal, kept here.
    scan_comp = analysis.get('scan_comparison', [])
    if scan_comp:
        lines.append("### Possible Blocking Detected")
        lines.append("")
        lines.append("Ports seen in baseline scan but missing from full scan (may indicate rate-limiting or blocking):")
        lines.append("")
        for entry in scan_comp:
            ports = ', '.join(str(p) for p in entry['ports_in_baseline_not_in_full'])
            lines.append(f"- **{entry['host']}**: ports {ports}")
        lines.append("")

    # --- PASSWORD SPRAYING ---
    spray = analysis.get('password_spray', {})
    mx_domains = spray.get('mx_domains', {})
    login_panels = spray.get('login_panels', [])
    emails = spray.get('emails', [])
    if mx_domains or login_panels or emails:
        lines.append("## Password Spraying")
        lines.append("")
        if mx_domains:
            lines.append("### Email Domains (MX Records)")
            lines.append("")
            lines.append("Domains with MX records — collect email addresses for spray attacks:")
            lines.append("")
            for domain, mx_hosts in sorted(mx_domains.items()):
                mx_str = ', '.join(mx_hosts[:5])
                lines.append(f"- **{domain}** → {mx_str}")
            lines.append("")
        if emails:
            lines.append("### Discovered Email Addresses")
            lines.append("")
            lines.append(f"{len(emails)} email addresses discovered (via OSINT/passive recon):")
            lines.append("")
            for email in sorted(emails):
                lines.append(f"- {email}")
            lines.append("")
        if login_panels:
            adfs_panels = [p for p in login_panels
                           if 'adfs' in (p.get('template_id') or '').lower()
                           or 'adfs' in (p.get('title') or '').lower()
                           or 'adfs' in (p.get('url') or '').lower()]
            if adfs_panels:
                lines.append("### ADFS Detected — Password Spray Target")
                lines.append("")
                lines.append("Active Directory Federation Services endpoints found. "
                             "ADFS is a high-value spray target — successful authentication "
                             "grants domain credentials without MFA bypass in many configurations.")
                lines.append("")
                for panel in adfs_panels:
                    url = panel.get('url', '')
                    lines.append(f"- `{url}`")
                lines.append("")

            grouped_panels = _group_login_panels(login_panels)
            lines.append("### Login Panels")
            lines.append("")
            if len(grouped_panels) < len(login_panels):
                lines.append(f"*{len(login_panels)} detections collapsed to "
                             f"{len(grouped_panels)} distinct panels "
                             f"(trailing-slash and overlapping-template duplicates merged).*")
                lines.append("")
            lines.append("| URL | Source | Detection(s) |")
            lines.append("|-----|--------|--------------|")
            for panel in grouped_panels:
                url = panel.get('url', '')
                source = panel.get('source', '')
                detail = '; '.join(panel.get('templates') or panel.get('titles') or [])
                detail = detail.replace('|', '/').replace('\n', ' ')
                lines.append(f"| {url} | {source} | {detail} |")
            lines.append("")

    # --- DEFAULT CREDENTIALS ---
    default_creds = analysis.get('default_creds_anon_access', [])
    if default_creds:
        lines.append("## Default Credentials / Anonymous Access")
        lines.append("")
        lines.append("| Host | Port | Script | Detail |")
        lines.append("|------|------|--------|--------|")
        for entry in default_creds:
            host = entry.get('host', '')
            port = entry.get('port', '')
            script = entry.get('script', '')
            detail = entry.get('detail', '').replace('\n', ' ')[:200]
            lines.append(f"| {host} | {port} | {script} | {detail} |")
        lines.append("")

    # --- NUCLEI FINDINGS ---
    nuclei = analysis.get('nuclei_findings', [])
    if nuclei:
        by_sev = defaultdict(list)
        for finding in nuclei:
            sev = (finding.get('severity') or 'unknown').lower()
            by_sev[sev].append(finding)

        crit_high = by_sev.get('critical', []) + by_sev.get('high', [])
        if crit_high:
            lines.append("## Nuclei Findings (Critical + High)")
            lines.append("")
            for sev in ('critical', 'high'):
                findings = by_sev.get(sev, [])
                if not findings:
                    continue
                lines.append(f"### {sev.upper()} ({len(findings)})")
                lines.append("")
                lines.append("| Host | Template | Title | Matched At |")
                lines.append("|------|----------|-------|------------|")
                for f in findings:
                    host = f.get('host', '')
                    tmpl = f.get('template_id', '')
                    title = f.get('title', '')
                    matched = f.get('matched_at', '')
                    lines.append(f"| {host} | {tmpl} | {title} | {matched} |")
                lines.append("")

    # --- BBOT FINDINGS ---
    bbot_findings = analysis.get('bbot_findings', [])
    if bbot_findings:
        sev_order = {'critical': 0, 'high': 1, 'medium': 2}
        reportable = [f for f in bbot_findings
                      if (f.get('severity') or 'info').lower() in sev_order]
        reportable.sort(key=lambda f: sev_order.get((f.get('severity') or '').lower(), 9))
        if reportable:
            lines.append("## BBOT Findings")
            lines.append("")
            lines.append("| Severity | Host | Finding | Detail |")
            lines.append("|----------|------|---------|--------|")
            for f in reportable:
                sev = f.get('severity', 'info')
                host = f.get('host', '')
                title = f.get('title', '')
                detail = (f.get('detail') or '')[:100]
                lines.append(f"| {sev.upper()} | {host} | {title} | {detail} |")
            lines.append("")

    # --- DNS SECURITY ---
    dns_sec = analysis.get('dns_security_findings', [])
    if dns_sec:
        lines.append("## DNS Security Findings")
        lines.append("")

        grouped = defaultdict(list)
        for f in dns_sec:
            grouped[f.get('check', 'unknown')].append(f)

        sev_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        sorted_groups = sorted(
            grouped.items(),
            key=lambda kv: sev_order.get(kv[1][0].get('severity', ''), 9),
        )

        for check_type, findings in sorted_groups:
            sev = findings[0].get('severity', 'INFO')
            detail = findings[0].get('detail', check_type)
            recommendation = findings[0].get('recommendation', '')
            lines.append(f"### {detail} ({len(findings)} domain{'s' if len(findings) != 1 else ''})")
            lines.append(f"**Severity:** {sev} | **Recommendation:** {recommendation}")
            lines.append("")
            for f in findings:
                domain = f.get('domain', '')
                evidence = (f.get('evidence') or '').strip()
                if evidence:
                    lines.append(f"- {domain} — `{evidence[:120]}`")
                else:
                    lines.append(f"- {domain}")
            lines.append("")

    # --- SMB SIGNING ---
    smb_signing = analysis.get('smb_signing_disabled', [])
    if smb_signing:
        lines.append("## SMB Signing Not Required (Relay Targets)")
        lines.append("")
        for entry in smb_signing:
            lines.append(f"- **{entry['host']}**:{entry.get('port') or 445}")
        lines.append("")

    # --- SENSITIVE PATHS ---
    sensitive_paths = analysis.get('sensitive_paths', [])
    if sensitive_paths:
        lines.append("## Sensitive Paths")
        lines.append("")
        lines.append("| URL | Status | Host |")
        lines.append("|-----|--------|------|")
        for entry in sensitive_paths:
            url = entry.get('url', '')
            status = entry.get('status', '')
            host = entry.get('host', '')
            lines.append(f"| {url} | {status} | {host} |")
        lines.append("")

    # --- DANGEROUS HTTP METHODS ---
    http_methods = analysis.get('http_methods', [])
    if http_methods:
        # Fold the methods list into a signature so hosts sharing a CDN /24 with
        # the identical method set (e.g. dozens of 198.18.14.x:443 exposing
        # TRACE) collapse into one grouped row instead of one row each.
        for entry in http_methods:
            entry['notes'] = ', '.join(entry.get('methods', []))
        method_groups, method_singles = _group_shared_host_ports(http_methods)

        lines.append("## Dangerous HTTP Methods")
        lines.append("")
        if method_groups:
            lines.append(f"*{len(method_groups)} CDN/shared-range group(s) collapsed "
                         f"below; hosts in a group share a /24 (or /48) and the same methods.*")
            lines.append("")
            lines.append("| Network | Port | Methods | Hosts |")
            lines.append("|---------|------|---------|-------|")
            for g in method_groups:
                lines.append(f"| {g['prefix']} | {g.get('port', '')} | "
                             f"{g.get('reason', '')} | {g['count']} |")
            lines.append("")
        lines.append("| Host | Port | Methods |")
        lines.append("|------|------|---------|")
        for entry in sorted(method_singles, key=lambda e: e.get('host', '')):
            host = entry.get('host', '')
            port = entry.get('port', '')
            methods = ', '.join(entry.get('methods', []))
            lines.append(f"| {host} | {port} | {methods} |")
        lines.append("")

    # --- MISCONFIGURATIONS ---
    nuclei_intel = analysis.get('nuclei_intel', {})
    misconfigs = nuclei_intel.get('misconfigs', [])
    exposed_panels = nuclei_intel.get('exposed_panels', [])

    if misconfigs:
        lines.append("## Misconfigurations (nuclei low/info)")
        lines.append("")

        # These are high-volume, low-severity detections (thousands of rows on a
        # large estate). A flat truncated table ("50 shown, 3831 more") hides
        # the shape of the noise. Lead with a per-template breakdown so the
        # reader sees which checks dominate, then show a capped sample.
        by_template = defaultdict(lambda: {'count': 0, 'hosts': set(), 'title': ''})
        for entry in misconfigs:
            tmpl = entry.get('template_id', '') or '(unknown)'
            bt = by_template[tmpl]
            bt['count'] += 1
            bt['hosts'].add(entry.get('host', ''))
            if not bt['title']:
                bt['title'] = entry.get('title', '')

        lines.append(f"{len(misconfigs)} low/info detections across "
                     f"{len(by_template)} template(s). Breakdown by template:")
        lines.append("")
        lines.append("| Template | Title | Findings | Hosts |")
        lines.append("|----------|-------|----------|-------|")
        for tmpl, bt in sorted(by_template.items(),
                               key=lambda kv: kv[1]['count'], reverse=True):
            title = (bt['title'] or '').replace('|', '/').replace('\n', ' ')
            lines.append(f"| {tmpl} | {title} | {bt['count']} | {len(bt['hosts'])} |")
        lines.append("")

    # --- EXPOSED PANELS ---
    if exposed_panels:
        # Dedup by (host, normalized-url, template) — the same panel is often
        # reported for both the slashed and unslashed URL.
        seen_panels = set()
        deduped_panels = []
        for entry in exposed_panels:
            key = (entry.get('host', ''),
                   _normalize_url(entry.get('matched_at', '')),
                   entry.get('template_id', ''))
            if key in seen_panels:
                continue
            seen_panels.add(key)
            deduped_panels.append(entry)

        lines.append("## Exposed Panels & Dashboards (nuclei)")
        lines.append("")
        if len(deduped_panels) < len(exposed_panels):
            lines.append(f"*{len(exposed_panels)} detections collapsed to "
                         f"{len(deduped_panels)} distinct panels.*")
            lines.append("")
        lines.append("| Host | URL | Template | Title |")
        lines.append("|------|-----|----------|-------|")
        for entry in deduped_panels:
            host = entry.get('host', '')
            url = _normalize_url(entry.get('matched_at', ''))
            tmpl = entry.get('template_id', '')
            title = entry.get('title', '')
            lines.append(f"| {host} | {url} | {tmpl} | {title} |")
        lines.append("")

    os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines) + '\n')


def run_analyze(prefix, **kwargs):
    """Run programmatic analysis on normalized JSONL scan results.

    Reads the JSONL files produced by the normalize module and generates
    a structured JSON analysis report.

    Args:
        prefix: Output file prefix (same prefix used during scanning)
        **kwargs: Additional arguments (fleet, target, etc.)

    Returns:
        dict: Module result with path to analysis JSON
    """
    prefix = kwargs.get('data_prefix', prefix)
    print('[*] Running programmatic analysis module')

    # Find normalized JSONL files
    nmap_jsonl = glob.glob(f"{prefix}*-nmap-normalized.jsonl")
    nuclei_jsonl = glob.glob(f"{prefix}*-nuclei-normalized.jsonl")
    subfinder_jsonl = glob.glob(f"{prefix}*-subfinder-normalized.jsonl")
    ffuf_jsonl = glob.glob(f"{prefix}*-ffuf-normalized.jsonl")
    ferox_jsonl = glob.glob(f"{prefix}*-feroxbuster-normalized.jsonl")
    bbot_jsonl = glob.glob(f"{prefix}*-bbot-normalized.jsonl")
    dns_sec_jsonl = [p for p in glob.glob(f"{prefix}*-dns-security.jsonl")
                     if not p.endswith("-dns-security-normalized.jsonl")]

    all_jsonl = nmap_jsonl + nuclei_jsonl + subfinder_jsonl + ffuf_jsonl + ferox_jsonl + bbot_jsonl + dns_sec_jsonl

    if not all_jsonl:
        logger.error("analyze module FAILED: no normalized JSONL files found")
        print(f'[!] ERROR: No normalized JSONL files found matching prefix: {prefix}')
        print('[!] The "normalize" module MUST run before "analyze".')
        print('[!] Add "normalize" to your workflow before "analyze", e.g.:')
        print('[!]   steps:')
        print('[!]     - normalize')
        print('[!]     - analyze')
        return {
            'module': 'analyze',
            'status': 'failed',
            'output_files': [],
            'error': 'normalize module must run before analyze — no JSONL input files found',
        }

    # Load records
    nmap_records = []
    for path in nmap_jsonl:
        nmap_records.extend(_read_jsonl(path))

    nuclei_records = []
    for path in nuclei_jsonl:
        nuclei_records.extend(_read_jsonl(path))
    # Collapse duplicate rows by finding_id (the raw tool can re-emit the same
    # match) so the reported nuclei total + severity split match scan.db, the
    # source of truth — and so ai_analyze isn't handed the same finding twice.
    nuclei_records = dedup_findings(nuclei_records)
    # Also collapse the weburls IP↔hostname dual-emit (same template on the IP
    # AND on a hostname that resolves to it) so the reported nuclei total matches
    # the deduped view the API/report present. Hostname-primary; IP alongside.
    try:
        from core import scan_db as _sdb
        _odir = os.path.dirname(os.path.dirname(prefix)) if prefix else None
        if _odir and os.path.exists(_sdb.db_path_for(_odir)):
            _c = _sdb.open_db(_odir)
            try:
                _h2i, _ = _sdb.host_ip_maps_from_parents(_c._conn)
            finally:
                _c.close(checkpoint=False)
            if _h2i:
                nuclei_records = _sdb.dedup_ip_hostname_findings(
                    nuclei_records, _h2i, claim_key="template_id")
    except Exception as exc:  # pragma: no cover - never fail analyze on dedup
        logger.debug("analyze: ip/hostname dedup skipped (%s)", exc)

    subfinder_records = []
    for path in subfinder_jsonl:
        subfinder_records.extend(_read_jsonl(path))

    dir_records = []
    for path in ffuf_jsonl + ferox_jsonl:
        dir_records.extend(_read_jsonl(path))

    bbot_records = []
    for path in bbot_jsonl:
        bbot_records.extend(_read_jsonl(path))

    dns_sec_records = []
    for path in dns_sec_jsonl:
        dns_sec_records.extend(_read_jsonl(path))

    print(f'[*] Loaded: {len(nmap_records)} nmap, {len(nuclei_records)} nuclei, '
          f'{len(subfinder_records)} subfinder, {len(dir_records)} dir-brute, '
          f'{len(bbot_records)} bbot, {len(dns_sec_records)} dns-security records')

    # Analysis
    password_spray = _build_password_spray_section(prefix, nmap_records, nuclei_records, bbot_records)
    scan_comparison = _compare_baseline_vs_full(nmap_records)
    severity_counts = _nuclei_severity_stats(nuclei_records)
    port_service_stats = _build_port_service_stats(nmap_records)
    os_fingerprint = _build_os_fingerprint(nmap_records)
    http_methods = _find_http_methods(nmap_records)
    default_creds = _find_default_creds_and_anon_access(nmap_records)
    ssl_issues = _find_ssl_tls_issues(nmap_records)
    smb_signing = _find_smb_signing_disabled(nmap_records)
    sensitive_paths = _find_sensitive_paths(dir_records)
    tech_stack = _build_tech_stack(nmap_records)
    outlier_ports = _find_outlier_ports(nmap_records)
    nuclei_intel = _extract_nuclei_intel(nuclei_records)

    open_port_set = set()
    hosts_with_open_ports = set()
    for rec in nmap_records:
        if rec.get('type') != 'open_port':
            continue
        host = rec.get('host', '')
        port = rec.get('port')
        proto = rec.get('proto', 'tcp')
        if host and port is not None:
            open_port_set.add((host, port, proto))
            hosts_with_open_ports.add(host)

    open_port_count = len(open_port_set)

    # Subdomain and web-content counts come from scan.db (source of truth), not
    # the per-tool JSONL: subfinder often produces nothing while dnsx/bbot/puredns
    # discover the subdomains, and content is found by katana/gau crawling as well
    # as ffuf/feroxbuster brute-force — all land in scan.db (targets / web_dirs).
    # Counting only subfinder_records / ffuf+ferox records reported 0/0 on a run
    # that actually had 14 subdomains and 45 crawled paths. Fall back to the JSONL
    # counts when scan.db is unavailable.
    subdomains_discovered = len(subfinder_records)
    directory_hits = len(dir_records)
    output_dir = os.path.dirname(os.path.dirname(prefix)) if prefix else None
    port_scan_warning = None   # set when the TCP scan looks like it failed to collect
    port_scan_scope_note = None  # set when no port scan ran because scope is name-only
    port_scan_incomplete_note = None  # set when scanners reached ports the scan missed
    try:
        from core import scan_db as _scan_db
        if output_dir and os.path.exists(_scan_db.db_path_for(output_dir)):
            _db = _scan_db.open_db(output_dir)
            try:
                subdomains_discovered = _db._conn.execute(
                    "SELECT COUNT(*) FROM targets WHERE target_type='subdomain'"
                ).fetchone()[0]
                directory_hits = _db._conn.execute(
                    "SELECT COUNT(*) FROM web_dirs").fetchone()[0]
                # (1) Honor an explicit degraded flag stamped by ax_nmap_tcp.
                try:
                    if _db.get_meta("port_scan_degraded") == "1":
                        hn = _db.get_meta("port_scan_health") or ""
                        port_scan_warning = (
                            "The TCP port scan collected almost no open ports on live "
                            "hosts" + (f" ({hn})" if hn else "") + " — it most likely "
                            "FAILED to collect (broken/blocked fleet nmap or lost "
                            "results), rather than the network being closed.")
                except Exception:
                    pass
                # (2) Cross-check even on older runs with no flag: the web layer
                # proves many live hosts, but the ports table is ~empty. This is
                # the strong contradiction that a closed network can't produce.
                if port_scan_warning is None:
                    try:
                        web_live = _db._conn.execute(
                            "SELECT COUNT(DISTINCT host) FROM web_endpoints "
                            "WHERE status_code IS NOT NULL").fetchone()[0]
                        open_hosts = _db._conn.execute(
                            "SELECT COUNT(DISTINCT host) FROM ports "
                            "WHERE state='open'").fetchone()[0]
                        if web_live >= 10 and open_hosts <= max(1, int(web_live * 0.1)):
                            port_scan_warning = (
                                f"{web_live} host(s) are live on the web but only "
                                f"{open_hosts} host(s) have ANY open port in the scan "
                                f"— the TCP port scan almost certainly failed to "
                                f"collect (a closed network cannot produce this).")
                    except Exception:
                        pass
                # (3) Name-only scope (INTENDED, not a failure): a domain-/url-only
                # run resolves IPs but they're name-safe (channel != 't'), so
                # nmap/ssh/smtp/snmp are skipped by design. Disclose it + how to
                # port-scan, so the empty service layer isn't a silent surprise.
                if port_scan_warning is None:
                    try:
                        ports_any = _db._conn.execute(
                            "SELECT COUNT(*) FROM ports").fetchone()[0]
                        name_only = _db._conn.execute(
                            "SELECT COUNT(*) FROM targets WHERE target_type='ip' "
                            "AND in_scope=1 AND (channel IS NULL OR channel!='t')"
                        ).fetchone()[0]
                        host_full = _db._conn.execute(
                            "SELECT COUNT(*) FROM targets WHERE target_type='ip' "
                            "AND in_scope=1 AND channel='t'").fetchone()[0]
                        if ports_any == 0 and name_only > 0 and host_full == 0:
                            port_scan_scope_note = (
                                f"No TCP port scan was performed: {name_only} in-scope "
                                f"IP(s) are name-only scope (resolved from `-d`/`-url`), "
                                f"which authorizes web/URL scanning but not host-full "
                                f"port scanning. Service-layer modules (ssh/smtp/snmp) "
                                f"were skipped for the same reason. To port-scan these "
                                f"IPs and run the service modules, re-run with "
                                f"`-t <ips/cidrs>`.")
                    except Exception:
                        pass
                # (4) Independent of the above: a scanner reached services on
                # ports the TCP scan never reported on host-full targets — the
                # port scan is incomplete for those hosts (likely SYN filtering /
                # rate-limiting), which makes their findings non-deterministic
                # across runs. Additive — can coexist with a clean overall scan.
                try:
                    missed = _services_outside_portscan(
                        nuclei_records, _db._conn, _scan_db)
                    if missed:
                        parts = ", ".join(
                            f"{ip}: {', '.join(str(p) for p in ports)}"
                            for ip, ports in sorted(missed.items()))
                        n_hosts = len(missed)
                        port_scan_incomplete_note = (
                            f"Port-scan coverage gap: scanners reached services on "
                            f"port(s) the TCP port scan did not report on "
                            f"{n_hosts} host(s) — {parts}. These host(s) most likely "
                            f"filter or rate-limit SYN scans (nmap saw those ports as "
                            f"closed/filtered), so results for them are best-effort and "
                            f"may vary between runs. Consider a slower full-connect "
                            f"re-scan (nmap `-sT`) of these hosts.")
                except Exception:
                    pass
                # (5) Reconcile FORWARD, not just warn: record ports a scanner
                # (nuclei/httpx) actually reached but the port scan never logged,
                # so the ports inventory (scan.db / API / report) is complete.
                try:
                    added = _record_scanner_ports(nuclei_records, _db, _scan_db)
                    if added:
                        logger.info("analyze: recorded %d scanner-discovered "
                                    "port(s) into scan.db", added)
                except Exception:
                    pass
            finally:
                _db.close(checkpoint=True)
    except Exception as exc:  # pragma: no cover - defensive, never fail analyze
        logger.warning("analyze: scan.db count fallback (%s)", exc)

    analysis = {
        'metadata': {
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'prefix': prefix,
            'port_scan_warning': port_scan_warning,
            'port_scan_scope_note': port_scan_scope_note,
            'port_scan_incomplete_note': port_scan_incomplete_note,
            'sources': {
                'nmap_files': [os.path.basename(p) for p in nmap_jsonl],
                'nuclei_files': [os.path.basename(p) for p in nuclei_jsonl],
                'subfinder_files': [os.path.basename(p) for p in subfinder_jsonl],
                'dirbrute_files': [os.path.basename(p) for p in ffuf_jsonl + ferox_jsonl],
                'bbot_files': [os.path.basename(p) for p in bbot_jsonl],
                'dns_security_files': [os.path.basename(p) for p in dns_sec_jsonl],
            },
        },
        'summary': {
            'total_hosts': len(hosts_with_open_ports),
            'total_open_ports': open_port_count,
            'unique_ports': len(port_service_stats['port_counts']),
            'unique_services': len(port_service_stats['service_counts']),
            'unique_service_versions': len(port_service_stats.get('service_version_counts', [])),
            'subdomains_discovered': subdomains_discovered,
            'directory_hits': directory_hits,
            'nuclei_findings_total': len(nuclei_records),
            'nuclei_severity_counts': severity_counts,
            'bbot_findings_total': len([r for r in bbot_records if r.get('type') == 'finding']),
            'dns_security_findings_total': len(dns_sec_records),
            'ports_disappeared_between_scans': len(scan_comparison),
        },
        'password_spray': password_spray,
        'port_service_stats': port_service_stats,
        'os_fingerprint': os_fingerprint,
        'http_methods': http_methods,
        'default_creds_anon_access': default_creds,
        'ssl_tls_issues': ssl_issues,
        'smb_signing_disabled': smb_signing,
        'sensitive_paths': sensitive_paths,
        'tech_stack': tech_stack,
        'outlier_ports': outlier_ports,
        'scan_comparison': scan_comparison,
        'nuclei_findings': nuclei_records,
        'nuclei_intel': nuclei_intel,
        'bbot_findings': [r for r in bbot_records if r.get('type') == 'finding'],
        'dns_security_findings': dns_sec_records,
    }

    # Write JSON output
    output_path = f"{prefix}-analysis.json"
    version_output_path(output_path)
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(analysis, f, indent=2)

    # Write Markdown report to reports folder
    reports_prefix = kwargs.get('reports_prefix', prefix)
    md_path = f"{reports_prefix}-analysis.md"
    version_output_path(md_path)
    _render_markdown(analysis, md_path)

    logger.info(f"Analysis written to {output_path}")
    logger.info(f"Markdown report written to {md_path}")
    print(f'[+] Analysis complete: {output_path}')
    print(f'[+] Markdown report: {md_path}')
    print(f'    Live hosts: {len(hosts_with_open_ports)} | Open ports: {open_port_count} | Unique ports: {len(port_service_stats["port_counts"])} | Unique services: {len(port_service_stats["service_counts"])} | Unique service/versions: {len(port_service_stats["service_version_counts"])}')
    if password_spray['mx_domains']:
        print(f'    Email domains (MX): {len(password_spray["mx_domains"])}')
    if password_spray['login_panels']:
        print(f'    Login panels found: {len(password_spray["login_panels"])}')
    if nuclei_records:
        print(f'    Nuclei findings: {len(nuclei_records)} ({severity_counts})')
        intel_parts = []
        if nuclei_intel['misconfigs']:
            intel_parts.append(f"{len(nuclei_intel['misconfigs'])} misconfigs")
        if nuclei_intel['exposed_panels']:
            intel_parts.append(f"{len(nuclei_intel['exposed_panels'])} panels")
        if nuclei_intel['tech_detections']:
            intel_parts.append(f"{len(nuclei_intel['tech_detections'])} hosts w/tech")
        if intel_parts:
            print(f'    Nuclei intel (low/info): {", ".join(intel_parts)}')
    if subfinder_records:
        print(f'    Subdomains discovered: {len(subfinder_records)}')
    if scan_comparison:
        print(f'    [!] Possible blocking detected on {len(scan_comparison)} host(s)')

    return {
        'module': 'analyze',
        'status': 'success',
        'output_files': [output_path, md_path],
        'analysis_path': output_path,
        'markdown_path': md_path,
        'summary': analysis['summary'],
    }
