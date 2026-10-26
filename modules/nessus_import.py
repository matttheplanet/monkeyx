"""Nessus import module — parses .nessus XML exports into normalized JSONL.

Imports findings from a Nessus export file (exported via the web UI) and produces
the same normalized JSONL format as the normalize module, so ai_analyze can
consume Nessus findings alongside nuclei/nmap data.

Also logs discovered hosts and open ports to the target ledger for enrichment.

Usage:
    monkeyx --continue ./output --nessus /path/to/export.nessus -m normalize ai_analyze
"""

import json
import logging
import os
import defusedxml.ElementTree as ET

logger = logging.getLogger('monkeyx.modules.nessus_import')

REQUIRED_INPUTS = frozenset()

SEVERITY_MAP = {"0": "info", "1": "low", "2": "medium", "3": "high", "4": "critical"}


def run_nessus_import(prefix, **kwargs):
    """Parse a .nessus XML file and produce normalized JSONL output."""
    prefix = kwargs.get('data_prefix', prefix)
    nessus_file = kwargs.get('nessus_file')

    if not nessus_file:
        msg = "No Nessus file provided. Use --nessus /path/to/file.nessus"
        print(f'[!] {msg}')
        return {'module': 'nessus_import', 'status': 'failed', 'output_files': [], 'error': msg}

    if not os.path.exists(nessus_file):
        msg = f"Nessus file not found: {nessus_file}"
        print(f'[!] {msg}')
        return {'module': 'nessus_import', 'status': 'failed', 'output_files': [], 'error': msg}

    print(f'[*] Importing Nessus results from: {nessus_file}')

    try:
        tree = ET.parse(nessus_file)
        root = tree.getroot()
    except ET.ParseError as e:
        msg = f"Failed to parse Nessus XML: {e}"
        print(f'[!] {msg}')
        return {'module': 'nessus_import', 'status': 'failed', 'output_files': [], 'error': msg}

    report = root.find('.//Report')
    if report is None:
        msg = "No <Report> element found in Nessus file"
        print(f'[!] {msg}')
        return {'module': 'nessus_import', 'status': 'failed', 'output_files': [], 'error': msg}

    output_path = f"{prefix}-nessus-normalized.jsonl"
    hosts_seen = set()
    findings_count = 0
    port_entries = []

    with open(output_path, 'w', encoding="utf-8") as out:
        for report_host in report.findall('ReportHost'):
            host_props = {}
            props_el = report_host.find('HostProperties')
            if props_el is not None:
                for tag in props_el.findall('tag'):
                    host_props[tag.get('name')] = tag.text

            host_ip = host_props.get('host-ip', report_host.get('name', ''))
            hostname = host_props.get('host-fqdn') or host_props.get('hostname') or None
            os_info = host_props.get('operating-system')
            hosts_seen.add(host_ip)

            for item in report_host.findall('ReportItem'):
                severity_num = item.get('severity', '0')
                severity = SEVERITY_MAP.get(severity_num, 'info')

                port = int(item.get('port', '0'))
                proto = item.get('protocol', 'tcp')
                svc_name = item.get('svc_name', '')
                plugin_id = item.get('pluginID', '')
                plugin_name = item.get('pluginName', '')
                plugin_family = item.get('pluginFamily', '')

                synopsis = _get_text(item, 'synopsis')
                description = _get_text(item, 'description')
                solution = _get_text(item, 'solution')
                plugin_output = _get_text(item, 'plugin_output')
                risk_factor = _get_text(item, 'risk_factor')

                cves = [cve.text for cve in item.findall('cve') if cve.text]
                cvss3 = _get_text(item, 'cvss3_base_score')
                cvss2 = _get_text(item, 'cvss_base_score')
                exploit_available = _get_text(item, 'exploit_available') == 'true'

                if port > 0:
                    port_entries.append({
                        'host': host_ip,
                        'port': port,
                        'proto': proto,
                        'service': svc_name,
                    })

                # Skip pure informational noise (severity 0 with no useful content)
                if severity_num == '0' and not plugin_output:
                    continue

                detail_parts = []
                if synopsis:
                    detail_parts.append(synopsis)
                if plugin_output:
                    detail_parts.append(plugin_output.strip())
                if solution and solution.lower() != 'n/a':
                    detail_parts.append(f"Solution: {solution}")

                record = {
                    'host': host_ip,
                    'hostname': hostname,
                    'port': port if port > 0 else None,
                    'proto': proto if port > 0 else None,
                    'service': svc_name if svc_name and svc_name != 'general' else None,
                    'tool': 'nessus',
                    'type': 'nessus_finding',
                    'severity': severity,
                    'title': plugin_name,
                    'detail': '\n'.join(detail_parts) if detail_parts else None,
                    'source_file': os.path.basename(nessus_file),
                    'plugin_id': plugin_id,
                    'plugin_family': plugin_family,
                    'cves': cves if cves else None,
                    'cvss3': float(cvss3) if cvss3 else None,
                    'cvss2': float(cvss2) if cvss2 else None,
                    'exploit_available': exploit_available,
                    'os': os_info,
                }

                out.write(json.dumps(record) + '\n')
                findings_count += 1

    print(f'[+] Imported {findings_count} findings from {len(hosts_seen)} hosts')
    print(f'[+] Output: {output_path}')

    output_files = [output_path]

    # Write alive hosts file for discovery extraction by the orchestrator
    alive_path = f"{prefix}-nessus-alive-hosts.txt"
    with open(alive_path, 'w', encoding="utf-8") as f:
        for ip in sorted(hosts_seen):
            f.write(ip + '\n')
    output_files.append(alive_path)

    # Produce a summary JSON for ai_analyze to pick up
    summary_path = f"{prefix}-nessus-summary.json"
    summary = _build_summary(output_path, hosts_seen)
    with open(summary_path, 'w', encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    output_files.append(summary_path)
    print(f'[+] Summary: {summary_path}')

    return {
        'module': 'nessus_import',
        'status': 'success',
        'output_files': output_files,
        'hosts_imported': len(hosts_seen),
        'findings_imported': findings_count,
    }


def _get_text(element, tag):
    """Get text content of a child element, or empty string if missing."""
    child = element.find(tag)
    return child.text if child is not None and child.text else ''


def _build_summary(jsonl_path, hosts):
    """Build a summary of findings by severity and host for ai_analyze."""
    by_severity = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    by_host = {}
    top_findings = []

    with open(jsonl_path, encoding="utf-8") as f:
        for line in f:
            record = json.loads(line)
            sev = record.get('severity', 'info')
            by_severity[sev] = by_severity.get(sev, 0) + 1

            host = record['host']
            if host not in by_host:
                by_host[host] = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
            if sev in by_host[host]:
                by_host[host][sev] += 1

            if sev in ('critical', 'high') and len(top_findings) < 50:
                top_findings.append({
                    'host': host,
                    'port': record.get('port'),
                    'title': record.get('title'),
                    'severity': sev,
                    'cves': record.get('cves'),
                    'cvss3': record.get('cvss3'),
                    'exploit_available': record.get('exploit_available'),
                })

    return {
        'source': 'nessus_import',
        'total_hosts': len(hosts),
        'total_findings': sum(by_severity.values()),
        'by_severity': by_severity,
        'by_host': by_host,
        'top_findings': top_findings,
    }
