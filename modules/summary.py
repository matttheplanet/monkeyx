"""End-of-run summary — operational debrief with coverage gaps and errors.

Called unconditionally from monkeyx.py's finally block after every run.
Focuses on: what ran, what failed, what looks suspicious, coverage gaps.
"""

import glob
import json
import logging
import os
import re
from collections import Counter
from datetime import datetime, timezone

from core.scan_db import is_finding_record as _is_finding_record
from core.utils import version_output_path
from modules.normalize import dedup_findings as _dedup_findings

logger = logging.getLogger('monkeyx.modules.summary')

REQUIRED_INPUTS = frozenset()

# Cloud / CDN / SaaS provider fingerprints. Each host or CNAME/MX target is
# matched by DNS suffix (longest suffix wins) to (provider, category). This is
# a descriptive inventory of infrastructure in use — NOT a scope/authorization
# judgment (the tool can't infer authorization from DNS; see the recon summary
# caveat in target_ledger). Categories: object-storage | cdn | hosting | mail.
_CLOUD_SUFFIXES = {
    # object storage (buckets)
    ".blob.core.windows.net": ("Azure", "object-storage"),
    ".s3.amazonaws.com": ("AWS S3", "object-storage"),
    ".amazonaws.com": ("AWS", "hosting"),
    ".storage.googleapis.com": ("GCP", "object-storage"),
    ".firebaseio.com": ("Firebase", "object-storage"),
    ".firebasestorage.app": ("Firebase", "object-storage"),
    ".digitaloceanspaces.com": ("DigitalOcean Spaces", "object-storage"),
    # CDN / edge
    ".cloudfront.net": ("CloudFront", "cdn"),
    ".azureedge.net": ("Azure", "cdn"),
    ".trafficmanager.net": ("Azure", "cdn"),
    ".fastly.net": ("Fastly", "cdn"),
    ".akamaiedge.net": ("Akamai", "cdn"),
    ".akamai.net": ("Akamai", "cdn"),
    ".edgekey.net": ("Akamai", "cdn"),
    ".cloudflare.net": ("Cloudflare", "cdn"),
    ".cdn.cloudflare.net": ("Cloudflare", "cdn"),
    # hosting / PaaS
    ".github.io": ("GitHub Pages", "hosting"),
    ".azurewebsites.net": ("Azure", "hosting"),
    ".herokudns.com": ("Heroku", "hosting"),
    # mail SaaS (MX targets)
    ".pphosted.com": ("Proofpoint", "mail"),
    ".mail.protection.outlook.com": ("Microsoft 365", "mail"),
    ".mailgun.org": ("Mailgun", "mail"),
    ".googlemail.com": ("Google Workspace", "mail"),
    ".google.com": ("Google Workspace", "mail"),
    ".mx.cloudflare.net": ("Cloudflare Email", "mail"),
    ".mimecast.com": ("Mimecast", "mail"),
    ".messagelabs.com": ("Symantec Email", "mail"),
    ".protection.office365.us": ("Microsoft 365", "mail"),
}

# bbot bucket module name -> (provider, category). Most reliable bucket signal.
_BBOT_BUCKET_PROVIDERS = {
    "bucket_amazon": ("AWS S3", "object-storage"),
    "bucket_google": ("GCP", "object-storage"),
    "bucket_azure": ("Azure", "object-storage"),
    "bucket_digitalocean": ("DigitalOcean Spaces", "object-storage"),
    "bucket_firebase": ("Firebase", "object-storage"),
}


def _match_provider(value: str) -> tuple[str, str] | None:
    """Map a host / CNAME / MX target to (provider, category) by DNS suffix.

    Longest matching suffix wins, so `.s3.amazonaws.com` beats `.amazonaws.com`.
    Returns None when nothing matches.
    """
    if not value:
        return None
    host = str(value).strip().lower().rstrip(".")
    best = None
    best_len = -1
    for suffix, provider in _CLOUD_SUFFIXES.items():
        if host.endswith(suffix) and len(suffix) > best_len:
            best = provider
            best_len = len(suffix)
    return best


def generate_summary(output_dir, results):
    """Generate end-of-run debrief from an output directory.

    Args:
        output_dir: Root output directory (contains discovery-ledger.jsonl, data/, reports/)
        results: List of module result dicts from the run

    Returns:
        Path to the written summary.md, or None if output_dir is missing.
    """
    if not output_dir or not os.path.isdir(output_dir):
        return None

    data_dir = os.path.join(output_dir, "data")
    reports_dir = os.path.join(output_dir, "reports")

    stats = _collect_stats(data_dir, output_dir, results)
    _print_terminal_summary(stats)

    md_path = os.path.join(reports_dir, "summary.md")
    _write_markdown_report(stats, md_path)
    _write_readme(output_dir)
    return md_path


def run_summary(prefix, **kwargs):
    """Module interface — allows running summary as an explicit workflow step."""
    prefix = kwargs.get('data_prefix', prefix)
    reports_prefix = kwargs.get('reports_prefix', prefix)

    data_dir = os.path.dirname(prefix) if prefix else '.'
    output_dir = os.path.dirname(data_dir)
    reports_dir = os.path.dirname(reports_prefix) if reports_prefix else data_dir

    stats = _collect_stats(data_dir, output_dir, [])
    _print_terminal_summary(stats)

    md_path = os.path.join(reports_dir, "summary.md")
    _write_markdown_report(stats, md_path)
    if output_dir and os.path.isdir(output_dir):
        _write_readme(output_dir)

    return {
        'module': 'summary',
        'status': 'success',
        'output_files': [md_path],
    }


_README_TEXT = """\
MonkeyX scan output — start here

  report.html    <- OPEN THIS FIRST: full findings report (self-contained HTML,
                 no install needed — just open it in a browser). Scan debrief,
                 findings, AI analysis (attack paths + prioritized
                 recommendations) and validation results. A prioritized "Start
                 Here" focus list and a written AI screenshot analysis appear
                 when the run produced them. It does NOT embed the screenshot
                 images themselves — those are files under reports/ (see below),
                 browsable as a gallery in the optional viewer.
  reports/       human-readable output: summary.md, AI analysis (.md), CSVs,
                 and the web screenshot images (gowitness/)
  data/          machine-readable scan data (JSONL / XML / JSON) for tooling
  logs/          operational logs (monkeyx.log, errors.log)
  viewer/        interactive report viewer (present in the results zip) — an
                 optional live web UI over this run's data: searchable/sortable
                 findings, ports, targets, web endpoints, and a Screenshots
                 gallery (AI-prioritized). See "Interactive viewer" below.
  *-results.zip  portable archive of the above

Interactive viewer (optional — report.html already has everything for a quick read)
  Needs Python 3.10+. One command creates a local virtualenv, installs two
  packages (fastapi + uvicorn), and opens the UI on http://127.0.0.1:8765:

    macOS/Linux:   ./viewer/run.sh
    Windows:       viewer\\run.bat

  Run it from the unzipped run directory (the folder holding scan.db). It reads
  scan.db read-only and binds localhost only. No MonkeyX engine required.

Machine/state files at this root (discovery-ledger.jsonl, progress.jsonl,
scan.db) drive the scan, the viewer, and cross-run merging.
"""


def _write_readme(output_dir):
    """Write a short orientation file at the output-dir root. Best-effort.

    Static text, overwritten each run — points a human at report.html and
    explains the folder layout. Never fatal: a README write failure must not
    fail the run.
    """
    try:
        with open(os.path.join(output_dir, "README.txt"), "w",
                  encoding="utf-8") as fh:
            fh.write(_README_TEXT)
    except OSError as e:
        logger.warning("Could not write README.txt to output-dir root: %s", e)


# ---------------------------------------------------------------------------
# Data collection
# ---------------------------------------------------------------------------

def _collect_stats(data_dir, output_dir, results):
    """Gather operational stats from ledger, output files, and module results."""
    stats = {
        'targets': {'ips': 0, 'domains': 0, 'urls': 0, 'subdomains': 0,
                    'ips_total': 0, 'domains_total': 0, 'urls_total': 0,
                    'subdomains_total': 0, 'ips_host': 0},
        'ports': {'total': 0, 'hosts_with_ports': 0},
        'attack_surface': {},   # port/service/OS overview (from analyze's analysis.json)
        'findings': {'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0},
        'modules': {'succeeded': [], 'failed': [], 'empty_output': [], 'skipped': []},
        'module_history': [],
        'clouds': [],
        'coverage': [],
        'warnings': [],
        'priorities': {'top': [], 'count': 0, 'confirmed': 0},
        'run': {'duration_hours': None, 'duration_human': None,
                'fleet_nodes': None, 'cost': None},
    }

    # Parse ledger for target counts (totals + a not-excluded fallback).
    ledger_path = os.path.join(output_dir, "discovery-ledger.jsonl")
    if os.path.exists(ledger_path):
        _parse_ledger(ledger_path, stats)

    # Run-level stats: wall-clock duration (from progress.jsonl) + fleet size.
    _collect_run_meta(output_dir, stats)

    # Host/port/service/OS overview from analyze's analysis.json — rendered in the
    # debrief's Attack Surface section (dropped from analysis.md to avoid the dup).
    _read_analysis_overview(data_dir, stats)

    # Correct the In-Scope counts from scan.db's authoritative `in_scope` flag.
    # The JSONL only records provenance `scope` (explicit/derived/excluded), so
    # the ledger-derived count above treats every DERIVED target as in-scope —
    # wrong for a derived IP that resolves out of scope (private/internal-DNS
    # leakage, or name-safe assets never host-scanned). scan.db is the source of
    # truth for the resolved flag; use it when present.
    _apply_scandb_scope_counts(output_dir, stats)

    # Parse normalized output for finding severity counts
    if os.path.isdir(data_dir):
        _parse_findings(data_dir, stats, output_dir)

    # Cloud / CDN / SaaS provider inventory from bbot buckets + DNS records
    if os.path.isdir(data_dir):
        _parse_clouds(data_dir, stats)

    # Technology-stack inventory from bbot TECHNOLOGY events
    if os.path.isdir(data_dir):
        _parse_technologies(data_dir, stats)

    # Analyze module results for failures and empty output
    _analyze_module_results(results, data_dir, stats)

    # Cumulative per-module run history (across all runs against this output dir)
    _build_module_history(output_dir, stats)

    # Check coverage gaps (what was fed to modules vs what was in the ledger)
    if os.path.isdir(data_dir):
        _check_coverage(data_dir, stats)

    # Top priorities from the focus module (if it ran)
    if os.path.isdir(data_dir):
        _parse_focus(data_dir, stats)

    return stats


def _collect_run_meta(output_dir, stats):
    """Populate stats['run']: total wall-clock duration + fleet node count.

    Duration comes from the min/max timestamps across all progress.jsonl events
    (spans --continue/--resume passes against this output dir, so it's the true
    elapsed time). Fleet size comes from the axiom source-IP file, which is
    `ax ls`'d live-instance IPs (one per node) — the actual fleet, not just the
    requested -n. A local-only run has no source-IP file, so fleet_nodes stays
    None (the row is omitted). Best-effort: any parse issue leaves the defaults.
    """
    import glob
    from datetime import datetime

    times = []
    prog = os.path.join(output_dir, "progress.jsonl")
    if os.path.exists(prog):
        with open(prog, encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except json.JSONDecodeError:
                    continue
                for key in ("started_at", "finished_at"):
                    if e.get(key):
                        times.append(e[key])
    if times:
        try:
            parsed = [datetime.fromisoformat(t) for t in times]
            secs = (max(parsed) - min(parsed)).total_seconds()
            if secs >= 0:
                stats['run']['duration_hours'] = round(secs / 3600, 2)
                stats['run']['duration_human'] = (
                    f"{int(secs // 3600)}h {int((secs % 3600) // 60)}m")
        except (ValueError, TypeError):
            pass

    ips = set()
    patterns = [os.path.join(output_dir, "logs", "*axiom-source-ips.txt"),
                os.path.join(output_dir, "*axiom-source-ips.txt")]
    for pattern in patterns:
        for path in glob.glob(pattern):
            try:
                with open(path, encoding="utf-8", errors="ignore") as fh:
                    for line in fh:
                        v = line.strip()
                        if v and not v.startswith("#"):
                            ips.add(v)
            except OSError:
                pass
    if ips:
        stats['run']['fleet_nodes'] = len(ips)

    # Structured cost/compute summary (fleet node-hours + AI cost), written by
    # core.cost_tracker just before the summary finalizer runs.
    cost_path = os.path.join(output_dir, "logs", "cost-summary.json")
    if os.path.exists(cost_path):
        try:
            with open(cost_path, encoding="utf-8") as fh:
                stats['run']['cost'] = json.load(fh)
        except (OSError, json.JSONDecodeError):
            pass


def _parse_focus(data_dir, stats):
    """Pull the top-ranked focus items so the debrief opens on priorities.

    Reads the newest `*-focus.json` the focus module wrote. Best-effort — a
    missing or malformed file just leaves the empty default (banner is skipped).
    """
    paths = [p for p in glob.glob(os.path.join(data_dir, "*-focus.json"))
             if not re.search(r'\.run\d+\.json$', p)]
    if not paths:
        return
    path = max(paths, key=os.path.getmtime)
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (json.JSONDecodeError, OSError):
        return
    items = data.get('focus') or []
    stats['priorities'] = {
        'count': data.get('count', len(items)),
        'confirmed': data.get('confirmed', 0),
        'top': items[:5],
    }


def _parse_ledger(ledger_path, stats):
    """Count targets by type from the discovery ledger."""
    # Track two figures per type: everything the ledger recorded (total, incl.
    # excluded/blocked targets) and what was actually in scope (not excluded), so
    # the debrief can show e.g. "4 IPs discovered, 3 in-scope (1 blocked)".
    ips, ips_all = set(), set()
    ips_host = set()   # non-excluded IPs on the HOST channel (-t / promoted) — the
                       # only ones nmap/masscan port-scan; name-safe (dl/ul) excluded
    domains, domains_all = set(), set()
    subdomains, subdomains_all = set(), set()
    urls, urls_all = set(), set()
    hosts_with_ports = set()
    port_count = 0

    try:
        with open(ledger_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue

                excluded = entry.get('scope') == 'excluded'
                t = entry.get('type')
                target = entry.get('target', '')

                if t == 'ip':
                    ips_all.add(target)
                    if not excluded:
                        ips.add(target)
                        if entry.get('channel') == 't':
                            ips_host.add(target)
                elif t == 'domain':
                    domains_all.add(target)
                    if not excluded:
                        domains.add(target)
                elif t == 'subdomain':
                    subdomains_all.add(target)
                    if not excluded:
                        subdomains.add(target)
                elif t == 'url':
                    urls_all.add(target)
                    if not excluded:
                        urls.add(target)
                elif t == 'port' and not excluded:
                    port_count += 1
                    hosts_with_ports.add(target)
    except OSError:
        return

    stats['targets']['ips'] = len(ips)
    stats['targets']['ips_host'] = len(ips_host)
    stats['targets']['domains'] = len(domains)
    stats['targets']['subdomains'] = len(subdomains)
    stats['targets']['urls'] = len(urls)
    stats['targets']['ips_total'] = len(ips_all)
    stats['targets']['domains_total'] = len(domains_all)
    stats['targets']['subdomains_total'] = len(subdomains_all)
    stats['targets']['urls_total'] = len(urls_all)
    stats['ports']['total'] = port_count
    stats['ports']['hosts_with_ports'] = len(hosts_with_ports)


def _apply_scandb_scope_counts(output_dir, stats):
    """Override the In-Scope (and Total) target counts from scan.db.

    scan.db's `targets.in_scope` is the resolved authorization flag (a derived
    IP that resolves out of scope is 0); the discovery-ledger JSONL only carries
    provenance `scope`, so the ledger-based count over-reports in-scope by
    counting every non-excluded derived target. Best-effort: if scan.db is
    absent or unreadable, the ledger fallback already in `stats` stands.

    Total = every target of that type the ledger recorded (incl. excluded);
    In-Scope = rows with in_scope = 1 — EXCEPT for IPs, where in-scope counts
    only host-authorized IPs (channel 't': an explicit -t IP or one inside a -t
    range). A name-derived IP stays in the ledger's in-scope set so its hostname
    gets scanned, but it is name-safe (never bare-IP scanned), so counting it as
    an in-scope IP over-reports what was actually scanned as a host. This matches
    the webserver targets view.
    """
    try:
        from core import scan_db as _scan_db
        if not os.path.exists(_scan_db.db_path_for(output_dir)):
            return
        db = _scan_db.open_db(output_dir)
    except Exception:
        return
    try:
        type_to_key = {'ip': 'ips', 'domain': 'domains',
                       'subdomain': 'subdomains', 'url': 'urls'}
        in_scope = {k: 0 for k in type_to_key.values()}
        total = {k: 0 for k in type_to_key.values()}
        for row in db._conn.execute(
                "SELECT target_type, in_scope, channel FROM targets"):
            key = type_to_key.get(row["target_type"])
            if not key:
                continue
            total[key] += 1
            if not row["in_scope"]:
                continue
            # Name-derived IPs are name-safe, not host-full IP targets.
            if row["target_type"] == "ip" and (row["channel"] or "") != "t":
                continue
            in_scope[key] += 1
    except Exception:
        return
    finally:
        try:
            db.close(checkpoint=False)
        except Exception:
            pass
    # If scan.db recorded no targets at all (e.g. a run that failed before the
    # ledger populated it), don't zero out the ledger-derived fallback.
    if sum(total.values()) == 0:
        return
    for key in ('ips', 'domains', 'subdomains', 'urls'):
        stats['targets'][key] = in_scope[key]
        stats['targets'][f"{key}_total"] = total[key]


def _parse_findings(data_dir, stats, output_dir=None):
    """Count findings by severity from normalized JSONL, with per-tool breakdown.

    JSONL-backed tools are counted from their ``*-normalized.jsonl``. Tools that
    write findings only to scan.db and have no normalized JSONL (e.g. gowitness,
    minted by ai_analyze_gowitness) are merged in from scan.db afterwards, keyed
    on the JSONL-tool set below so nothing is counted twice.
    """
    severity_counter = Counter()
    tool_findings = {}

    patterns = [
        ("nuclei", os.path.join(data_dir, "*-nuclei-normalized.jsonl")),
        ("nessus", os.path.join(data_dir, "*-nessus-normalized.jsonl")),
        ("bbot", os.path.join(data_dir, "*-bbot-normalized.jsonl")),
        ("dns_security", os.path.join(data_dir, "*-dns-security.jsonl")),
        ("testssl", os.path.join(data_dir, "*-testssl-normalized.jsonl")),
        # nmap-normalized mixes open_port + info script_output + real
        # vulnerability rows; _is_finding_record keeps only the findings so the
        # state-classified nmap vulns are counted without the context noise.
        ("nmap", os.path.join(data_dir, "*-nmap-normalized.jsonl")),
    ]
    jsonl_tools = {name for name, _ in patterns}

    for tool_name, pattern in patterns:
        tool_sev = Counter()
        tool_records = []
        for path in glob.glob(pattern):
            try:
                with open(path, encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            record = json.loads(line)
                        except json.JSONDecodeError:
                            continue

                        # Only count genuine findings: real finding-type rows or
                        # anything above info. Excludes open_port / info-level
                        # script_output context (ssl-cert, http-title, ...).
                        if not _is_finding_record(record):
                            continue
                        tool_records.append(record)
            except OSError:
                continue
        # Collapse duplicate JSONL rows by finding_id so the count matches
        # scan.db (the source of truth) instead of over-counting re-emitted rows.
        for record in _dedup_findings(tool_records):
            severity = _extract_severity(record)
            severity_counter[severity] += 1
            tool_sev[severity] += 1
        if sum(tool_sev.values()) > 0:
            tool_findings[tool_name] = dict(tool_sev)
            tool_findings[tool_name]['total'] = sum(tool_sev.values())

    # Merge scan.db-only finding tools (no normalized JSONL) — e.g. gowitness.
    _merge_scandb_only_findings(output_dir, jsonl_tools, severity_counter, tool_findings)

    stats['findings']['total'] = sum(severity_counter.values())
    for sev in ('critical', 'high', 'medium', 'low', 'info'):
        stats['findings'][sev] = severity_counter.get(sev, 0)
    stats['findings']['by_tool'] = tool_findings


def _merge_scandb_only_findings(output_dir, jsonl_tools, severity_counter, tool_findings):
    """Add findings from tools that live only in scan.db (no ``*-normalized.jsonl``).

    Counts finding rows whose ``tool`` is NOT one of the JSONL-backed tools, so
    JSONL-counted tools (nuclei/bbot/testssl/…) are never double-counted. gowitness
    is the current case: ai_analyze_gowitness mints its findings straight to
    scan.db. Best-effort — a missing/locked DB just leaves the JSONL totals as-is.
    """
    if not output_dir:
        return
    try:
        from core import scan_db as _scan_db
        if not os.path.exists(_scan_db.db_path_for(output_dir)):
            return
        db = _scan_db.open_db(output_dir)
        if db is None:
            return
        try:
            rows = db._conn.execute(
                "SELECT tool, LOWER(COALESCE(severity, 'info')) AS sev, COUNT(*) AS c "
                "FROM findings GROUP BY tool, sev"
            ).fetchall()
        finally:
            db.close(checkpoint=False)
    except Exception as exc:  # pragma: no cover - defensive; DB never fails summary
        logger.debug("scan.db finding merge skipped: %s", exc)
        return

    for row in rows:
        tool = row["tool"] or ""
        if not tool or tool in jsonl_tools:
            continue
        sev = row["sev"] if row["sev"] in ("critical", "high", "medium", "low", "info") else "info"
        count = row["c"] or 0
        if count <= 0:
            continue
        severity_counter[sev] += count
        bucket = tool_findings.setdefault(tool, {})
        bucket[sev] = bucket.get(sev, 0) + count
        bucket['total'] = bucket.get('total', 0) + count


def _extract_severity(record):
    """Pull severity string from a normalized record."""
    sev = record.get('severity', '')
    if not sev and isinstance(record.get('data'), dict):
        sev = record['data'].get('severity', '')
    sev = sev.lower() if sev else 'info'
    return sev if sev in ('critical', 'high', 'medium', 'low', 'info') else 'info'


def _parse_clouds(data_dir, stats):
    """Inventory cloud/CDN/SaaS providers from bbot buckets + DNS records.

    Two signal sources:
    - bbot STORAGE_BUCKET events (`*-bbot-normalized.jsonl`): the bucket provider
      comes from bbot's own module name (`bucket_azure`, ...) when present, else
      the bucket host suffix.
    - DNS resolve report (`*-resolve-report.jsonl`): each CNAME target and MX host
      is suffix-matched — reveals CDN fronting (cloudfront/akamai/fastly) and mail
      SaaS (Proofpoint/M365/Mailgun). `cdn`/`cdn-name` (fleet recon path only)
      upgrades a cname signal to "cdn".

    Populates stats['clouds'] as a sorted list of
    {provider, category, signals[], host_count, sample_hosts[]}.
    """
    # provider -> {"category": str, "signals": set, "hosts": set}
    providers: dict[str, dict] = {}

    def _add(match, signal, host):
        if not match:
            return
        provider, category = match
        p = providers.setdefault(
            provider, {"category": category, "signals": set(), "hosts": set()})
        p["signals"].add(signal)
        if host:
            p["hosts"].add(str(host).strip().lower().rstrip("."))

    # --- bbot storage buckets ---
    for path in glob.glob(os.path.join(data_dir, "*-bbot-normalized.jsonl")):
        try:
            with open(path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    # Select on bbot_type — `type` is the generic "finding".
                    if rec.get('bbot_type') != 'STORAGE_BUCKET':
                        continue
                    host = rec.get('host') or ''
                    match = _BBOT_BUCKET_PROVIDERS.get(rec.get('bbot_module'))
                    if not match:
                        match = _match_provider(host)
                    _add(match, 'bucket', host)
        except OSError:
            continue

    # --- DNS resolve report: CNAME + MX ---
    for path in glob.glob(os.path.join(data_dir, "*-resolve-report.jsonl")):
        try:
            with open(path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    host = rec.get('hostname') or ''
                    has_cdn = bool(rec.get('cdn') or rec.get('cdn-name'))
                    for cname in _as_list(rec.get('cname')):
                        _add(_match_provider(cname),
                             'cdn' if has_cdn else 'cname', host)
                    for mx in _as_list(rec.get('mx')):
                        mx_host = mx if isinstance(mx, str) else (
                            mx.get('host') if isinstance(mx, dict) else str(mx))
                        _add(_match_provider(mx_host), 'mx', host)
        except OSError:
            continue

    stats['clouds'] = [
        {
            'provider': name,
            'category': data['category'],
            'signals': sorted(data['signals']),
            'host_count': len(data['hosts']),
            'sample_hosts': sorted(data['hosts'])[:5],
        }
        for name, data in sorted(
            providers.items(), key=lambda kv: (-len(kv[1]['hosts']), kv[0]))
    ]


def _parse_technologies(data_dir, stats):
    """Inventory detected web technologies from bbot TECHNOLOGY events.

    normalize emits bbot TECHNOLOGY events as info-severity `technology` records
    (consumed by ai_analyze but previously never surfaced to a human). This rolls
    them up into stats['technologies'] as a deduped tech -> hosts inventory, so
    the debrief shows the target's tech stack. Best-effort; missing/malformed
    files are skipped.
    """
    tech_hosts: dict[str, set] = {}
    for path in glob.glob(os.path.join(data_dir, "*-bbot-normalized.jsonl")):
        try:
            with open(path, encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if rec.get("type") != "technology":
                        continue
                    tech = (rec.get("detail") or rec.get("title") or "").strip()
                    if not tech:
                        continue
                    host = (rec.get("host") or "").strip()
                    tech_hosts.setdefault(tech[:120], set())
                    if host and host != "unknown":
                        tech_hosts[tech[:120]].add(host)
        except OSError:
            continue
    stats['technologies'] = [
        {
            'tech': tech,
            'host_count': len(hosts),
            'sample_hosts': sorted(hosts)[:5],
        }
        for tech, hosts in sorted(
            tech_hosts.items(), key=lambda kv: (-len(kv[1]), kv[0]))
    ]


def _as_list(value):
    """Normalize a dnsx field that may be a scalar, list, or absent, to a list."""
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _analyze_module_results(results, data_dir, stats):
    """Categorize modules by outcome: success, failed, or suspicious empty output.

    If results list is empty (e.g. run was killed), falls back to reading
    progress.jsonl for completed/failed step info.
    """
    if not results:
        _load_from_progress_file(data_dir, stats)
        _check_ai_truncation(data_dir, stats)
        return

    for r in results:
        if not isinstance(r, dict):
            continue

        # Prefer the 'module' key, but fall back to 'name'/'step' so a module
        # whose result dict omits 'module' still shows its name instead of '?'.
        name = r.get('module') or r.get('name') or r.get('step') or '?'
        status = r.get('status', '')

        if status == 'failed':
            error = (r.get('error') or 'no error message').splitlines()[0]
            if len(error) > 120:
                error = error[:117] + "..."
            stats['modules']['failed'].append({'name': name, 'error': error})
        elif status == 'skipped':
            # Fed no in-scope targets (e.g. a host-class scan on a URL-only run).
            # Reported honestly, not as a clean success.
            stats['modules']['skipped'].append(name)
        elif status == 'warning':
            # run_module downgrades "ran but produced no output" to warning.
            # Surface it as an empty-output issue — never as a success.
            reason = (r.get('warning') or 'ran but produced no output').splitlines()[0]
            if len(reason) > 160:
                reason = reason[:157] + "..."
            stats['modules']['empty_output'].append(
                {'name': name, 'file': '', 'reason': reason})
        elif status == 'success':
            stats['modules']['succeeded'].append(name)
            # Check for empty output files
            output_files = r.get('output_files', [])
            for fpath in output_files:
                if not fpath:
                    continue
                full_path = fpath if os.path.isabs(fpath) else os.path.join(data_dir, os.path.basename(fpath))
                if os.path.exists(full_path):
                    size = os.path.getsize(full_path)
                    if size == 0:
                        stats['modules']['empty_output'].append({
                            'name': name,
                            'file': os.path.basename(full_path),
                            'reason': 'file is empty (0 bytes)',
                        })

            # Flag AI modules that truncated data
            if r.get('data_truncated'):
                stats['warnings'].append(
                    f"{name}: data was truncated due to limits — not all hosts/services were analyzed")

    # Also check ai-analysis.json for detailed truncation info
    _check_ai_truncation(data_dir, stats)


def _load_from_progress_file(data_dir, stats):
    """Fallback: read progress.jsonl when module results aren't available."""
    progress_path = os.path.join(data_dir, '..', 'progress.jsonl')
    if not os.path.exists(progress_path):
        return

    started = set()
    completed = set()
    failed = {}
    skipped = set()
    warned = {}  # name -> real warning message (first line), not a generic label

    try:
        with open(progress_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue

                name = event.get('step', '')
                etype = event.get('event', '')

                if etype == 'step_started':
                    started.add(name)
                elif etype == 'step_completed':
                    completed.add(name)
                    # A module fed nothing records status "skipped"; one that ran
                    # but produced no output records "warning". Track both
                    # separately so neither is reported as a clean success. Last
                    # write wins (a later run may have actually fed it/produced
                    # output), so track per-name.
                    st = event.get('status')
                    if st == 'skipped':
                        skipped.add(name); warned.pop(name, None)
                    elif st == 'warning':
                        # Keep the module's real message (e.g. "2 in-scope targets
                        # produced no results: …") — not a generic label.
                        warned[name] = (event.get('warning')
                                        or 'ran but produced no output').splitlines()[0]
                        skipped.discard(name)
                    else:
                        skipped.discard(name); warned.pop(name, None)
                elif etype == 'step_failed':
                    error = event.get('error', 'unknown error')
                    if len(error) > 120:
                        error = error[:117] + "..."
                    failed[name] = error
    except OSError:
        return

    skipped -= set(failed.keys())
    warned = {n: r for n, r in warned.items() if n not in failed and n not in skipped}
    stats['modules']['skipped'] = sorted(skipped)
    stats['modules']['succeeded'] = sorted(
        completed - set(failed.keys()) - skipped - set(warned))
    for name, error in failed.items():
        stats['modules']['failed'].append({'name': name, 'error': error})
    for name in sorted(warned):
        reason = warned[name]
        if len(reason) > 160:
            reason = reason[:157] + "..."
        stats['modules']['empty_output'].append(
            {'name': name, 'file': '', 'reason': reason})

    # Modules that started but neither completed nor failed = killed mid-run
    incomplete = started - completed - set(failed.keys())
    if incomplete:
        for name in sorted(incomplete):
            stats['modules']['failed'].append({'name': name, 'error': 'interrupted (did not complete)'})


def _build_module_history(output_dir, stats):
    """Build cumulative per-module run history from progress.jsonl.

    Unlike the succeeded/failed lists (which reflect only the most recent run),
    progress.jsonl is append-only and accumulates across every run against this
    output directory (--continue/--resume). For each module we report how many
    times it ran and the timestamp of its most recent completion or failure.
    """
    progress_path = os.path.join(output_dir, "progress.jsonl")
    if not os.path.exists(progress_path):
        return

    # module name -> {'runs': int, 'last_run': iso str, 'last_status': str}
    history = {}

    try:
        with open(progress_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue

                etype = event.get('event', '')
                if etype == 'step_completed':
                    # Honor the recorded outcome — a step can complete with
                    # 'warning' (ran but produced no output) or 'skipped'. Reporting
                    # those as 'success' hides real coverage gaps.
                    status = event.get('status') or 'success'
                elif etype == 'step_failed':
                    status = 'failed'
                else:
                    continue

                name = event.get('step', '')
                if not name:
                    continue

                ts = event.get('finished_at', '')
                # step_completed records duration_seconds directly; step_failed
                # doesn't, so derive it from started_at/finished_at.
                dur = event.get('duration_seconds')
                if dur is None:
                    dur = _secs_between(event.get('started_at'), ts)
                entry = history.setdefault(
                    name, {'runs': 0, 'last_run': '', 'last_status': '',
                           'last_duration': None})
                entry['runs'] += 1
                # Timestamps are ISO 8601 (UTC), so string comparison orders them.
                if ts >= entry['last_run']:
                    entry['last_run'] = ts
                    entry['last_status'] = status
                    entry['last_duration'] = dur
    except OSError:
        return

    stats['module_history'] = [
        {
            'name': name,
            'runs': data['runs'],
            'last_run': data['last_run'],
            'last_status': data['last_status'],
            'last_duration': data['last_duration'],
        }
        for name, data in sorted(history.items())
    ]


def _read_analysis_overview(data_dir, stats):
    """Load the port/service/OS overview from analyze's `analysis.json`.

    analyze emits this data to JSON but no longer renders it in analysis.md; the
    debrief is its human home (Attack Surface section). Skips the sibling
    `ai-analysis.json` (different file, same glob)."""
    for path in sorted(glob.glob(os.path.join(data_dir, "*-analysis.json"))):
        if "ai-analysis" in os.path.basename(path):
            continue
        try:
            with open(path, encoding="utf-8") as f:
                d = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue
        pss = d.get("port_service_stats") or {}
        summ = d.get("summary") or {}
        stats["attack_surface"] = {
            "port_counts": pss.get("port_counts") or {},
            "service_version_counts": pss.get("service_version_counts") or [],
            "os_fingerprint": d.get("os_fingerprint") or {},
            "unique_ports": summ.get("unique_ports"),
            "unique_services": summ.get("unique_services"),
        }
        # Surface analyze's port-scan coverage notes in the debrief's Needs
        # Attention block — they otherwise only appear in analysis.md.
        meta = d.get("metadata") or {}
        for key in ("port_scan_warning", "port_scan_scope_note",
                    "port_scan_incomplete_note"):
            note = meta.get(key)
            if note and note not in stats["warnings"]:
                stats["warnings"].append(note)
        return


def _check_ai_truncation(data_dir, stats):
    """Read ai-analysis.json for truncation details and AI settings."""
    for path in glob.glob(os.path.join(data_dir, "*-ai-analysis.json")):
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue

        meta = data.get('metadata', {})
        if meta and 'ai_settings' not in stats:
            stats['ai_settings'] = {
                'provider': meta.get('ai_provider', 'unknown'),
                'model': meta.get('ai_model', 'unknown'),
                'depth': meta.get('depth', 'standard'),
                'hosts_analyzed': meta.get('hosts_analyzed', '?'),
                'hosts_total': meta.get('hosts_total', '?'),
            }
            usage = meta.get('ai_usage', {})
            if usage:
                stats['ai_settings']['input_tokens'] = usage.get('input_tokens', 0)
                stats['ai_settings']['output_tokens'] = usage.get('output_tokens', 0)

        truncation = data.get('truncation')
        if not truncation:
            continue

        if truncation.get('hosts_truncated'):
            analyzed = truncation.get('hosts_analyzed', '?')
            total = truncation.get('hosts_total', '?')
            stats['coverage'].append(
                f"ai_analyze reviewed {analyzed}/{total} hosts (increase with ai_depth=deep or ai_max_hosts=unlimited)")

        if truncation.get('findings_truncated'):
            hosts = truncation.get('findings_truncated_hosts', [])
            count = len(hosts)
            stats['coverage'].append(
                f"ai_analyze capped findings on {count} host(s) — some findings not reviewed")

        if truncation.get('web_dirs_truncated'):
            hosts = truncation.get('web_dirs_truncated_hosts', [])
            count = len(hosts)
            stats['coverage'].append(
                f"ai_analyze capped web directory results on {count} host(s)")


def _check_coverage(data_dir, stats):
    """Compare ledger target counts vs what modules actually received."""
    snapshot_dir = os.path.join(data_dir, "step-snapshots")
    if not os.path.isdir(snapshot_dir):
        return

    # Count ledger totals for comparison. For nmap/masscan the right denominator
    # is the HOST-channel (-t / promoted) IP set — NOT every ledger IP. Name-safe
    # (dl/ul) IPs resolved from -d/-url are deliberately never port-scanned, so
    # comparing nmap's input against all ledger IPs reported a huge, misleading
    # "not scanned" gap that was really the host-vs-name-safe boundary working.
    host_ips = stats['targets']['ips_host']
    ledger_urls = stats['targets']['urls']

    # Look at what nmap received vs the host-authorized target set it SHOULD scan.
    nmap_snapshots = glob.glob(os.path.join(snapshot_dir, "*-ax_nmap_tcp-target.txt"))
    for snap in nmap_snapshots:
        try:
            with open(snap, encoding="utf-8") as f:
                fed_count = sum(1 for line in f if line.strip())
            if host_ips > 0 and fed_count < host_ips:
                gap = host_ips - fed_count
                stats['coverage'].append(
                    f"ax_nmap_tcp received {fed_count}/{host_ips} host-authorized IPs "
                    f"({gap} in-scope host targets not scanned — exclusions or scope filter)")
        except OSError:
            continue

    # Check nuclei URL coverage
    nuclei_snapshots = glob.glob(os.path.join(snapshot_dir, "*-ax_nuclei-urls.txt"))
    for snap in nuclei_snapshots:
        try:
            with open(snap, encoding="utf-8") as f:
                fed_count = sum(1 for line in f if line.strip())
            if ledger_urls > 0 and fed_count < ledger_urls:
                gap = ledger_urls - fed_count
                stats['coverage'].append(
                    f"ax_nuclei received {fed_count}/{ledger_urls} URLs ({gap} not scanned)")
        except OSError:
            continue

    # Check gowitness URL coverage
    gowitness_snapshots = glob.glob(os.path.join(snapshot_dir, "*-ax_gowitness-urls.txt"))
    for snap in gowitness_snapshots:
        try:
            with open(snap, encoding="utf-8") as f:
                fed_count = sum(1 for line in f if line.strip())
            if ledger_urls > 0 and fed_count < ledger_urls:
                gap = ledger_urls - fed_count
                stats['coverage'].append(
                    f"ax_gowitness received {fed_count}/{ledger_urls} URLs ({gap} not screenshotted)")
        except OSError:
            continue


# ---------------------------------------------------------------------------
# Terminal output
# ---------------------------------------------------------------------------

def _print_terminal_summary(stats):
    """Print operational debrief to stdout."""
    t = stats['targets']
    p = stats['ports']
    f = stats['findings']
    m = stats['modules']

    print(f"\n{'='*60}")
    print("  SCAN DEBRIEF")
    print(f"{'='*60}")

    # Module execution status
    skipped_mods = m.get('skipped', [])
    total_modules = len(m['succeeded']) + len(m['failed']) + len(skipped_mods)
    print(f"\n  Execution")
    print(f"    Modules run: {total_modules}")
    print(f"    Succeeded:   {len(m['succeeded'])}")
    if m['empty_output']:
        print(f"    No output:   {len(m['empty_output'])} (ran but produced nothing)")
    if skipped_mods:
        print(f"    Skipped:     {len(skipped_mods)} (fed no in-scope targets)")
    if m['failed']:
        print(f"    Failed:      {len(m['failed'])}")

    # Per-module run times (most recent run), slowest first — the data is in
    # module_history; skip the block entirely if no durations were recorded
    # (e.g. an older progress.jsonl).
    history = stats.get('module_history', [])
    timed = [h for h in history if h.get('last_duration') is not None]
    if timed:
        timed.sort(key=lambda h: h['last_duration'], reverse=True)
        name_w = min(max((len(h['name']) for h in timed), default=0), 32)
        print(f"\n  Module Run Times (most recent run)")
        for h in timed:
            status = h.get('last_status') or 'success'
            tag = '' if status == 'success' else f"  ({status})"
            print(f"    {h['name']:<{name_w}}  {_fmt_duration(h['last_duration']):>8}{tag}")

    # Scope / discovery stats
    print(f"\n  Scope")
    print(f"    IPs:         {t['ips']}")
    print(f"    Domains:     {t['domains']}")
    if t['subdomains']:
        print(f"    Subdomains:  {t['subdomains']}")
    print(f"    URLs:        {t['urls']}")
    print(f"    Open ports:  {p['total']} across {p['hosts_with_ports']} hosts")

    # Finding counts
    if f['total']:
        print(f"\n  Findings")
        print(f"    Critical: {f['critical']}  High: {f['high']}  Medium: {f['medium']}  Low: {f['low']}  Info: {f['info']}")

    # Cloud / CDN / SaaS providers
    clouds = stats.get('clouds', [])
    if clouds:
        print(f"\n  Cloud Providers")
        for c in clouds:
            print(f"    {c['provider']} ({c['category']}): {c['host_count']} host(s)")

    # === NEEDS ATTENTION ===
    has_issues = m['failed'] or m['empty_output'] or stats['coverage'] or stats['warnings']
    if has_issues:
        print(f"\n  {'─'*56}")
        print(f"  NEEDS ATTENTION")
        print(f"  {'─'*56}")

        if m['failed']:
            print(f"\n  Failed Modules:")
            for item in m['failed']:
                print(f"    ✗ {item['name']}: {item['error']}")

        if m['empty_output']:
            print(f"\n  Empty Output (ran OK but produced nothing):")
            for item in m['empty_output']:
                if item['file']:
                    print(f"    ? {item['name']}: {item['file']} — {item['reason']}")
                else:
                    print(f"    ? {item['name']}: {item['reason']}")

        if stats['coverage']:
            print(f"\n  Coverage Gaps:")
            for gap in stats['coverage']:
                print(f"    ! {gap}")

        if stats['warnings']:
            print(f"\n  Warnings:")
            for w in stats['warnings']:
                print(f"    ! {w}")

    print(f"\n{'='*60}\n")


# ---------------------------------------------------------------------------
# Markdown report
# ---------------------------------------------------------------------------

def _format_timestamp(iso_ts):
    """Render an ISO 8601 timestamp as 'YYYY-MM-DD HH:MM UTC' for the report."""
    if not iso_ts:
        return "-"
    try:
        dt = datetime.fromisoformat(iso_ts)
    except (ValueError, TypeError):
        return iso_ts
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')


def _secs_between(started_at, finished_at):
    """Seconds between two ISO 8601 timestamps, or None if either is unparseable."""
    try:
        start = datetime.fromisoformat(started_at)
        end = datetime.fromisoformat(finished_at)
    except (ValueError, TypeError):
        return None
    return (end - start).total_seconds()


def _fmt_duration(seconds):
    """Seconds -> compact per-module runtime: '45s', '2m 10s', '1h 03m'."""
    try:
        s = int(round(float(seconds)))
    except (ValueError, TypeError):
        return "-"
    if s < 0:
        return "-"
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m {s % 60:02d}s"
    return f"{s // 3600}h {(s % 3600) // 60:02d}m"


def _md_cell(value):
    """Escape a value for a markdown table cell (pipes/newlines break tables)."""
    s = str(value if value is not None else '')
    return s.replace('|', '\\|').replace('\n', ' ').replace('\r', ' ').strip()


def _fmt_secs(seconds):
    """Seconds -> 'Xh Ym' for the report."""
    try:
        s = float(seconds)
    except (ValueError, TypeError):
        return "-"
    return f"{int(s // 3600)}h {int((s % 3600) // 60)}m"


def _append_cost_compute(lines, stats):
    """Render the consolidated Cost & Compute block: total run time, fleet
    node-hours (+ instance type when configured), and AI spend — so a reader can
    calculate their own cloud cost. Run time / fleet-node count come from
    progress.jsonl + the source-IP list (always available); node-hours,
    instance type, and AI cost come from logs/cost-summary.json (written by the
    engine's cost tracker at finalize). Renders whatever is present."""
    run = stats.get('run', {})
    cost = run.get('cost') or {}
    fleet = cost.get('fleet') or {}
    ai = cost.get('ai') or {}
    duration_h = run.get('duration_hours')
    nodes = fleet.get('nodes') if fleet.get('nodes') is not None else run.get('fleet_nodes')

    if duration_h is None and nodes is None and not ai:
        return  # nothing to show (e.g. a bare re-run of summary alone)

    lines.append("\n## Cost & Compute\n")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    if duration_h is not None:
        human = run.get('duration_human')
        lines.append(f"| Total run time | {duration_h} h{f' ({human})' if human else ''} |")
    if nodes is not None:
        lines.append(f"| Fleet nodes | {nodes} |")
    if fleet.get('instance_type'):
        lines.append(f"| Instance type | {_md_cell(fleet['instance_type'])} |")
    if fleet.get('uptime_s') is not None:
        lines.append(f"| Fleet uptime | {_fmt_secs(fleet['uptime_s'])} |")
    if fleet.get('node_hours') is not None:
        lines.append(f"| Cloud instance-hours (node-hours) | {fleet['node_hours']} |")
    if ai:
        prov = ", ".join(ai.get('providers') or []) or "?"
        model = ", ".join(ai.get('models') or []) or "?"
        lines.append(f"| AI provider / model | {_md_cell(prov)} / {_md_cell(model)} |")
        if ai.get('calls'):
            lines.append(f"| AI calls | {ai['calls']} |")
        toks = ai.get('input_tokens', 0) + ai.get('output_tokens', 0)
        if toks:
            lines.append(f"| AI tokens | {toks:,} |")
        c = ai.get('total_cost_usd')
        if c:
            est = " (est.)" if ai.get('cost_is_estimate') else ""
            lines.append(f"| AI cost | ${c:.4f}{est} |")
        elif ai.get('cost_unknown'):
            lines.append("| AI cost | unknown (no pricing for the model used) |")
    lines.append("")

    if fleet.get('node_hours') is not None:
        nh = fleet['node_hours']
        if fleet.get('instance_type'):
            lines.append(
                f"_Estimated fleet cost = **{nh} node-hours × the hourly price of "
                f"`{_md_cell(fleet['instance_type'])}`** from your cloud provider._")
        else:
            lines.append(
                f"_Estimated fleet cost = **{nh} node-hours × your cloud provider's "
                f"hourly price per instance**. Tip: set `fleet.instance_type` in "
                f"monkeyx.config so this report names the instance size and you can "
                f"plug in its exact rate._")


def _write_markdown_report(stats, md_path):
    """Write structured markdown debrief."""
    t = stats['targets']
    p = stats['ports']
    f = stats['findings']
    m = stats['modules']

    lines = []
    lines.append("# Scan Debrief")
    lines.append(f"\nGenerated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")

    # Execution
    skipped_mods = m.get('skipped', [])
    total_modules = len(m['succeeded']) + len(m['failed']) + len(skipped_mods)
    lines.append("\n## Execution\n")
    lines.append(f"| Metric | Value |")
    lines.append(f"|--------|-------|")
    lines.append(f"| Modules run | {total_modules} |")
    lines.append(f"| Succeeded | {len(m['succeeded'])} |")
    if m['empty_output']:
        lines.append(f"| Ran, no output | {len(m['empty_output'])} |")
    if skipped_mods:
        lines.append(f"| Skipped (no input) | {len(skipped_mods)} |")
    lines.append(f"| Failed | {len(m['failed'])} |")

    # (No per-module "Succeeded:" list here — the Execution count above plus the
    # Module Run History section already cover which modules ran.)
    if skipped_mods:
        # These modules ran but were fed nothing in scope — e.g. a host-class
        # port scan on a URL/domain-only run. Reported honestly, not as success.
        line = f"\n**Skipped (fed no in-scope targets):** {', '.join(skipped_mods)}"
        _HOST_CLASS = {"ax_nmap_tcp", "ax_nmap_udp", "ssh_audit_scan",
                       "snmp_sweep", "smtp_security"}
        if _HOST_CLASS.intersection(skipped_mods):
            # Disclose WHY + how to get a port scan, so an empty service layer
            # on a `-d`/`-url` run isn't a silent surprise.
            line += ("\n\n_The skipped host-full modules above (TCP/UDP port scan + "
                     "ssh/smtp/snmp posture) require `-t` host-full targets. IPs "
                     "resolved from `-d`/`-url` are name-safe scope (web/URL only), "
                     "so no port scan was performed. To port-scan those IPs and run "
                     "the service modules, re-run with `-t <ips/cidrs>`._")
        lines.append(line)
    if m['failed']:
        lines.append(f"\n**Failed:** {', '.join(item['name'] for item in m['failed'])}")

    # Cost & Compute — total run time + fleet node-hours + AI spend, consolidated
    # so a reader can calculate their own cloud cost (node-hours × their rate).
    _append_cost_compute(lines, stats)

    # Needs Attention — ONE consolidated block covering everything that didn't
    # complete cleanly: outright failures plus the warning family (warnings,
    # empty output, coverage gaps). Positioned right after Execution so coverage
    # problems are seen before the results tables. Nothing here reads as clean —
    # each item carries its real reason so gaps stay auditable. Failed modules
    # lead (a crashed module outranks a warning); the warning family follows in
    # warnings → empty-output → coverage-gaps order.
    has_issues = (m['failed'] or stats.get('warnings') or m['empty_output']
                  or stats.get('coverage'))
    if has_issues:
        lines.append("\n## Needs Attention\n")
        lines.append("These items completed with a problem or failed outright. Do "
                     "**not** assume the affected targets are clean — verify before "
                     "reporting.\n")

        if m['failed']:
            lines.append("### Failed Modules\n")
            lines.append("| Module | Error |")
            lines.append("|--------|-------|")
            for item in m['failed']:
                error_escaped = item['error'].replace('|', '\\|')
                lines.append(f"| {item['name']} | {error_escaped} |")

        if stats.get('warnings'):
            lines.append("\n### Warnings\n")
            for w in stats['warnings']:
                lines.append(f"- {w}")

        if m['empty_output']:
            lines.append("\n### Empty Output\n")
            lines.append("These modules ran successfully but produced no output — "
                         "likely a config issue or no matching targets.\n")
            lines.append("| Module | File | Reason |")
            lines.append("|--------|------|--------|")
            for item in m['empty_output']:
                reason_escaped = item['reason'].replace('|', '\\|')
                lines.append(f"| {item['name']} | {item['file'] or '—'} | {reason_escaped} |")

        if stats.get('coverage'):
            lines.append("\n### Coverage Gaps\n")
            for gap in stats['coverage']:
                lines.append(f"- {gap}")

    # Module run history (cumulative across all runs against this output dir)
    history = stats.get('module_history', [])
    if history:
        lines.append("\n## Module Run History\n")
        lines.append("Cumulative across all runs against this output directory.\n")
        lines.append("| Module | Times Run | Run Time | Last Run | Last Status |")
        lines.append("|--------|-----------|----------|----------|-------------|")
        for item in history:
            lines.append(
                f"| {item['name']} "
                f"| {item['runs']} "
                f"| {_fmt_duration(item.get('last_duration'))} "
                f"| {_format_timestamp(item['last_run'])} "
                f"| {item['last_status']} |"
            )

    # Scope
    lines.append("\n## Scope\n")
    lines.append("**Total** = everything discovered (including blocked/excluded); "
                 "**In-Scope** = authorized and actually scanned (excluded targets "
                 "removed). A gap between them means targets were excluded.\n")
    lines.append(f"| Target Type | Total | In-Scope |")
    lines.append(f"|-------------|-------|----------|")
    lines.append(f"| IPs | {t.get('ips_total', t['ips'])} | {t['ips']} |")
    lines.append(f"| Domains | {t.get('domains_total', t['domains'])} | {t['domains']} |")
    if t.get('subdomains_total', t['subdomains']):
        lines.append(f"| Subdomains | {t.get('subdomains_total', t['subdomains'])} | {t['subdomains']} |")
    lines.append(f"| URLs | {t.get('urls_total', t['urls'])} | {t['urls']} |")
    lines.append(f"| Open ports | — | {p['total']} across {p['hosts_with_ports']} hosts |")
    a = stats.get('attack_surface') or {}
    if a.get('unique_ports') is not None or a.get('unique_services') is not None:
        lines.append(f"| Unique ports / services | — | {a.get('unique_ports') or 0} ports, "
                     f"{a.get('unique_services') or 0} services |")

    # Attack Surface — port/service/OS inventory (moved here from analysis.md,
    # sourced from analyze's analysis.json).
    port_counts = a.get('port_counts') or {}
    svc = a.get('service_version_counts') or []
    os_fp = a.get('os_fingerprint') or {}
    if port_counts or svc or os_fp:
        lines.append("\n## Attack Surface\n")
        if port_counts:
            lines.append("### Open Ports\n")
            lines.append("| Port | Hosts |")
            lines.append("|------|-------|")
            for port, count in list(port_counts.items())[:40]:
                lines.append(f"| {_md_cell(port)} | {_md_cell(count)} |")
            lines.append("")
        if svc:
            lines.append("### Service / Version Inventory\n")
            lines.append("| Service | Product | Version | Count |")
            lines.append("|---------|---------|---------|-------|")
            for e in svc[:20]:
                lines.append(f"| {_md_cell(e.get('service', ''))} "
                             f"| {_md_cell(e.get('product', ''))} "
                             f"| {_md_cell(e.get('version', ''))} "
                             f"| {_md_cell(e.get('count', 0))} |")
            lines.append("")
        if os_fp:
            lines.append("### OS Fingerprinting\n")
            lines.append("| Operating System | Hosts |")
            lines.append("|-----------------|-------|")
            for os_name, hosts in os_fp.items():
                n = len(hosts) if isinstance(hosts, (list, tuple, set, dict)) else hosts
                lines.append(f"| {_md_cell(os_name)} | {_md_cell(n)} |")
            lines.append("")

    # Cloud / CDN / SaaS providers
    clouds = stats.get('clouds', [])
    if clouds:
        lines.append("\n## Cloud / CDN / SaaS Providers\n")
        lines.append("Providers observed in use (from storage buckets and DNS "
                     "records). Descriptive inventory — not a scope judgment.\n")
        lines.append("| Provider | Category | Signals | Hosts | Examples |")
        lines.append("|----------|----------|---------|-------|----------|")
        for c in clouds:
            examples = ', '.join(c['sample_hosts'])
            if c['host_count'] > len(c['sample_hosts']):
                examples += ', …'
            lines.append(
                f"| {c['provider']} | {c['category']} "
                f"| {', '.join(c['signals'])} | {c['host_count']} | {examples} |")

    # Technology stack (from bbot TECHNOLOGY events)
    technologies = stats.get('technologies', [])
    if technologies:
        lines.append("\n## Technology Stack\n")
        lines.append("Web technologies detected across the target (from bbot). "
                     "Descriptive inventory.\n")
        lines.append("| Technology | Hosts | Examples |")
        lines.append("|------------|-------|----------|")
        for t in technologies[:40]:
            examples = ', '.join(t['sample_hosts'])
            if t['host_count'] > len(t['sample_hosts']):
                examples += ', …'
            lines.append(f"| {t['tech']} | {t['host_count']} | {examples} |")

    # Findings
    if f['total']:
        lines.append("\n## Findings\n")
        lines.append(f"| Severity | Count |")
        lines.append(f"|----------|-------|")
        for sev in ('critical', 'high', 'medium', 'low', 'info'):
            if f[sev]:
                lines.append(f"| {sev.capitalize()} | {f[sev]} |")
        lines.append(f"| **Total** | **{f['total']}** |")

        by_tool = f.get('by_tool', {})
        if by_tool:
            lines.append("\n### Findings by Tool\n")
            lines.append("| Tool | Critical | High | Medium | Low | Info | Total |")
            lines.append("|------|----------|------|--------|-----|------|-------|")
            for tool_name in sorted(by_tool.keys()):
                td = by_tool[tool_name]
                lines.append(
                    f"| {tool_name} "
                    f"| {td.get('critical', 0) or '-'} "
                    f"| {td.get('high', 0) or '-'} "
                    f"| {td.get('medium', 0) or '-'} "
                    f"| {td.get('low', 0) or '-'} "
                    f"| {td.get('info', 0) or '-'} "
                    f"| {td['total']} |"
                )

    # AI Settings
    ai = stats.get('ai_settings')
    if ai:
        lines.append("\n## AI Configuration\n")
        lines.append(f"| Setting | Value |")
        lines.append(f"|---------|-------|")
        lines.append(f"| Provider | {ai['provider']} |")
        lines.append(f"| Model | {ai['model']} |")
        lines.append(f"| Depth | {ai['depth']} |")
        lines.append(f"| Hosts analyzed | {ai['hosts_analyzed']}/{ai['hosts_total']} |")
        if ai.get('input_tokens'):
            total_tokens = ai['input_tokens'] + ai.get('output_tokens', 0)
            lines.append(f"| Tokens used | {total_tokens:,} |")

    lines.append("")

    os.makedirs(os.path.dirname(md_path), exist_ok=True)
    version_output_path(md_path)
    with open(md_path, 'w', encoding="utf-8") as fh:
        fh.write('\n'.join(lines))

    print(f"[+] Scan debrief written to: {md_path}")
