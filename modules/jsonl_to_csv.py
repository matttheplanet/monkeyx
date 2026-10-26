"""JSONL to CSV conversion module.

Converts each JSONL file in the data output directory to a CSV file
in the reports output directory. One CSV per JSONL, preserving all fields.
"""

import csv
import glob
import json
import os

from core.scan_db import is_finding_record
from core.utils import version_output_path
from modules.normalize import dedup_findings

REQUIRED_INPUTS = frozenset()

# Characters that trigger formula evaluation when a cell is opened in a
# spreadsheet. Scan-derived values (banners, subdomains, nuclei titles) can
# contain these, so we neutralize them (CSV injection / "formula injection").
_CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _csv_safe(value):
    """Neutralize spreadsheet formula injection in a single cell value."""
    if isinstance(value, str) and value and value[0] in _CSV_FORMULA_PREFIXES:
        return "'" + value
    return value


def _sanitize_record(obj):
    """Return a copy of a record dict with all string cells made CSV-safe."""
    return {k: _csv_safe(v) for k, v in obj.items()}


def _write_csv(csv_path, fieldnames, records):
    """Write records to an Excel-friendly CSV.

    Two Excel-specific concessions on top of RFC-4180: a UTF-8 BOM (encoding
    utf-8-sig) so Excel detects UTF-8, and a leading `sep=,` line so double-click
    opens split on commas regardless of the machine's regional list separator
    (which defaults to `;` in many locales, dumping the whole row into one cell).
    Programmatic consumers should read the JSONL under data/; readers that must
    parse these CSVs skip the first line.
    """
    with open(csv_path, "w", encoding="utf-8-sig", newline="") as fh:
        fh.write("sep=,\r\n")
        writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(_sanitize_record(r) for r in records)


def run_jsonl_to_csv(prefix, **kwargs):
    """Convert all JSONL files matching the data prefix to CSV in the reports directory.

    Args:
        prefix: Output file prefix (fallback)
        **kwargs: Must include data_prefix and reports_prefix for split output

    Returns:
        dict: Results with list of created CSV files
    """
    data_prefix = kwargs.get('data_prefix', prefix)
    reports_prefix = kwargs.get('reports_prefix', prefix)
    reports_dir = os.path.dirname(reports_prefix) if os.path.dirname(reports_prefix) else '.'

    print("[*] Running JSONL to CSV conversion module")

    jsonl_files = sorted(glob.glob(f"{data_prefix}*.jsonl"))

    # Skip a RAW tool output when its `-normalized` sibling is also present: the
    # normalized CSV carries the same findings with lean, human-useful columns,
    # whereas the raw file (e.g. nuclei) embeds full request/response bodies and
    # base64 blobs per row — producing a huge, redundant {prefix}-nuclei.csv.
    # The raw JSONL stays on disk (evidence grounding for ai_validate); we just
    # don't ALSO dump it to CSV. Tools with no normalized form still convert.
    _normalized = {p for p in jsonl_files if p.endswith("-normalized.jsonl")}
    def _has_normalized_sibling(path):
        if path.endswith("-normalized.jsonl"):
            return False
        return path[:-len(".jsonl")] + "-normalized.jsonl" in _normalized
    skipped_raw = [p for p in jsonl_files if _has_normalized_sibling(p)]
    jsonl_files = [p for p in jsonl_files if not _has_normalized_sibling(p)]
    for p in skipped_raw:
        print(f"[*] jsonl_to_csv: skipping raw {os.path.basename(p)} "
              f"(normalized CSV supersedes it)")

    if not jsonl_files:
        print("[!] jsonl_to_csv: no JSONL files found")
        return {
            "module": "jsonl_to_csv",
            "status": "warning",
            "output_files": [],
            "warning": "No JSONL files found matching prefix",
        }

    os.makedirs(reports_dir, exist_ok=True)

    converted = []
    total_rows = 0

    for jsonl_path in jsonl_files:
        basename = os.path.basename(jsonl_path).rsplit(".jsonl", 1)[0]
        csv_path = os.path.join(reports_dir, f"{basename}.csv")

        records = []
        fieldnames = []
        seen_fields = set()

        with open(jsonl_path, "r", encoding="utf-8", errors="ignore") as fh:
            for raw_line in fh:
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                records.append(obj)
                for key in obj:
                    if key not in seen_fields:
                        fieldnames.append(key)
                        seen_fields.add(key)

        if not records:
            continue

        version_output_path(csv_path)
        _write_csv(csv_path, fieldnames, records)

        row_count = len(records)
        total_rows += row_count
        converted.append(csv_path)
        print(f"[+] {os.path.basename(jsonl_path)} -> {os.path.basename(csv_path)} ({row_count} rows)")

    print(f"[+] jsonl_to_csv: {len(converted)} files, {total_rows} total rows")

    # Consolidated findings CSV — all normalized findings in one file
    findings_csv = _write_consolidated_findings(data_prefix, reports_dir)
    if findings_csv:
        converted.append(findings_csv)

    return {
        "module": "jsonl_to_csv",
        "status": "success",
        "output_files": converted,
        "file_count": len(converted),
        "row_count": total_rows,
    }


_FINDINGS_FIELDS = [
    "severity", "tool", "host", "hostname", "port", "proto",
    "title", "detail", "evidence", "recommendation", "type", "source_file",
]

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _write_consolidated_findings(data_prefix, reports_dir):
    """Merge genuine normalized findings into a single CSV sorted by severity.

    Sources ONLY `*-normalized.jsonl`. normalize already emits
    `*-dns-security-normalized.jsonl`, so globbing the raw `*-dns-security.jsonl`
    too would merge every dns finding a SECOND time (with UPPER-case severity vs
    the normalized lower-case) — double-counting the file's namesake findings.

    A "finding" is defined by scan_db.is_finding_record (real finding types or
    a non-info severity). The old `type=='finding' or has-severity` test admitted
    everything, because normalize stamps `severity:"info"` on every open_port,
    subdomain, and nmap script_output row — so 18k info rows buried the handful
    of real findings in a file literally named findings-all.csv.
    """
    all_files = sorted(glob.glob(f"{data_prefix}*-normalized.jsonl"))

    if not all_files:
        return None

    findings = []
    for path in all_files:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for raw_line in fh:
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if is_finding_record(obj):
                    findings.append(obj)

    if not findings:
        return None

    # Collapse duplicate rows by finding_id so findings-all.csv carries one line
    # per finding — matching scan.db (the source of truth) instead of the raw,
    # re-emitted JSONL row count.
    findings = dedup_findings(findings)

    findings.sort(key=lambda f: _SEV_ORDER.get((f.get("severity") or "info").lower(), 5))

    csv_path = os.path.join(reports_dir, "findings-all.csv")
    version_output_path(csv_path)

    fieldnames = list(_FINDINGS_FIELDS)
    seen = set(fieldnames)
    for f in findings:
        for key in f:
            if key not in seen:
                fieldnames.append(key)
                seen.add(key)

    _write_csv(csv_path, fieldnames, findings)

    print(f"[+] Consolidated findings: {csv_path} ({len(findings)} findings)")
    return csv_path
