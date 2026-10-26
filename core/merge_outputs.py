"""Cross-run output versioning and merging.

When the same module runs multiple times in an output directory (via --continue),
this module preserves each run's output in a `runs/` subdirectory and produces a
merged/deduplicated canonical file at the original path. Downstream modules
(normalize, analyze, jsonl_to_csv) consume the canonical path unchanged.
"""

from __future__ import annotations

import glob
import json
import logging
import os
import re
import shutil
# defusedxml safely PARSES untrusted XML but does not export Element/SubElement/
# ElementTree. Parse untrusted input with ET; build the merged output tree with
# the stdlib (_ETbuild) — constructing our own elements is not a security risk.
import defusedxml.ElementTree as ET
import xml.etree.ElementTree as _ETbuild

logger = logging.getLogger("monkeyx.merge_outputs")


_MODULE_MERGE_CONFIG: dict[str, dict] = {
    "ax_nmap_tcp":                     {"suffix": "-tcpscan.xml",      "strategy": "nmap_xml", "dedup_keys": ("addr", "portid", "protocol")},
    "ax_nmap_udp": {"suffix": "-udpscan.xml",              "strategy": "nmap_xml", "dedup_keys": ("addr", "portid", "protocol")},
    "ax_nuclei":         {"suffix": "-nuclei.jsonl",             "strategy": "jsonl",    "dedup_keys": ("template-id", "matched-at")},
    "subfinder":         {"suffix": "-subfinder-output.jsonl",   "strategy": "jsonl",    "dedup_keys": ("host",)},
    "ax_ffuf":           {"suffix": "-ffuf.jsonl",               "strategy": "jsonl",    "dedup_keys": ("url",)},
    "ax_feroxbuster":    {"suffix": "-feroxbuster.txt",          "strategy": "text_url"},
    "dns_resolve":       {"suffix": "-resolve-report.jsonl",     "strategy": "jsonl",    "dedup_keys": ("hostname", "ip")},
    "ax_naabu":          {"suffix": "-naabu.txt",                "strategy": "text_line"},
    "bbot_cloud":        {"suffix": "-bbot-cloud.jsonl",         "strategy": "jsonl",    "dedup_keys": ("type", "data")},
    "bbot_takeover":     {"suffix": "-bbot-takeover.jsonl",      "strategy": "jsonl",    "dedup_keys": ("type", "data")},
    "bbot_passive":      {"suffix": "-bbot-passive.jsonl",       "strategy": "jsonl",    "dedup_keys": ("type", "data")},
    "bbot_code":         {"suffix": "-bbot-code.jsonl",          "strategy": "jsonl",    "dedup_keys": ("type", "data")},
    "bbot_dast":         {"suffix": "-bbot-dast.jsonl",          "strategy": "jsonl",    "dedup_keys": ("type", "data")},
    "bbot_recon":        {"suffix": "-bbot-recon.jsonl",         "strategy": "jsonl",    "dedup_keys": ("type", "data")},
    "ax_testssl":        {"suffix": "-testssl.txt",              "strategy": "text_line"},
    "ax_wafw00f":        {"suffix": "-wafw00f.txt",              "strategy": "text_line"},
    "ax_katana":         {"suffix": "-katana.txt",               "strategy": "text_url"},
    "ax_gau":            {"suffix": "-gau.txt",                  "strategy": "text_url"},
    "ax_corsy":          {"suffix": "-corsy.txt",                "strategy": "text_line"},
    "ax_dalfox":         {"suffix": "-dalfox.txt",               "strategy": "text_line"},
    "ax_mantra":         {"suffix": "-mantra.txt",               "strategy": "text_line"},
    "ax_subjs":          {"suffix": "-subjs.txt",                "strategy": "text_url"},
    "ax_arjun":          {"suffix": "-arjun.txt",                "strategy": "text_url"},
    "ax_amass":          {"suffix": "-amass.txt",                "strategy": "text_line"},
    "shodan_enrich":     {"suffix": "-shodan.jsonl",             "strategy": "jsonl",    "dedup_keys": ("host", "port", "shodan_claim")},
    "ssh_audit_scan":    {"suffix": "-ssh-audit.jsonl",          "strategy": "jsonl",    "dedup_keys": ("host", "port", "title")},
    "snmp_sweep":        {"suffix": "-snmp-sweep.jsonl",         "strategy": "jsonl",    "dedup_keys": ("host", "port", "title")},
    "smtp_security":     {"suffix": "-smtp-security.jsonl",      "strategy": "jsonl",    "dedup_keys": ("host", "port", "title")},
}


def should_version(module_name: str) -> bool:
    """Return True if this module's outputs should be versioned/merged across runs."""
    return module_name in _MODULE_MERGE_CONFIG


def _runs_dir(data_prefix: str) -> str:
    return os.path.join(os.path.dirname(data_prefix) or ".", "runs")


def _canonical_path(data_prefix: str, suffix: str) -> str:
    return f"{data_prefix}{suffix}"


def _versioned_path(data_prefix: str, suffix: str, run_number: int) -> str:
    base = os.path.basename(data_prefix)
    stem, ext = os.path.splitext(suffix)
    runs = _runs_dir(data_prefix)
    return os.path.join(runs, f"{base}{stem}.run{run_number}{ext}")


def _versioned_pattern(data_prefix: str, suffix: str) -> str:
    base = os.path.basename(data_prefix)
    stem, ext = os.path.splitext(suffix)
    runs = _runs_dir(data_prefix)
    return os.path.join(runs, f"{base}{stem}.run*{ext}")


_RUN_NUM_RE = re.compile(r"\.run(\d+)\.[^.]+$")


def _get_next_run_number(data_prefix: str, suffix: str) -> int:
    pattern = _versioned_pattern(data_prefix, suffix)
    existing = glob.glob(pattern)
    max_n = 0
    for path in existing:
        match = _RUN_NUM_RE.search(os.path.basename(path))
        if match:
            try:
                n = int(match.group(1))
                if n > max_n:
                    max_n = n
            except ValueError:
                continue
    return max_n + 1


def archive_existing_output(module_name: str, data_prefix: str) -> str | None:
    """Move an existing canonical output to runs/ before a new run overwrites it.

    Called pre-step in continue mode, but only when runs/ has no prior versions
    for this module. Once the merge cycle has begun, the canonical file holds
    merged content and should NOT be re-archived (it would duplicate prior runs).

    Returns the path the file was moved to, or None.
    """
    cfg = _MODULE_MERGE_CONFIG.get(module_name)
    if cfg is None:
        return None

    suffix = cfg["suffix"]
    canonical = _canonical_path(data_prefix, suffix)
    if not os.path.exists(canonical):
        return None

    pattern = _versioned_pattern(data_prefix, suffix)
    if glob.glob(pattern):
        # Prior run versions already exist; canonical is a merged view of them.
        # Removing the canonical lets the module write fresh, then post-step
        # archive captures the new output as runN+1 and re-merges.
        os.remove(canonical)
        logger.debug("Removed merged canonical %s before new run", canonical)
        return None

    runs = _runs_dir(data_prefix)
    os.makedirs(runs, exist_ok=True)

    dest = _versioned_path(data_prefix, suffix, 1)
    shutil.move(canonical, dest)
    logger.info("Archived first run %s -> %s", canonical, dest)
    return dest


def version_and_merge(module_name: str, data_prefix: str) -> str | None:
    """Move new canonical output to runs/, then merge all runs into canonical.

    Called post-step on successful runs in continue mode. Returns the merged
    canonical path, or None if there was nothing to merge.
    """
    cfg = _MODULE_MERGE_CONFIG.get(module_name)
    if cfg is None:
        return None

    suffix = cfg["suffix"]
    canonical = _canonical_path(data_prefix, suffix)
    runs = _runs_dir(data_prefix)
    os.makedirs(runs, exist_ok=True)

    if os.path.exists(canonical):
        n = _get_next_run_number(data_prefix, suffix)
        dest = _versioned_path(data_prefix, suffix, n)
        shutil.move(canonical, dest)
        logger.info("Archived new run %s -> %s", canonical, dest)

    pattern = _versioned_pattern(data_prefix, suffix)
    run_files = sorted(glob.glob(pattern))
    if not run_files:
        return None

    if len(run_files) == 1:
        shutil.copy2(run_files[0], canonical)
        logger.info("Single run for %s — copied to canonical %s", module_name, canonical)
        return canonical

    strategy = cfg["strategy"]
    if strategy == "nmap_xml":
        _merge_nmap_xml(run_files, canonical, cfg["dedup_keys"])
    elif strategy == "jsonl":
        _merge_jsonl(run_files, canonical, cfg["dedup_keys"])
    elif strategy == "text_url":
        _merge_text_url(run_files, canonical)
    elif strategy == "text_line":
        _merge_text_line(run_files, canonical)
    else:
        logger.warning("Unknown merge strategy '%s' for %s", strategy, module_name)
        return None

    logger.info("Merged %d runs of %s -> %s", len(run_files), module_name, canonical)
    return canonical


def _merge_nmap_xml(file_paths: list[str], output_path: str, dedup_keys: tuple) -> None:
    """Merge multiple nmap XML files, deduplicating ports per host.

    Dedup key is (host_addr, portid, protocol). When the same port appears in
    multiple runs, the entry with more service attributes is preferred.
    """
    seen_hosts: dict[str, _ETbuild.Element] = {}
    seen_ports: dict[tuple, _ETbuild.Element] = {}

    base_attrs = None
    for path in file_paths:
        try:
            tree = ET.parse(path)
            root = tree.getroot()
        except ET.ParseError as e:
            logger.warning("Skipping invalid XML in merge: %s (%s)", path, e)
            continue
        if root.tag != "nmaprun":
            continue
        if base_attrs is None:
            base_attrs = dict(root.attrib)

        for host in root.iter("host"):
            addr_el = host.find("address[@addrtype='ipv4']") or host.find("address")
            if addr_el is None:
                continue
            addr = addr_el.get("addr", "")
            if not addr:
                continue

            if addr not in seen_hosts:
                new_host = _ETbuild.Element("host", host.attrib)
                for child in host:
                    if child.tag != "ports":
                        new_host.append(child)
                ports_el = _ETbuild.SubElement(new_host, "ports")
                seen_hosts[addr] = new_host

            host_el = seen_hosts[addr]
            ports_el = host_el.find("ports")

            src_ports = host.find("ports")
            if src_ports is None:
                continue
            for port_el in src_ports.findall("port"):
                portid = port_el.get("portid", "")
                proto = port_el.get("protocol", "")
                key = (addr, portid, proto)

                existing = seen_ports.get(key)
                if existing is None:
                    ports_el.append(port_el)
                    seen_ports[key] = port_el
                else:
                    # Prefer entry with more service attributes
                    new_svc = port_el.find("service")
                    old_svc = existing.find("service")
                    new_attrs = len(new_svc.attrib) if new_svc is not None else 0
                    old_attrs = len(old_svc.attrib) if old_svc is not None else 0
                    if new_attrs > old_attrs:
                        # Replace existing port with this one
                        parent_ports = ports_el
                        parent_ports.remove(existing)
                        parent_ports.append(port_el)
                        seen_ports[key] = port_el

    root_attrs = base_attrs or {"scanner": "nmap", "args": "merged", "version": "merged"}
    new_root = _ETbuild.Element("nmaprun", root_attrs)
    for host_el in seen_hosts.values():
        new_root.append(host_el)

    tree = _ETbuild.ElementTree(new_root)
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "wb") as f:
        f.write(b'<?xml version="1.0" encoding="UTF-8"?>\n')
        f.write(b'<!DOCTYPE nmaprun>\n')
        tree.write(f, encoding="utf-8", xml_declaration=False)


def _merge_jsonl(file_paths: list[str], output_path: str, dedup_keys: tuple) -> None:
    """Merge JSONL files, deduplicating by composite key."""
    seen: set = set()
    out_records = []

    for path in file_paths:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    key = tuple(_extract_key(rec, k) for k in dedup_keys)
                    if key in seen:
                        continue
                    seen.add(key)
                    out_records.append(rec)
        except OSError as e:
            logger.warning("Skipping unreadable JSONL: %s (%s)", path, e)

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        for rec in out_records:
            f.write(json.dumps(rec) + "\n")


def _extract_key(rec: dict, key_path: str):
    """Extract a value from a dict, supporting dotted paths like 'info.severity'."""
    if "." not in key_path:
        return rec.get(key_path)
    parts = key_path.split(".")
    cur = rec
    for p in parts:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(p)
    return cur


def _merge_text_url(file_paths: list[str], output_path: str) -> None:
    """Merge text files (e.g., feroxbuster) deduplicating by extracted URL."""
    seen_urls: set[str] = set()
    out_lines: list[str] = []

    url_re = re.compile(r"https?://\S+")
    for path in file_paths:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    stripped = line.rstrip("\n")
                    if not stripped.strip():
                        continue
                    match = url_re.search(stripped)
                    if not match:
                        continue
                    url = match.group(0)
                    if url in seen_urls:
                        continue
                    seen_urls.add(url)
                    out_lines.append(stripped)
        except OSError as e:
            logger.warning("Skipping unreadable text file: %s (%s)", path, e)

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        for line in out_lines:
            f.write(line + "\n")


def _merge_text_line(file_paths: list[str], output_path: str) -> None:
    """Merge text files deduplicating by full line (e.g., naabu host:port)."""
    seen: set[str] = set()
    out_lines: list[str] = []

    for path in file_paths:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    stripped = line.rstrip("\n").strip()
                    if not stripped or stripped in seen:
                        continue
                    seen.add(stripped)
                    out_lines.append(stripped)
        except OSError as e:
            logger.warning("Skipping unreadable text file: %s (%s)", path, e)

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        for line in out_lines:
            f.write(line + "\n")
