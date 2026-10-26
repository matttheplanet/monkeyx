"""Shared helpers for DNS resolution modules (dns_resolve, dnsx_resolve).

Contains target-file parsing, scope checking, subdomain loading, dnsx JSONL
parsing, output writing, and PTR result parsing — logic that was previously
copy-pasted across all three modules.
"""

import ipaddress
import json
import logging
import os
import shutil
from datetime import datetime, timezone

logger = logging.getLogger("monkeyx.core.dns_helpers")


# ---------------------------------------------------------------------------
# Target file parsing
# ---------------------------------------------------------------------------

def parse_target_file(target_path):
    """Split a target file into scope networks, hostnames, and passthrough IPs.

    Returns:
        (scope_networks, hostnames, passthrough_ips)
    """
    scope_networks = []
    hostnames = set()
    passthrough_ips = set()

    with open(target_path) as f:
        for line in f:
            entry = line.strip()
            if not entry or entry.startswith("#"):
                continue
            if "/" in entry:
                try:
                    scope_networks.append(ipaddress.ip_network(entry, strict=False))
                except ValueError:
                    hostnames.add(entry)
            elif is_ip(entry):
                passthrough_ips.add(entry)
                try:
                    scope_networks.append(ipaddress.ip_network(entry + "/32", strict=False))
                except ValueError:
                    pass
            else:
                hostnames.add(entry)

    return scope_networks, hostnames, passthrough_ips


def is_ip(value):
    """Check if a string is a valid IP address."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def ip_in_scope(ip_str, scope_networks):
    """Check if an IP falls within any of the scope networks."""
    if not scope_networks:
        return True
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in scope_networks)
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Reading earlier modules' output (subdomain discoveries)
# ---------------------------------------------------------------------------

def load_hostnames_from_dir(prefix, name_pattern):
    """Load hostnames from files matching a pattern in the prefix directory.

    Handles both plain text (one host per line) and JSONL ({"host": "..."}).
    """
    hosts = set()
    prefix_dir = os.path.dirname(prefix) if os.path.dirname(prefix) else "."
    if not os.path.isdir(prefix_dir):
        return hosts

    for fn in os.listdir(prefix_dir):
        if name_pattern not in fn:
            continue
        if not (fn.endswith(".txt") or fn.endswith(".jsonl")):
            continue
        path = os.path.join(prefix_dir, fn)
        try:
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if line.startswith("{"):
                        try:
                            rec = json.loads(line)
                            host = rec.get("host", "")
                            if host:
                                hosts.add(host)
                        except json.JSONDecodeError:
                            continue
                    else:
                        hosts.add(line)
        except Exception as e:
            logger.warning("Failed to read %s: %s", path, e)

    return hosts


def load_subfinder_output(prefix):
    return load_hostnames_from_dir(prefix, "subfinder")


def load_puredns_bruteforce_output(prefix):
    return load_hostnames_from_dir(prefix, "puredns-bruteforce")


# ---------------------------------------------------------------------------
# dnsx JSONL parsing
# ---------------------------------------------------------------------------

def parse_dnsx_jsonl(path):
    """Parse dnsx -j JSONL output. Returns list of dicts (one per hostname)."""
    records = []
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or not line.startswith("{"):
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError as e:
                    logger.warning("Skipping invalid JSONL line: %s", e)
    except Exception as e:
        logger.warning("Failed to read %s: %s", path, e)
    return records


# ---------------------------------------------------------------------------
# PTR output parsing
# ---------------------------------------------------------------------------

def parse_ptr_output(ptr_output_path):
    """Parse dnsx -ptr JSONL output. Returns {ip: [hostname, ...]}."""
    ptr_map = {}
    if not os.path.exists(ptr_output_path):
        return ptr_map
    try:
        with open(ptr_output_path) as f:
            for line in f:
                line = line.strip()
                if not line or not line.startswith("{"):
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                host = rec.get("host", "").strip()
                ptrs = rec.get("ptr", []) or []
                if host and ptrs:
                    cleaned = [p.rstrip(".") for p in ptrs if p.strip()]
                    if cleaned:
                        ptr_map[host] = cleaned
    except Exception as e:
        logger.warning("Failed to parse PTR output: %s", e)
    return ptr_map


# ---------------------------------------------------------------------------
# Step snapshot helper
# ---------------------------------------------------------------------------

def snapshot_actual_input(input_file, prefix, module_name):
    """Copy the actual input file into step-snapshots/actual-inputs/ for audit trail."""
    if not os.path.exists(input_file):
        return
    data_dir = os.path.dirname(prefix)
    if not data_dir:
        return
    snap_dir = os.path.join(data_dir, "step-snapshots", "actual-inputs")
    try:
        os.makedirs(snap_dir, exist_ok=True)
        dest = os.path.join(snap_dir, f"{module_name}-dnsx-input.txt")
        shutil.copy2(input_file, dest)
    except Exception as e:
        logger.warning("Could not snapshot actual dnsx input: %s", e)


# ---------------------------------------------------------------------------
# Output writing (shared by both dnsx modules)
# ---------------------------------------------------------------------------

def write_resolve_outputs(prefix, module_name, passthrough_ips, dnsx_records,
                          scope_networks, scope_filter, raw_output=None,
                          ptr_map=None):
    """Write resolve outputs: resolved-targets.txt and resolve-report.jsonl.

    Returns the module result dict.
    """
    ptr_map = ptr_map or {}
    resolved_targets = set(passthrough_ips)
    report_entries = []
    in_scope_count = 0
    out_of_scope_count = 0
    no_resolve_count = 0
    now = datetime.now(timezone.utc).isoformat()
    # "in_scope" here is decided against the -t IP/CIDR scope. With no -t, there
    # is no host scope to test, so resolved IPs are name-safe (in-scope by name,
    # NOT port-scannable). Record which basis applied so the report isn't
    # mistaken for a host-scope grant.
    host_scope = "t-range" if scope_networks else "none"

    resolved_hostnames = {r.get("host") for r in dnsx_records if r.get("host")}

    for record in dnsx_records:
        hostname = record.get("host", "")
        ips = record.get("a", []) or []
        if not ips:
            no_resolve_count += 1
            entry = _make_report_entry(record, hostname, None, "no_answer",
                                       in_scope=False, scope_filter=scope_filter,
                                       now=now, host_scope=host_scope)
            report_entries.append(entry)
            continue

        for ip in ips:
            in_scope = ip_in_scope(ip, scope_networks)

            if in_scope:
                resolved_targets.add(ip)
                in_scope_count += 1
            elif scope_filter == "none":
                resolved_targets.add(ip)
                in_scope_count += 1
            elif scope_filter == "warn":
                resolved_targets.add(ip)
                out_of_scope_count += 1
            else:
                out_of_scope_count += 1

            entry = _make_report_entry(
                record, hostname, ip, "resolved",
                in_scope=in_scope, scope_filter=scope_filter, now=now,
                included=(ip in resolved_targets), host_scope=host_scope,
            )
            report_entries.append(entry)

    for ip in sorted(passthrough_ips):
        ptr_names = ptr_map.get(ip, [])
        if ptr_names:
            entry = {
                "hostname": None,
                "ip": ip,
                "status": "ptr",
                "in_scope": True,
                "scope_action": "included",
                "host_scope": host_scope,
                "resolved_at": now,
                "scope_filter_mode": scope_filter,
                "ptr_hostnames": ptr_names,
            }
            report_entries.append(entry)

    for entry in report_entries:
        ip = entry.get("ip")
        if ip and ip in ptr_map and "ptr_hostnames" not in entry:
            entry["ptr_hostnames"] = ptr_map[ip]

    resolved_target_file = f"{prefix}-resolved-targets.txt"
    report_file = f"{prefix}-resolve-report.jsonl"

    with open(resolved_target_file, "w") as f:
        for ip in sorted(resolved_targets):
            f.write(ip + "\n")

    with open(report_file, "w") as f:
        for entry in report_entries:
            f.write(json.dumps(entry) + "\n")

    ptr_total = sum(len(v) for v in ptr_map.values())
    print(f"[+] {module_name} complete:")
    print(f"    Resolved IPs: {len(resolved_targets)} (passthrough: {len(passthrough_ips)})")
    if host_scope == "none":
        print(f"    In-scope (name-safe — no -t host scope defined): {in_scope_count}"
              f"  Out-of-scope: {out_of_scope_count}")
    else:
        print(f"    In-scope: {in_scope_count}  Out-of-scope: {out_of_scope_count}")
    print(f"    No A record: {no_resolve_count}")
    print(f"    Hostnames returned by dnsx: {len(resolved_hostnames)}")
    print(f"    PTR hostnames: {ptr_total} for {len(ptr_map)} IPs")
    if scope_filter == "warn" and out_of_scope_count > 0:
        print(f"[!] WARN: {out_of_scope_count} out-of-scope IPs included")
    elif scope_filter == "strict" and out_of_scope_count > 0:
        print(f"[!] STRICT: {out_of_scope_count} out-of-scope IPs excluded")

    output_files = [resolved_target_file, report_file]
    if raw_output and os.path.exists(raw_output):
        output_files.append(raw_output)

    return {
        "module": module_name,
        "status": "success",
        "output_files": output_files,
        "resolved_target_file": resolved_target_file,
        "target_count": len(resolved_targets),
        "in_scope_count": in_scope_count,
        "out_of_scope_count": out_of_scope_count,
        "no_resolve_count": no_resolve_count,
        "resolved_hostname_count": len(resolved_hostnames),
        "ptr_hostname_count": ptr_total,
        "ptr_ip_count": len(ptr_map),
    }


def _make_report_entry(record, hostname, ip, status, *, in_scope, scope_filter,
                       now, included=False, host_scope="t-range"):
    """Build a normalized report entry preserving all dnsx fields.

    ``host_scope`` records what "in_scope" was decided against: "t-range" when a
    -t IP/CIDR scope was supplied, or "none" when no -t was given. With "none",
    every resolved IP is reported in_scope, but only in the NAME-SAFE sense — it
    is not authorized for host/port scanning (the ledger's channel model, not
    this file, gates that). This flag makes that distinction explicit for anyone
    reading the report.
    """
    entry = {
        "hostname": hostname,
        "ip": ip,
        "status": status,
        "in_scope": in_scope,
        "scope_action": "included" if (in_scope or included) else "excluded",
        "host_scope": host_scope,
        "resolved_at": now,
        "scope_filter_mode": scope_filter,
    }

    for key in ("a", "aaaa", "cname", "ns", "mx", "txt", "srv", "ptr", "soa",
                "caa", "asn", "cdn", "cdn-name", "cdn-type", "wildcard",
                "all", "rcode", "query-time", "resolver"):
        if key in record:
            entry[key] = record[key]

    return entry
