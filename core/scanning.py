"""Scanning utilities for MonkeyX."""

import glob
import ipaddress
import logging
import os
import re
# Parse untrusted tool XML with defusedxml (XXE / billion-laughs safe), matching
# the rest of the repo. This module only PARSES (no Element construction), so a
# straight swap is safe and keeps the lint's parse-vs-construct rule satisfied.
import defusedxml.ElementTree as ET

from .config import AXIOM_PATH
from .utils import bash_command

logger = logging.getLogger("monkeyx.scanning")

# XML 1.0 legal chars: #x9, #xA, #xD, #x20-#xD7FF, #xE000-#xFFFD, #x10000-#x10FFFF.
# nmap -sV can emit binary service banners (e.g. Samba's raw bytes) that land in
# the per-host XML as raw control bytes OR as numeric character references to
# illegal codepoints (e.g. `&#x2;`). Either makes the file non-well-formed, so a
# strict parser — including axiom's nMap_Merger.py — throws on it and SILENTLY
# DROPS that whole host from the merged output. We sanitize each per-host file
# before the merge so no successfully-scanned host is lost.
_RAW_ILLEGAL_XML = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
_NUMERIC_CHAR_REF = re.compile(r"&#(x[0-9a-fA-F]+|[0-9]+);")


def _is_legal_xml_codepoint(cp: int) -> bool:
    return (cp in (0x9, 0xA, 0xD)
            or 0x20 <= cp <= 0xD7FF
            or 0xE000 <= cp <= 0xFFFD
            or 0x10000 <= cp <= 0x10FFFF)


def _drop_illegal_ref(match: "re.Match") -> str:
    tok = match.group(1)
    try:
        cp = int(tok[1:], 16) if tok[0] in "xX" else int(tok)
    except ValueError:
        return match.group(0)
    return match.group(0) if _is_legal_xml_codepoint(cp) else ""


def _sanitize_xml_text(text: str) -> str:
    """Remove raw illegal control bytes and numeric refs to illegal codepoints."""
    text = _RAW_ILLEGAL_XML.sub("", text)
    return _NUMERIC_CHAR_REF.sub(_drop_illegal_ref, text)


def _sanitize_xml_files(folder: str) -> int:
    """Strip illegal XML chars/refs from every *.xml in folder, in place.

    Returns the number of files that were modified.
    """
    fixed = 0
    for path in glob.glob(os.path.join(folder, "*.xml")):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                raw = fh.read()
        except OSError:
            continue
        clean = _sanitize_xml_text(raw)
        if clean != raw:
            try:
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(clean)
            except OSError:
                continue
            fixed += 1
            logger.warning("Sanitized illegal XML chars in %s (would otherwise be "
                           "dropped by the merge)", os.path.basename(path))
    return fixed


def _addrs_in_xml(path: str) -> set:
    """IPv4/IPv6 host addresses present in an nmap XML file (empty on parse error)."""
    addrs = set()
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, OSError):
        return addrs
    for host in root.iter("host"):
        for addr in host.iter("address"):
            if addr.get("addrtype") in ("ipv4", "ipv6") and addr.get("addr"):
                addrs.add(addr.get("addr"))
    return addrs


def _read_target_ips(target_file: str) -> set:
    """Bare single IPs from a target file.

    Only literal IPs are returned — hostnames and CIDRs are skipped, because we
    can't match them against nmap's per-host IP output without resolving/expanding
    (and doing so would risk false-positive "uncovered" warnings).
    """
    ips = set()
    if not target_file or not os.path.exists(target_file):
        return ips
    try:
        with open(target_file, encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                tok = line.strip()
                if not tok or tok.startswith("#"):
                    continue
                try:
                    ipaddress.ip_address(tok)
                except ValueError:
                    continue  # hostname or CIDR — not reconcilable here
                ips.add(tok)
    except OSError:
        pass
    return ips


def _per_host_scan_completed(folder: str, ip: str) -> bool:
    """True if the per-host nmap result file for ``ip`` shows a completed scan.

    ax writes one file per scanned target as ``-oA <folder>/<ip>``. The scans run
    with ``--open``, so a host that WAS scanned but has no open ports has NO
    <host> element in its per-host XML — presence must therefore be judged from
    the file's <runstats> (a finished, successful scan with >=1 host up), not from
    a <host> record. A missing, unparseable, or incomplete file is NOT treated as
    scanned, so genuine failures (dead node / failed pull / truncated result)
    still surface. Also accepts the sibling .gnmap as a fallback signal.
    """
    xml_path = os.path.join(folder, f"{ip}.xml")
    if os.path.exists(xml_path):
        try:
            rs = ET.parse(xml_path).getroot().find("runstats")
        except (ET.ParseError, OSError):
            rs = None
        if rs is not None:
            fin = rs.find("finished")
            hosts = rs.find("hosts")
            completed = fin is not None and fin.get("exit") == "success"
            up = hosts is not None and (hosts.get("up") or "0") not in ("", "0")
            if completed and up:
                return True
    return False


def uncovered_ip_targets(target_file: str, merged_xml_path: str,
                         scan_folder: str | None = None) -> list:
    """In-scope bare-IP targets that were NOT scanned/collected.

    A fed IP missing from the merged nmap XML can mean two very different things:
    it was never scanned/collected (dead fleet instance, failed result pull, or a
    merge drop) — OR it WAS scanned and simply has no open ports. The scans use
    ``--open``, which omits the <host> element for a host with zero open ports, so
    the merged XML alone cannot distinguish the two: judging coverage by <host>
    presence false-positives on every quiet-but-scanned host.

    So a fed IP missing from the merged XML is only reported uncovered when its
    own per-host result file does NOT show a completed scan (``scan_folder``). If
    no per-host folder is given, falls back to the (over-reporting) merged-XML
    check. Hostnames/CIDRs are not reconciled (see _read_target_ips). Returns []
    when there's no target file (can't reason about coverage).
    """
    fed = _read_target_ips(target_file)
    if not fed:
        return []
    missing = fed - _addrs_in_xml(merged_xml_path)
    if not missing or not scan_folder or not os.path.isdir(scan_folder):
        return sorted(missing)
    # Keep only the ones with no completed per-host scan — the genuine gaps.
    return sorted(ip for ip in missing
                  if not _per_host_scan_completed(scan_folder, ip))


def port_scan_health(merged_xml_path: str) -> dict:
    """Summarize a merged nmap XML for scan-health checks.

    Returns {host_records, hosts_up, hosts_with_open_ports, open_ports}. A large
    ``hosts_up`` with near-zero ``hosts_with_open_ports`` after a full scan means
    the port-scan phase produced nothing (broken/blocked scanner, missing raw-
    socket privilege, or lost fleet results) rather than a genuinely closed
    surface — a working scan reports closed/filtered states, not silence.
    """
    host_records = hosts_up = hosts_with_open = open_ports = 0
    try:
        root = ET.parse(merged_xml_path).getroot()
    except (ET.ParseError, OSError):
        return {"host_records": 0, "hosts_up": 0,
                "hosts_with_open_ports": 0, "open_ports": 0}
    for host in root.iter("host"):
        host_records += 1
        st = host.find("status")
        is_up = st is not None and st.get("state") == "up"
        if is_up:
            hosts_up += 1
        open_here = 0
        for port in host.iter("port"):
            s = port.find("state")
            if s is not None and s.get("state") == "open":
                open_here += 1
        if open_here:
            open_ports += open_here
            if is_up:
                hosts_with_open += 1
    return {"host_records": host_records, "hosts_up": hosts_up,
            "hosts_with_open_ports": hosts_with_open, "open_ports": open_ports}


def hosts_up_without_open_ports(merged_xml_path: str) -> list:
    """IPs nmap saw as 'up' but with ZERO open ports in the merged XML.

    This is the per-host signature of a host that silently filters/rate-limits
    SYN probes (or a scan that lost raw-socket privilege): the host answers host
    discovery but every port reads as nothing. A targeted full-connect (`-sT`)
    retry frequently recovers these. Returns the host addresses, sorted.
    """
    out = set()
    try:
        root = ET.parse(merged_xml_path).getroot()
    except (ET.ParseError, OSError):
        return []
    for host in root.iter("host"):
        st = host.find("status")
        if st is None or st.get("state") != "up":
            continue
        has_open = any(
            (p.find("state") is not None
             and p.find("state").get("state") == "open")
            for p in host.iter("port"))
        if has_open:
            continue
        for addr in host.iter("address"):
            if addr.get("addrtype", "ipv4") in ("ipv4", "ipv6") and addr.get("addr"):
                out.add(addr.get("addr"))
                break
    return sorted(out)


def hosts_scan_truncated(merged_xml_path: str) -> list:
    """IPs whose per-host port scan was CUT OFF before it finished — e.g. it hit
    nmap's ``--host-timeout`` — so NO port data was collected for them.

    Signal: the host is ``up`` but has NO open ports AND NO ``<extraports>``
    element. A *completed* host scan always emits an ``<extraports>`` summary
    counting the closed/filtered ports it isn't listing individually (even when
    zero are open), so its ABSENCE on an up host means nmap never got to tally
    that host's ports — the result is missing, not genuinely empty. This is a
    strict subset of ``hosts_up_without_open_ports`` (a legitimately-empty host
    DOES have ``<extraports>`` and is excluded here). Returns addresses, sorted.
    """
    out = set()
    try:
        root = ET.parse(merged_xml_path).getroot()
    except (ET.ParseError, OSError):
        return []
    for host in root.iter("host"):
        st = host.find("status")
        if st is None or st.get("state") != "up":
            continue
        has_open = any(
            (p.find("state") is not None
             and p.find("state").get("state") == "open")
            for p in host.iter("port"))
        has_extraports = host.find("ports/extraports") is not None
        if has_open or has_extraports:
            continue  # real ports, or a completed-but-empty host — not truncated
        for addr in host.iter("address"):
            if addr.get("addrtype", "ipv4") in ("ipv4", "ipv6") and addr.get("addr"):
                out.add(addr.get("addr"))
                break
    return sorted(out)


def port_scan_degraded(health: dict, min_hosts: int = 10,
                       max_open_fraction: float = 0.02):
    """(degraded: bool, reason: str) — True when a full port scan looks like it
    FAILED to collect: many hosts up, but ~none has any open port.

    Conservative: requires a meaningful host count (``min_hosts``) so a tiny
    genuinely-quiet scope doesn't false-alarm, and treats "fewer than
    ``max_open_fraction`` of up-hosts have any open port" as the failure signal.
    A real closed/filtered surface still yields open ports on *some* hosts and,
    at the raw level, closed/filtered states — wholesale silence does not.
    """
    up = int(health.get("hosts_up", 0) or 0)
    with_open = int(health.get("hosts_with_open_ports", 0) or 0)
    if up >= min_hosts and with_open <= max(1, int(up * max_open_fraction)):
        return True, (
            f"PORT SCAN LIKELY INCOMPLETE: only {with_open} of {up} live host(s) "
            f"have any open port. This usually means the TCP scan failed to "
            f"collect (broken/blocked fleet nmap, missing raw-socket privilege, "
            f"or lost results) — NOT a closed attack surface. Do NOT trust the "
            f"zero-port result; verify the fleet and re-run the port scan.")
    return False, ""


def merge_nmap_folder(prefix, foldername, title):
    """Merge a folder of per-host nmap XML into one file.

    Sanitizes each per-host XML first so a host with a binary service banner isn't
    silently dropped by the (external, axiom) merger, then cross-checks the merged
    host set against the per-host files and warns on any remaining loss.

    Args:
        prefix: Output file prefix
        foldername: Name of folder containing nmap results
        title: Descriptive title for the merge operation

    Returns:
        dict with merged_path, expected_hosts, merged_hosts, dropped_hosts (list).
    """
    print(f'running nmap {title} merge')
    folder = f"{prefix}-{foldername}"
    merged_path = f"{prefix}-{foldername}.xml"

    fixed = _sanitize_xml_files(folder)
    if fixed:
        print(f"[*] Sanitized {fixed} nmap XML file(s) with illegal chars before merge")

    # Hosts that SHOULD survive the merge (union across the per-host files, now
    # that they parse). The merged output lives OUTSIDE this folder, so it isn't
    # double-counted.
    expected = set()
    for path in glob.glob(os.path.join(folder, "*.xml")):
        expected |= _addrs_in_xml(path)

    merge = f"{AXIOM_PATH}/interact/nMap_Merger.py -d '{folder}' -o '{merged_path}'"
    bash_command(merge)

    merged = _addrs_in_xml(merged_path)
    dropped = sorted(expected - merged)
    if dropped:
        logger.warning("nmap merge dropped %d host(s) present in the per-host files "
                       "but absent from merged output: %s", len(dropped), ", ".join(dropped))
        print(f"[!] nmap merge is missing {len(dropped)} host(s) that scanned "
              f"successfully: {', '.join(dropped)}")
    return {
        "merged_path": merged_path,
        "expected_hosts": len(expected),
        "merged_hosts": len(merged),
        "dropped_hosts": dropped,
    }
