"""Normalize module — converts each tool's scan output into per-tool JSONL files.

One JSON record per finding, suitable for streaming to an LLM for analysis.
Each tool gets its own output file: {prefix}-nmap-normalized.jsonl, etc.

Record schema:
  host        str   IP address or hostname
  hostname    str   Reverse DNS / hostname (null if unknown)
  port        int   Port number (null for host-level findings)
  proto       str   "tcp" | "udp" | null
  tool        str   Source tool name
  type        str   "open_port" | "script_output" | "nuclei_finding" |
                    "subdomain" | "dir_hit"
  severity    str   "info" | "low" | "medium" | "high" | "critical"
  title       str   Short description
  detail      str   Full detail / banner / script output (null if none)
  source_file str   Basename of the source file
"""

import glob
import json
import logging
import os
import re
import sqlite3
# defusedxml provides safe PARSING of untrusted XML (parse/fromstring/ParseError)
# but deliberately does NOT export Element/SubElement/etc. Use the stdlib types
# (aliased _ETtypes) purely for type annotations and any element construction.
import defusedxml.ElementTree as ET
import xml.etree.ElementTree as _ETtypes

from core import scan_db
from core.nmap_service_parse import clean_service_name

logger = logging.getLogger("monkeyx.modules.normalize")

REQUIRED_INPUTS = frozenset()

# Record types that earn a row in the findings table. Open ports / subdomains /
# dir hits are tracked elsewhere (ports table, ledger) and stay out of findings.
_FINDING_RECORD_TYPES = frozenset({
    "nuclei_finding", "script_output", "finding", "vulnerability",
})

_CLAIM_IN_TITLE = re.compile(r"\[([^\]]+)\]")

TOOL_OUTPUT_SUFFIXES = {
    "nmap":         "-nmap-normalized.jsonl",
    "nuclei":       "-nuclei-normalized.jsonl",
    "subfinder":    "-subfinder-normalized.jsonl",
    "ffuf":         "-ffuf-normalized.jsonl",
    "feroxbuster":  "-feroxbuster-normalized.jsonl",
    "katana":       "-katana-normalized.jsonl",
    "gau":          "-gau-normalized.jsonl",
    "bbot":         "-bbot-normalized.jsonl",
    "dns_security": "-dns-security-normalized.jsonl",
    "testssl":      "-testssl-normalized.jsonl",
    "wafw00f":      "-wafw00f-normalized.jsonl",
    "mantra":       "-mantra-normalized.jsonl",
    "corsy":        "-corsy-normalized.jsonl",
    "dalfox":       "-dalfox-normalized.jsonl",
    "ssh_audit":    "-ssh-audit-normalized.jsonl",
    "snmp_sweep":   "-snmp-sweep-normalized.jsonl",
    "smtp_security": "-smtp-security-normalized.jsonl",
}

# Local finding modules that already emit normalize-shaped JSONL. normalize just
# passes their finding rows through (and mints them) so they reach analyze /
# ai_analyze / ai_validate / scan.db via the same path as everything else.
# Maps tool key -> (glob pattern relative to prefix, output suffix key).
_PASSTHROUGH_JSONL_TOOLS = {
    "ssh_audit":    "*-ssh-audit.jsonl",
    "snmp_sweep":   "*-snmp-sweep.jsonl",
    "smtp_security": "*-smtp-security.jsonl",
}


# ---------------------------------------------------------------------------
# nmap XML
# ---------------------------------------------------------------------------

def _parse_nmap_xml(xml_path: str) -> list[dict]:
    records = []
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except ET.ParseError:
        return records

    if root.tag != "nmaprun":
        return records

    src = os.path.basename(xml_path)

    for host in root.iter("host"):
        # Prefer IPv4; fall back to any address element. NOTE: must use an
        # explicit `is not None` test — an <address> is a childless (leaf)
        # element, which evaluates falsy, so `a or b` would ALWAYS skip the IPv4
        # match and take the first address (possibly a MAC/IPv6).
        addr_el = host.find("address[@addrtype='ipv4']")
        if addr_el is None:
            addr_el = host.find("address")
        if addr_el is None:
            continue
        ip = addr_el.get("addr", "")

        # Extract hostnames (reverse DNS, user-provided, etc.)
        hostnames = []
        for hn_el in host.findall("hostnames/hostname"):
            name = hn_el.get("name", "").strip()
            if name:
                hostnames.append(name)
        hostname_str = ", ".join(hostnames) if hostnames else None
        display_host = f"{ip} ({hostnames[0]})" if hostnames else ip

        ports_el = host.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue

                port_num = int(port_el.get("portid", 0))
                proto = port_el.get("protocol", "tcp")
                status = state_el.get("state", "")
                reason = state_el.get("reason", "")

                svc = port_el.find("service")
                svc_name = clean_service_name(svc.get("name", "")) if svc is not None else ""
                tunnel   = svc.get("tunnel", "") if svc is not None else ""
                method   = svc.get("method", "") if svc is not None else ""
                conf     = svc.get("conf", "") if svc is not None else ""
                product  = svc.get("product", "") if svc is not None else ""
                version  = svc.get("version", "") if svc is not None else ""
                extra    = svc.get("extrainfo", "") if svc is not None else ""
                banner_parts = [p for p in (product, version, extra) if p]
                banner = " ".join(banner_parts) or None

                confidence = ""
                if conf:
                    try:
                        confidence = float(conf) / 10
                    except ValueError:
                        confidence = conf

                records.append({
                    "host": ip,
                    "hostname": hostname_str,
                    "port": port_num,
                    "proto": proto,
                    "status": status,
                    "service": svc_name,
                    "tunnel": tunnel,
                    "source": "scanner",
                    "method": method,
                    "confidence": confidence,
                    "reason": reason,
                    "product": product,
                    "version": version,
                    "extra": extra,
                    "tool": "nmap",
                    "type": "open_port",
                    "severity": "info",
                    "title": f"{proto.upper()}/{port_num} open — {svc_name}" if svc_name else f"{proto.upper()}/{port_num} open",
                    "detail": banner,
                    "source_file": src,
                })

                for script_el in port_el.findall("script"):
                    _emit_script_records(records, script_el, ip, hostname_str, port_num, proto, src)

        # Host-level scripts (smb-os-discovery, smb2-security-mode, dns-brute, etc.)
        hostscript_el = host.find("hostscript")
        if hostscript_el is not None:
            for script_el in hostscript_el.findall("script"):
                _emit_script_records(records, script_el, ip, hostname_str, None, None, src)

    return records


def _flatten_script_elems(script_el: _ETtypes.Element) -> str:
    """Reconstruct a compact "key=value" summary from an NSE script's structured
    <table>/<elem> tree.

    Only used as a FALLBACK when a script has no `output` attribute. Keys can
    repeat and nest (e.g. ssl-cert extensions each have name/value/critical), so
    we keep insertion order and prefix each keyed value; unkeyed elems (list
    items) are joined bare. This is a single string for one row — never one row
    per elem (that fan-out exploded a single ssl-cert result into ~280 rows).
    """
    parts = []
    for elem in script_el.findall(".//elem"):
        val = (elem.text or "").strip()
        if not val:
            continue
        key = elem.get("key", "")
        parts.append(f"{key}={val}" if key else val)
    return "; ".join(parts)


def _nse_vuln_state(script_el: _ETtypes.Element) -> str | None:
    """Return the NSE vuln-library state for a script, if it reported one.

    Scripts built on nmap's `vulns` library emit a structured
    ``<elem key="state">VULNERABLE|LIKELY VULNERABLE|NOT VULNERABLE|...</elem>``.
    This is nmap's OWN verdict on whether the host is affected — the reliable
    discriminator between a real finding and a script that merely ran. Scripts
    with no state elem (ssl-cert, http-title, http-methods, service probes that
    just report facts) return None and are treated as context, not findings.
    """
    for elem in script_el.findall(".//elem[@key='state']"):
        val = (elem.text or "").strip().upper()
        if val:
            return val
    return None


# NSE vuln states that mean "this host IS (or is probably) affected". A plain
# "NOT VULNERABLE" (or a script that ran without emitting a state) is NOT a
# finding — the vuln script executed and cleared the host.
_VULN_STATE_POSITIVE = ("VULNERABLE", "LIKELY VULNERABLE", "EXPLOITABLE")


def _classify_nse_script(script_el: _ETtypes.Element) -> tuple[str, str]:
    """Map an NSE script result to (record_type, severity).

    A vuln-library script whose state says the host is affected becomes a real
    ``vulnerability`` finding at medium severity (VULNERABLE/EXPLOITABLE) or low
    (LIKELY VULNERABLE — nmap hedged). Everything else — pure-info scripts and
    vuln scripts that reported NOT VULNERABLE — stays ``script_output``/``info``,
    so it remains queryable context without polluting the findings view.
    """
    state = _nse_vuln_state(script_el)
    if state and "NOT" not in state and any(p in state for p in _VULN_STATE_POSITIVE):
        severity = "low" if state.startswith("LIKELY") else "medium"
        return "vulnerability", severity
    return "script_output", "info"


def _emit_script_records(
    records: list[dict],
    script_el: _ETtypes.Element,
    ip: str,
    hostname_str: str | None,
    port_num: int | None,
    proto: str | None,
    src: str,
) -> None:
    """Emit exactly ONE record per NSE script per host:port.

    An NSE script result (ssl-cert, smb-os-discovery, http-vuln-*, ...) is ONE
    logical row. nmap's `output` attribute already holds its complete
    human-readable form; the structured <table>/<elem> tree is the same data
    decomposed. Prefer `output`; fall back to reconstructing from the elems.

    The row's type/severity come from _classify_nse_script: a vuln-library
    script whose state says the host is affected is a real ``vulnerability``
    finding; pure-info scripts and cleared vuln checks stay
    ``script_output``/``info`` (context, not findings). This is what keeps the
    findings table/report/CSV from drowning genuine vulns under thousands of
    ssl-cert / http-title context rows.

    Historically this emitted one row per leaf <elem key>, which shattered a
    single certificate into hundreds of meaningless fragment rows — 13,375
    ssl-cert rows from 394 ports in one real scan.
    """
    script_id = script_el.get("id", "")
    detail = (script_el.get("output") or "").strip()
    if not detail:
        detail = _flatten_script_elems(script_el)
    if not detail:
        return

    rtype, severity = _classify_nse_script(script_el)
    state = _nse_vuln_state(script_el)
    title = (f"{script_id}: {state.lower()}" if rtype == "vulnerability" and state
             else f"{script_id} output")

    record = {
        "host": ip,
        "hostname": hostname_str,
        "port": port_num,
        "proto": proto,
        "source": "script",
        "method": script_id,
        "extra": detail[:2000],
        "tool": "nmap",
        "type": rtype,
        "severity": severity,
        "title": title,
        "detail": detail[:2000],
        "source_file": src,
    }
    if state:
        record["nse_state"] = state
    records.append(record)


# ---------------------------------------------------------------------------
# nuclei — JSONL preferred (-oJ), text fallback for older runs
# ---------------------------------------------------------------------------

_NUCLEI_SEV_RE = re.compile(r"\[(critical|high|medium|low|info)\]", re.IGNORECASE)
_NUCLEI_URL_RE = re.compile(r"https?://([^\s\]]+)")
_IP_PORT_RE    = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})(?::(\d+))?")

# The canonical severity vocabulary every downstream consumer ranks/counts by
# (focus._SEVERITY_RANK, summary's tallies, the webserver chips).
_VALID_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})


def _clamp_severity(sev) -> str:
    """Map a tool severity to the canonical set; anything else -> 'info'.

    nuclei emits 'unknown' for templates whose author left severity unset (3 on
    a real run). Left verbatim it leaked a non-canonical value into findings —
    summary already tallied it as info and focus ranked it at the info tier, so
    normalize was the lone place storing 'unknown'. Clamp here so the source of
    truth agrees with every reader (unclassified = info; never inflated).
    """
    s = (sev or "info").strip().lower()
    return s if s in _VALID_SEVERITIES else "info"


def _host_port_from_url(url: str) -> tuple[str, int | None]:
    """Extract (host, port) from a URL string.

    When a scheme is present but no explicit port, the port is INFERRED from the
    scheme (https→443, http→80). nuclei emits most matched-at values as
    scheme-only URLs ("https://host/path"), so without this the majority of web
    findings were normalized with a NULL port — orphaning them from the ports
    table and from any host:port verdict join, and setting proto to NULL
    downstream. A schemeless "host:port" (what nuclei emits as matched-at for
    network/tcp templates — redis:6379, ssh:22, weblogic, etc.) is also split so
    those findings keep their port/proto and join back to ai_validate verdicts.
    A bare host (or raw-text fallback) infers nothing.
    """
    m = _NUCLEI_URL_RE.search(url)
    if not m:
        ip_m = _IP_PORT_RE.search(url)
        if ip_m:
            return ip_m.group(1), int(ip_m.group(2)) if ip_m.group(2) else None
        # Schemeless "host:port" (network/tcp templates). Split off a trailing
        # numeric port, but leave IPv6 alone (bracketed, or bare with >1 colon).
        if ":" in url and not url.startswith("["):
            host, _sep, port_str = url.rpartition(":")
            if host and ":" not in host and port_str.isdigit():
                return host, int(port_str)
        return url, None
    scheme = m.group(0).split("://", 1)[0].lower()
    default_port = 443 if scheme == "https" else 80 if scheme == "http" else None
    host_port = m.group(1).split("/")[0]
    if ":" in host_port:
        host, port_str = host_port.rsplit(":", 1)
        try:
            return host, int(port_str)
        except ValueError:
            return host_port, default_port
    return host_port, default_port


# nuclei's DNS templates report the DNS QUERY NAME as matched-at, not the asset
# host: a PTR check yields the reversed '198.18.13.149.in-addr.arpa', a DMARC/SRV
# check yields '_dmarc.ex.com' / '_ldap._tcp.ex.com', and wildcard-dns-detect
# yields a random '<rand>-<rand>.ex.com' probe. Stored verbatim as `host`, these
# pin findings to non-existent hosts (reversed IPs, service labels) and pad the
# host inventory with alarming-looking artifacts. Map them back to the real asset.
_WILDCARD_PROBE_RE = re.compile(r"^[a-z0-9]{20,}-[a-z0-9]{20,}\.")


def _normalize_dns_host(host: str) -> str:
    """Map a nuclei DNS-template query name back to the real asset host.

    - '<octets>.in-addr.arpa' -> the un-reversed IPv4; '<nibbles>.ip6.arpa' ->
      the IPv6 address.
    - leading service labels ('_dmarc', '_dkim', '_ldap._tcp', ...) are stripped
      to the parent domain.
    - a leading wildcard-detection probe label ('<rand>-<rand>.') is stripped.
    Anything without these markers is returned unchanged.
    """
    if not host:
        return host
    h = host.strip().rstrip(".").lower()
    if h.endswith(".in-addr.arpa"):
        labels = h[: -len(".in-addr.arpa")].split(".")
        if len(labels) == 4 and all(x.isdigit() and int(x) < 256 for x in labels):
            return ".".join(reversed(labels))
        return h
    if h.endswith(".ip6.arpa"):
        nibbles = h[: -len(".ip6.arpa")].split(".")
        if len(nibbles) == 32 and all(len(n) == 1 for n in nibbles):
            packed = "".join(reversed(nibbles))
            groups = ":".join(packed[i:i + 4] for i in range(0, 32, 4))
            try:
                import ipaddress
                return str(ipaddress.ip_address(groups))
            except ValueError:
                return h
        return h
    labels = h.split(".")
    while labels and labels[0].startswith("_"):
        labels.pop(0)
    h = ".".join(labels)
    h = _WILDCARD_PROBE_RE.sub("", h)
    return h or host


def _parse_nuclei_jsonl(path: str) -> list[dict]:
    """Parse nuclei -oJ JSONL output. Each line is a nuclei finding object."""
    records = []
    src = os.path.basename(path)
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for raw_line in fh:
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue

                matched_at = obj.get("matched-at") or obj.get("host") or ""
                # DNS-template matched-at values are bare query names (PTR
                # '<rev>.in-addr.arpa', '_dmarc.x', SRV, wildcard) with no
                # scheme. Normalize BEFORE host/port extraction: otherwise
                # _host_port_from_url matches the reversed dotted-quad as an IP
                # and strips '.in-addr.arpa', so the PTR un-reversal never fires
                # (phantom reversed-IP hosts). URLs keep the extract-then-
                # normalize order (normalizing a full URL string would mangle it).
                if "://" in matched_at:
                    host, port = _host_port_from_url(matched_at)
                    host = _normalize_dns_host(host)
                else:
                    host, port = _host_port_from_url(_normalize_dns_host(matched_at))

                info = obj.get("info", {})
                severity = _clamp_severity(info.get("severity"))
                template_id = obj.get("template-id") or obj.get("templateID") or ""
                template = obj.get("template") or ""
                name = info.get("name") or template_id
                description = info.get("description") or None
                extracted = obj.get("extracted-results") or None
                if isinstance(extracted, list):
                    extracted = "\n".join(str(d) for d in extracted)
                if isinstance(description, list):
                    description = "\n".join(str(d) for d in description)

                tags = info.get("tags")
                if isinstance(tags, list):
                    tags = ", ".join(tags)

                authors = info.get("author")
                if isinstance(authors, list):
                    authors = ", ".join(authors)

                classification = info.get("classification", {})
                cve_id = classification.get("cve-id")
                if isinstance(cve_id, list):
                    cve_id = ", ".join(str(c) for c in cve_id if c)
                cwe_id = classification.get("cwe-id")
                if isinstance(cwe_id, list):
                    cwe_id = ", ".join(str(c) for c in cwe_id if c)

                records.append({
                    "host": host,
                    "hostname": None,
                    "port": port,
                    "proto": "tcp" if port else None,
                    "tool": "nuclei",
                    "type": "nuclei_finding",
                    "severity": severity,
                    "template_id": template_id,
                    "template": template,
                    "title": f"[{template_id}] {name}" if template_id and name != template_id else name,
                    "description": description,
                    "detail": extracted,
                    "matched_at": matched_at,
                    "nuclei_type": obj.get("type"),
                    "tags": tags or None,
                    "author": authors or None,
                    "cve_id": cve_id or None,
                    "cwe_id": cwe_id or None,
                    "matcher_name": obj.get("matcher-name"),
                    "curl_command": obj.get("curl-command"),
                    "timestamp": obj.get("timestamp"),
                    "source_file": src,
                })
    except OSError:
        pass
    return records


def _parse_nuclei_text(path: str) -> list[dict]:
    """Parse nuclei plain-text output (fallback for runs without -oJ)."""
    records = []
    src = os.path.basename(path)
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for raw_line in fh:
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue

                sev_m = _NUCLEI_SEV_RE.search(line)
                severity = sev_m.group(1).lower() if sev_m else "info"
                host, port = _host_port_from_url(line)

                records.append({
                    "host": host,
                    "hostname": None,
                    "port": port,
                    "proto": "tcp" if port else None,
                    "tool": "nuclei",
                    "type": "nuclei_finding",
                    "severity": severity,
                    "title": line[:300],
                    "detail": None,
                    "source_file": src,
                })
    except OSError:
        pass
    return records


# ---------------------------------------------------------------------------
# subfinder
# ---------------------------------------------------------------------------

def _parse_subfinder_file(sub_path: str) -> list[dict]:
    records = []
    src = os.path.basename(sub_path)
    try:
        with open(sub_path, "r", encoding="utf-8", errors="ignore") as fh:
            for raw_line in fh:
                subdomain = raw_line.strip()
                if not subdomain or subdomain.startswith("#"):
                    continue
                records.append({
                    "host": subdomain,
                    "hostname": subdomain,
                    "port": None,
                    "proto": None,
                    "tool": "subfinder",
                    "type": "subdomain",
                    "severity": "info",
                    "title": f"Subdomain: {subdomain}",
                    "detail": None,
                    "source_file": src,
                })
    except OSError:
        pass
    return records


# ---------------------------------------------------------------------------
# ffuf / feroxbuster (one record per hit line)
# ---------------------------------------------------------------------------

def _iter_json_objects(path: str):
    """Yield every top-level JSON object in a file.

    Tolerant of BOTH true JSONL (one object per line) AND ax's ``-oJ`` output,
    which concatenates full ffuf/nuclei report objects onto a single line with
    no separators (one per fleet target). We read the whole buffer and walk it
    object-by-object with ``raw_decode``; on a decode error we resync to the
    next ``{``. This is why the old per-line ``json.loads`` silently dropped
    every ffuf hit — the file was one 80 KB line of 37 concatenated reports.
    """
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            data = fh.read()
    except OSError:
        return
    dec = json.JSONDecoder()
    i, n = 0, len(data)
    while i < n:
        while i < n and data[i] in " \t\r\n":
            i += 1
        if i >= n:
            break
        try:
            obj, end = dec.raw_decode(data, i)
        except json.JSONDecodeError:
            nxt = data.find("{", i + 1)
            if nxt == -1:
                break
            i = nxt
            continue
        yield obj
        i = end


def _parse_ffuf_jsonl(path: str) -> list[dict]:
    """Parse ffuf ``-oJ`` output into per-hit dir_hit records.

    ax's ``-oJ`` emits ffuf's ``-of json`` **report** objects
    (``{commandline, time, results:[...]}``) — one per fleet target, all
    concatenated on a single line. The actual hits live in each report's
    ``results`` array. We also accept flat per-line result objects (true JSONL)
    for back-compat / direct-tool runs.
    """
    src = os.path.basename(path)

    def _as_int(v):
        try:
            return int(v)
        except (TypeError, ValueError):
            return None

    def _mk(url, status_code, length, words):
        host, port = _host_port_from_url(url)
        title = f"{url} [{status_code}] [Size:{length}] [Words:{words}]"
        return {
            "host": host,
            "hostname": None,
            "port": port,
            "proto": "tcp" if port else None,
            "tool": "ffuf",
            "type": "dir_hit",
            "severity": "info",
            "title": title[:300],
            "detail": None,
            "source_file": src,
            # explicit fields for the web_dirs table / web viewer
            "url": url,
            "status_code": _as_int(status_code),
            "size": _as_int(length),
            "words": _as_int(words),
        }

    records = []
    for obj in _iter_json_objects(path):
        if not isinstance(obj, dict):
            continue
        results = obj.get("results")
        if isinstance(results, list):
            # ffuf report object — hits are nested in `results`.
            for r in results:
                if not isinstance(r, dict):
                    continue
                url = r.get("url") or r.get("input", {}).get("FUZZ", "")
                if not url:
                    continue
                records.append(_mk(url, r.get("status", ""),
                                   r.get("length", ""), r.get("words", "")))
        else:
            # Flat per-line result (true JSONL) — back-compat.
            url = obj.get("url") or obj.get("input", {}).get("FUZZ", "")
            if not url:
                continue
            records.append(_mk(url, obj.get("status", ""),
                               obj.get("length", ""), obj.get("words", "")))
    return records


def _parse_subfinder_jsonl(path: str) -> list[dict]:
    """Parse subfinder -oJ JSONL output."""
    records = []
    src = os.path.basename(path)
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for raw_line in fh:
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue

                subdomain = obj.get("host") or obj.get("input") or ""
                if not subdomain:
                    continue
                source = obj.get("source") or obj.get("sources") or None
                if isinstance(source, list):
                    source = ", ".join(source)

                records.append({
                    "host": subdomain,
                    "hostname": subdomain,
                    "port": None,
                    "proto": None,
                    "tool": "subfinder",
                    "type": "subdomain",
                    "severity": "info",
                    "title": f"Subdomain: {subdomain}",
                    "detail": f"Source: {source}" if source else None,
                    "source_file": src,
                })
    except OSError:
        pass
    return records


def _parse_crawled_urls(path: str, tool: str) -> list[dict]:
    """Parse a crawler's one-URL-per-line output (katana, gau) into `dir_hit`
    records so the discovered web content lands in scan.db's web_dirs table and
    the web viewer's Directories view — the same home as ffuf/feroxbuster hits.

    Only URLs that carry a path (or query) are minted: a crawler emits the bare
    site root too (``https://host``), which is an endpoint, not discovered
    content, and already shows in the endpoints view. Deduped by URL within the
    file. No status/size columns — a crawl records the URL, not a response line.
    """
    from urllib.parse import urlparse
    records = []
    src = os.path.basename(path)
    seen: set[str] = set()
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for raw_line in fh:
                url = raw_line.strip()
                if not url or url.startswith("#") or url in seen:
                    continue
                if not (url.startswith("http://") or url.startswith("https://")):
                    continue
                parsed = urlparse(url)
                # Skip bare roots — no path segment and no query means "the site",
                # not a discovered directory/endpoint.
                if parsed.path.strip("/") == "" and not parsed.query:
                    continue
                seen.add(url)
                host, port = _host_port_from_url(url)
                records.append({
                    "host": host,
                    "hostname": None,
                    "port": port,
                    "proto": "tcp" if port else None,
                    "tool": tool,
                    "type": "dir_hit",
                    "severity": "info",
                    "title": url[:300],
                    "detail": None,
                    "source_file": src,
                    # explicit fields for the web_dirs table / web viewer
                    "url": url,
                    "status_code": None,
                    "size": None,
                    "words": None,
                    "lines": None,
                })
    except OSError:
        pass
    return records


def _parse_dirbrute_file(path: str, tool: str) -> list[dict]:
    """Parse plain-text directory brute force output (legacy fallback)."""
    records = []
    src = os.path.basename(path)
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for raw_line in fh:
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                host, port = "", None
                url_m = _NUCLEI_URL_RE.search(line)
                if url_m:
                    host_port = url_m.group(1).split("/")[0]
                    if ":" in host_port:
                        host, port_str = host_port.rsplit(":", 1)
                        try:
                            port = int(port_str)
                        except ValueError:
                            host = host_port
                    else:
                        host = host_port
                # feroxbuster text columns, e.g.:
                #   200      GET        3l        9w      120c http://h/path
                # Best-effort: a missing token just leaves the field blank.
                u = re.search(r"https?://\S+", line)
                st = re.match(r"\s*(\d{3})\b", line)
                sz = re.search(r"(\d+)c\b", line)
                wd = re.search(r"(\d+)w\b", line)
                ln = re.search(r"(\d+)l\b", line)
                records.append({
                    "host": host,
                    "hostname": None,
                    "port": port,
                    "proto": "tcp" if port else None,
                    "tool": tool,
                    "type": "dir_hit",
                    "severity": "info",
                    "title": line[:300],
                    "detail": None,
                    "source_file": src,
                    # explicit fields for the web_dirs table / web viewer
                    "url": u.group(0) if u else None,
                    "status_code": int(st.group(1)) if st else None,
                    "size": int(sz.group(1)) if sz else None,
                    "words": int(wd.group(1)) if wd else None,
                    "lines": int(ln.group(1)) if ln else None,
                })
    except OSError:
        pass
    return records


# ---------------------------------------------------------------------------
# bbot JSONL (output from bbot_cloud, bbot_recon, bbot_passive, etc.)
# ---------------------------------------------------------------------------

_BBOT_SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "INFO": "info",
}


def _parse_bbot_jsonl(path: str) -> list[dict]:
    """Parse bbot JSON output into normalized records.

    Extracts FINDING, VULNERABILITY, OPEN_TCP_PORT, TECHNOLOGY, STORAGE_BUCKET,
    CODE_REPOSITORY, SOCIAL, EMAIL_ADDRESS, URL_HINT, AZURE_TENANT, and WAF
    events into the standard normalize schema. AZURE_TENANT/WAF/EMAIL_ADDRESS are
    minted as info-severity findings (intel that belongs in the findings view /
    web viewer, not vulnerabilities); TECHNOLOGY stays an `open`-less info record
    that ai_analyze and the summary tech inventory read.
    """
    records = []
    src = os.path.basename(path)
    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue

                etype = event.get("type", "")
                # bbot carries the STRUCTURED payload in `data_json` (a dict);
                # `data` is the string form and is often absent for rich events
                # (SOCIAL/CODE_REPOSITORY/FINDING). Reading only `data` left every
                # structured field — url, platform, description — empty, minting
                # blank-title findings. Prefer data_json when it's a dict.
                data = event.get("data", "")
                data_json = event.get("data_json")
                if isinstance(data_json, dict):
                    data = data_json
                host = event.get("host", "")
                resolved_hosts = event.get("resolved_hosts", [])

                if etype in ("FINDING", "VULNERABILITY"):
                    description = ""
                    severity_raw = "INFO"
                    if isinstance(data, dict):
                        description = data.get("description", "")
                        host = data.get("host", host) or host
                        severity_raw = data.get("severity") or "INFO"
                    elif isinstance(data, str):
                        description = data

                    severity = _BBOT_SEVERITY_MAP.get(severity_raw.upper(), "info")
                    module_name = event.get("module", "bbot")

                    records.append({
                        "host": str(host) if host else "unknown",
                        "hostname": None,
                        "port": None,
                        "proto": None,
                        "tool": "bbot",
                        "type": "finding",
                        "severity": severity,
                        "title": description[:300] if description else f"{etype} from {module_name}",
                        "detail": description,
                        "source_file": src,
                        "bbot_module": module_name,
                        "bbot_type": etype,
                    })

                elif etype == "OPEN_TCP_PORT":
                    port_host = str(data) if isinstance(data, str) else ""
                    port = None
                    if ":" in port_host:
                        h, _, p = port_host.rpartition(":")
                        host = h or host
                        try:
                            port = int(p)
                        except ValueError:
                            pass
                    records.append({
                        "host": str(host) if host else "unknown",
                        "hostname": None,
                        "port": port,
                        "proto": "tcp",
                        "tool": "bbot",
                        "type": "open_port",
                        "severity": "info",
                        "title": f"Open port {port}/tcp" if port else "Open TCP port",
                        "detail": None,
                        "source_file": src,
                        "bbot_module": event.get("module", "bbot"),
                        "bbot_type": etype,
                    })

                elif etype == "TECHNOLOGY":
                    tech = ""
                    if isinstance(data, dict):
                        tech = data.get("technology", str(data))
                        host = data.get("host", host) or host
                    elif isinstance(data, str):
                        tech = data
                    records.append({
                        "host": str(host) if host else "unknown",
                        "hostname": None,
                        "port": None,
                        "proto": None,
                        "tool": "bbot",
                        "type": "technology",
                        "severity": "info",
                        "title": f"Technology: {tech[:200]}",
                        "detail": tech,
                        "source_file": src,
                        "bbot_module": event.get("module", "bbot"),
                        "bbot_type": etype,
                    })

                elif etype == "STORAGE_BUCKET":
                    bucket_name = ""
                    if isinstance(data, dict):
                        bucket_name = data.get("name", data.get("url", str(data)))
                    elif isinstance(data, str):
                        bucket_name = data
                    records.append({
                        "host": str(host) if host else "unknown",
                        "hostname": None,
                        "port": None,
                        "proto": None,
                        "tool": "bbot",
                        "type": "finding",
                        "severity": "medium",
                        "title": f"Storage bucket: {bucket_name[:200]}",
                        "detail": bucket_name,
                        "source_file": src,
                        "bbot_module": event.get("module", "bbot"),
                        "bbot_type": etype,
                    })

                elif etype == "AZURE_TENANT":
                    # bbot's azure_tenant module: Azure/M365 tenant name/id +
                    # federated domains — org mapping + M365 attack surface
                    # (password-spray target set). Was fully dropped before.
                    name, domains = "", []
                    if isinstance(data, dict):
                        name = (data.get("tenant-id") or data.get("tenant_id")
                                or data.get("name") or "")
                        tnames = data.get("tenant-names") or data.get("tenant_names") or []
                        if not name and tnames:
                            name = tnames[0] if isinstance(tnames, list) and tnames else str(tnames)
                        domains = data.get("domains") or []
                        host = data.get("host", host) or host
                    elif isinstance(data, str):
                        name = data
                    detail = f"Azure/M365 tenant {name}".strip()
                    if domains:
                        detail += " — domains: " + ", ".join(str(d) for d in domains[:20])
                    records.append({
                        "host": str(host) if host else "unknown",
                        "hostname": None,
                        "port": None,
                        "proto": None,
                        "tool": "bbot",
                        "type": "finding",
                        "severity": "info",
                        "title": f"Azure/M365 tenant: {str(name)[:150]}" if name else "Azure/M365 tenant",
                        "detail": detail,
                        "source_file": src,
                        "bbot_module": event.get("module", "bbot"),
                        "bbot_type": etype,
                    })

                elif etype == "WAF":
                    # WAF/CDN vendor per host — origin-discovery lead + explains
                    # nuclei false-negatives on protected endpoints. Was dropped.
                    waf_name, url = "", ""
                    if isinstance(data, dict):
                        waf_name = data.get("waf") or data.get("WAF") or data.get("name") or ""
                        url = data.get("url", "")
                        host = data.get("host", host) or host
                    elif isinstance(data, str):
                        waf_name = data
                    records.append({
                        "host": str(host) if host else "unknown",
                        "hostname": None,
                        "port": None,
                        "proto": None,
                        "tool": "bbot",
                        "type": "finding",
                        "severity": "info",
                        "title": f"WAF/CDN detected: {str(waf_name)[:150]}" if waf_name else "WAF/CDN detected",
                        "detail": (f"{waf_name} ({url})" if url else str(waf_name)).strip() or None,
                        "source_file": src,
                        "bbot_module": event.get("module", "bbot"),
                        "bbot_type": etype,
                    })

                elif etype == "CODE_REPOSITORY":
                    repo_url = ""
                    if isinstance(data, dict):
                        repo_url = data.get("url", "") or str(data)
                        host = data.get("host", host) or host
                    elif isinstance(data, str):
                        repo_url = data
                    module_name = event.get("module", "bbot")
                    title = (f"Code repository: {repo_url[:200]}" if repo_url
                             else f"Code repository ({module_name})")
                    records.append({
                        "host": str(host) if host else "unknown",
                        "hostname": None,
                        "port": None,
                        "proto": None,
                        "tool": "bbot",
                        "type": "finding",
                        "severity": "info",
                        "title": title,
                        "detail": repo_url or None,
                        "source_file": src,
                        "bbot_module": module_name,
                        "bbot_type": etype,
                    })

                elif etype == "SOCIAL":
                    social_url = ""
                    platform = ""
                    profile = ""
                    if isinstance(data, dict):
                        social_url = data.get("url", "")
                        platform = data.get("platform", "")
                        profile = data.get("profile_name", "")
                        host = data.get("host", host) or host
                    elif isinstance(data, str):
                        social_url = data
                    module_name = event.get("module", "bbot")
                    label = f"[{platform}] " if platform else ""
                    who = f"{profile} " if profile else ""
                    title = f"Social profile: {label}{who}{social_url[:200]}".strip()
                    if title == "Social profile:":
                        title = f"Social profile ({module_name})"
                    records.append({
                        "host": str(host) if host else "unknown",
                        "hostname": None,
                        "port": None,
                        "proto": None,
                        "tool": "bbot",
                        "type": "finding",
                        "severity": "info",
                        "title": title,
                        "detail": social_url or None,
                        "source_file": src,
                        "bbot_module": module_name,
                        "bbot_type": etype,
                    })

                elif etype == "EMAIL_ADDRESS":
                    email = ""
                    if isinstance(data, dict):
                        email = data.get("email", str(data))
                        host = data.get("host", host) or host
                    elif isinstance(data, str):
                        email = data
                    records.append({
                        "host": str(host) if host else "unknown",
                        "hostname": None,
                        "port": None,
                        "proto": None,
                        "tool": "bbot",
                        # Minted as an info finding (was type "email", which was
                        # in neither FINDING_TYPES nor read by ai_analyze, so the
                        # parsing was thrown away). Emails are spray/cred intel —
                        # surface them in the findings view/web viewer.
                        "type": "finding",
                        "severity": "info",
                        "title": f"Email address: {email}",
                        "detail": email,
                        "source_file": src,
                        "bbot_module": event.get("module", "bbot"),
                        "bbot_type": etype,
                    })

                elif etype == "URL_HINT":
                    url = ""
                    if isinstance(data, dict):
                        url = data.get("url", str(data))
                        host = data.get("host", host) or host
                    elif isinstance(data, str):
                        url = data
                    records.append({
                        "host": str(host) if host else "unknown",
                        "hostname": None,
                        "port": None,
                        "proto": None,
                        "tool": "bbot",
                        "type": "url_hint",
                        "severity": "info",
                        "title": f"Historical URL: {url[:200]}",
                        "detail": url,
                        "source_file": src,
                        "bbot_module": event.get("module", "bbot"),
                        "bbot_type": etype,
                    })

    except OSError:
        pass
    return records


# ---------------------------------------------------------------------------
# testssl.sh (plain-text report; ax runs `testssl.sh -U -iL input`)
# ---------------------------------------------------------------------------

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
# testssl target banner:  " Start ... -->> 1.2.3.4:443 (example.com) <<--"
_TESTSSL_TARGET_RE = re.compile(r"-->>\s*([^\s:]+):(\d+)\s*(?:\(([^)]*)\))?\s*<<--")
# Vulnerability / weakness lines carry a CVE and/or a clear severity marker.
_TESTSSL_CVE_RE = re.compile(r"(CVE-\d{4}-\d+)")
# Check headers sit at the left margin (indent ~1); testssl wraps long results
# into the verdict column (indent ~40+), so anything more indented than this is a
# continuation line, not a new check.
_TESTSSL_LABEL_MAX_INDENT = 10


# testssl flags many named weaknesses whose real-world severity varies widely.
# Keying every "vulnerable" line to "high" (the old behaviour) inflated CBC/cipher
# issues — LUCKY13, BEAST, SWEET32 — into highs, drowning the genuinely serious
# ones. Map the well-known names/CVEs to a defensible severity instead. Matching
# on the vuln NAME is reliable: testssl always prints it at the start of the line
# (e.g. "SWEET32 (CVE-2016-2183) ... VULNERABLE"). Checked in order; first match
# wins, so put narrower tokens ahead of broader ones. (Bare "ccs" is avoided — it
# is a substring of "success"/"access"; we match the parenthesised CVE form.)
_TESTSSL_VULN_SEVERITY = (
    (("heartbleed", "cve-2014-0160"), "high"),
    (("drown", "cve-2016-0800", "cve-2016-0703"), "high"),
    (("ticketbleed", "cve-2016-9244"), "high"),
    (("ccs (cve", "ccs injection", "cve-2014-0224"), "high"),
    (("robot",), "high"),
    (("winshock", "cve-2014-6321"), "high"),
    (("poodle", "cve-2014-3566", "cve-2014-8730"), "medium"),
    (("freak", "cve-2015-0204"), "medium"),
    (("logjam", "cve-2015-4000"), "medium"),
    (("sweet32", "cve-2016-2183", "cve-2016-6329"), "medium"),
    (("crime", "cve-2012-4929"), "medium"),
    (("breach", "cve-2013-3587"), "medium"),
    (("rc4", "cve-2013-2566", "cve-2015-2808"), "medium"),
    (("sslv2",), "medium"),
    (("sslv3",), "medium"),
    (("beast", "cve-2011-3389"), "low"),
    (("lucky13", "lucky 13", "cve-2013-0169"), "low"),
)


def _testssl_severity(line: str, name_hint: str = "") -> str | None:
    """Classify a testssl line, or return None if it isn't a weakness.

    Lines marked OK / "not vulnerable" are not findings. A recognised named
    weakness gets its mapped severity; an unrecognised-but-flagged "vulnerable"
    line defaults to "medium" (conservative — no longer a blanket "high"); weak
    crypto / protocol enablement testssl marks "(not ok)" defaults to low, bumped
    to medium for the known-broken ciphers. The raw report stays on disk for the
    operator regardless.

    `name_hint` is the current check's header text (e.g. "BEAST (CVE-2011-3389)")
    for the case where testssl wraps a long result and the VULNERABLE verdict
    lands on its own continuation line that no longer carries the check name — so
    the name-keyed severity map can still recognise it. The hint only feeds the
    NAME→severity match; whether the line is a finding at all is decided purely
    from the line itself, so a hint never manufactures a finding.
    """
    low = line.lower()
    if "not vulnerable" in low or "(ok)" in low or " ok " in f" {low} ":
        return None
    # Detection is unchanged from before: a finding is a line testssl marked
    # "vulnerable" or "(not ok)". Only the SEVERITY assignment changed — so this
    # never widens what counts as a finding (which would pull in advisory prose
    # that merely mentions e.g. "SSLv2"), it just stops rating everything "high".
    is_vuln = "vulnerable" in low
    is_notok = "(not ok)" in low
    if not (is_vuln or is_notok):
        return None
    match_text = f"{name_hint.lower()} {low}" if name_hint else low
    for keywords, sev in _TESTSSL_VULN_SEVERITY:
        if any(k in match_text for k in keywords):
            return sev
    if is_vuln:
        # Unrecognised but flagged: conservative default (was a blanket "high").
        return "medium"
    # Weak crypto / protocol enablement testssl flags "(not ok)"; export/NULL-grade
    # ciphers are the serious unmapped ones.
    if any(t in low for t in ("export", "null", "anon")):
        return "medium"
    return "low"


def _parse_testssl_text(path: str) -> list[dict]:
    records: list[dict] = []
    src = os.path.basename(path)
    cur_host, cur_port, cur_name = "", None, None
    # testssl prints each check as "<Name> (CVE-...)   <verdict>" at the left
    # margin, but a long result (e.g. BEAST listing every weak cipher) WRAPS so
    # the VULNERABLE verdict lands on its own deeply-indented continuation line
    # that carries neither the check name nor the CVE. We track the last check
    # header (name + CVE) so those continuation verdicts are attributed to the
    # right check — otherwise BEAST was recorded as a generic "medium VULNERABLE"
    # with its CVE and its (low) mapped severity both lost.
    cur_check_label, cur_check_cve = None, None
    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            for raw in fh:
                line = _ANSI_RE.sub("", raw).rstrip("\n")
                banner = _TESTSSL_TARGET_RE.search(line)
                if banner:
                    cur_host = banner.group(1)
                    try:
                        cur_port = int(banner.group(2))
                    except ValueError:
                        cur_port = None
                    cur_name = (banner.group(3) or "").strip() or None
                    cur_check_label, cur_check_cve = None, None  # new target
                    continue
                if not cur_host:
                    continue
                stripped = line.strip()
                indent = len(line) - len(line.lstrip())
                # A check HEADER sits at the left margin; a wrapped continuation
                # line is pushed out into the verdict column (indent ~40+). Only a
                # header (re)sets the current check context.
                is_header = bool(stripped) and indent <= _TESTSSL_LABEL_MAX_INDENT
                if is_header:
                    cur_check_label = re.split(r"\s{2,}", stripped, maxsplit=1)[0].strip() or None
                    hm = _TESTSSL_CVE_RE.search(line)
                    cur_check_cve = hm.group(1) if hm else None
                sev = _testssl_severity(line, name_hint="" if is_header else (cur_check_label or ""))
                if sev is None:
                    continue
                text = stripped
                if not text:
                    continue
                own_cve = _TESTSSL_CVE_RE.search(text)
                # A continuation verdict has no CVE/name of its own — inherit the
                # tracked check's. A self-contained header line uses its own.
                cve_id = own_cve.group(1) if own_cve else (None if is_header else cur_check_cve)
                if is_header:
                    label = re.split(r"\s{2,}", text, maxsplit=1)[0].strip() or text[:60]
                else:
                    label = cur_check_label or re.split(r"\s{2,}", text, maxsplit=1)[0].strip() or text[:60]
                claim = cve_id or label
                records.append({
                    "host": cur_host,
                    "hostname": cur_name,
                    "port": cur_port,
                    "proto": "tcp",
                    "tool": "testssl",
                    "type": "finding",
                    "severity": sev,
                    "title": f"[{claim}] {text[:200]}",
                    "detail": text[:2000],
                    "cve_id": cve_id,
                    "source_file": src,
                })
    except OSError:
        pass
    return records


# ---------------------------------------------------------------------------
# wafw00f (plain-text report; one line per URL)
# ---------------------------------------------------------------------------

# wafw00f prints e.g. "[+] The site https://x is behind Cloudflare (Cloudflare Inc.) WAF."
# or "[-] No WAF detected by the generic detection".
_WAFW00F_BEHIND_RE = re.compile(
    r"(https?://[^\s]+)\s+is behind\s+(.+?)\s+WAF", re.IGNORECASE)


def _parse_wafw00f_text(path: str) -> list[dict]:
    records: list[dict] = []
    src = os.path.basename(path)
    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            for raw in fh:
                line = _ANSI_RE.sub("", raw).strip()
                m = _WAFW00F_BEHIND_RE.search(line)
                if not m:
                    continue
                url, waf = m.group(1), m.group(2).strip()
                host, port = _host_port_from_url(url)
                records.append({
                    "host": host,
                    "hostname": None,
                    "port": port,
                    "proto": "tcp" if port else None,
                    "tool": "wafw00f",
                    "type": "finding",
                    "severity": "info",
                    "title": f"[waf] {url} behind {waf}",
                    "detail": f"WAF/CDN detected: {waf}",
                    "waf": waf,
                    "matched_at": url,
                    "source_file": src,
                })
    except OSError:
        pass
    return records


# ---------------------------------------------------------------------------
# mantra / corsy / dalfox (plain-text finding output)
# ---------------------------------------------------------------------------

def _finding_from_url_line(line: str, url: str, *, tool: str, type_: str,
                           severity: str, claim: str, src: str,
                           title: str | None = None) -> dict:
    host, port = _host_port_from_url(url)
    return {
        "host": host or "unknown",
        "hostname": None,
        "port": port,
        "proto": "tcp" if port else None,
        "tool": tool,
        "type": type_,
        "severity": severity,
        "title": f"[{claim}] {(title or line)[:200]}",
        "detail": line[:2000],
        "matched_at": url,
        "source_file": src,
    }


def _parse_mantra_text(path: str) -> list[dict]:
    """mantra prints lines containing a secret and the URL it was found at."""
    records: list[dict] = []
    src = os.path.basename(path)
    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            for raw in fh:
                line = _ANSI_RE.sub("", raw).strip()
                if not line:
                    continue
                m = _NUCLEI_URL_RE.search(line)
                if not m:
                    continue
                records.append(_finding_from_url_line(
                    line, m.group(0), tool="mantra", type_="finding",
                    severity="medium", claim="secret", src=src,
                    title="Possible secret in response"))
    except OSError:
        pass
    return records


def _parse_corsy_text(path: str) -> list[dict]:
    """Corsy prints one block/line per URL with a misconfiguration class."""
    records: list[dict] = []
    src = os.path.basename(path)
    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            for raw in fh:
                line = _ANSI_RE.sub("", raw).strip()
                if not line:
                    continue
                m = _NUCLEI_URL_RE.search(line)
                if not m:
                    continue
                low = line.lower()
                if not any(t in low for t in ("origin", "cors", "wildcard",
                                              "null", "reflect", "credential")):
                    continue
                records.append(_finding_from_url_line(
                    line, m.group(0), tool="corsy", type_="finding",
                    severity="medium", claim="cors", src=src,
                    title="CORS misconfiguration"))
    except OSError:
        pass
    return records


def _parse_dalfox_text(path: str) -> list[dict]:
    """dalfox prints [POC]/[VULN] lines with the affected URL."""
    records: list[dict] = []
    src = os.path.basename(path)
    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            for raw in fh:
                line = _ANSI_RE.sub("", raw).strip()
                if not line:
                    continue
                low = line.lower()
                if "[poc]" in low or "[vuln]" in low:
                    m = _NUCLEI_URL_RE.search(line)
                    url = m.group(0) if m else ""
                    records.append(_finding_from_url_line(
                        line, url, tool="dalfox", type_="vulnerability",
                        severity="high", claim="xss", src=src,
                        title="XSS (dalfox)"))
    except OSError:
        pass
    return records


# ---------------------------------------------------------------------------
# shodan_enrich (JSONL — the module already emits normalize-shaped records)
# ---------------------------------------------------------------------------

def _parse_normalized_jsonl(path: str, default_tool: str) -> list[dict]:
    """Pass through JSONL records already in the normalize schema.

    Keeps only finding/vulnerability rows (context rows like host_info are
    dropped — the producing module logs those elsewhere). Used for modules that
    emit normalize-shaped JSONL directly: shodan_enrich, ssh_audit_scan,
    snmp_sweep, smtp_security.
    """
    records: list[dict] = []
    src = os.path.basename(path)
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
                if rec.get("type") not in ("finding", "vulnerability"):
                    continue
                rec.setdefault("tool", default_tool)
                rec.setdefault("source_file", src)
                records.append(rec)
    except OSError:
        pass
    return records


def _parse_shodan_jsonl(path: str) -> list[dict]:
    """shodan_enrich records (see _parse_normalized_jsonl)."""
    return _parse_normalized_jsonl(path, "shodan")


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

def _dedup_nmap_records(records: list[dict]) -> list[dict]:
    """Deduplicate nmap records, keeping the richest version of each.

    open_port records are keyed by (host, port, proto) — last-write-wins so
    that full-scan results with service info override baseline syn-only hits.
    script_output records are keyed by (host, port, method, detail[:200]).
    """
    port_best = {}
    script_seen = {}
    other = []

    for rec in records:
        rtype = rec.get('type')
        if rtype == 'open_port':
            key = (rec.get('host'), rec.get('port'), rec.get('proto', 'tcp'))
            existing = port_best.get(key)
            if existing is None:
                port_best[key] = rec
            else:
                if _richer_port_record(rec, existing):
                    port_best[key] = rec
        elif rtype == 'script_output':
            key = (rec.get('host'), rec.get('port'), rec.get('method', ''),
                   (rec.get('detail') or '')[:200])
            if key not in script_seen:
                script_seen[key] = rec
        else:
            other.append(rec)

    return list(port_best.values()) + list(script_seen.values()) + other


def _richer_port_record(new, old):
    """Return True if new has more service detail than old."""
    new_detail = bool(new.get('product') or new.get('version') or new.get('detail'))
    old_detail = bool(old.get('product') or old.get('version') or old.get('detail'))
    if new_detail and not old_detail:
        return True
    if not new_detail and old_detail:
        return False
    new_score = sum(1 for k in ('product', 'version', 'extra') if new.get(k))
    old_score = sum(1 for k in ('product', 'version', 'extra') if old.get(k))
    return new_score > old_score


# ---------------------------------------------------------------------------
# JSONL writer helper
# ---------------------------------------------------------------------------

def _write_tool_jsonl(output_path: str, records: list[dict]) -> bool:
    try:
        with open(output_path, "w", encoding="utf-8") as out:
            for record in records:
                out.write(json.dumps(record) + "\n")
        return True
    except OSError as e:
        print(f"[!] Failed to write {output_path}: {e}")
        return False


# ---------------------------------------------------------------------------
# Module entry point
# ---------------------------------------------------------------------------

def _claim_for(record: dict) -> str:
    """Tool discriminator that, with (host, port, proto), identifies a finding.

    Must match what ai_validate recomputes from the same record so both mint the
    same finding_id: nuclei -> template_id, nmap script -> method (script id),
    bbot -> bbot_type + module + title, dns_security -> the `[check]` slug (stored
    only in title). Falls back to the leading [bracketed] token in the title, else "".
    """
    tool = record.get("tool", "")
    if tool == "nuclei":
        return record.get("template_id") or ""
    if tool == "nmap":
        return record.get("method") or ""
    if tool == "bbot":
        # bbot emits many distinct events per host that share a bbot_type (every
        # FINDING is type "FINDING"), so keying on bbot_type alone collapses them
        # all onto one finding_id and all but the last are lost on upsert. Fold in
        # the emitting module and the title (which carries the description / port /
        # tech / bucket name) so semantically distinct events stay distinct while
        # genuinely identical ones still dedup.
        parts = (record.get("bbot_type") or "",
                 record.get("bbot_module") or "",
                 (record.get("title") or "").strip())
        return " | ".join(p for p in parts if p)
    if tool == "shodan":
        return record.get("shodan_claim") or ""
    # dns_security / testssl / wafw00f (and any tool that carries the
    # discriminator as the leading [bracketed] token in the title)
    title = record.get("title") or ""
    m = _CLAIM_IN_TITLE.match(title.strip())
    return m.group(1) if m else ""


def finding_key(record: dict):
    """The shared finding_id for a normalized record, or None if it has no host.

    Mirrors `_mint_findings` exactly (host falls back to hostname; discriminator
    is `_claim_for`), so a record's key here equals the scan.db findings PK it was
    minted under. Returns None when there is no host — such a record can't form a
    finding_id and scan.db skips it too, so callers keep it un-collapsed instead
    of merging distinct host-less rows.
    """
    host = record.get("host") or record.get("hostname")
    if not host:
        return None
    return scan_db.finding_id(host, record.get("port"), record.get("proto"),
                              _claim_for(record))


def dedup_findings(records):
    """Collapse duplicate finding records by their shared finding_id, order-stable.

    normalize's JSONL can carry the SAME finding more than once (the raw tool
    emitted a match twice); scan.db's findings primary key silently collapses
    those to one row, which is why a raw JSONL count (report/CSV/summary) can be
    2x the scan.db 'source of truth'. Deduping by `finding_key` here reproduces
    that collapse so the human-facing counts agree with the viewer. First-seen
    wins; host-less records (no finding_id) are ALL kept — never merged.
    """
    seen = set()
    out = []
    hostless = 0
    for rec in records:
        fid = finding_key(rec)
        if fid is None:
            key = ("\0hostless", hostless)
            hostless += 1
        else:
            key = fid
        if key in seen:
            continue
        seen.add(key)
        out.append(rec)
    return out


def _mint_findings(records: list[dict], db, now: str) -> None:
    """Upsert findings-type records into scan.db. Non-fatal; JSONL is authoritative."""
    if db is None:
        return
    for rec in records:
        if rec.get("type") not in _FINDING_RECORD_TYPES:
            continue
        host = rec.get("host") or rec.get("hostname")
        if not host:
            continue
        claim = _claim_for(rec)
        try:
            fid = scan_db.finding_id(host, rec.get("port"), rec.get("proto"), claim)
            db.upsert_finding(
                finding_id=fid, host=host, port=rec.get("port"),
                proto=rec.get("proto"), claim=claim, tool=rec.get("tool", ""),
                type=rec.get("type"), severity=rec.get("severity"),
                title=rec.get("title"), detail=rec.get("detail"),
                matched_at=rec.get("matched_at"), cve_id=rec.get("cve_id"),
                tags=rec.get("tags"), source_file=rec.get("source_file"),
                hostname=rec.get("hostname"), template=rec.get("template"),
                description=rec.get("description"), cwe_id=rec.get("cwe_id"),
                matcher_name=rec.get("matcher_name"), now=now)
        except Exception as exc:  # pragma: no cover - defensive, DB never aborts a run
            logger.warning("scan.db finding mint failed for %s: %s", host, exc)


def _mint_web_dirs(records: list[dict], db, now: str) -> None:
    """Upsert content-discovery hits (ffuf/feroxbuster `dir_hit` records) into
    scan.db's web_dirs table so the web viewer can browse them. Deduped on
    (url, tool) by upsert_web_dir. Non-fatal; the normalized JSONL is
    authoritative. Records without a URL are skipped (nothing to key on)."""
    if db is None:
        return
    for rec in records:
        if rec.get("type") != "dir_hit":
            continue
        url = rec.get("url")
        if not url:
            continue
        host = rec.get("host") or rec.get("hostname") or ""
        if not host:
            h, _p = _host_port_from_url(url)
            host = h or ""
        try:
            db.upsert_web_dir(
                url=url, tool=rec.get("tool", ""), host=host or None,
                port=rec.get("port"), status_code=rec.get("status_code"),
                size=rec.get("size"), words=rec.get("words"), lines=rec.get("lines"),
                source_file=rec.get("source_file"), now=now)
        except Exception as exc:  # pragma: no cover - defensive, DB never aborts
            logger.warning("scan.db web_dir write failed for %s: %s", url, exc)


def _mint_web_endpoints(prefix: str, db, now: str) -> None:
    """Mint httpx web-service fingerprints into scan.db's web_endpoints table.

    httpx output is never normalized (no *-httpx-normalized.jsonl), so ai_analyze
    reads it raw today. Minting it lets that reader move to the DB in Stage E.
    Reads the raw ``{prefix}*-httpx.jsonl`` files, which are kept on disk.
    Non-fatal; the raw files remain authoritative.
    """
    if db is None:
        return
    for path in sorted(glob.glob(f"{prefix}*-httpx.jsonl")):
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
                    url = rec.get("url") or rec.get("input") or ""
                    host = rec.get("host") or rec.get("input") or url
                    if not url or not host:
                        continue
                    tech = rec.get("tech") or rec.get("technologies")
                    tls = rec.get("tls")
                    db.upsert_web_endpoint(
                        host=host, url=url, port=rec.get("port"),
                        scheme=rec.get("scheme"), status_code=rec.get("status_code"),
                        title=rec.get("title"), webserver=rec.get("webserver"),
                        tech=json.dumps(tech) if tech is not None else None,
                        content_type=rec.get("content_type"),
                        cdn=bool(rec.get("cdn")),
                        tls=json.dumps(tls) if tls is not None else None,
                        source_file=os.path.basename(path), now=now)
        except OSError as exc:  # pragma: no cover - defensive
            logger.warning("scan.db web_endpoint mint failed for %s: %s", path, exc)


def _find_gowitness_sqlite(output_dir: str) -> str | None:
    """Locate the gowitness SQLite DB under reports/ (best-effort)."""
    if not output_dir:
        return None
    reports_dir = os.path.join(output_dir, "reports")
    for base in (reports_dir, output_dir):
        if not os.path.isdir(base):
            continue
        for dirpath, _dirnames, filenames in os.walk(base):
            if "gowitness.sqlite3" in filenames:
                return os.path.join(dirpath, "gowitness.sqlite3")
            for f in filenames:
                if f.endswith(".sqlite3") and "gowitness" in dirpath.lower():
                    return os.path.join(dirpath, f)
    return None


def _link_gowitness_screenshots(output_dir: str, db) -> None:
    """Attach gowitness screenshot paths to web_endpoints rows.

    gowitness records url->filename in its own sqlite; the JPEGs sit beside that
    DB. We store each screenshot as a path RELATIVE to the output-dir root, so it
    resolves the same whether the run dir is served in place or unzipped by a
    client. If a screenshotted URL has no httpx endpoint yet, we create a minimal
    web_endpoints row so the capture still surfaces. Best-effort and non-fatal.
    """
    if db is None or not output_dir:
        return
    db_path = _find_gowitness_sqlite(output_dir)
    if not db_path:
        return
    db_dir = os.path.dirname(db_path)
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=30.0)
        conn.row_factory = sqlite3.Row
    except sqlite3.Error as exc:  # pragma: no cover - defensive
        logger.warning("Could not open gowitness DB %s: %s", db_path, exc)
        return
    linked = 0
    # Pull the web fields gowitness records (title / HTTP status / detected
    # technologies), not just the screenshot path, so a URL that ONLY gowitness
    # saw (no httpx fingerprint) surfaces with real metadata in the web view
    # instead of a blank row. Best-effort: older gowitness schemas may lack these
    # columns/the technologies table, so fall back to the screenshot-only query.
    rows = None
    try:
        rows = conn.execute(
            "SELECT r.url, r.final_url, r.filename, r.perception_hash_group_id, "
            "r.title, r.response_code, "
            "(SELECT group_concat(t.value, ', ') FROM technologies t "
            " WHERE t.result_id = r.id) AS tech "
            "FROM results r "
            "WHERE r.failed = 0 AND r.filename IS NOT NULL AND r.filename != ''"
        ).fetchall()
    except sqlite3.Error:
        try:
            rows = conn.execute(
                "SELECT url, final_url, filename, perception_hash_group_id "
                "FROM results "
                "WHERE failed = 0 AND filename IS NOT NULL AND filename != ''"
            ).fetchall()
        except sqlite3.Error as exc:  # pragma: no cover - defensive
            logger.warning("gowitness DB query failed (%s): %s", db_path, exc)
            conn.close()
            return
    conn.close()
    for row in rows:
        filename = row["filename"]
        abs_path = os.path.join(db_dir, filename)
        if not os.path.isfile(abs_path):
            continue
        rel = os.path.relpath(abs_path, output_dir)
        phash = row["perception_hash_group_id"]
        keys = row.keys()
        g_title = row["title"] if "title" in keys else None
        g_status = row["response_code"] if "response_code" in keys else None
        g_tech = row["tech"] if "tech" in keys else None
        for url in (row["url"], row["final_url"]):
            if not url:
                continue
            try:
                updated = db.set_web_screenshot(url, rel, phash_group=phash)
                if not updated:
                    # No httpx row for this URL — create an endpoint from
                    # gowitness's own metadata so the capture surfaces WITH its
                    # title/status/tech, not a blank row. httpx-fingerprinted rows
                    # keep their authoritative data (only the screenshot is
                    # attached above), so gowitness never clobbers httpx.
                    from urllib.parse import urlparse
                    host = urlparse(url).hostname or url
                    db.upsert_web_endpoint(host=host, url=url, screenshot=rel,
                                           phash_group=phash,
                                           status_code=g_status, title=g_title,
                                           tech=g_tech,
                                           source_file=os.path.basename(db_path))
                linked += 1
            except Exception as exc:  # pragma: no cover - defensive
                logger.warning("screenshot link failed for %s: %s", url, exc)
    if linked:
        logger.info("Linked %d gowitness screenshot(s) into web_endpoints", linked)


_NORM_STATE_FILE = ".normalize-state.json"


def _file_sig(paths) -> str | None:
    """Signature of a tool's input file set: sorted (basename, size, mtime_ns).
    None when there are no inputs (nothing to skip). Any append/replace changes
    size or mtime, so a grown file (e.g. --continue adds a nuclei run) re-parses."""
    items = []
    for p in sorted(paths):
        try:
            st = os.stat(p)
        except OSError:
            continue
        items.append((os.path.basename(p), st.st_size, st.st_mtime_ns))
    return json.dumps(items) if items else None


def _load_norm_state(output_dir) -> dict:
    if not output_dir:
        return {}
    try:
        with open(os.path.join(output_dir, _NORM_STATE_FILE), encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {}


def _save_norm_state(output_dir, state) -> None:
    if not output_dir:
        return
    try:
        with open(os.path.join(output_dir, _NORM_STATE_FILE), "w", encoding="utf-8") as fh:
            json.dump(state, fh)
    except OSError as e:
        logger.warning("normalize: could not persist incremental state: %s", e)


def run_normalize(prefix: str, **kwargs) -> dict:
    """Convert each tool's scan output into a per-tool JSONL results file.

    Searches for nmap XML, nuclei, subfinder, ffuf, and feroxbuster output
    files matching the given prefix and writes per-tool JSONL files:
    {prefix}-nmap-normalized.jsonl, {prefix}-nuclei-normalized.jsonl, etc.

    Args:
        prefix: Output file prefix (includes directory path)
        **kwargs: Ignored; accepted for module interface compatibility

    Returns:
        dict: Module result with output file paths and record counts
    """
    prefix = kwargs.get('data_prefix', prefix)
    print("[*] Running normalize module")
    from core.target_ledger import _url_cov_key
    url_max_per_host = kwargs.get('url_max_per_host')

    output_files: list[str] = []
    tool_counts: dict[str, int] = {}
    total_count: int = 0

    # Incremental skip: normalize runs several times in a workflow (early mint,
    # after nuclei, after bbot_dast, final), and each pass used to re-parse EVERY
    # raw file — including a multi-GB katana.txt / nuclei.jsonl — and re-mint. The
    # mints are idempotent (upsert), so re-doing unchanged work is pure waste. We
    # fingerprint each parse-heavy tool's input file set; if it is byte-identical
    # to the previous pass AND the normalized output still exists, skip the parse,
    # the rewrite, and the (already-done) mint. scan.db absence disables skipping
    # so a rebuilt DB is always re-minted.
    output_dir = os.path.dirname(os.path.dirname(prefix)) if prefix else None
    _db_present = bool(output_dir) and os.path.exists(scan_db.db_path_for(output_dir))
    _prev_state = _load_norm_state(output_dir)
    _new_state: dict = {}

    def _unchanged(tool: str, inputs: list, out_path: str) -> bool:
        """Record this tool's current input signature and report whether it (and
        its output) are unchanged since the last normalize, so the whole block
        can be skipped. Always records the signature so a skip doesn't drop it."""
        sig = _file_sig(inputs)
        _new_state[tool] = sig
        return bool(sig and _db_present and _prev_state.get(tool) == sig
                    and os.path.exists(out_path))

    # --- nmap XML ---
    nmap_records: list[dict] = []
    nmap_inputs = sorted(glob.glob(f"{prefix}*.xml"))
    nmap_out = f"{prefix}{TOOL_OUTPUT_SUFFIXES['nmap']}"
    if _unchanged("nmap", nmap_inputs, nmap_out):
        print("[*] nmap:        unchanged since last normalize — skipping")
        output_files.append(nmap_out)
    else:
        for xml_path in nmap_inputs:
            records = _parse_nmap_xml(xml_path)
            if records:
                print(f"[*] nmap:        {len(records):>5} records  {os.path.basename(xml_path)}")
                nmap_records.extend(records)
        if nmap_records:
            nmap_records = _dedup_nmap_records(nmap_records)
            if _write_tool_jsonl(nmap_out, nmap_records):
                output_files.append(nmap_out)
                tool_counts["nmap"] = len(nmap_records)
                total_count += len(nmap_records)

    # --- nuclei — prefer JSONL output, fall back to legacy text files ---
    nuclei_records: list[dict] = []
    nuclei_jsonl = sorted(glob.glob(f"{prefix}*-nuclei.jsonl"))
    nuclei_text  = sorted(glob.glob(f"{prefix}*.nuclei") + glob.glob(f"{prefix}*-nuclei.txt"))
    jsonl_stems = {os.path.splitext(p)[0].replace("-nuclei", "") for p in nuclei_jsonl}
    nuclei_text_fallback = [
        p for p in nuclei_text
        if os.path.splitext(p)[0].replace("-nuclei", "") not in jsonl_stems
    ]
    nuclei_out = f"{prefix}{TOOL_OUTPUT_SUFFIXES['nuclei']}"
    if _unchanged("nuclei", nuclei_jsonl + nuclei_text_fallback, nuclei_out):
        print("[*] nuclei:      unchanged since last normalize — skipping")
        output_files.append(nuclei_out)
    else:
        for path in nuclei_jsonl:
            records = _parse_nuclei_jsonl(path)
            if records:
                print(f"[*] nuclei:      {len(records):>5} records  {os.path.basename(path)}")
                nuclei_records.extend(records)
        for path in nuclei_text_fallback:
            records = _parse_nuclei_text(path)
            if records:
                print(f"[*] nuclei(txt): {len(records):>5} records  {os.path.basename(path)}")
                nuclei_records.extend(records)
        if nuclei_records and _write_tool_jsonl(nuclei_out, nuclei_records):
            output_files.append(nuclei_out)
            tool_counts["nuclei"] = len(nuclei_records)
            total_count += len(nuclei_records)

    # --- subfinder — prefer JSONL, fall back to plain text ---
    subfinder_records: list[dict] = []
    subfinder_jsonl = sorted(glob.glob(f"{prefix}*subfinder*.jsonl"))
    subfinder_text = sorted(glob.glob(f"{prefix}*subfinder*.txt"))
    jsonl_stems = {os.path.splitext(p)[0] for p in subfinder_jsonl}
    subfinder_text_fallback = [
        p for p in subfinder_text
        if os.path.splitext(p)[0] not in jsonl_stems
    ]
    subfinder_out = f"{prefix}{TOOL_OUTPUT_SUFFIXES['subfinder']}"
    if _unchanged("subfinder", subfinder_jsonl + subfinder_text_fallback, subfinder_out):
        print("[*] subfinder:   unchanged since last normalize — skipping")
        output_files.append(subfinder_out)
    else:
        for path in subfinder_jsonl:
            records = _parse_subfinder_jsonl(path)
            if records:
                print(f"[*] subfinder:   {len(records):>5} records  {os.path.basename(path)}")
                subfinder_records.extend(records)
        for path in subfinder_text_fallback:
            records = _parse_subfinder_file(path)
            if records:
                print(f"[*] subfinder(txt): {len(records):>5} records  {os.path.basename(path)}")
                subfinder_records.extend(records)
        if subfinder_records and _write_tool_jsonl(subfinder_out, subfinder_records):
            output_files.append(subfinder_out)
            tool_counts["subfinder"] = len(subfinder_records)
            total_count += len(subfinder_records)

    # --- ffuf — prefer JSONL, fall back to plain text ---
    ffuf_records: list[dict] = []
    ffuf_jsonl = sorted(glob.glob(f"{prefix}*-ffuf.jsonl"))
    ffuf_text = sorted(glob.glob(f"{prefix}*-ffuf.txt"))
    jsonl_stems = {os.path.splitext(p)[0] for p in ffuf_jsonl}
    ffuf_text_fallback = [
        p for p in ffuf_text
        if os.path.splitext(p)[0] not in jsonl_stems
    ]
    ffuf_out = f"{prefix}{TOOL_OUTPUT_SUFFIXES['ffuf']}"
    if _unchanged("ffuf", ffuf_jsonl + ffuf_text_fallback, ffuf_out):
        print("[*] ffuf:        unchanged since last normalize — skipping")
        output_files.append(ffuf_out)
    else:
        for path in ffuf_jsonl:
            records = _parse_ffuf_jsonl(path)
            if records:
                print(f"[*] ffuf:        {len(records):>5} records  {os.path.basename(path)}")
                ffuf_records.extend(records)
        for path in ffuf_text_fallback:
            records = _parse_dirbrute_file(path, "ffuf")
            if records:
                print(f"[*] ffuf(txt):   {len(records):>5} records  {os.path.basename(path)}")
                ffuf_records.extend(records)
        if ffuf_records and _write_tool_jsonl(ffuf_out, ffuf_records):
            output_files.append(ffuf_out)
            tool_counts["ffuf"] = len(ffuf_records)
            total_count += len(ffuf_records)

    # --- feroxbuster ---
    ferox_records: list[dict] = []
    ferox_inputs = sorted(glob.glob(f"{prefix}*-feroxbuster.txt"))
    ferox_out = f"{prefix}{TOOL_OUTPUT_SUFFIXES['feroxbuster']}"
    if _unchanged("feroxbuster", ferox_inputs, ferox_out):
        print("[*] feroxbuster: unchanged since last normalize — skipping")
        output_files.append(ferox_out)
    else:
        for path in ferox_inputs:
            records = _parse_dirbrute_file(path, "feroxbuster")
            if records:
                print(f"[*] feroxbuster: {len(records):>5} records  {os.path.basename(path)}")
                ferox_records.extend(records)
        if ferox_records and _write_tool_jsonl(ferox_out, ferox_records):
            output_files.append(ferox_out)
            tool_counts["feroxbuster"] = len(ferox_records)
            total_count += len(ferox_records)

    # --- crawlers (katana / gau): one-URL-per-line → web_dirs content ---
    # The katana file is the single biggest raw output on large scopes (multi-GB);
    # skipping its re-parse on unchanged passes is the main win here. When skipped,
    # its web_dirs are already minted, so leaving tool_recs empty is correct.
    crawl_records: list[dict] = []
    for tool, pattern in (("katana", f"{prefix}*-katana.txt"),
                          ("gau", f"{prefix}*-gau.txt")):
        tool_inputs = sorted(glob.glob(pattern))
        tool_out = f"{prefix}{TOOL_OUTPUT_SUFFIXES[tool]}"
        if _unchanged(tool, tool_inputs, tool_out):
            print(f"[*] {tool}:{' ' * (12 - len(tool))}unchanged since last normalize — skipping")
            if os.path.exists(tool_out):
                output_files.append(tool_out)
            continue
        tool_recs: list[dict] = []
        for path in tool_inputs:
            recs = _parse_crawled_urls(path, tool)
            if recs:
                print(f"[*] {tool}:{' ' * (12 - len(tool))}{len(recs):>5} records  {os.path.basename(path)}")
                tool_recs.extend(recs)
        # Opt-in per-host cap (--url-max-per-host): mirror the ledger-ingestion cap
        # so web_dirs don't balloon on a wildcard-scope crawl. Keep the first N
        # per host:port; the raw file is untouched.
        if url_max_per_host and url_max_per_host > 0 and tool_recs:
            per_host: dict = {}
            capped = []
            for r in tool_recs:
                key = _url_cov_key(r.get("url") or "") or (r.get("url") or "")
                if per_host.get(key, 0) >= url_max_per_host:
                    continue
                per_host[key] = per_host.get(key, 0) + 1
                capped.append(r)
            if len(capped) != len(tool_recs):
                print(f"[*] {tool}:{' ' * (12 - len(tool))}capped to {len(capped)} web_dir records "
                      f"(--url-max-per-host={url_max_per_host})")
            tool_recs = capped
        if tool_recs:
            if _write_tool_jsonl(tool_out, tool_recs):
                output_files.append(tool_out)
                tool_counts[tool] = len(tool_recs)
                total_count += len(tool_recs)
            crawl_records.extend(tool_recs)

    # --- bbot (all bbot_* module outputs) ---
    bbot_records: list[dict] = []
    bbot_inputs = [p for p in sorted(glob.glob(f"{prefix}*-bbot-*.jsonl"))
                   if not p.endswith("-bbot-normalized.jsonl")]
    bbot_out = f"{prefix}{TOOL_OUTPUT_SUFFIXES['bbot']}"
    if _unchanged("bbot", bbot_inputs, bbot_out):
        print("[*] bbot:        unchanged since last normalize — skipping")
        output_files.append(bbot_out)
    else:
        for path in bbot_inputs:
            records = _parse_bbot_jsonl(path)
            if records:
                print(f"[*] bbot:        {len(records):>5} records  {os.path.basename(path)}")
                bbot_records.extend(records)
        if bbot_records and _write_tool_jsonl(bbot_out, bbot_records):
            output_files.append(bbot_out)
            tool_counts["bbot"] = len(bbot_records)
            total_count += len(bbot_records)

    # --- dns_security ---
    dns_sec_records: list[dict] = []
    for path in sorted(glob.glob(f"{prefix}*-dns-security.jsonl")):
        if path.endswith("-dns-security-normalized.jsonl"):
            continue
        try:
            with open(path, encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        finding = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    severity_map = {"CRITICAL": "critical", "HIGH": "high",
                                    "MEDIUM": "medium", "LOW": "low"}
                    dns_sec_records.append({
                        "host": finding.get("domain", "unknown"),
                        "hostname": finding.get("domain"),
                        "port": None,
                        "proto": None,
                        "tool": "dns_security",
                        "type": "finding",
                        "severity": severity_map.get(finding.get("severity", ""), "info"),
                        "title": f"[{finding.get('check', '')}] {(finding.get('detail') or '')[:200]}",
                        "detail": finding.get("detail", ""),
                        "evidence": finding.get("evidence", ""),
                        "recommendation": finding.get("recommendation", ""),
                        "source_file": os.path.basename(path),
                    })
        except Exception as e:
            logger.warning("Failed to parse dns_security file %s: %s", path, e)
    if dns_sec_records:
        print(f"[*] dns_security: {len(dns_sec_records):>5} records")
        out_path = f"{prefix}{TOOL_OUTPUT_SUFFIXES['dns_security']}"
        if _write_tool_jsonl(out_path, dns_sec_records):
            output_files.append(out_path)
            tool_counts["dns_security"] = len(dns_sec_records)
            total_count += len(dns_sec_records)

    # --- testssl (plain-text report) ---
    testssl_records: list[dict] = []
    for path in sorted(glob.glob(f"{prefix}*-testssl.txt")):
        records = _parse_testssl_text(path)
        if records:
            print(f"[*] testssl:     {len(records):>5} records  {os.path.basename(path)}")
            testssl_records.extend(records)
    if testssl_records:
        out_path = f"{prefix}{TOOL_OUTPUT_SUFFIXES['testssl']}"
        if _write_tool_jsonl(out_path, testssl_records):
            output_files.append(out_path)
            tool_counts["testssl"] = len(testssl_records)
            total_count += len(testssl_records)

    # --- wafw00f (plain-text report) ---
    wafw00f_records: list[dict] = []
    for path in sorted(glob.glob(f"{prefix}*-wafw00f.txt")):
        records = _parse_wafw00f_text(path)
        if records:
            print(f"[*] wafw00f:     {len(records):>5} records  {os.path.basename(path)}")
            wafw00f_records.extend(records)
    if wafw00f_records:
        out_path = f"{prefix}{TOOL_OUTPUT_SUFFIXES['wafw00f']}"
        if _write_tool_jsonl(out_path, wafw00f_records):
            output_files.append(out_path)
            tool_counts["wafw00f"] = len(wafw00f_records)
            total_count += len(wafw00f_records)

    # --- mantra / corsy / dalfox (plain-text finding output) ---
    _TEXT_FINDING_PARSERS = {
        "mantra": (f"{prefix}*-mantra.txt", _parse_mantra_text),
        "corsy":  (f"{prefix}*-corsy.txt", _parse_corsy_text),
        "dalfox": (f"{prefix}*-dalfox.txt", _parse_dalfox_text),
    }
    text_finding_records: dict[str, list[dict]] = {}
    for tool, (pattern, parser) in _TEXT_FINDING_PARSERS.items():
        recs: list[dict] = []
        for path in sorted(glob.glob(pattern)):
            got = parser(path)
            if got:
                print(f"[*] {tool}:{' ' * (11 - len(tool))}{len(got):>5} records  {os.path.basename(path)}")
                recs.extend(got)
        if recs:
            out_path = f"{prefix}{TOOL_OUTPUT_SUFFIXES[tool]}"
            if _write_tool_jsonl(out_path, recs):
                output_files.append(out_path)
                tool_counts[tool] = len(recs)
                total_count += len(recs)
                text_finding_records[tool] = recs

    # --- shodan_enrich (JSONL findings from the enrichment module) ---
    shodan_records: list[dict] = []
    for path in sorted(glob.glob(f"{prefix}*-shodan.jsonl")):
        if path.endswith("-shodan-normalized.jsonl"):
            continue
        records = _parse_shodan_jsonl(path)
        if records:
            print(f"[*] shodan:      {len(records):>5} records  {os.path.basename(path)}")
            shodan_records.extend(records)
    if shodan_records:
        out_path = f"{prefix}-shodan-normalized.jsonl"
        if _write_tool_jsonl(out_path, shodan_records):
            output_files.append(out_path)
            tool_counts["shodan"] = len(shodan_records)
            total_count += len(shodan_records)

    # --- local finding modules that emit normalize-shaped JSONL directly ---
    passthrough_records: dict[str, list[dict]] = {}
    for tool, pattern in _PASSTHROUGH_JSONL_TOOLS.items():
        recs: list[dict] = []
        for path in sorted(glob.glob(f"{prefix}{pattern}")):
            if path.endswith(TOOL_OUTPUT_SUFFIXES[tool]):
                continue
            got = _parse_normalized_jsonl(path, tool)
            if got:
                recs.extend(got)
        if recs:
            out_path = f"{prefix}{TOOL_OUTPUT_SUFFIXES[tool]}"
            if _write_tool_jsonl(out_path, recs):
                output_files.append(out_path)
                tool_counts[tool] = len(recs)
                total_count += len(recs)
                passthrough_records[tool] = recs

    # --- mint findings into scan.db (dual-write; JSONL above is authoritative) ---
    # output_dir (output_dir/data/<name>) was resolved at the top for the
    # incremental-skip check. Skipped tools contribute empty record lists here, so
    # their (already-minted) rows are simply not re-written — the upserts are
    # idempotent, so this is correct, not lossy.
    db = scan_db.open_db(output_dir) if output_dir else None
    if db is not None:
        now = scan_db._iso_now()
        _mint_findings(nuclei_records, db, now)
        _mint_findings(bbot_records, db, now)
        _mint_findings(dns_sec_records, db, now)
        _mint_findings(nmap_records, db, now)  # only script_output rows qualify
        _mint_findings(testssl_records, db, now)
        _mint_findings(wafw00f_records, db, now)
        for _recs in text_finding_records.values():
            _mint_findings(_recs, db, now)
        _mint_findings(shodan_records, db, now)
        for _recs in passthrough_records.values():
            _mint_findings(_recs, db, now)
        _mint_web_dirs(ffuf_records + ferox_records + crawl_records, db, now)  # dir-brute + crawled
        _mint_web_endpoints(prefix, db, now)   # httpx fingerprints (raw file kept)
        _link_gowitness_screenshots(output_dir, db)  # attach screenshot paths
        # This is a secondary short-lived handle; leave WAL checkpointing to the
        # run's final ledger.close() so the two handles can't race on it.
        db.close(checkpoint=False)

    # Persist the per-tool input signatures so the next normalize can skip the
    # tools whose raw files didn't change.
    _save_norm_state(output_dir, _new_state)

    # --- summary ---
    # total_count counts only records parsed THIS pass; a fully-incremental pass
    # (every tool unchanged) legitimately parses nothing yet still has reused
    # outputs. Only warn when there is genuinely nothing — no records AND no
    # carried-forward outputs.
    if total_count == 0 and not output_files:
        print("[!] normalize: no records found — check that scan modules ran successfully")
        return {
            "module": "normalize",
            "status": "warning",
            "output_files": [],
            "record_count": 0,
            "tool_counts": {},
            "warning": "No results found matching prefix",
        }

    if total_count == 0:
        print(f"[+] normalize: all tool outputs unchanged since last pass — "
              f"{len(output_files)} file(s) reused")
    else:
        print(f"[+] normalize: {total_count} total records -> {len(output_files)} files")
        for tool_name, count in tool_counts.items():
            print(f"    {tool_name}: {count} records")

    return {
        "module": "normalize",
        "status": "success",
        "output_files": output_files,
        "record_count": total_count,
        "tool_counts": tool_counts,
    }
