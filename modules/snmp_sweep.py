"""SNMP default-community sweep across discovered SNMP services (local, no fleet).

For every in-scope host with UDP/161 open, tries a small allowlist of common
READ community strings ("public", "private", "community", "manager") with a
read-only snmpwalk of the system OID. A response means the device exposes SNMP
with a guessable community — a common external finding on network gear.

Read-only: snmpwalk (GET/GETNEXT), never snmpset. Community strings come from a
fixed allowlist, not free text. Uses the shared core.tool_runners layer.

Inputs:  none required (reads the ledger open-ports file); no fleet.
Outputs: {prefix}-snmp-sweep.jsonl
"""

from __future__ import annotations

import glob
import json
import logging
import os

from core import tool_runners

logger = logging.getLogger("monkeyx.modules.snmp_sweep")

REQUIRED_INPUTS = frozenset()

# Default READ community allowlist — the common vendor/factory defaults. Order
# matters only cosmetically (we stop at the first that answers per host). The
# operator can override via monkeyx.config `modules.snmp_sweep.communities`
# (list or comma-separated string) or a wordlist file (`community_file`). Kept
# modest by default because each string is a UDP snmpwalk with its own timeout,
# so a huge list × many hosts adds real wall-clock.
_COMMUNITIES = (
    "public", "private", "community", "manager", "admin", "default",
    "cisco", "snmp", "snmpd", "read", "write", "monitor", "security",
    "router", "switch", "network", "guest", "public@es0", "all private",
)
_SNMP_PORT = 161


def _resolve_communities(kwargs) -> tuple:
    """Communities to try: operator override (list / CSV string / wordlist file),
    else the built-in defaults. Deduped, order-preserving, blanks dropped."""
    raw = kwargs.get("communities")
    values: list[str] = []
    if isinstance(raw, str):
        values = [c.strip() for c in raw.split(",")]
    elif isinstance(raw, (list, tuple)):
        values = [str(c).strip() for c in raw]

    cfile = kwargs.get("community_file")
    if cfile and os.path.isfile(cfile):
        try:
            with open(cfile, encoding="utf-8", errors="ignore") as fh:
                values.extend(l.strip() for l in fh)
        except OSError:
            pass

    if not values:
        return _COMMUNITIES
    seen, out = set(), []
    for c in values:
        if c and c not in seen:
            seen.add(c)
            out.append(c)
    return tuple(out)


def _iter_snmp_hosts(open_ports_file: str | None):
    """Yield hosts with UDP/161 recorded. The ledger port file doesn't carry
    proto per port, so we match port 161 and rely on scope + the snmpwalk
    response itself to confirm (no response = no finding)."""
    if not open_ports_file or not os.path.exists(open_ports_file):
        return
    try:
        with open(open_ports_file, encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line or "\t" not in line:
                    continue
                host, ports = line.split("\t", 1)
                if any(p.strip() == str(_SNMP_PORT) for p in ports.split(",")):
                    yield host.strip()
    except OSError:
        pass


def _iter_snmp_hosts_from_service_files(prefix: str | None):
    """Yield hosts from the UDP scan's purpose-built SNMP host lists,
    `{prefix}*-snmp-hosts.txt` (written by `nmap_to_udphosts` as `ip:port` for
    each state=open service=snmp port). This is the authoritative SNMP list —
    the ledger's per-host port export is TCP-oriented and can miss the UDP port,
    so relying on it alone made snmp_sweep skip hosts the scan clearly found."""
    if not prefix:
        return
    for path in glob.glob(f"{prefix}*-snmp-hosts.txt"):
        try:
            with open(path, encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    host = line.rsplit(":", 1)[0].strip()  # ip:port -> ip (IPv6-safe)
                    if host:
                        yield host
        except OSError:
            continue


def _looks_like_response(output: str) -> bool:
    if not output:
        return False
    low = output.lower()
    if low.startswith(("error", "timeout")):
        return False
    if "no response" in low or "timeout" in low:
        return False
    # A successful walk returns SNMP varbinds, typically starting "iso" or "SNMPv2".
    return ("iso." in output or "snmpv2" in low or "::" in output)


def run_snmp_sweep(prefix=None, target=None, **kwargs) -> dict:
    prefix = kwargs.get("data_prefix", prefix)
    # SNMP is UDP/161. The default open-ports file is TCP-only, so read the UDP
    # variant the orchestrator regenerates; fall back to open_ports_file only for
    # standalone invocations that don't provide it.
    open_ports_file = kwargs.get("udp_open_ports_file") or kwargs.get("open_ports_file")
    scope = tool_runners.load_scope(target, prefix)

    if not tool_runners.tool_available("snmpwalk"):
        msg = "snmp_sweep: snmpwalk not installed"
        print(f"[!] {msg}")
        return {"module": "snmp_sweep", "status": "skipped",
                "output_files": [], "warning": msg}

    candidates = set(_iter_snmp_hosts(open_ports_file))
    candidates.update(_iter_snmp_hosts_from_service_files(prefix))
    hosts = [h for h in sorted(candidates) if scope.contains(h)]
    if not hosts:
        msg = "snmp_sweep: no in-scope SNMP (port 161) hosts found"
        print(f"[*] {msg}")
        return {"module": "snmp_sweep", "status": "skipped",
                "output_files": [], "warning": msg}

    communities = _resolve_communities(kwargs)
    records: list[dict] = []
    for host in hosts:
        for community in communities:
            output = tool_runners.snmp_walk(host, community=community)
            if not _looks_like_response(output):
                continue
            sev = "high" if community == "private" else "medium"
            sysdescr = next((l.strip() for l in output.splitlines()
                             if l.strip()), "")[:300]
            records.append({
                "host": host, "hostname": None, "port": _SNMP_PORT, "proto": "udp",
                "tool": "snmp_sweep", "type": "finding", "severity": sev,
                "title": f"[snmp_default_community] '{community}' accepted on {host}",
                "detail": f"SNMP responded to community '{community}'. sysDescr: {sysdescr}",
                "evidence": output[:1000], "source_file": "snmp-sweep",
            })
            print(f"[+] snmp_sweep: {host} responds to community '{community}'")
            break  # one finding per host is enough to flag it

    out = f"{prefix}-snmp-sweep.jsonl"
    try:
        with open(out, "w", encoding="utf-8") as fh:
            for r in records:
                fh.write(json.dumps(r) + "\n")
    except OSError as e:
        return {"module": "snmp_sweep", "status": "failed",
                "output_files": [], "error": str(e)}

    print(f"[+] snmp_sweep: {len(records)} finding(s) across {len(hosts)} host(s)")
    return {"module": "snmp_sweep", "status": "success",
            "output_files": [out], "findings": len(records)}
