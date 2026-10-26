"""SMTP transport-security posture across discovered mail services (local, no fleet).

Extends dns_security (which only reads SPF/DMARC *records*) into the live mail
server: for each in-scope host with an SMTP port open, grabs the banner + EHLO
capability list and flags:
  * STARTTLS not offered on a submission/relay port (cleartext auth risk)
  * VRFY / EXPN advertised (user-enumeration exposure)
  * AUTH offered without STARTTLS in the same session (credential exposure)
  * POSSIBLE OPEN RELAY — the server accepts an external recipient without auth,
    tested across the classic addressing-trick vectors (see
    tool_runners.smtp_relay_probe). Reported HIGH + UNCONFIRMED: RCPT acceptance
    doesn't prove onward relay (no DATA sent; could be a catch-all sink), so it's
    flagged for manual verification, not asserted as a confirmed open relay.

The relay test is NON-DESTRUCTIVE: it issues MAIL FROM / RCPT TO and reads the
reply codes, but never issues DATA, so no message is relayed/delivered. It runs
on 25/587 by default; disable with modules.smtp_security.skip_relay: true. It
still does NOT attempt VRFY user-enumeration (that stays in ai_validate's
intrusive tier). Uses core.tool_runners.

Inputs:  none required (reads the ledger open-ports file); no fleet.
Outputs: {prefix}-smtp-security.jsonl
"""

from __future__ import annotations

import json
import logging
import os

from core import tool_runners

logger = logging.getLogger("monkeyx.modules.smtp_security")

REQUIRED_INPUTS = frozenset()

_SMTP_PORTS = (25, 465, 587)


def _iter_smtp_endpoints(open_ports_file: str | None):
    if not open_ports_file or not os.path.exists(open_ports_file):
        return
    try:
        with open(open_ports_file, encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line or "\t" not in line:
                    continue
                host, ports = line.split("\t", 1)
                open_ = {p.strip() for p in ports.split(",")}
                for port in _SMTP_PORTS:
                    if str(port) in open_:
                        yield host.strip(), port
    except OSError:
        pass


def _assess(host: str, port: int, probe: str) -> list[dict]:
    """Turn an EHLO probe into read-only findings."""
    if probe.startswith(("ERROR", "TIMEOUT")):
        return []
    low = probe.lower()
    findings: list[dict] = []

    def _mk(claim, sev, detail):
        return {
            "host": host, "hostname": None, "port": port, "proto": "tcp",
            "tool": "smtp_security", "type": "finding", "severity": sev,
            "title": f"[{claim}] {detail[:180]}", "detail": detail,
            "evidence": probe[:1000], "source_file": "smtp-security",
        }

    has_starttls = "starttls" in low
    advertises_auth = "auth " in low or "auth=" in low
    # Submission/relay ports should offer STARTTLS.
    if not has_starttls and port in (25, 587):
        findings.append(_mk(
            "starttls_missing", "medium",
            f"SMTP on {host}:{port} does not advertise STARTTLS (cleartext session)."))
    if advertises_auth and not has_starttls:
        findings.append(_mk(
            "auth_without_tls", "high",
            f"SMTP on {host}:{port} offers AUTH without STARTTLS — credentials in cleartext."))
    if "vrfy" in low:
        findings.append(_mk(
            "vrfy_enabled", "low",
            f"SMTP on {host}:{port} advertises VRFY (user-enumeration exposure)."))
    if "expn" in low:
        findings.append(_mk(
            "expn_enabled", "low",
            f"SMTP on {host}:{port} advertises EXPN (mailing-list enumeration)."))
    return findings


def _assess_relay(host: str, port: int, probe: dict) -> list[dict]:
    """Flag when the server accepts an EXTERNAL recipient without auth.

    This is a POSSIBLE open relay, reported HIGH + explicitly UNCONFIRMED — not a
    definitive CRITICAL. RCPT-TO acceptance alone does not prove onward relay: the
    probe stops at RCPT and never issues DATA, and many servers accept-and-discard
    (a catch-all/sink) or reject at DATA. Overclaiming a confirmed open relay from
    RCPT-accept is a false positive in a client report, so we surface it for
    manual verification instead. If EVERY tested vector is accepted, that more
    often indicates a catch-all sink than a true relay — noted in the detail.
    """
    if not isinstance(probe, dict) or probe.get("error"):
        return []
    results = probe.get("results") or []
    accepted = [name for name, ok, _resp in results if ok]
    if not accepted:
        return []
    all_accepted = len(accepted) == len(results) and len(results) > 1
    detail = (
        f"SMTP on {host}:{port} accepted an off-server (external) recipient "
        f"without authentication via: {', '.join(accepted)}. POSSIBLE open relay "
        f"— UNCONFIRMED: the probe stops at RCPT TO and never issues DATA, so "
        f"onward delivery is not proven; the server may accept-and-discard "
        f"(catch-all/sink) or reject at DATA."
        + (" It accepted EVERY tested vector, which more often indicates a "
           "catch-all sink than a true relay." if all_accepted else "")
        + " Verify manually before reporting as an open relay."
    )
    evidence = "; ".join(f"{name}: {resp}" for name, ok, resp in results if ok)
    return [{
        "host": host, "hostname": None, "port": port, "proto": "tcp",
        "tool": "smtp_security", "type": "finding", "severity": "high",
        "title": (f"[smtp_open_relay_suspected] {host}:{port} accepts external "
                  f"RCPT without auth (unconfirmed — DATA not sent)"),
        "detail": detail, "evidence": evidence[:1000], "source_file": "smtp-security",
    }]


_RELAY_PORTS = (25, 587)   # plaintext/submission; 465 is implicit-TLS, skipped


def run_smtp_security(prefix=None, target=None, **kwargs) -> dict:
    prefix = kwargs.get("data_prefix", prefix)
    open_ports_file = kwargs.get("open_ports_file")
    # Open-relay probing issues MAIL FROM/RCPT TO (no DATA — non-destructive).
    # On by default; set modules.smtp_security.skip_relay: true to disable.
    skip_relay = kwargs.get("skip_relay", False)
    scope = tool_runners.load_scope(target, prefix)

    endpoints = [(h, p) for h, p in _iter_smtp_endpoints(open_ports_file)
                 if scope.contains(h)]
    if not endpoints:
        msg = "smtp_security: no in-scope SMTP endpoints (25/465/587) found"
        print(f"[*] {msg}")
        return {"module": "smtp_security", "status": "skipped",
                "output_files": [], "warning": msg}

    records: list[dict] = []
    for host, port in endpoints:
        print(f"[*] smtp_security: probing {host}:{port}")
        probe = tool_runners.smtp_probe(host, port)
        records.extend(_assess(host, port, probe))
        if not skip_relay and port in _RELAY_PORTS:
            relay = tool_runners.smtp_relay_probe(host, port)
            records.extend(_assess_relay(host, port, relay))

    out = f"{prefix}-smtp-security.jsonl"
    try:
        with open(out, "w", encoding="utf-8") as fh:
            for r in records:
                fh.write(json.dumps(r) + "\n")
    except OSError as e:
        return {"module": "smtp_security", "status": "failed",
                "output_files": [], "error": str(e)}

    print(f"[+] smtp_security: {len(records)} finding(s) across {len(endpoints)} endpoint(s)")
    return {"module": "smtp_security", "status": "success",
            "output_files": [out], "findings": len(records)}
