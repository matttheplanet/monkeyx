"""SSH audit across discovered SSH services (local, no fleet).

Scoped deliberately to the two things nuclei's default ssh-* templates do NOT
turn into actionable findings:

  1. Password authentication enabled — queries the server's permitted auth
     methods WITHOUT trying any credentials (PreferredAuthentications=none) and
     flags the host if `password`/`keyboard-interactive` is accepted. nuclei's
     ssh-auth-methods only *lists* methods as info; this is the finding.
  2. CVEs affecting the detected OpenSSH — parsed from ssh-audit's `(cve)`
     section, which includes Terrapin (CVE-2023-48795) and version-mapped CVEs.

The weak-KEX/MAC/CBC/SHA-1 algorithm lines that ssh-audit also prints are NOT
emitted here — nuclei's ssh-weak-*/ssh-cbc-*/ssh-sha1-*/logjam templates already
cover them, so re-minting them was pure duplication.

Coverage honesty: an ssh-audit that never completed (connection refused/timeout,
not an SSH service, tool missing) produces no CVE lines — on disk that looks
identical to a genuinely clean audit. So each host also gets a status record:
`ssh_audit_incomplete` (info) when the audit couldn't run — an explicit coverage
gap, never a silent empty — or `ssh_audit_ok` (info) when it completed with
nothing actionable, which both confirms the host was assessed and keeps output
non-empty so the engine's generic "produced no output" warning doesn't misfire.

Uses the shared, non-AI tool-runner layer (core.tool_runners) — scope-safe,
read-only (no credentials attempted).

Inputs:  none required (reads the ledger open-ports file); no fleet.
Outputs: {prefix}-ssh-audit.jsonl
"""

from __future__ import annotations

import json
import logging
import os
import re

from core import tool_runners

# ssh-audit colourizes its output (ANSI SGR escapes) and pads columns for
# terminal alignment. Strip the escapes and collapse the padding so a finding
# title/detail is readable text, not "^[[0;33m(kex) ...        -- [warn] ...^[[0m".
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
_WS_RE = re.compile(r"\s+")


def _clean_line(raw: str) -> str:
    return _WS_RE.sub(" ", _ANSI_RE.sub("", raw)).strip()

logger = logging.getLogger("monkeyx.modules.ssh_audit_scan")

REQUIRED_INPUTS = frozenset()

# ssh-audit prints CVEs affecting the detected version in a `(cve)` section, e.g.
#   (cve) CVE-2023-48795 -- (CVSSv2: 5.9) allows prefix truncation ... (Terrapin)
_CVE_LINE_RE = re.compile(
    r"\(cve\)\s+(CVE-\d{4}-\d+)\s*--\s*(?:\(CVSSv?\d?:?\s*([\d.]+)\))?\s*(.*)",
    re.IGNORECASE)
# Auth methods that mean interactive password login is possible.
_PASSWORD_METHODS = ("password", "keyboard-interactive")

# Section markers ssh-audit prints when it actually completed a handshake and
# audited the server. If NONE appear, the tool never got a usable result
# (connection refused/timed out, not-an-SSH-service, tool error) — which is a
# COVERAGE GAP, not a clean "no findings". We must not let the two look alike.
_AUDIT_OK_MARKERS = ("(gen)", "(kex)", "(key)", "(enc)", "(mac)", "(fin)",
                     "(cve)", "banner:")


def _audit_completed(output: str) -> bool:
    """True if ssh-audit returned a real audit (vs. an error/timeout/empty)."""
    if not output or output.startswith(("ERROR", "TIMEOUT")):
        return False
    clean = _ANSI_RE.sub("", output)
    return any(marker in clean for marker in _AUDIT_OK_MARKERS)


def _audit_banner(output: str) -> str:
    """Pull the SSH banner/software line from ssh-audit output, if present."""
    for raw in output.splitlines():
        text = _clean_line(raw)
        low = text.lower()
        if "banner:" in low or "software:" in low:
            frag = text.split(":", 1)[-1].strip() if ":" in text else text
            return f" ({frag})" if frag else ""
    return ""


def _failure_reason(output: str) -> str:
    """One-line reason an audit didn't complete, for the coverage-gap record."""
    if not output or output == "(no output)":
        return "no output"
    first = _clean_line(output.splitlines()[0]) if output.splitlines() else output
    return first[:160]


def _cvss_to_severity(cvss: float | None) -> str:
    if cvss is None:
        return "medium"
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    return "low"


def _iter_ssh_endpoints(open_ports_file: str | None):
    """Yield (host, port) for hosts with an SSH port from the ledger port file.

    ledger-open-ports.txt format: 'host\\tport1,port2,...'. We can't see service
    names there, so we treat port 22 as SSH; other SSH ports are picked up when
    present in the list AND validated in scope by the caller.
    """
    if not open_ports_file or not os.path.exists(open_ports_file):
        return
    try:
        with open(open_ports_file, encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line or "\t" not in line:
                    continue
                host, ports = line.split("\t", 1)
                for p in ports.split(","):
                    p = p.strip()
                    if p == "22":
                        yield host.strip(), 22
    except OSError:
        pass


def run_ssh_audit_scan(prefix=None, target=None, **kwargs) -> dict:
    prefix = kwargs.get("data_prefix", prefix)
    open_ports_file = kwargs.get("open_ports_file")
    scope = tool_runners.load_scope(target, prefix)

    if not tool_runners.tool_available("ssh-audit"):
        msg = "ssh_audit_scan: ssh-audit not installed"
        print(f"[!] {msg}")
        return {"module": "ssh_audit_scan", "status": "skipped",
                "output_files": [], "warning": msg}

    endpoints = [(h, p) for h, p in _iter_ssh_endpoints(open_ports_file)
                 if scope.contains(h)]
    if not endpoints:
        msg = "ssh_audit_scan: no in-scope SSH (port 22) endpoints found"
        print(f"[*] {msg}")
        return {"module": "ssh_audit_scan", "status": "skipped",
                "output_files": [], "warning": msg}

    def _rec(host, port, sev, title, detail):
        return {
            "host": host, "hostname": None, "port": port, "proto": "tcp",
            "tool": "ssh_audit", "type": "finding", "severity": sev,
            "title": title[:200], "detail": detail[:2000],
            "source_file": "ssh-audit",
        }

    records: list[dict] = []
    audit_failed: list[str] = []   # hosts ssh-audit could not complete against
    for host, port in endpoints:
        print(f"[*] ssh_audit_scan: auditing {host}:{port}")

        # (1) Password authentication enabled — no credentials attempted.
        methods = tool_runners.ssh_auth_methods(host, port)
        pw = [m for m in methods if m in _PASSWORD_METHODS]
        if pw:
            records.append(_rec(
                host, port, "medium",
                f"[ssh_password_auth] Password authentication enabled on {host}:{port}",
                f"SSH on {host}:{port} permits interactive password login "
                f"(methods offered: {', '.join(methods)}) — exposed to "
                f"brute-force / credential-stuffing. Prefer publickey-only "
                f"(PasswordAuthentication no; KbdInteractiveAuthentication no)."))

        # (2) CVEs affecting the detected OpenSSH (Terrapin + version-mapped),
        # from ssh-audit's `(cve)` section. Weak-algorithm lines are intentionally
        # NOT emitted (nuclei's ssh-* templates already cover them).
        output = tool_runners.ssh_audit(host, port)

        # Coverage honesty: an ssh-audit that never completed (refused/timeout/
        # not-SSH/tool-missing) yields no CVE lines — identical on disk to a
        # genuinely clean audit. Emit an explicit gap record so "we couldn't
        # check" is never silently read as "we checked and it's clean".
        if not _audit_completed(output):
            audit_failed.append(f"{host}:{port}")
            records.append(_rec(
                host, port, "info",
                f"[ssh_audit_incomplete] Could not complete SSH audit of {host}:{port}",
                f"ssh-audit did not return a usable result for {host}:{port} "
                f"({_failure_reason(output)}). This is a COVERAGE GAP, not a clean "
                f"result — the server's SSH algorithms and version-mapped CVEs "
                f"(including Terrapin) were NOT assessed. Verify connectivity from "
                f"the scanner and re-run."))
            continue

        cve_found = False
        for raw in output.splitlines():
            text = _clean_line(raw)
            m = _CVE_LINE_RE.search(text)
            if not m:
                continue
            cve_found = True
            cve, cvss_s, desc = m.group(1), m.group(2), m.group(3).strip()
            try:
                cvss = float(cvss_s) if cvss_s else None
            except ValueError:
                cvss = None
            sev = _cvss_to_severity(cvss)
            cvss_note = f" (CVSS {cvss})" if cvss is not None else ""
            records.append(_rec(
                host, port, sev,
                f"[ssh_cve] {cve}{cvss_note}: {desc}",
                f"{host}:{port} OpenSSH is affected by {cve}{cvss_note}. {desc}"))

        # Positive coverage confirmation: audit completed but nothing actionable.
        # Writing this (a) tells the reader we DID assess this host, and (b) keeps
        # the output non-empty so the engine's generic "produced no output" warning
        # (which reads as "may not have reached the target") doesn't misfire.
        if not cve_found and not pw:
            records.append(_rec(
                host, port, "info",
                f"[ssh_audit_ok] {host}:{port} audited — no password-auth or known-CVE findings",
                f"ssh-audit completed against {host}:{port}{_audit_banner(output)}. "
                f"Interactive password auth is not offered and no version-mapped "
                f"CVEs (including Terrapin) were reported. Weak-algorithm details, "
                f"if any, are covered by nuclei's ssh-* templates."))

    out = f"{prefix}-ssh-audit.jsonl"
    try:
        with open(out, "w", encoding="utf-8") as fh:
            for r in records:
                fh.write(json.dumps(r) + "\n")
    except OSError as e:
        return {"module": "ssh_audit_scan", "status": "failed",
                "output_files": [], "error": str(e)}

    print(f"[+] ssh_audit_scan: {len(records)} finding(s) across {len(endpoints)} host(s)")
    result = {"module": "ssh_audit_scan", "status": "success",
              "output_files": [out], "findings": len(records)}
    # Surface a specific, actionable warning when some hosts couldn't be audited
    # — clearer than the engine's generic empty-output downgrade, and it still
    # fires even though we wrote records (so the generic check stays quiet).
    if audit_failed:
        result["status"] = "warning"
        result["warning"] = (
            f"ssh_audit_scan: could not complete SSH audit on "
            f"{len(audit_failed)} host(s): {', '.join(audit_failed)}. Assessed "
            f"{len(endpoints) - len(audit_failed)}/{len(endpoints)}.")
        print(f"[!] {result['warning']}")
    return result
