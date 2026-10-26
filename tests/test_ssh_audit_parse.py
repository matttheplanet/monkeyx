"""ssh_audit_scan output parsing.

The module is scoped to what nuclei's default ssh-* templates do NOT turn into
findings:
  1. Password authentication enabled (from an auth-methods probe that tries no
     credentials).
  2. CVEs affecting the detected OpenSSH (ssh-audit's `(cve)` section — Terrapin
     + version-mapped).
The weak-KEX/MAC/CBC/SHA-1 algorithm lines ssh-audit prints are intentionally
NOT emitted (nuclei covers them), so `[fail]`/`[warn]` lines produce no findings.
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import core.tool_runners as tool_runners
import modules.ssh_audit_scan as ssh_audit_scan


# ssh-audit output: weak-algo lines (ignored now) + a (cve) section (kept).
_SSH_AUDIT_OUTPUT = """\
(gen) banner: SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.19
(gen) software: OpenSSH 9.6p1
(kex) diffie-hellman-group14-sha1 -- [fail] using broken SHA-1 hash algorithm
(mac) hmac-sha1 -- [warn] using weak hashing algorithm
(cve) CVE-2023-48795 -- (CVSSv2: 5.9) allows prefix truncation attacks (Terrapin)
(cve) CVE-2023-51385 -- (CVSSv2: 6.5) command injection if ProxyCommand uses %h/%p
"""


class _AllInScope:
    def contains(self, host):
        return True


def _patch(monkeypatch, audit_output="", auth_methods=None):
    monkeypatch.setattr(tool_runners, "tool_available", lambda name: True)
    monkeypatch.setattr(tool_runners, "load_scope",
                        lambda target, prefix: _AllInScope())
    monkeypatch.setattr(tool_runners, "ssh_audit", lambda host, port: audit_output)
    monkeypatch.setattr(tool_runners, "ssh_auth_methods",
                        lambda host, port: list(auth_methods or []))


def _write_ports(tmp_path):
    f = tmp_path / "open-ports.txt"
    f.write_text("198.18.10.10\t22,80\n")
    return str(f)


def _run(tmp_path):
    prefix = str(tmp_path / "run")
    ssh_audit_scan.run_ssh_audit_scan(
        prefix=prefix, data_prefix=prefix, target=None,
        open_ports_file=_write_ports(tmp_path))
    return [json.loads(ln) for ln in open(f"{prefix}-ssh-audit.jsonl") if ln.strip()]


def test_cve_lines_parsed_weak_algo_ignored(tmp_path, monkeypatch):
    _patch(monkeypatch, _SSH_AUDIT_OUTPUT, auth_methods=["publickey"])
    recs = _run(tmp_path)
    # Two CVEs kept; the [fail]/[warn] algorithm lines produce nothing.
    cves = [r for r in recs if "ssh_cve" in r["title"]]
    assert len(cves) == 2
    assert not [r for r in recs if "[fail]" in r["title"] or "[warn]" in r["title"]]
    terrapin = next(r for r in cves if "CVE-2023-48795" in r["title"])
    assert terrapin["severity"] == "medium"          # CVSS 5.9 -> medium
    assert "Terrapin" in terrapin["title"]


def test_cvss_severity_mapping(tmp_path, monkeypatch):
    out = ("(cve) CVE-9999-0001 -- (CVSSv2: 9.8) rce\n"
           "(cve) CVE-9999-0002 -- (CVSSv2: 7.5) high thing\n"
           "(cve) CVE-9999-0003 -- (CVSSv2: 3.1) low thing\n"
           "(cve) CVE-9999-0004 -- unrated thing\n")
    _patch(monkeypatch, out, auth_methods=["publickey"])
    sev = {r["title"].split()[1].rstrip(":").split("(")[0]: r["severity"]
           for r in _run(tmp_path) if "ssh_cve" in r["title"]}
    assert sev["CVE-9999-0001"] == "critical"
    assert sev["CVE-9999-0002"] == "high"
    assert sev["CVE-9999-0003"] == "low"
    assert sev["CVE-9999-0004"] == "medium"          # no CVSS -> medium default


def test_password_auth_flagged(tmp_path, monkeypatch):
    _patch(monkeypatch, "", auth_methods=["publickey", "password"])
    recs = _run(tmp_path)
    pw = [r for r in recs if "ssh_password_auth" in r["title"]]
    assert len(pw) == 1 and pw[0]["severity"] == "medium"
    assert "password" in pw[0]["detail"]


def test_keyboard_interactive_flagged(tmp_path, monkeypatch):
    _patch(monkeypatch, "", auth_methods=["publickey", "keyboard-interactive"])
    assert [r for r in _run(tmp_path) if "ssh_password_auth" in r["title"]]


def test_publickey_only_no_password_finding(tmp_path, monkeypatch):
    _patch(monkeypatch, "", auth_methods=["publickey"])
    assert not [r for r in _run(tmp_path) if "ssh_password_auth" in r["title"]]


def test_ansi_stripped_from_cve_title(tmp_path, monkeypatch):
    out = ("\x1b[0;31m(cve) CVE-2023-48795 -- (CVSSv2: 5.9) Terrapin\x1b[0m\n")
    _patch(monkeypatch, out, auth_methods=[])
    recs = _run(tmp_path)
    assert recs and "\x1b" not in recs[0]["title"] and "CVE-2023-48795" in recs[0]["title"]


# --- Coverage-honesty records: distinguish "couldn't audit" from "clean". ---

_CLEAN_OUTPUT = """\
(gen) banner: SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.19
(gen) software: OpenSSH 9.6p1
(key) ssh-ed25519 -- [info] available since OpenSSH 6.5
"""


def _run_full(tmp_path):
    prefix = str(tmp_path / "run")
    res = ssh_audit_scan.run_ssh_audit_scan(
        prefix=prefix, data_prefix=prefix, target=None,
        open_ports_file=_write_ports(tmp_path))
    recs = [json.loads(ln) for ln in open(f"{prefix}-ssh-audit.jsonl") if ln.strip()]
    return res, recs


def test_incomplete_when_audit_errors(tmp_path, monkeypatch):
    _patch(monkeypatch, "ERROR: tool not found: ssh-audit", auth_methods=["publickey"])
    res, recs = _run_full(tmp_path)
    inc = [r for r in recs if "ssh_audit_incomplete" in r["title"]]
    # A coverage gap ("couldn't check") is info, not a low-severity vuln.
    assert len(inc) == 1 and inc[0]["severity"] == "info"
    assert "COVERAGE GAP" in inc[0]["detail"]
    assert not [r for r in recs if "ssh_audit_ok" in r["title"]]   # not "clean"
    assert res["status"] == "warning" and "could not complete" in res["warning"]


def test_incomplete_when_empty_output(tmp_path, monkeypatch):
    _patch(monkeypatch, "", auth_methods=["publickey"])
    _, recs = _run_full(tmp_path)
    assert [r for r in recs if "ssh_audit_incomplete" in r["title"]]


def test_ok_record_when_audited_clean(tmp_path, monkeypatch):
    _patch(monkeypatch, _CLEAN_OUTPUT, auth_methods=["publickey"])
    res, recs = _run_full(tmp_path)
    ok = [r for r in recs if "ssh_audit_ok" in r["title"]]
    assert len(ok) == 1 and ok[0]["severity"] == "info"
    assert "OpenSSH 9.6p1" in ok[0]["detail"] or "SSH-2.0-OpenSSH" in ok[0]["detail"]
    assert not [r for r in recs if "ssh_audit_incomplete" in r["title"]]
    assert res["status"] == "success"          # reached + clean != warning


def test_no_ok_record_when_cve_found(tmp_path, monkeypatch):
    _patch(monkeypatch, _SSH_AUDIT_OUTPUT, auth_methods=["publickey"])
    _, recs = _run_full(tmp_path)
    assert not [r for r in recs if "ssh_audit_ok" in r["title"]]   # CVEs, not clean


def test_no_ok_record_when_password_auth(tmp_path, monkeypatch):
    # Completed audit, no CVE, but password auth present -> that's the finding,
    # not a clean "ok".
    _patch(monkeypatch, _CLEAN_OUTPUT, auth_methods=["publickey", "password"])
    _, recs = _run_full(tmp_path)
    assert not [r for r in recs if "ssh_audit_ok" in r["title"]]
    assert [r for r in recs if "ssh_password_auth" in r["title"]]


def test_audit_completed_detection():
    assert ssh_audit_scan._audit_completed(_CLEAN_OUTPUT)
    assert ssh_audit_scan._audit_completed("\x1b[0;36m(kex) foo\x1b[0m")
    assert not ssh_audit_scan._audit_completed("")
    assert not ssh_audit_scan._audit_completed("ERROR: connection refused")
    assert not ssh_audit_scan._audit_completed("TIMEOUT: exceeded 45s")
    assert not ssh_audit_scan._audit_completed("some banner with no markers")
