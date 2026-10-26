"""smtp_security open-relay probing.

The relay test is non-destructive: it issues MAIL FROM / RCPT TO across the
classic addressing-trick vectors and reads the reply codes, but never issues
DATA. Any external RCPT accepted (250/251) without auth = open relay (critical).
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import modules.smtp_security as smtp


class _AllInScope:
    def contains(self, host):
        return True


def _patch(monkeypatch, banner_probe, relay_result):
    monkeypatch.setattr(smtp.tool_runners, "load_scope",
                        lambda target, prefix: _AllInScope())
    monkeypatch.setattr(smtp.tool_runners, "smtp_probe",
                        lambda host, port: banner_probe)
    monkeypatch.setattr(smtp.tool_runners, "smtp_relay_probe",
                        lambda host, port: relay_result)


def _ports(tmp_path):
    f = tmp_path / "open-ports.txt"
    f.write_text("198.18.10.10\t25\n")
    return str(f)


def test_open_relay_flagged_critical(tmp_path, monkeypatch):
    relay = {"local": "mail.x", "starttls_required": False, "results": [
        ("external-to-external", True, "250 OK"),
        ("null-sender", False, "550 relay denied"),
        ("percent-hack", True, "250 OK"),
    ]}
    _patch(monkeypatch, "banner: 220 mail.x\nehlo:\n  250 STARTTLS", relay)
    pfx = str(tmp_path / "scan")
    res = smtp.run_smtp_security(prefix=pfx, data_prefix=pfx,
                                 open_ports_file=_ports(tmp_path))
    recs = [json.loads(l) for l in open(f"{pfx}-smtp-security.jsonl") if l.strip()]
    relay_findings = [r for r in recs if "open_relay" in r["title"]]
    assert len(relay_findings) == 1
    f = relay_findings[0]
    # Reframed: POSSIBLE open relay, HIGH + unconfirmed (RCPT-accept != confirmed
    # relay; no DATA sent). Not a definitive CRITICAL.
    assert f["severity"] == "high"
    assert "unconfirmed" in f["title"].lower()
    assert "external-to-external" in f["detail"] and "percent-hack" in f["detail"]
    assert "null-sender" not in f["detail"]      # only accepted vectors listed
    assert "UNCONFIRMED" in f["detail"] and "DATA" in f["detail"]


def test_closed_relay_no_finding(tmp_path, monkeypatch):
    relay = {"local": "mail.x", "starttls_required": False, "results": [
        ("external-to-external", False, "554 relay denied"),
        ("null-sender", False, "550 denied"),
    ]}
    _patch(monkeypatch, "banner: 220 mail.x\nehlo:\n  250 STARTTLS", relay)
    pfx = str(tmp_path / "scan")
    smtp.run_smtp_security(prefix=pfx, data_prefix=pfx,
                           open_ports_file=_ports(tmp_path))
    recs = [json.loads(l) for l in open(f"{pfx}-smtp-security.jsonl") if l.strip()]
    assert not [r for r in recs if "open_relay" in r["title"]]


def test_skip_relay_disables_probe(tmp_path, monkeypatch):
    called = {"n": 0}
    monkeypatch.setattr(smtp.tool_runners, "load_scope",
                        lambda target, prefix: _AllInScope())
    monkeypatch.setattr(smtp.tool_runners, "smtp_probe",
                        lambda host, port: "banner: 220 mail.x\nehlo:\n  250 STARTTLS")

    def _relay(host, port):
        called["n"] += 1
        return {"results": []}
    monkeypatch.setattr(smtp.tool_runners, "smtp_relay_probe", _relay)

    pfx = str(tmp_path / "scan")
    smtp.run_smtp_security(prefix=pfx, data_prefix=pfx,
                           open_ports_file=_ports(tmp_path), skip_relay=True)
    assert called["n"] == 0


def test_smtp_probe_reads_full_multiline_ehlo():
    """Regression: smtp_probe must read the FULL multiline EHLO, not just the
    first '250-<host>' line (a single recv() truncated it -> false-positive
    starttls_missing + missed AUTH/VRFY/EXPN)."""
    import core.tool_runners as tr

    class _FakeSock:
        def __init__(self, chunks):
            self._q = list(chunks)
        def recv(self, n):
            return self._q.pop(0) if self._q else b""
        def sendall(self, data):
            pass

    sock = _FakeSock([b"250-mail.lab\r\n",
                      b"250-STARTTLS\r\n250-AUTH LOGIN PLAIN\r\n",
                      b"250-VRFY\r\n250 EXPN\r\n"])
    full = tr._smtp_read(sock)
    for cap in ("STARTTLS", "AUTH", "VRFY", "EXPN"):
        assert cap in full, f"{cap} missing from multiline read: {full!r}"


def test_starttls_present_no_false_positive():
    from modules.smtp_security import _assess
    probe = "banner: 220 x\nehlo:\n  250-mail\n  250-STARTTLS\n  250 AUTH LOGIN"
    titles = " ".join(f["title"] for f in _assess("h", 587, probe))
    assert "starttls_missing" not in titles      # STARTTLS advertised -> no FP
    assert "auth_without_tls" not in titles       # AUTH but STARTTLS present -> ok
