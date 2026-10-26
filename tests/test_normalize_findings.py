"""Stage 3: normalize mints findings into scan.db without changing JSONL output.

Guards: the finding_id normalize mints equals what scan_db.finding_id produces
from the same (host, port, proto, claim); only findings-type records become rows
(open_port / subdomain do not); the claim mapping is correct per tool; and the
JSONL normalize writes is byte-identical whether or not scan.db is present.
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules import normalize
from core import scan_db


class TestClaimFor:
    def test_nuclei_uses_template_id(self):
        rec = {"tool": "nuclei", "template_id": "CVE-2019-9874", "title": "x"}
        assert normalize._claim_for(rec) == "CVE-2019-9874"

    def test_nmap_uses_method(self):
        rec = {"tool": "nmap", "method": "http-title", "title": "x"}
        assert normalize._claim_for(rec) == "http-title"

    def test_bbot_claim_discriminates_by_module_and_title(self):
        # bbot_type alone ("FINDING") collapses every FINDING on a host onto one
        # finding_id; the claim folds in module + title so distinct events stay
        # distinct while identical ones still dedup.
        rec = {"tool": "bbot", "bbot_type": "FINDING",
               "bbot_module": "hunt", "title": "Possible SQLi in id param"}
        assert normalize._claim_for(rec) == "FINDING | hunt | Possible SQLi in id param"
        # Same host+type, different module -> different claim -> no collision.
        other = {"tool": "bbot", "bbot_type": "FINDING",
                 "bbot_module": "bypass403", "title": "403 bypass via header"}
        assert normalize._claim_for(other) != normalize._claim_for(rec)
        # Missing module/title degrade gracefully to bbot_type only.
        assert normalize._claim_for({"tool": "bbot", "bbot_type": "FINDING"}) == "FINDING"

    def test_dns_security_parses_bracket_from_title(self):
        rec = {"tool": "dns_security", "title": "[dmarc_missing] No DMARC record"}
        assert normalize._claim_for(rec) == "dmarc_missing"

    def test_missing_discriminator_is_empty(self):
        assert normalize._claim_for({"tool": "nuclei", "title": "no brackets"}) == ""


class TestMintFindings:
    def test_only_finding_types_minted(self, tmp_path):
        db = scan_db.open_db(str(tmp_path))
        records = [
            {"tool": "nuclei", "type": "nuclei_finding", "host": "h.tld",
             "port": 443, "proto": "tcp", "template_id": "cve-x", "severity": "high"},
            {"tool": "nmap", "type": "open_port", "host": "h.tld", "port": 80,
             "proto": "tcp", "method": "", "severity": "info"},  # excluded
            {"tool": "nmap", "type": "script_output", "host": "h.tld", "port": 25,
             "proto": "tcp", "method": "smtp-commands", "severity": "info"},
        ]
        normalize._mint_findings(records, db, scan_db._iso_now())
        rows = db._conn.execute("SELECT host, port, claim, tool FROM findings "
                                "ORDER BY port").fetchall()
        # open_port (80) is excluded; nuclei (443) and script_output (25) kept.
        assert [(r["port"], r["claim"]) for r in rows] == [
            (25, "smtp-commands"), (443, "cve-x")]
        db.close()

    def test_minted_id_matches_scan_db_recipe(self, tmp_path):
        db = scan_db.open_db(str(tmp_path))
        rec = {"tool": "nuclei", "type": "nuclei_finding", "host": "H.TLD.",
               "port": 443, "proto": "tcp", "template_id": "cve-x"}
        normalize._mint_findings([rec], db, scan_db._iso_now())
        expected = scan_db.finding_id("h.tld", 443, "tcp", "cve-x")
        assert db.get_finding(expected) is not None
        db.close()

    def test_none_db_is_noop(self):
        # Must not raise when scan.db is unavailable.
        normalize._mint_findings([{"tool": "nuclei", "type": "nuclei_finding",
                                   "host": "h", "template_id": "c"}], None, "t")


class TestRunNormalizeIntegration:
    def test_jsonl_byte_identical_with_and_without_db(self, tmp_path):
        # Two identical engagements; one keeps scan.db, one has it disabled.
        def run(dirname, disable_db):
            # Engine layout: output_dir/data/<name>; scan.db lives at output_dir/.
            output_dir = tmp_path / dirname / "out"
            data_dir = output_dir / "data"
            data_dir.mkdir(parents=True)
            prefix = str(data_dir / "scan")
            # Minimal nuclei JSONL input (matched-at drives host/port).
            with open(f"{prefix}-nuclei.jsonl", "w") as fh:
                fh.write(json.dumps({
                    "matched-at": "https://h.tld:443/x",
                    "template-id": "CVE-2019-9874",
                    "info": {"severity": "critical", "name": "Sitecore RCE"},
                }) + "\n")
            if disable_db:
                orig = scan_db.open_db
                scan_db.open_db = lambda *a, **k: None
                try:
                    normalize.run_normalize(prefix)
                finally:
                    scan_db.open_db = orig
            else:
                normalize.run_normalize(prefix)
            with open(f"{prefix}-nuclei-normalized.jsonl", "rb") as fh:
                return fh.read()

        with_db = run("withdb", disable_db=False)
        without_db = run("nodb", disable_db=True)
        assert with_db == without_db  # JSONL output unaffected by dual-write

        # And the DB engagement actually minted the finding.
        db = scan_db.open_db(str(tmp_path / "withdb" / "out"))
        fid = scan_db.finding_id("h.tld", 443, "tcp", "CVE-2019-9874")
        row = db.get_finding(fid)
        assert row is not None and row["severity"] == "critical"
        db.close()


class TestWidenedFindingsAndWebEndpoints:
    """Stage B: normalize mints the widened nuclei columns + httpx web_endpoints."""

    def test_nuclei_widened_columns_minted(self, tmp_path):
        db = scan_db.open_db(str(tmp_path))
        rec = {"tool": "nuclei", "type": "nuclei_finding", "host": "h.tld",
               "hostname": "h.tld", "port": 443, "proto": "tcp",
               "template_id": "CVE-2019-9874",
               "template": "cves/2019/CVE-2019-9874.yaml",
               "description": "Sitecore RCE", "cve_id": "CVE-2019-9874",
               "cwe_id": "CWE-502", "matcher_name": "status"}
        normalize._mint_findings([rec], db, scan_db._iso_now())
        fid = scan_db.finding_id("h.tld", 443, "tcp", "CVE-2019-9874")
        row = db.get_finding(fid)
        assert row["template"] == "cves/2019/CVE-2019-9874.yaml"
        assert row["description"] == "Sitecore RCE"
        assert row["cwe_id"] == "CWE-502"
        assert row["matcher_name"] == "status"
        assert row["hostname"] == "h.tld"
        db.close()

    def test_httpx_minted_to_web_endpoints(self, tmp_path):
        data = tmp_path / "data"
        data.mkdir()
        prefix = str(data / "scan")
        with open(f"{prefix}-httpx.jsonl", "w") as f:
            f.write(json.dumps({
                "url": "https://h.tld/", "host": "h.tld", "port": 443,
                "scheme": "https", "status_code": 200, "title": "Home",
                "webserver": "nginx", "tech": ["nginx", "PHP"],
                "content_type": "text/html", "cdn": True,
                "tls": {"version": "TLS1.3"},
            }) + "\n")
        db = scan_db.open_db(str(tmp_path))
        normalize._mint_web_endpoints(prefix, db, scan_db._iso_now())
        row = db._conn.execute(
            "SELECT * FROM web_endpoints WHERE url='https://h.tld/'").fetchone()
        assert row["webserver"] == "nginx" and row["status_code"] == 200
        assert json.loads(row["tech"]) == ["nginx", "PHP"]
        assert json.loads(row["tls"]) == {"version": "TLS1.3"}
        assert row["cdn"] == 1
        db.close()

    def test_web_endpoints_none_db_is_noop(self):
        normalize._mint_web_endpoints("/nonexistent/scan", None, "t")
