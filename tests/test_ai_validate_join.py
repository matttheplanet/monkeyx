"""Stage 4: ai_validate's exact finding_id join back to normalize-minted rows.

The join must be deterministic: recompute finding_id from the same raw evidence
record normalize used, keyed on the [template-id]/CVE token the recommendation
carries. Two findings on one host:port with different claims must resolve to
DIFFERENT ids (the whole point); a genuinely ambiguous case resolves to none.
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules import ai_validate as aiv
from modules import normalize
from core import scan_db


class TestClaimTokens:
    def test_bracket_and_cve_tokens(self):
        f = {"action": "Exploit [phpmyadmin-panel]",
             "evidence": "Nuclei template [CVE-2019-9874] matched",
             "commands": ["curl -sk https://h/x"]}
        toks = aiv._finding_claim_tokens(f)
        assert "phpmyadmin-panel" in toks
        assert "cve-2019-9874" in toks

    def test_tokens_from_commands_list(self):
        f = {"commands": ["nuclei -t cves/2019/CVE-2019-9874.yaml -u https://h"]}
        assert "cve-2019-9874" in aiv._finding_claim_tokens(f)

    def test_no_tokens(self):
        assert aiv._finding_claim_tokens({"action": "poke the thing"}) == set()


class TestMatchFindingIds:
    def _index(self, recs):
        idx = {}
        for r in recs:
            idx.setdefault((r.get("host") or "").lower().rstrip("."), []).append(r)
        return idx

    def test_token_selects_exact_record_among_many(self):
        # Two findings on the SAME host:port, different templates.
        recs = [
            {"host": "h.tld", "port": 443, "proto": "tcp", "tool": "nuclei",
             "type": "nuclei_finding", "template_id": "phpmyadmin-panel"},
            {"host": "h.tld", "port": 443, "proto": "tcp", "tool": "nuclei",
             "type": "nuclei_finding", "template_id": "wordpress-login"},
        ]
        idx = self._index(recs)
        finding = {"target": "h.tld:443", "action": "test [phpmyadmin-panel]"}
        ids = aiv._match_finding_ids(finding, idx)
        assert ids == [scan_db.finding_id("h.tld", 443, "tcp", "phpmyadmin-panel")]
        # And it is NOT the other template's id.
        assert scan_db.finding_id("h.tld", 443, "tcp", "wordpress-login") not in ids

    def test_cve_token_matches_cve_id_field(self):
        recs = [{"host": "h.tld", "port": 443, "proto": "tcp", "tool": "nuclei",
                 "type": "nuclei_finding", "template_id": "sitecore-rce",
                 "cve_id": "CVE-2019-9874"}]
        finding = {"target": "https://h.tld:443/x",
                   "evidence": "matched CVE-2019-9874"}
        ids = aiv._match_finding_ids(finding, self._index(recs))
        assert ids == [scan_db.finding_id("h.tld", 443, "tcp", "sitecore-rce")]

    def test_single_record_no_token_still_joins(self):
        recs = [{"host": "h.tld", "port": 21, "proto": "tcp", "tool": "nmap",
                 "type": "script_output", "method": "ftp-anon"}]
        finding = {"target": "h.tld:21", "action": "check anonymous ftp"}
        ids = aiv._match_finding_ids(finding, self._index(recs))
        assert ids == [scan_db.finding_id("h.tld", 21, "tcp", "ftp-anon")]

    def test_ambiguous_multi_record_no_token_returns_none(self):
        recs = [
            {"host": "h.tld", "port": 443, "proto": "tcp", "tool": "nuclei",
             "type": "nuclei_finding", "template_id": "a"},
            {"host": "h.tld", "port": 443, "proto": "tcp", "tool": "nuclei",
             "type": "nuclei_finding", "template_id": "b"},
        ]
        finding = {"target": "h.tld:443", "action": "no claim token here"}
        assert aiv._match_finding_ids(finding, self._index(recs)) == []

    def test_open_port_records_are_not_join_candidates(self):
        # Only findings-type records are joinable; a lone open_port isn't.
        recs = [{"host": "h.tld", "port": 443, "proto": "tcp", "tool": "nmap",
                 "type": "open_port", "method": ""}]
        finding = {"target": "h.tld:443", "action": "x"}
        assert aiv._match_finding_ids(finding, self._index(recs)) == []

    def test_unknown_host_returns_none(self):
        assert aiv._match_finding_ids({"target": "nope.tld:1"}, {}) == []


class TestVerdictWriteParity:
    """normalize mints -> ai_validate join recomputes the SAME id and sets verdict."""

    def test_verdict_lands_on_the_normalize_minted_row(self, tmp_path):
        db = scan_db.open_db(str(tmp_path))
        rec = {"host": "h.tld", "port": 443, "proto": "tcp", "tool": "nuclei",
               "type": "nuclei_finding", "template_id": "CVE-2019-9874",
               "severity": "critical", "cve_id": "CVE-2019-9874"}
        normalize._mint_findings([rec], db, scan_db._iso_now())

        # ai_validate recomputes the id from the same raw record.
        idx = {"h.tld": [rec]}
        finding = {"target": "https://h.tld:443/x",
                   "evidence": "Nuclei [CVE-2019-9874] confirmed"}
        ids = aiv._match_finding_ids(finding, idx)
        assert len(ids) == 1
        # It's exactly the row normalize created.
        assert db.get_finding(ids[0]) is not None

        db.set_verdict(ids[0], "confirmed")
        assert db.get_finding(ids[0])["verdict"] == "confirmed"
        db.close()
