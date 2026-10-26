"""Tests for modules/focus.py — the prioritized focus list.

Covers the two things that make the list trustworthy: the confirmed-first sort
(a confirmed finding outranks an unverified higher-severity one; refuted/FP sink
to the bottom) and the spine+plus merge (validated recommendations that map to a
finding row are NOT double-listed; chains with no finding row ARE added).
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core import scan_db
from modules import focus


def _seed_db(output_dir):
    """Two findings (a confirmed medium, an unverified critical) + validations."""
    db = scan_db.ScanDB(output_dir)
    fid_med = scan_db.finding_id("10.0.0.5", 445, "tcp", "smb-vuln")
    fid_crit = scan_db.finding_id("10.0.0.1", 443, "tcp", "cve-x")
    db.upsert_finding(finding_id=fid_med, host="10.0.0.5", port=445, proto="tcp",
                      claim="smb-vuln", tool="nmap", type="vulnerability",
                      severity="medium", title="SMB signing disabled")
    db.upsert_finding(finding_id=fid_crit, host="10.0.0.1", port=443, proto="tcp",
                      claim="cve-x", tool="nuclei", type="nuclei_finding",
                      severity="critical", title="RCE candidate")
    # Confirm the medium; leave the critical unverified.
    db.record_validation(finding_id=fid_med, host="10.0.0.5", port=445, proto="tcp",
                         verdict="confirmed", evidence="signing off",
                         poc_command="crackmapexec smb 10.0.0.5")
    db.set_verdict(fid_med, "confirmed")
    db.close()
    return fid_med, fid_crit


def _prefixes(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    (tmp_path / "reports").mkdir()
    data_prefix = str(data_dir / "scan")
    reports_prefix = str(tmp_path / "reports" / "scan")
    return data_prefix, reports_prefix


class TestSort:
    def test_confirmed_outranks_higher_severity_unverified(self, tmp_path):
        _seed_db(str(tmp_path))
        data_prefix, reports_prefix = _prefixes(tmp_path)
        res = focus.run_focus(str(tmp_path / "scan"),
                              data_prefix=data_prefix, reports_prefix=reports_prefix)
        assert res["status"] == "success"
        with open(f"{data_prefix}-focus.json") as f:
            items = json.load(f)["focus"]
        # Confirmed medium ranks above unverified critical.
        assert items[0]["target"] == "10.0.0.5:445"
        assert items[0]["verdict"] == "confirmed"
        assert items[0]["proof"] == "crackmapexec smb 10.0.0.5"
        assert items[1]["target"] == "10.0.0.1:443"
        assert items[1]["verdict"] == "unverified"

    def test_refuted_and_false_positive_sink(self, tmp_path):
        db = scan_db.ScanDB(str(tmp_path))
        good = scan_db.finding_id("h1", 80, "tcp", "a")
        ref = scan_db.finding_id("h2", 80, "tcp", "b")
        fp = scan_db.finding_id("h3", 80, "tcp", "c")
        db.upsert_finding(finding_id=good, host="h1", port=80, proto="tcp",
                          claim="a", tool="nuclei", type="nuclei_finding",
                          severity="low", title="minor")
        db.upsert_finding(finding_id=ref, host="h2", port=80, proto="tcp",
                          claim="b", tool="nuclei", type="nuclei_finding",
                          severity="critical", title="refuted crit")
        db.set_verdict(ref, "refuted")
        db.upsert_finding(finding_id=fp, host="h3", port=80, proto="tcp",
                          claim="c", tool="nuclei", type="nuclei_finding",
                          severity="critical", title="fp crit")
        # Mark false positive directly.
        db._conn.execute("UPDATE findings SET false_positive=1 WHERE finding_id=?", (fp,))
        db._conn.commit()
        db.close()
        data_prefix, reports_prefix = _prefixes(tmp_path)
        focus.run_focus(str(tmp_path / "scan"),
                        data_prefix=data_prefix, reports_prefix=reports_prefix)
        with open(f"{data_prefix}-focus.json") as f:
            items = json.load(f)["focus"]
        # The unremarkable low-sev finding beats a refuted crit and an FP crit.
        assert items[0]["target"] == "h1:80"
        assert items[-1]["false_positive"] is True


class TestMerge:
    def test_validated_rec_with_finding_id_not_duplicated(self, tmp_path):
        fid_med, _ = _seed_db(str(tmp_path))
        data_prefix, reports_prefix = _prefixes(tmp_path)
        # A validated-findings.json entry that DID map to the medium finding.
        with open(f"{data_prefix}-validated-findings.json", "w") as f:
            json.dump([{
                "verdict": "confirmed", "severity": "medium",
                "finding_id": fid_med, "finding_ids": [fid_med],
                "finding": {"target": "10.0.0.5:445", "action": "SMB signing disabled"},
            }], f)
        focus.run_focus(str(tmp_path / "scan"),
                        data_prefix=data_prefix, reports_prefix=reports_prefix)
        with open(f"{data_prefix}-focus.json") as f:
            items = json.load(f)["focus"]
        # No duplicate for 10.0.0.5:445 — the finding-row spine wins.
        assert sum(1 for i in items if i["target"] == "10.0.0.5:445") == 1

    def test_chain_without_finding_id_is_added(self, tmp_path):
        _seed_db(str(tmp_path))
        data_prefix, reports_prefix = _prefixes(tmp_path)
        with open(f"{data_prefix}-validated-findings.json", "w") as f:
            json.dump([{
                "verdict": "unclear", "severity": "high",
                "finding_id": None, "finding_ids": [],
                "finding": {"target": "10.0.0.5:445 -> 10.0.0.9:22",
                            "action": "SMB creds reused for SSH"},
            }], f)
        focus.run_focus(str(tmp_path / "scan"),
                        data_prefix=data_prefix, reports_prefix=reports_prefix)
        with open(f"{data_prefix}-focus.json") as f:
            items = json.load(f)["focus"]
        chains = [i for i in items if i["source"] == "analysis"]
        assert len(chains) == 1
        assert chains[0]["action"] == "SMB creds reused for SSH"

    def test_fallback_to_ai_analysis_when_no_validation(self, tmp_path):
        _seed_db(str(tmp_path))
        data_prefix, reports_prefix = _prefixes(tmp_path)
        # No validated-findings.json -> read ai-analysis.json recommendations.
        with open(f"{data_prefix}-ai-analysis.json", "w") as f:
            json.dump({"recommendations": {
                "attack_chains": [{"target": "10.0.0.1:443 -> 10.0.0.2",
                                   "action": "pivot via RCE", "impact": "CRITICAL",
                                   "commands": ["curl http://10.0.0.1"]}],
                "quick_wins": [], "requires_verification": [], "cve_research": [],
            }}, f)
        focus.run_focus(str(tmp_path / "scan"),
                        data_prefix=data_prefix, reports_prefix=reports_prefix)
        with open(f"{data_prefix}-focus.json") as f:
            items = json.load(f)["focus"]
        chains = [i for i in items if i["source"] == "analysis"]
        assert len(chains) == 1
        assert chains[0]["severity"] == "critical"
        assert chains[0]["proof"] == "curl http://10.0.0.1"


class TestInfoInclusion:
    """Info findings are suppressed as noise EXCEPT when flagged: validated
    confirmed/unclear, or carrying proof. Refuted/unverified info stays out."""

    def _run(self, tmp_path):
        data_prefix, reports_prefix = _prefixes(tmp_path)
        focus.run_focus(str(tmp_path / "scan"),
                        data_prefix=data_prefix, reports_prefix=reports_prefix)
        with open(f"{data_prefix}-focus.json") as f:
            return {e["target"]: e for e in json.load(f)["focus"]}

    def test_confirmed_info_surfaces_unverified_info_hidden(self, tmp_path):
        db = scan_db.ScanDB(str(tmp_path))
        conf = scan_db.finding_id("h1", 80, "tcp", "info-a")
        noise = scan_db.finding_id("h2", 80, "tcp", "info-b")
        db.upsert_finding(finding_id=conf, host="h1", port=80, proto="tcp",
                          claim="info-a", tool="nuclei", severity="info",
                          title="exposed .git (info-rated)")
        db.upsert_finding(finding_id=noise, host="h2", port=80, proto="tcp",
                          claim="info-b", tool="nuclei", severity="info",
                          title="tech-detect nginx")
        db.record_validation(finding_id=conf, host="h1", port=80, proto="tcp",
                             verdict="confirmed", evidence="repo readable",
                             poc_command="curl -s http://h1/.git/config")
        db.set_verdict(conf, "confirmed")
        db.close()
        by_target = self._run(tmp_path)
        assert "h1:80" in by_target                # flagged info surfaces
        assert by_target["h1:80"]["verdict"] == "confirmed"
        assert "h2:80" not in by_target            # unverified info stays hidden

    def test_info_with_proof_surfaces(self, tmp_path):
        db = scan_db.ScanDB(str(tmp_path))
        fid = scan_db.finding_id("h3", 22, "tcp", "info-c")
        db.upsert_finding(finding_id=fid, host="h3", port=22, proto="tcp",
                          claim="info-c", tool="nmap", severity="info",
                          title="banner grab")
        # proof present but verdict unclear -> still flagged (unclear qualifies).
        db.record_validation(finding_id=fid, host="h3", port=22, proto="tcp",
                             verdict="unclear", evidence="partial",
                             poc_command="nc h3 22")
        db.close()
        assert "h3:22" in self._run(tmp_path)

    def test_refuted_info_stays_hidden(self, tmp_path):
        db = scan_db.ScanDB(str(tmp_path))
        fid = scan_db.finding_id("h4", 80, "tcp", "info-d")
        db.upsert_finding(finding_id=fid, host="h4", port=80, proto="tcp",
                          claim="info-d", tool="nuclei", severity="info",
                          title="maybe-thing")
        db.record_validation(finding_id=fid, host="h4", port=80, proto="tcp",
                             verdict="refuted", evidence="not present")
        db.set_verdict(fid, "refuted")
        db.close()
        assert "h4:80" not in self._run(tmp_path)

    def test_info_nuclei_finding_type_excluded(self, tmp_path):
        """Regression: an info-severity finding whose TYPE is a real finding type
        (nuclei_finding / dns_security) must still be excluded from focus. These
        are nuclei's detection templates (tech-detect, DNS SPF/MX/NS fingerprints,
        wildcard-dns) — is_finding_record keeps them as findings/CSV context, but
        focus must not be drowned by them (a real run leaked 138 such rows)."""
        db = scan_db.ScanDB(str(tmp_path))
        keep = scan_db.finding_id("h5", 443, "tcp", "cve-1")
        drop_nuclei = scan_db.finding_id("h6", 53, "udp", "spf-detect")
        drop_dns = scan_db.finding_id("h7", 53, "udp", "ns-detect")
        db.upsert_finding(finding_id=keep, host="h5", port=443, proto="tcp",
                          claim="cve-1", tool="nuclei", type="vulnerability",
                          severity="high", title="real CVE")
        db.upsert_finding(finding_id=drop_nuclei, host="h6", port=53, proto="udp",
                          claim="spf-detect", tool="nuclei", type="nuclei_finding",
                          severity="info", title="[spf-record-detect] SPF Record")
        db.upsert_finding(finding_id=drop_dns, host="h7", port=53, proto="udp",
                          claim="ns-detect", tool="dns_security", type="dns_security",
                          severity="info", title="NS record detected")
        db.close()
        by_target = self._run(tmp_path)
        assert "h5:443" in by_target                 # real non-info finding kept
        assert "h6:53" not in by_target              # info nuclei_finding dropped
        assert "h7:53" not in by_target              # info dns_security dropped


class TestEmpty:
    def test_no_findings_writes_empty_list(self, tmp_path):
        scan_db.ScanDB(str(tmp_path)).close()
        data_prefix, reports_prefix = _prefixes(tmp_path)
        res = focus.run_focus(str(tmp_path / "scan"),
                              data_prefix=data_prefix, reports_prefix=reports_prefix)
        assert res["count"] == 0
        with open(f"{data_prefix}-focus.json") as f:
            assert json.load(f)["focus"] == []
        assert os.path.exists(f"{reports_prefix}-focus.md")


# --- #3 clustering + #2 re-rating annotation --------------------------------

from modules.focus import _cluster_entries, _sev_label


def test_cluster_collapses_same_title_replicas():
    entries = [
        {"title": "Spoofed Host header", "severity": "low", "tool": "bbot",
         "verdict": "unverified", "target": f"h{i}.tld"} for i in range(368)
    ]
    out = _cluster_entries(entries)
    assert len(out) == 1
    assert out[0]["member_count"] == 368
    assert len(out[0]["members"]) == 25            # capped
    assert out[0]["members_truncated"] is True


def test_cluster_keeps_distinct_titles_and_verdicts_separate():
    entries = [
        {"title": "X", "severity": "high", "tool": "nuclei", "verdict": "confirmed",
         "target": "a", "proof": "curl a"},
        {"title": "X", "severity": "high", "tool": "nuclei", "verdict": "unverified",
         "target": "b"},
        {"title": "X", "severity": "high", "tool": "nuclei", "verdict": "unverified",
         "target": "c"},
        {"title": "Y", "severity": "medium", "tool": "nuclei", "verdict": "unverified",
         "target": "d"},
    ]
    out = _cluster_entries(entries)
    # confirmed-X (1), unverified-X cluster (2), Y (1) = 3 rows; confirmed NOT
    # merged into the unverified cluster.
    assert len(out) == 3
    conf = [e for e in out if e["verdict"] == "confirmed"]
    assert len(conf) == 1 and conf[0]["member_count"] == 1
    unv = [e for e in out if e["title"] == "X" and e["verdict"] == "unverified"][0]
    assert unv["member_count"] == 2


def test_cluster_singleton_unchanged():
    out = _cluster_entries([{"title": "solo", "severity": "high", "tool": "nuclei",
                             "verdict": "unverified", "target": "h"}])
    assert len(out) == 1 and out[0]["member_count"] == 1
    assert "members" not in out[0]


def test_sev_label_annotates_rerating():
    assert _sev_label({"severity": "high", "severity_source": "monkeyx_rule",
                       "original_severity": "info"}) == "HIGH (↑ from INFO)"
    assert _sev_label({"severity": "high", "severity_source": "tool"}) == "HIGH"
