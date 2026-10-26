"""Tests for three output-review design fixes:

#9  MX domains logged from the resolve report into the ledger/scan.db.
#12 AI cost estimation resolves rates for Bedrock inference-profile ARNs and a
    config price override (was always $0 for ARN model ids).
#14 Prior-run snapshot files (.run<N>) excluded from the results zip.
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# --- #12: cost rate resolution ------------------------------------------- #

from core.ai_provider import resolve_cost_rates


class TestResolveCostRates:
    def test_exact_model_key(self):
        assert resolve_cost_rates("gpt-4o") == {"input": 2.5, "output": 10.0}

    def test_bedrock_arn_substring_family(self):
        # An inference-profile ARN embeds the model name -> family match.
        arn = ("arn:aws:bedrock:us-east-1:123:inference-profile/"
               "us.anthropic.claude-sonnet-4-20250101-v1:0")
        assert resolve_cost_rates(arn) == {"input": 3.0, "output": 15.0}

    def test_haiku_beats_generic(self):
        arn = "arn:...:inference-profile/us.anthropic.claude-haiku-4-5"
        assert resolve_cost_rates(arn) == {"input": 0.8, "output": 4.0}

    def test_opaque_arn_needs_config_override(self):
        # An application-inference-profile ARN embeds no model name.
        opaque = ("arn:aws:bedrock:us-east-1:123456789012:"
                  "application-inference-profile/exampleprofileid")
        assert resolve_cost_rates(opaque) is None
        # The credentials.yaml override prices it.
        rates = resolve_cost_rates(opaque, {"input_price_per_1m": 3.0,
                                            "output_price_per_1m": 15.0})
        assert rates == {"input": 3.0, "output": 15.0}

    def test_config_override_wins_over_model(self):
        rates = resolve_cost_rates("gpt-4o", {"input_price_per_1m": 1.0,
                                             "output_price_per_1m": 2.0})
        assert rates == {"input": 1.0, "output": 2.0}

    def test_unknown_returns_none(self):
        assert resolve_cost_rates("llama3:70b") is None
        assert resolve_cost_rates("") is None


# --- #14: prior-run snapshot exclusion ----------------------------------- #

import monkeyx


class TestPriorRunSnapshot:
    def test_matches_run_snapshots(self):
        assert monkeyx._is_prior_run_snapshot("report.run2.html")
        assert monkeyx._is_prior_run_snapshot("summary.run1.md")
        assert monkeyx._is_prior_run_snapshot("2026-07-28-ai-analysis.run1.json")

    def test_does_not_match_current_files(self):
        assert not monkeyx._is_prior_run_snapshot("report.html")
        assert not monkeyx._is_prior_run_snapshot("summary.md")
        assert not monkeyx._is_prior_run_snapshot("2026-07-28-nmap-normalized.jsonl")
        # "run" in a normal name (no .run<digits>.) is fine.
        assert not monkeyx._is_prior_run_snapshot("run-notes.txt")


# --- #9: MX domains logged from the resolve report ----------------------- #

from core.target_ledger import TargetLedger
from core import scan_db
from workflows import _log_ips_from_resolve_report


class TestMxDomainLogging:
    def test_mx_from_resolve_report_reaches_ledger_and_db(self, tmp_path):
        report = tmp_path / "scan-resolve-report.jsonl"
        report.write_text(
            json.dumps({"hostname": "example.net", "status": "resolved",
                        "ip": "1.2.3.4",
                        "mx": ["mxa.pphosted.com", "mxb.pphosted.com"]}) + "\n"
            + json.dumps({"hostname": "emails.example.com", "status": "resolved",
                          "ip": "5.6.7.8", "mx": ["reply.exacttarget.com"]}) + "\n"
            # no_answer rows carry a blank placeholder [""] — must be ignored.
            + json.dumps({"hostname": "referral.example.com", "status": "no_answer",
                          "mx": [""]}) + "\n"
        )
        led = TargetLedger(str(tmp_path))
        _log_ips_from_resolve_report(str(report), "dnsx_resolve", led)

        mx = led.get_mx_domains()
        assert mx.get("example.net") == ["mxa.pphosted.com", "mxb.pphosted.com"]
        assert mx.get("emails.example.com") == ["reply.exacttarget.com"]
        # Blank-placeholder row did not create an entry.
        assert "referral.example.com" not in mx

        led.sync_scope_to_db()
        db = scan_db.open_db(str(tmp_path))
        rows = {r["domain"]: json.loads(r["mx_hosts"])
                for r in db._conn.execute("SELECT domain, mx_hosts FROM mx_domains")}
        assert rows.get("example.net") == ["mxa.pphosted.com", "mxb.pphosted.com"]
        assert "referral.example.com" not in rows
        db.close()
        led.close()
