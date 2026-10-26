"""bbot 'info' surfacing: events that used to be dropped now reach findings /
the tech inventory.

- AZURE_TENANT and WAF were fully dropped by normalize; EMAIL_ADDRESS was parsed
  but emitted as a `type:"email"` record that was in neither FINDING_TYPES nor
  read by ai_analyze (thrown away). All three now mint as info-severity findings.
- TECHNOLOGY events roll up into summary's Technology Stack inventory.
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.normalize import _parse_bbot_jsonl
from modules import summary as summary_mod
from core import scan_db


def _write(path, events):
    with open(path, "w", encoding="utf-8") as fh:
        for e in events:
            fh.write(json.dumps(e) + "\n")


def _by_bbot_type(records):
    return {r.get("bbot_type"): r for r in records}


class TestBbotInfoFindings:
    def test_azure_tenant_waf_email_become_info_findings(self, tmp_path):
        p = tmp_path / "scan-bbot-passive.jsonl"
        _write(p, [
            {"type": "AZURE_TENANT",
             "data": {"tenant-id": "contoso.onmicrosoft.com",
                      "domains": ["contoso.com", "mail.contoso.com"]},
             "host": "contoso.com", "module": "azure_tenant"},
            {"type": "WAF",
             "data": {"waf": "Cloudflare", "url": "https://x.example.com"},
             "host": "x.example.com", "module": "waf"},
            {"type": "EMAIL_ADDRESS", "data": "admin@example.com",
             "host": "example.com", "module": "emails"},
        ])
        recs = _by_bbot_type(_parse_bbot_jsonl(str(p)))

        az = recs["AZURE_TENANT"]
        assert az["type"] == "finding" and az["severity"] == "info"
        assert "Azure/M365 tenant" in az["title"]
        assert "contoso.com" in az["detail"] and "mail.contoso.com" in az["detail"]

        waf = recs["WAF"]
        assert waf["type"] == "finding" and waf["severity"] == "info"
        assert "Cloudflare" in waf["title"]

        email = recs["EMAIL_ADDRESS"]
        assert email["type"] == "finding" and email["severity"] == "info"
        assert email["title"] == "Email address: admin@example.com"

        # All three are real finding types (so they mint into scan.db findings).
        for r in (az, waf, email):
            assert r["type"] in scan_db.FINDING_TYPES

    def test_azure_tenant_from_string_data(self, tmp_path):
        # Defensive: data may be a bare string, not a dict.
        p = tmp_path / "scan-bbot-cloud.jsonl"
        _write(p, [{"type": "AZURE_TENANT", "data": "contoso.onmicrosoft.com",
                    "host": "", "module": "azure_tenant"}])
        recs = _by_bbot_type(_parse_bbot_jsonl(str(p)))
        assert recs["AZURE_TENANT"]["type"] == "finding"
        assert "contoso.onmicrosoft.com" in recs["AZURE_TENANT"]["title"]


class TestTechnologyInventory:
    def test_summary_rolls_up_technologies(self, tmp_path):
        # normalized bbot records: nginx on two hosts, php on one, plus a
        # non-technology record that must be ignored.
        p = tmp_path / "scan-bbot-normalized.jsonl"
        _write(p, [
            {"type": "technology", "detail": "nginx", "host": "a.example.com"},
            {"type": "technology", "detail": "nginx", "host": "b.example.com"},
            {"type": "technology", "detail": "php", "host": "a.example.com"},
            {"type": "finding", "detail": "not a tech", "host": "a.example.com"},
        ])
        stats = {}
        summary_mod._parse_technologies(str(tmp_path), stats)
        techs = {t["tech"]: t for t in stats["technologies"]}
        assert techs["nginx"]["host_count"] == 2
        assert techs["php"]["host_count"] == 1
        # Sorted by host_count desc: nginx first.
        assert stats["technologies"][0]["tech"] == "nginx"
        assert "a.example.com" in techs["nginx"]["sample_hosts"]
