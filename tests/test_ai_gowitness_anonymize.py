"""ai_analyze_gowitness must alias client IPs/domains in the TEXT it sends to the
vision API (URLs, titles, technologies, image labels, synthesis payload) and
restore them in the response — mirroring ai_analyze.

Scope note: this covers the text channel only. The screenshot JPEGs themselves
are sent unaltered and still carry identifying content; that is a documented,
irreducible limitation of vision analysis (see core/anonymize.py and
docs/AI_DATA_HANDLING.md), not something these tests assert away.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import modules.ai_analyze_gowitness as gw
from core.anonymize import build_alias_map, extract_domains_from_text


def _maps_for(*urls):
    ips, domains, seen = [], set(), set()
    for u in urls:
        from urllib.parse import urlparse
        host = urlparse(u if "://" in u else f"http://{u}").hostname or ""
        if gw._IP_RE.match(host):
            if host not in seen:
                seen.add(host)
                ips.append(host)
        extract_domains_from_text(u, domains)
    return build_alias_map(ips, domains)


class TestSingletonAnonymization:
    def test_text_aliased_out_and_findings_restored(self, monkeypatch, tmp_path):
        entries = [{
            "id": 1, "url": "https://portal.acme-client.com/login", "final_url": "",
            "title": "Acme Client Login", "response_code": 200,
            "technologies": ["nginx"], "content_length": 100, "filename": "a.jpg",
        }]
        monkeypatch.setattr(gw, "_load_screenshot_base64", lambda *a, **k: "BASE64IMG")

        captured = {}

        def _fake_vision(ai, system_prompt, user_text, images, max_tokens):
            captured["user_text"] = user_text
            captured["labels"] = [lbl for _, lbl in images]
            # The model only ever sees the alias; it echoes it back.
            return {"findings": [{
                "url": "D1/login", "title": "Login", "category": "login_panel",
                "severity": "HIGH", "description": "login form on D1",
                "technologies": [], "attack_notes": "", "evidence": "",
            }]}

        monkeypatch.setattr(gw, "_query_vision_anthropic", _fake_vision)

        t2a, a2t = _maps_for("https://portal.acme-client.com/login")
        out = gw._analyze_singletons(
            object(), entries, str(tmp_path),
            {"max_image_size_kb": 300, "max_tokens": 8000},
            token_to_alias=t2a, alias_to_token=a2t)

        # Nothing client-identifying left in the egressed text.
        assert "acme-client.com" not in captured["user_text"]
        assert "D1" in captured["user_text"]
        assert all("acme-client.com" not in lbl for lbl in captured["labels"])
        # Response de-aliased before it reaches the caller / disk.
        assert out[0]["url"] == "portal.acme-client.com/login"
        assert "portal.acme-client.com" in out[0]["description"]


class TestGroupAnonymization:
    def test_group_metadata_aliased_and_result_restored(self, monkeypatch, tmp_path):
        members = [{
            "id": 1, "url": "http://10.9.8.7:8080/admin", "final_url": "",
            "title": "Admin", "response_code": 200, "technologies": [],
            "content_length": 500, "filename": "g.jpg",
        }]
        monkeypatch.setattr(gw, "_load_screenshot_base64", lambda *a, **k: "IMG")

        captured = {}

        def _fake_vision(ai, system_prompt, user_text, images, max_tokens):
            captured["user_text"] = user_text
            return {"group_assessment": "interesting", "category": "admin_interface",
                    "severity": "CRITICAL", "description": "admin on H1",
                    "notable_urls": ["H1:8080/admin"], "technologies": []}

        monkeypatch.setattr(gw, "_query_vision_anthropic", _fake_vision)

        t2a, a2t = _maps_for("http://10.9.8.7:8080/admin")
        result = gw._analyze_group(
            object(), "5", members, str(tmp_path),
            {"max_image_size_kb": 300, "max_screenshots_per_group": 1},
            token_to_alias=t2a, alias_to_token=a2t)

        assert "10.9.8.7" not in captured["user_text"]
        assert "H1" in captured["user_text"]
        assert result["description"] == "admin on 10.9.8.7"
        assert result["notable_urls"] == ["10.9.8.7:8080/admin"]


class TestAliasMapBuilder:
    def test_collects_ips_and_domains_from_groups(self):
        groups = {
            "0": [{"url": "https://api.example.org/v1", "final_url": "",
                   "title": "x", "technologies": ["cdn.example.org"]},
                  {"url": "http://192.168.5.5/", "final_url": "", "title": "",
                   "technologies": []}],
        }
        t2a, a2t = gw._build_screenshot_alias_map(groups)
        assert t2a.get("192.168.5.5") == "H1"
        # both the URL host and a domain mentioned in technologies get aliased
        assert "api.example.org" in t2a
        assert "cdn.example.org" in t2a
