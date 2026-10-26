"""nuclei_scan must resolve template IDs, not abort with 'no templates provided'.

Regression: `_build_command` mapped the agent's `templates` value straight to
nuclei `-t`. nuclei's `-t` takes a template FILE/DIR/URL path, so a bare
template id like `CVE-2022-0543` (exactly what the agent passes for CVE
validation) made nuclei abort — `[FTL] no templates provided` — silently failing
4/6 validation calls and flipping a real Redis RCE to "unclear". IDs now route to
`-id`, paths to `-t`.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.ai_validate import _build_command, _split_nuclei_selectors


class TestSplitSelectors:
    def test_bare_id_is_an_id(self):
        assert _split_nuclei_selectors("CVE-2022-0543") == ([], ["CVE-2022-0543"])

    def test_path_is_a_path(self):
        assert _split_nuclei_selectors("http/cves/2022/CVE-2022-0543.yaml") == (
            ["http/cves/2022/CVE-2022-0543.yaml"], [])

    def test_mixed_and_whitespace(self):
        paths, ids = _split_nuclei_selectors("CVE-2022-0543, misc/foo.yml , redis-detect")
        assert paths == ["misc/foo.yml"]
        assert ids == ["CVE-2022-0543", "redis-detect"]


class TestBuildCommand:
    def test_template_id_routes_to_id_flag(self):
        argv, _ = _build_command(
            "nuclei_scan",
            {"target": "http://h.tld:6379", "templates": "CVE-2022-0543"},
            allow_intrusive=False)
        assert "-id" in argv
        assert argv[argv.index("-id") + 1] == "CVE-2022-0543"
        # Must NOT feed the id to -t (that's what aborted the scan).
        assert "-t" not in argv

    def test_template_path_routes_to_t_flag(self):
        argv, _ = _build_command(
            "nuclei_scan",
            {"target": "http://h.tld", "templates": "http/cves/CVE-2022-0543.yaml"},
            allow_intrusive=False)
        assert "-t" in argv
        assert argv[argv.index("-t") + 1] == "http/cves/CVE-2022-0543.yaml"
        assert "-id" not in argv

    def test_no_templates_selector_still_runs(self):
        # No selector at all -> nuclei runs its full set; must not inject -t/-id.
        argv, _ = _build_command(
            "nuclei_scan", {"target": "http://h.tld"}, allow_intrusive=False)
        assert argv[:4] == ["nuclei", "-u", "http://h.tld", "-silent"]
        assert "-t" not in argv and "-id" not in argv
