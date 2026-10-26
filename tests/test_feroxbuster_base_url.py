"""feroxbuster base-URL targeting.

feroxbuster is recursive, so it must be fed ONE root per scheme://host:port and
left to discover the tree — not the full deep-path inventory (which would make
it recursively brute-force every path). _base_url_kwargs collapses its url_file
to deduplicated base URLs; other modules and missing inputs are untouched.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import workflows
from core.output_layout import ledger_file


def _make_urls(tmp_path, lines):
    p = tmp_path / "urls.txt"
    p.write_text("\n".join(lines) + "\n")
    return str(p)


class TestBaseUrlKwargs:
    def test_ferox_input_collapsed_to_unique_base_urls(self, tmp_path):
        src = _make_urls(tmp_path, [
            "https://a.example.com/admin/login",
            "https://a.example.com/api/v1/users",
            "https://a.example.com/",                 # same root as above
            "http://b.example.com:8080/dashboard",
            "http://b.example.com:8080/status/health",
            "# comment", "",                           # ignored
        ])
        out = workflows._base_url_kwargs(
            "ax_feroxbuster", {"url_file": src}, str(tmp_path))

        remapped = out["url_file"]
        assert remapped == ledger_file(str(tmp_path), "ledger-urls-ferox-base.txt")
        bases = [l for l in open(remapped).read().splitlines() if l]
        # Three deep a.example.com URLs collapse to one root; two b:8080 to one.
        assert bases == ["https://a.example.com", "http://b.example.com:8080"]

    def test_non_ferox_module_untouched(self, tmp_path):
        src = _make_urls(tmp_path, ["https://a.example.com/x"])
        kw = {"url_file": src}
        assert workflows._base_url_kwargs("ax_nuclei", kw, str(tmp_path)) is kw

    def test_missing_file_is_fail_open(self, tmp_path):
        kw = {"url_file": str(tmp_path / "nope.txt")}
        # Unchanged (same dict) — the module falls back to its original input.
        assert workflows._base_url_kwargs("ax_feroxbuster", kw, str(tmp_path)) == kw

    def test_no_url_file_kwarg_untouched(self, tmp_path):
        kw = {}
        assert workflows._base_url_kwargs("ax_feroxbuster", kw, str(tmp_path)) == {}

    def test_all_unparseable_urls_fail_open(self, tmp_path):
        # Lines with no scheme/host yield no base URL -> leave input unchanged.
        src = _make_urls(tmp_path, ["not-a-url", "///"])
        kw = {"url_file": src}
        out = workflows._base_url_kwargs("ax_feroxbuster", kw, str(tmp_path))
        assert out["url_file"] == src
