"""Tests: each bbot module (and puredns) is fed the input that suits its job,
not the unconditional union of every ledger source.

Background: collect_bbot_targets() merges domains + IPs + every deep URL +
host:port. Name-scoped modules (cloud/takeover/code) only act on names; passive
keys off names/IPs; dast (invasive) must fuzz known-live URLs/ports, not
re-crawl from names. Over-feeding inflated runtimes/timeouts and, for bbot_code,
produced invalid "domains" from mangled URLs/IPs.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

import workflows
from workflows import ModuleStep
from modules.bbot_code import _extract_apex_domains
import modules.bbot_passive as bbot_passive
import modules.bbot_cloud as bbot_cloud
import modules.bbot_takeover as bbot_takeover
import modules.bbot_code as bbot_code
import modules.bbot_dast as bbot_dast


# ---- bbot_code apex extractor rejects non-hostnames -------------------------

def test_extract_apex_drops_urls_ips_and_hostports():
    out = _extract_apex_domains([
        "https://api.example.com/v1/users",   # URL — was mangled to example.com/v1/users
        "1.2.3.4",                            # IP — was mangled to 3.4
        "mail.example.com:587",               # host:port
        "www.foo.com",                        # -> foo.com
        "example.com",                        # apex kept
        "sub.deep.example.org",               # -> example.org
    ])
    assert out == ["example.com", "example.org", "foo.com"]


# ---- each module scopes collect_bbot_targets to what it can use -------------

def _spy_collect(monkeypatch, module):
    """Patch the module's collect_bbot_targets to capture kwargs and short-circuit."""
    seen = {}

    def _fake(**kwargs):
        seen.update(kwargs)
        return []  # empty -> module returns early, no shell-out

    monkeypatch.setattr(module, "collect_bbot_targets", _fake)
    return seen


def test_bbot_cloud_feeds_domains_only(monkeypatch):
    seen = _spy_collect(monkeypatch, bbot_cloud)
    bbot_cloud.run_bbot_cloud(domainlist="d.txt", target="t.txt",
                              url_file="u.txt", open_ports_file="p.txt")
    assert set(seen) == {"domainlist"}


def test_bbot_takeover_feeds_domains_only(monkeypatch):
    seen = _spy_collect(monkeypatch, bbot_takeover)
    bbot_takeover.run_bbot_takeover(domainlist="d.txt", target="t.txt",
                                    url_file="u.txt", open_ports_file="p.txt")
    assert set(seen) == {"domainlist"}


def test_bbot_code_feeds_domains_only(monkeypatch):
    seen = _spy_collect(monkeypatch, bbot_code)
    bbot_code.run_bbot_code(domainlist="d.txt", target="t.txt",
                            url_file="u.txt", open_ports_file="p.txt")
    assert set(seen) == {"domainlist"}


def test_bbot_passive_feeds_names_and_ips_not_urls(monkeypatch):
    seen = _spy_collect(monkeypatch, bbot_passive)
    bbot_passive.run_bbot_passive(domainlist="d.txt", target="t.txt",
                                  url_file="u.txt", open_ports_file="p.txt")
    assert set(seen) == {"domainlist", "target"}


def test_bbot_dast_feeds_live_urls_and_ports_not_names(monkeypatch):
    seen = _spy_collect(monkeypatch, bbot_dast)
    bbot_dast.run_bbot_dast(domainlist="d.txt", target="t.txt",
                            url_file="u.txt", open_ports_file="p.txt")
    assert set(seen) == {"url_file", "open_ports_file"}


# ---- enrollment in the input-narrowing sets --------------------------------

def test_live_and_base_url_set_membership():
    for m in ("ax_wafw00f", "ax_testssl", "bbot_dast"):
        assert m in workflows._LIVE_URL_SCANNERS
    for m in ("ax_ffuf", "ax_wpscan", "ax_wafw00f", "ax_testssl", "ax_feroxbuster"):
        assert m in workflows._BASE_URL_SCANNERS


# ---- puredns root-domain remap applies on the PARALLEL path too -------------

class _FakeLedger:
    """Minimal ledger: export_root_domains writes a root-domains file."""
    def export_root_domains(self, path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fh:
            fh.write("example.com\n")
        return 1


def test_puredns_parallel_path_uses_root_domains(tmp_path):
    base = {"domainlist": str(tmp_path / "full-domains.txt")}
    mk = workflows._member_kwargs(
        ModuleStep(name="ax_puredns_bruteforce"), base, str(tmp_path),
        ledger=_FakeLedger())
    assert mk["domainlist"].endswith("ledger-root-domains.txt")
