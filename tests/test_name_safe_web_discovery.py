"""Tests for option-A name-safe web discovery.

For -d/-url hosts (name-safe, possibly shared infra), web modules must get a URL
surface WITHOUT a host-class port scan. Two mechanisms:
  1. ledger.synthesize_name_urls() seeds http://name + https://name for
     name-safe in-scope hosts, inheriting the host's channel.
  2. _auto_inject_web_discovery() does NOT inject the host-class nmap web scan
     for a domains-only run (it would be gated to nothing); synthesis covers it.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import workflows
from monkeyx import _auto_inject_web_discovery
from workflows import ModuleStep, ParallelGroup
from core.target_ledger import (
    TargetLedger, TYPE_DOMAIN, TYPE_SUBDOMAIN, TYPE_URL,
    CHANNEL_DOMAIN, CHANNEL_URL, CHANNEL_TARGET,
)


def _seed(tmp_path, targets=None, domains=None):
    tf = df = None
    if targets is not None:
        tf = tmp_path / "t.txt"; tf.write_text("\n".join(targets) + "\n")
    if domains is not None:
        df = tmp_path / "d.txt"; df.write_text("\n".join(domains) + "\n")
    led = TargetLedger(str(tmp_path))
    led.seed_user_inputs(str(tf) if tf else None, str(df) if df else None, None)
    return led


# --- synthesize_name_urls -------------------------------------------------

def test_synthesizes_http_and_https_for_dl_host(tmp_path):
    led = _seed(tmp_path, domains=["example.com"])
    led.log_discovery("api.example.com", TYPE_SUBDOMAIN, "subfinder",
                      parent="example.com")
    n = led.synthesize_name_urls(only_channels=(CHANNEL_DOMAIN, CHANNEL_URL))
    assert n == 4  # example.com + api.example.com, each http+https
    assert led.get_channel("http://api.example.com", TYPE_URL) == CHANNEL_DOMAIN
    assert led.get_channel("https://api.example.com", TYPE_URL) == CHANNEL_DOMAIN


def test_synthesis_skips_excluded_hosts(tmp_path):
    led = _seed(tmp_path, domains=["example.com"])
    led.log_discovery("bad.example.com", TYPE_SUBDOMAIN, "subfinder",
                      parent="example.com")
    excl = tmp_path / "x.txt"; excl.write_text("bad.example.com\n")
    led.seed_exclusions(str(excl))
    led.synthesize_name_urls(only_channels=(CHANNEL_DOMAIN, CHANNEL_URL))
    assert led.get_channel("http://bad.example.com", TYPE_URL) is None


def test_synthesis_idempotent(tmp_path):
    led = _seed(tmp_path, domains=["example.com"])
    first = led.synthesize_name_urls()
    second = led.synthesize_name_urls()
    assert first == 2
    assert second == 0  # already seeded


def test_channel_filter_excludes_t_hosts(tmp_path):
    """-t hosts should be left to nmap discovery, not synthesized here."""
    led = _seed(tmp_path, targets=["thost.example.com"], domains=["example.com"])
    led.synthesize_name_urls(only_channels=(CHANNEL_DOMAIN, CHANNEL_URL))
    # example.com (dl) synthesized; thost.example.com (t) not
    assert led.get_channel("http://example.com", TYPE_URL) == CHANNEL_DOMAIN
    assert led.get_channel("http://thost.example.com", TYPE_URL) is None


def test_synthesis_runs_during_regeneration(tmp_path):
    led = _seed(tmp_path, domains=["example.com"])
    base = {"prefix": "s", "data_prefix": str(tmp_path / "s")}
    workflows._regenerate_target_files(led, base, str(tmp_path), "strict")
    urls = [l.strip() for l in open(base["url_file"])] if base.get("url_file") else []
    assert "http://example.com" in urls
    assert "https://example.com" in urls


# --- auto-injection behavior ----------------------------------------------

def test_no_nmap_injection_for_domains_only_run():
    items = [ModuleStep(name="ax_nuclei")]
    new_items, injected = _auto_inject_web_discovery(
        items, has_targets=False, has_domains=True, has_urls=False)
    assert "ax_nmap_tcp" not in injected
    # nuclei still present, nothing host-class prepended
    names = [i.name for i in new_items if isinstance(i, ModuleStep)]
    assert "ax_nmap_tcp" not in names
    assert "ax_nuclei" in names


def test_nmap_still_injected_with_t_targets():
    items = [ModuleStep(name="ax_nuclei")]
    new_items, injected = _auto_inject_web_discovery(
        items, has_targets=True, has_domains=False, has_urls=False)
    assert "ax_nmap_tcp" in injected


def test_no_injection_when_urls_present():
    items = [ModuleStep(name="ax_nuclei")]
    new_items, injected = _auto_inject_web_discovery(
        items, has_targets=True, has_domains=True, has_urls=True)
    assert injected == []
