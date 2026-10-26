"""Tests for the httpx-live URL prune (export_urls_live).

The prune feeds heavy web scanners only httpx-confirmed-live URLs, so thousands
of dead historical/crawled URLs (gau/katana) don't hit the fleet — while never
dropping URLs on a host httpx hasn't covered (fail-open).
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import core.target_ledger as tl
from core.target_ledger import TargetLedger, TYPE_URL


def _ledger(tmp_path, monkeypatch):
    # export_urls* resolves hostnames for the private-IP filter; disable it so
    # these unit tests never touch the network.
    monkeypatch.setattr(tl, "_PRIVATE_FILTER_ENABLED", False)
    return TargetLedger(str(tmp_path))


def _log(led, *urls):
    for u in urls:
        led.log_discovery(u, TYPE_URL, "ax_gau")


def _live(led, tmp_path):
    out = str(tmp_path / "urls-live.txt")
    n = led.export_urls_live(out, "none")
    with open(out) as f:
        return sorted(l.strip() for l in f if l.strip())


def test_covered_host_prunes_dead_keeps_live(tmp_path, monkeypatch):
    led = _ledger(tmp_path, monkeypatch)
    _log(led, "http://a.example.com/live", "http://a.example.com/d1",
         "http://a.example.com/d2", "http://a.example.com/d3")
    led.record_httpx_result("http://a.example.com/live", 200)
    assert _live(led, tmp_path) == ["http://a.example.com/live"]


def test_uncovered_host_fails_open(tmp_path, monkeypatch):
    led = _ledger(tmp_path, monkeypatch)
    _log(led, "http://b.example.com/x", "http://b.example.com/y")
    # no httpx result for b.example.com -> both kept
    assert _live(led, tmp_path) == ["http://b.example.com/x", "http://b.example.com/y"]


def test_policy_interesting_drops_404(tmp_path, monkeypatch):
    led = _ledger(tmp_path, monkeypatch)
    _log(led, "http://c.example.com/ok", "http://c.example.com/nf")
    led.record_httpx_result("http://c.example.com/ok", 200)
    led.record_httpx_result("http://c.example.com/nf", 404)
    out = str(tmp_path / "u.txt")
    led.export_urls_live(out, "none", policy="interesting")
    interesting = sorted(l.strip() for l in open(out) if l.strip())
    assert interesting == ["http://c.example.com/ok"]
    # under "live", the 404 responder is kept
    led.export_urls_live(out, "none", policy="live")
    live = sorted(l.strip() for l in open(out) if l.strip())
    assert live == ["http://c.example.com/nf", "http://c.example.com/ok"]


def test_max_per_host_caps(tmp_path, monkeypatch):
    led = _ledger(tmp_path, monkeypatch)
    _log(led, *[f"http://d.example.com/p{i}" for i in range(10)])  # uncovered -> fail-open
    out = str(tmp_path / "u.txt")
    led.export_urls_live(out, "none", max_per_host=3)
    assert len([l for l in open(out) if l.strip()]) == 3


def test_live_is_subset_of_full(tmp_path, monkeypatch):
    led = _ledger(tmp_path, monkeypatch)
    _log(led, "http://e.example.com/a", "http://e.example.com/b", "http://e.example.com/c")
    led.record_httpx_result("http://e.example.com/a", 200)
    full_path, live_path = str(tmp_path / "full.txt"), str(tmp_path / "live.txt")
    full = led.export_urls(full_path, "none")
    live = led.export_urls_live(live_path, "none")
    assert live <= full and live == 1


# --- wiring: scanner remap + httpx auto-injection ------------------------- #

import workflows
import monkeyx
from workflows import ModuleStep, ParallelGroup


def test_live_url_kwargs_remaps_only_heavy_scanners(tmp_path):
    live = tmp_path / "live.txt"
    live.write_text("http://x/\n")
    kw = {"url_file": str(tmp_path / "full.txt"), "url_file_live": str(live)}

    # heavy scanner -> remapped to the live file
    assert workflows._live_url_kwargs("ax_nuclei", dict(kw))["url_file"] == str(live)
    # discovery module (needs full list) -> unchanged
    assert workflows._live_url_kwargs("ax_katana", dict(kw))["url_file"] == kw["url_file"]
    # the prober itself -> unchanged
    assert workflows._live_url_kwargs("ax_httpx", dict(kw))["url_file"] == kw["url_file"]


def _flat(items):
    out = []
    for it in items:
        if isinstance(it, str):
            out.append(it)
        elif isinstance(it, ModuleStep):
            out.append(it.name)
        elif isinstance(it, ParallelGroup):
            out += [s.name for s in it.steps]
    return out


def test_httpx_injected_before_first_scanner():
    new, injected = monkeyx._auto_inject_httpx_for_prune(["ax_katana", "ax_nuclei", "ax_gowitness"])
    assert injected == ["ax_httpx"]
    flat = _flat(new)
    assert flat.index("ax_httpx") < flat.index("ax_nuclei")


def test_httpx_not_injected_when_already_present():
    new, injected = monkeyx._auto_inject_httpx_for_prune(["ax_httpx", "ax_nuclei"])
    assert injected == []


def test_httpx_not_injected_without_scanners():
    new, injected = monkeyx._auto_inject_httpx_for_prune(["subfinder", "dnsx_resolve", "normalize"])
    assert injected == []


def test_member_kwargs_carries_pruned_url_file(tmp_path):
    # A parallel-group member's kwargs (used for BOTH the run and the step
    # snapshot) must carry the remapped live URL file, so the forensic snapshot
    # reflects what the scanner was actually fed.
    live = tmp_path / "live.txt"
    live.write_text("http://x/\n")
    base = {"url_file": str(tmp_path / "full.txt"), "url_file_live": str(live)}
    mk = workflows._member_kwargs(ModuleStep(name="ax_nuclei"), base, str(tmp_path))
    assert mk["url_file"] == str(live)
