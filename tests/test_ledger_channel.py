"""Tests for input-channel authorization tracking in the target ledger.

The channel (t/dl/ul) is the ceiling that host-class vs name-class module
gating reads. These tests pin down: seed assignment, derived inheritance via the
parent chain, highest-authorization-wins precedence, lead (no-channel) targets,
JSONL persistence, and channel restoration on reload.
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.target_ledger import (
    TargetLedger, TYPE_IP, TYPE_DOMAIN, TYPE_SUBDOMAIN, TYPE_URL,
    CHANNEL_TARGET, CHANNEL_DOMAIN, CHANNEL_URL, _channel_max,
)


def _seed(tmp_path, targets=None, domains=None, urls=None):
    tf = df = uf = None
    if targets is not None:
        tf = tmp_path / "t.txt"; tf.write_text("\n".join(targets) + "\n")
    if domains is not None:
        df = tmp_path / "d.txt"; df.write_text("\n".join(domains) + "\n")
    if urls is not None:
        uf = tmp_path / "u.txt"; uf.write_text("\n".join(urls) + "\n")
    led = TargetLedger(str(tmp_path))
    led.seed_user_inputs(str(tf) if tf else None,
                         str(df) if df else None,
                         str(uf) if uf else None)
    return led


def test_channel_max_precedence():
    assert _channel_max(CHANNEL_TARGET, CHANNEL_DOMAIN) == CHANNEL_TARGET
    assert _channel_max(CHANNEL_DOMAIN, CHANNEL_URL) == CHANNEL_DOMAIN
    assert _channel_max(CHANNEL_URL, None) == CHANNEL_URL
    assert _channel_max(None, None) is None
    assert _channel_max(CHANNEL_DOMAIN, CHANNEL_TARGET) == CHANNEL_TARGET  # order-agnostic


def test_seed_assigns_channels(tmp_path):
    led = _seed(tmp_path, targets=["10.0.0.1"], domains=["example.com"],
                urls=["https://app.example.com"])
    assert led.get_channel("10.0.0.1", TYPE_IP) == CHANNEL_TARGET
    assert led.get_channel("example.com", TYPE_DOMAIN) == CHANNEL_DOMAIN
    assert led.get_channel("https://app.example.com", TYPE_URL) == CHANNEL_URL


def test_derived_subdomain_inherits_dl(tmp_path):
    led = _seed(tmp_path, domains=["example.com"])
    led.log_discovery("api.example.com", TYPE_SUBDOMAIN, "subfinder",
                      parent="example.com")
    assert led.get_channel("api.example.com", TYPE_SUBDOMAIN) == CHANNEL_DOMAIN


def test_derived_ip_from_dl_name_inherits_dl_not_target(tmp_path):
    """The core safety property: an IP discovered only because a -d name
    resolved to it is name-safe (dl), NOT fully-authorized (t)."""
    led = _seed(tmp_path, domains=["example.com"])
    led.log_discovery("api.example.com", TYPE_SUBDOMAIN, "subfinder",
                      parent="example.com")
    led.log_discovery("203.0.113.9", TYPE_IP, "dns_resolve",
                      parent="api.example.com")
    assert led.get_channel("203.0.113.9", TYPE_IP) == CHANNEL_DOMAIN


def test_derived_ip_from_t_host_inherits_target(tmp_path):
    led = _seed(tmp_path, targets=["host.example.com"])
    led.log_discovery("203.0.113.10", TYPE_IP, "dns_resolve",
                      parent="host.example.com")
    assert led.get_channel("203.0.113.10", TYPE_IP) == CHANNEL_TARGET


def test_highest_channel_wins_when_reachable_from_both(tmp_path):
    """A host reachable from both a -t entry and a -d name is authorized at t."""
    led = _seed(tmp_path, targets=["203.0.113.20"], domains=["example.com"])
    # discovered as resolving from a -d subdomain too
    led.log_discovery("sub.example.com", TYPE_SUBDOMAIN, "subfinder",
                      parent="example.com")
    led.log_discovery("203.0.113.20", TYPE_IP, "dns_resolve",
                      parent="sub.example.com")
    # explicit -t channel must not be downgraded to dl
    assert led.get_channel("203.0.113.20", TYPE_IP) == CHANNEL_TARGET


def test_lead_has_no_channel(tmp_path):
    """A discovery with no in-scope parent is a lead — no channel, host-gated out."""
    led = _seed(tmp_path, targets=["10.0.0.1"])
    led.log_discovery("unrelated.evil.com", TYPE_SUBDOMAIN, "bbot",
                      parent="evil.com")
    assert led.get_channel("unrelated.evil.com", TYPE_SUBDOMAIN) is None


def test_channel_persisted_to_jsonl(tmp_path):
    led = _seed(tmp_path, domains=["example.com"])
    led.log_discovery("api.example.com", TYPE_SUBDOMAIN, "subfinder",
                      parent="example.com")
    entries = [json.loads(l) for l in open(led.path) if l.strip()]
    by_target = {e["target"]: e for e in entries if e.get("type") in
                 (TYPE_DOMAIN, TYPE_SUBDOMAIN)}
    assert by_target["example.com"]["channel"] == CHANNEL_DOMAIN
    assert by_target["api.example.com"]["channel"] == CHANNEL_DOMAIN


def test_channel_restored_on_reload(tmp_path):
    led = _seed(tmp_path, targets=["203.0.113.1"], domains=["example.com"])
    led.log_discovery("api.example.com", TYPE_SUBDOMAIN, "subfinder",
                      parent="example.com")
    led.log_discovery("198.51.100.5", TYPE_IP, "dns_resolve",
                      parent="api.example.com")

    led2 = TargetLedger(str(tmp_path))
    led2.load_from_disk()
    assert led2.get_channel("203.0.113.1", TYPE_IP) == CHANNEL_TARGET
    assert led2.get_channel("example.com", TYPE_DOMAIN) == CHANNEL_DOMAIN
    assert led2.get_channel("api.example.com", TYPE_SUBDOMAIN) == CHANNEL_DOMAIN
    assert led2.get_channel("198.51.100.5", TYPE_IP) == CHANNEL_DOMAIN


class TestAuthorizationChannel:
    """`_authorization_channel` is the display/audit ceiling the scan.db `channel`
    column (and the web viewer's "access" badge) reads. It must mirror the export
    gate: host-full ("t") only when a HOST-class scan is actually authorized —
    via -t directly or ownership-promotion into a -t range — else the name-safe
    channel, else None for a lead."""

    def test_t_ip_is_host_full(self, tmp_path):
        led = _seed(tmp_path, targets=["203.0.113.5"])
        assert led._authorization_channel("203.0.113.5", TYPE_IP) == CHANNEL_TARGET

    def test_dl_derived_ip_no_t_is_name_safe(self, tmp_path):
        """No -t range at all: a -d-resolved IP is name-safe (dl), never host-full
        — this is the case the viewer used to mislabel as scannable in_scope."""
        led = _seed(tmp_path, domains=["example.com"])
        led.log_discovery("api.example.com", TYPE_SUBDOMAIN, "subfinder",
                          parent="example.com")
        led.log_discovery("198.51.100.7", TYPE_IP, "dns_resolve",
                          parent="api.example.com")
        assert led._authorization_channel("198.51.100.7", TYPE_IP) == CHANNEL_DOMAIN

    def test_dl_ip_promoted_into_t_range_is_host_full(self, tmp_path):
        """Ownership promotion: a -d-resolved IP that lands inside a -t CIDR is
        owned address space, so it reports host-full even though it arrived via dl."""
        led = _seed(tmp_path, targets=["203.0.113.0/24"], domains=["example.com"])
        led.log_discovery("api.example.com", TYPE_SUBDOMAIN, "subfinder",
                          parent="example.com")
        led.log_discovery("203.0.113.42", TYPE_IP, "dns_resolve",
                          parent="api.example.com")
        assert led._authorization_channel("203.0.113.42", TYPE_IP) == CHANNEL_TARGET

    def test_dl_name_resolving_into_t_range_is_host_full(self, tmp_path):
        led = _seed(tmp_path, targets=["203.0.113.0/24"], domains=["example.com"])
        led.log_discovery("api.example.com", TYPE_SUBDOMAIN, "subfinder",
                          parent="example.com")
        led.log_discovery("203.0.113.42", TYPE_IP, "dns_resolve",
                          parent="api.example.com")
        host_to_ips = led.get_hostname_to_ips()
        assert led._authorization_channel(
            "api.example.com", TYPE_SUBDOMAIN, host_to_ips) == CHANNEL_TARGET

    def test_dl_name_resolving_outside_t_range_stays_name_safe(self, tmp_path):
        led = _seed(tmp_path, targets=["203.0.113.0/24"], domains=["example.com"])
        led.log_discovery("api.example.com", TYPE_SUBDOMAIN, "subfinder",
                          parent="example.com")
        led.log_discovery("198.51.100.7", TYPE_IP, "dns_resolve",
                          parent="api.example.com")
        host_to_ips = led.get_hostname_to_ips()
        assert led._authorization_channel(
            "api.example.com", TYPE_SUBDOMAIN, host_to_ips) == CHANNEL_DOMAIN

    def test_lead_has_no_channel(self, tmp_path):
        led = _seed(tmp_path, targets=["10.0.0.1"])
        led.log_discovery("unrelated.evil.com", TYPE_SUBDOMAIN, "bbot",
                          parent="evil.com")
        assert led._authorization_channel(
            "unrelated.evil.com", TYPE_SUBDOMAIN) is None


def test_reload_reseeds_channel_for_pre_field_ledger(tmp_path):
    """A ledger written before the channel field still gets correct channels for
    explicit targets on reload (re-seeded from the explicit sets)."""
    # Simulate an old ledger: entries with scope but no channel key.
    path = tmp_path / "discovery-ledger.jsonl"
    rows = [
        {"target": "10.0.0.1", "type": TYPE_IP, "source": "user_input",
         "scope": "explicit", "parent": None},
        {"target": "example.com", "type": TYPE_DOMAIN, "source": "user_input",
         "scope": "explicit", "parent": None},
    ]
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n")

    led = TargetLedger(str(tmp_path))
    led.load_from_disk()
    assert led.get_channel("10.0.0.1", TYPE_IP) == CHANNEL_TARGET
    assert led.get_channel("example.com", TYPE_DOMAIN) == CHANNEL_DOMAIN
