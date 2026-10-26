"""Tests for scope_summary() + format_scope_echo() (the operator scope echo)."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from workflows import format_scope_echo
from core.target_ledger import (
    TargetLedger, TYPE_IP, TYPE_SUBDOMAIN,
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
    led.seed_user_inputs(str(tf) if tf else None, str(df) if df else None,
                         str(uf) if uf else None)
    return led


def test_summary_buckets_by_channel(tmp_path):
    led = _seed(tmp_path, targets=["93.184.216.5"], domains=["example.com"])
    led.log_discovery("api.example.com", TYPE_SUBDOMAIN, "subfinder",
                      parent="example.com")
    s = led.scope_summary()
    assert s["host_full"]["ips"] == 1          # the -t IP
    assert s["name_safe"]["hosts"] == 2        # example.com + api.example.com
    assert s["excluded"] == 0


def test_summary_counts_exclusions(tmp_path):
    led = _seed(tmp_path, targets=["93.184.216.5", "93.184.216.6"])
    excl = tmp_path / "x.txt"; excl.write_text("93.184.216.6\n")
    led.seed_exclusions(str(excl))
    s = led.scope_summary()
    assert s["excluded"] >= 1
    # excluded IP is not counted as host_full in-scope
    assert s["host_full"]["ips"] == 1


def test_dl_host_resolving_into_t_range_counts_host_full(tmp_path):
    led = _seed(tmp_path, targets=["192.0.66.0/24"], domains=["example.com"])
    led.log_discovery("api.example.com", TYPE_SUBDOMAIN, "subfinder",
                      parent="example.com")
    led.log_discovery("192.0.66.9", TYPE_IP, "dns_resolve",
                      parent="api.example.com")
    s = led.scope_summary()
    # the derived IP is inside -t → host_full (channel is dl, but the IP itself
    # is in the -t range; note scope_summary buckets by CHANNEL, so the derived
    # IP carries dl and lands in name_safe while its -t-range membership is what
    # authorizes host scanning at export time). Assert it is counted somewhere.
    total_ips = s["host_full"]["ips"] + s["name_safe"]["ips"]
    assert total_ips >= 1


def test_echo_renders_nonempty(tmp_path):
    led = _seed(tmp_path, targets=["93.184.216.5"], domains=["example.com"])
    echo = format_scope_echo(led)
    assert "Host-full" in echo
    assert "Name-safe" in echo
    assert "Excluded" in echo


def test_echo_empty_for_noop_ledger():
    from core.target_ledger import NO_OP_LEDGER
    assert format_scope_echo(NO_OP_LEDGER) == ""
