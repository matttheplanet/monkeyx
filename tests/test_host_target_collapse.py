"""Tests for host-class target collapse (export_host_targets).

HOST-class port scanners (nmap/naabu/masscan/...) are fed UNIQUE IPs, not one
line per resolved hostname — so a shared IP that many in-scope names resolve to
is scanned ONCE, not once per name. NAME/web modules still read the
name-expanded ledger-targets.txt (export_targets), so vhost/SNI coverage is
unaffected.

Two invariants the collapse must never violate:
  #1 an unresolved -t name is still scanned (by name) — never silently dropped;
  #2 a name resolving to multiple IPs contributes ALL of them (union).

Uses PUBLIC, non-documentation IPs on purpose: RFC1918 and the TEST-NET ranges
are stripped by the private-IP export filter before the scope gate runs.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.target_ledger import TargetLedger, TYPE_IP


def _read(path):
    with open(path) as f:
        return sorted(line.strip() for line in f if line.strip())


def _seed(tmp_path, mode="provenance", targets_text=None, domains_text=None):
    if targets_text is not None:
        (tmp_path / "t.txt").write_text(targets_text)
    if domains_text is not None:
        (tmp_path / "d.txt").write_text(domains_text)
    led = TargetLedger(str(tmp_path))
    led.set_ip_scope_mode(mode)
    led.seed_user_inputs(
        str(tmp_path / "t.txt") if targets_text is not None else None,
        str(tmp_path / "d.txt") if domains_text is not None else None,
        None,
    )
    return led


def _host_targets(led, tmp_path, scope_filter="none"):
    out = str(tmp_path / "h.txt")
    led.export_host_targets(out, scope_filter)
    return _read(out)


def test_many_names_one_ip_collapse_to_single_ip(tmp_path):
    # The headline case: hundreds of in-scope names on one IP must not become
    # hundreds of scan targets for that IP.
    led = _seed(tmp_path, targets_text="app.example.com\napi.example.com\nwww.example.com\n")
    for name in ("app.example.com", "api.example.com", "www.example.com"):
        led.log_discovery("198.18.10.10", TYPE_IP, "dns_resolve", parent=name)

    assert _host_targets(led, tmp_path) == ["198.18.10.10"]

    # Contrast: the name-expanded file (fed to NAME/web modules) is unchanged.
    name_out = str(tmp_path / "names.txt")
    led.export_targets(name_out, "none")
    assert set(_read(name_out)) == {"app.example.com", "api.example.com", "www.example.com"}


def test_multi_ip_name_unions_all_ips(tmp_path):
    # #2 — a round-robin/GeoDNS name must contribute every IP it resolves to.
    led = _seed(tmp_path, targets_text="multi.example.com\n")
    led.log_discovery("198.18.10.10", TYPE_IP, "dns_resolve", parent="multi.example.com")
    led.log_discovery("104.16.5.5", TYPE_IP, "dns_resolve", parent="multi.example.com")

    assert _host_targets(led, tmp_path) == ["104.16.5.5", "198.18.10.10"]


def test_unresolved_t_name_falls_back_to_hostname(tmp_path):
    # #1 — a -t name that has not resolved yet is scanned by name, not dropped.
    led = _seed(tmp_path, targets_text="unresolved.example.com\n")
    assert _host_targets(led, tmp_path) == ["unresolved.example.com"]


def test_resolved_name_emitted_as_ip_not_name(tmp_path):
    led = _seed(tmp_path, targets_text="web.example.com\n")
    led.log_discovery("198.18.10.10", TYPE_IP, "dns_resolve", parent="web.example.com")
    lines = _host_targets(led, tmp_path)
    assert "198.18.10.10" in lines
    assert "web.example.com" not in lines  # resolved -> represented by its IP


def test_explicit_t_ip_and_cidr_pass_through(tmp_path):
    led = _seed(tmp_path, targets_text="8.8.8.8\n198.18.10.0/24\n")
    assert _host_targets(led, tmp_path) == ["198.18.10.0/24", "8.8.8.8"]


def test_strict_resolved_out_of_range_name_not_readded(tmp_path):
    # A -t name resolving OUTSIDE the -t ranges is dropped by strict-resolved and
    # must NOT be re-added by the unresolved-name fallback (that would defeat
    # strict's intent). The -t CIDR itself still survives.
    led = _seed(tmp_path, mode="strict-resolved",
                targets_text="198.18.10.0/24\noutrange.example.com\n")
    led.log_discovery("9.9.9.9", TYPE_IP, "dns_resolve", parent="outrange.example.com")
    lines = _host_targets(led, tmp_path)
    assert "198.18.10.0/24" in lines
    assert "9.9.9.9" not in lines             # out-of-range named IP dropped
    assert "outrange.example.com" not in lines  # not re-added by name


def test_dl_name_not_host_scanned(tmp_path):
    # A -d name is name-safe only: neither it nor its resolved IP may appear in
    # a HOST-class target list (no -t authorization).
    led = _seed(tmp_path, domains_text="shared.example.com\n")
    led.log_discovery("198.18.10.10", TYPE_IP, "dns_resolve", parent="shared.example.com")
    lines = _host_targets(led, tmp_path)
    assert "198.18.10.10" not in lines
    assert "shared.example.com" not in lines
