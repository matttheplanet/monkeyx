"""_resolve_target_arg: inline targets vs file-path detection.

Regression: a CIDR passed inline ('-t 140.95.0.0/16') was rejected as a
"file path that doesn't exist" because it contains '/', which tripped the
os.sep path heuristic. IPs/CIDRs must be treated as inline data.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

import monkeyx


@pytest.mark.parametrize("tok", [
    "140.95.0.0/16", "10.0.0.0/8", "2001:db8::/32",   # CIDRs
    "1.2.3.4", "::1",                                  # bare IPs
])
def test_cidr_and_ip_treated_as_inline(tok, tmp_path):
    path = monkeyx._resolve_target_arg(tok, str(tmp_path), "targets")
    assert open(path).read().strip() == tok


def test_comma_separated_cidrs(tmp_path):
    path = monkeyx._resolve_target_arg("10.0.0.0/8, 192.168.0.0/16",
                                       str(tmp_path), "targets")
    assert open(path).read().split() == ["10.0.0.0/8", "192.168.0.0/16"]


@pytest.mark.parametrize("bad", [
    "./targets/x.txt", "targets.txt", "/tmp/nope/does-not-exist-list",
    "sub/dir/hosts.lst",
])
def test_missing_file_path_still_rejected(bad, tmp_path):
    with pytest.raises(FileNotFoundError):
        monkeyx._resolve_target_arg(bad, str(tmp_path), "targets")


def test_existing_file_returned_unchanged(tmp_path):
    f = tmp_path / "real-targets.txt"
    f.write_text("1.2.3.4\n")
    assert monkeyx._resolve_target_arg(str(f), str(tmp_path), "targets") == str(f)


def test_hostname_inline_ok(tmp_path):
    path = monkeyx._resolve_target_arg("host.example.com", str(tmp_path), "targets")
    assert open(path).read().strip() == "host.example.com"
