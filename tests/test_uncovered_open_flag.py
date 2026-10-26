"""uncovered_ip_targets must not false-positive on scanned-but-quiet hosts.

Root cause of a real run's "416 in-scope targets produced no results" warning:
the scans run with `--open`, so nmap OMITS the <host> element for a host with
zero open ports. The merged XML therefore contains only open-port hosts, and the
old fed-vs-merged diff flagged every scanned-but-quiet host as "uncovered." That
false warning also set status=warning, which (before the ingest fix) dropped the
run's real open ports. The fix re-checks each missing IP against its own per-host
result file: a completed <runstats> scan == covered, even with no <host>.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import core.scanning as scanning

# A per-host nmap XML as `--open` writes it for a host with NO open ports:
# a successful runstats, but NO <host> element.
_SCANNED_QUIET = ('<?xml version="1.0"?><nmaprun>'
                  '<runstats><finished exit="success"/>'
                  '<hosts up="1" down="0" total="1"/></runstats></nmaprun>')
# An incomplete / failed artifact (truncated pull): no usable runstats.
_INCOMPLETE = '<?xml version="1.0"?><nmaprun><taskbegin/></nmaprun>'

_MERGED = ('<?xml version="1.0"?><nmaprun>'
           '<host><status state="up"/><address addr="198.18.10.1" addrtype="ipv4"/>'
           '<ports><port portid="443"><state state="open"/></port></ports></host>'
           '</nmaprun>')


def _setup(tmp_path):
    # Fed four literal IPs.
    tf = tmp_path / "targets.txt"
    tf.write_text("198.18.10.1\n198.18.10.2\n198.18.10.3\n198.18.10.4\n")
    # Merged XML has only the open-port host (.1).
    merged = tmp_path / "scan.xml"
    merged.write_text(_MERGED)
    # Per-host folder: .2 scanned-quiet (ok), .4 incomplete, .3 has NO file.
    folder = tmp_path / "scan"
    folder.mkdir()
    (folder / "198.18.10.2.xml").write_text(_SCANNED_QUIET)
    (folder / "198.18.10.4.xml").write_text(_INCOMPLETE)
    return str(tf), str(merged), str(folder)


def test_quiet_scanned_host_not_flagged(tmp_path):
    tf, merged, folder = _setup(tmp_path)
    # .1 covered (in merged), .2 covered (scanned, no open ports) ->
    # only .3 (no file) and .4 (incomplete) are genuine gaps.
    assert scanning.uncovered_ip_targets(tf, merged, folder) == ["198.18.10.3", "198.18.10.4"]


def test_without_folder_falls_back_to_merged_only(tmp_path):
    tf, merged, _ = _setup(tmp_path)
    # Legacy behavior (over-reports the quiet host) when no per-host folder given.
    assert scanning.uncovered_ip_targets(tf, merged) == \
        ["198.18.10.2", "198.18.10.3", "198.18.10.4"]


def test_all_scanned_quiet_is_fully_covered(tmp_path):
    # The real-run shape: many fed IPs, none open -> empty merged, but all have
    # completed per-host files -> ZERO uncovered (not "all uncovered").
    tf = tmp_path / "t.txt"
    ips = [f"198.18.10.{i}" for i in range(1, 11)]
    tf.write_text("\n".join(ips) + "\n")
    merged = tmp_path / "m.xml"
    merged.write_text('<?xml version="1.0"?><nmaprun></nmaprun>')
    folder = tmp_path / "s"
    folder.mkdir()
    for ip in ips:
        (folder / f"{ip}.xml").write_text(_SCANNED_QUIET)
    assert scanning.uncovered_ip_targets(str(tf), str(merged), str(folder)) == []


def test_no_target_file_returns_empty(tmp_path):
    assert scanning.uncovered_ip_targets(None, "nope.xml", None) == []
