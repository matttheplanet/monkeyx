"""bbot output parsing must honor bbot's own `wildcard` event tag.

bbot tags DNS_NAME/URL events that resolved only via a wildcard/catch-all record.
Those are phantom hosts (random labels, different every run) — logging them wastes
scan time and pollutes findings. IP_ADDRESS events are kept (the shared IP is real).
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.target_ledger import TargetLedger, TYPE_SUBDOMAIN
from workflows import _log_discoveries_from_bbot_jsonl


def _write_jsonl(path, events):
    with open(path, "w") as f:
        for ev in events:
            f.write(json.dumps(ev) + "\n")


def test_wildcard_tagged_dns_name_skipped(tmp_path):
    domains = tmp_path / "domains.txt"
    domains.write_text("foo.com\n")
    led = TargetLedger(str(tmp_path))
    led.seed_user_inputs(None, str(domains), None)

    jsonl = str(tmp_path / "bbot.jsonl")
    _write_jsonl(jsonl, [
        {"type": "DNS_NAME", "data": "real.foo.com", "tags": ["subdomain"]},
        {"type": "DNS_NAME", "data": "x9q7z.foo.com", "tags": ["wildcard", "subdomain"]},
        {"type": "URL", "data": "http://z8k2.foo.com/", "tags": ["wildcard"]},
    ])

    _log_discoveries_from_bbot_jsonl(jsonl, "bbot_recon", led)

    out = str(tmp_path / "ledger-domains.txt")
    led.export_domains(out, scope_filter="strict")
    with open(out) as f:
        lines = [ln.strip() for ln in f if ln.strip()]
    assert "real.foo.com" in lines
    assert "x9q7z.foo.com" not in lines
    assert "z8k2.foo.com" not in "\n".join(lines)
    led.close()


def test_ip_address_kept_regardless_of_wildcard_tag(tmp_path):
    targets = tmp_path / "targets.txt"
    targets.write_text("198.18.10.10\n")
    led = TargetLedger(str(tmp_path))
    led.seed_user_inputs(str(targets), None, None)

    jsonl = str(tmp_path / "bbot.jsonl")
    # A wildcard-tagged IP_ADDRESS: the underlying IP is real, keep it.
    _write_jsonl(jsonl, [{"type": "IP_ADDRESS", "data": "198.18.10.10", "tags": ["wildcard"]}])
    _log_discoveries_from_bbot_jsonl(jsonl, "bbot_recon", led)

    out = str(tmp_path / "ledger-targets.txt")
    led.export_targets(out, scope_filter="strict")
    with open(out) as f:
        assert "198.18.10.10" in f.read()
    led.close()
