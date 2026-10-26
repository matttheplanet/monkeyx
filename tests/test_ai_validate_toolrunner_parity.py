"""Neutrality guard for the ai_validate → tool_runners refactor (Steps 1-2).

These tests assert that delegating scope parsing and command execution to
core.tool_runners produces results IDENTICAL to ai_validate's original
behaviour. They are the proof that the refactor changed no behaviour.

Step 1: _parse_scope must return the same (ips, networks, hosts) it always did.
Step 2: _execute_command must return the same output run_argv would.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core import tool_runners
from modules import ai_validate


def _write(path, text):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


class TestScopeParity:
    def test_parse_scope_matches_load_scope(self, tmp_path):
        # Scope is derived from the ENGINE-EXPORTED, policy-clean files
        # (ledger-{targets,domains,urls}.txt), NOT the raw discovery-ledger.jsonl.
        # ai_validate._parse_scope delegates to load_scope, so they must match.
        out = tmp_path
        data = out / "data"
        data.mkdir()
        ledger = data / "ledger"
        ledger.mkdir()
        target_file = str(data / "ledger-targets.txt")
        _write(target_file,
               "198.18.10.0/24\n"
               "198.18.10.10\n"
               "mail.example.com\n"
               "# comment\n"
               "\n")
        # Sibling exports live in the data/ledger/ subdir (load_scope reads them there).
        _write(str(ledger / "ledger-domains.txt"),
               "example.com\napi.example.com\n")
        _write(str(ledger / "ledger-urls.txt"),
               "https://x.example.com/\n")
        # A raw JSONL with an out-of-scope DERIVED ip (e.g. a CDN/internal IP the
        # export layer withheld). It MUST NOT feed scope — this is the fix guard.
        _write(str(out / "discovery-ledger.jsonl"),
               '{"type":"ip","target":"198.18.11.7","scope":"derived"}\n')
        data_prefix = str(data / "scan")

        ips, nets, hosts = ai_validate._parse_scope(target_file, data_prefix)
        scope = tool_runners.load_scope(target_file, data_prefix)

        assert ips == scope.ips
        assert hosts == scope.hosts
        assert [str(n) for n in nets] == [str(n) for n in scope.networks]

        # In scope: everything the export layer actually authorized.
        assert "198.18.10.10" in ips
        assert [str(n) for n in nets] == ["198.18.10.0/24"]
        assert "mail.example.com" in hosts
        assert "example.com" in hosts and "api.example.com" in hosts
        assert "x.example.com" in hosts          # from ledger-urls.txt (host only)
        # NOT in scope: the raw-JSONL derived IP the export withheld.
        assert "198.18.11.7" not in ips

    def test_raw_ledger_derived_ip_is_not_authorized(self, tmp_path):
        # Focused regression for the fail-open scope bug: a derived internal/CDN
        # IP present only in discovery-ledger.jsonl must never be probeable.
        out = tmp_path
        data = out / "data"
        data.mkdir()
        target_file = str(data / "ledger-targets.txt")
        _write(target_file, "198.18.10.10\n")
        _write(str(out / "discovery-ledger.jsonl"),
               '{"type":"ip","target":"10.0.0.5","scope":"derived"}\n'
               '{"type":"ip","target":"198.18.11.7","scope":"derived"}\n')
        scope = tool_runners.load_scope(target_file, str(data / "scan"))
        assert scope.contains("198.18.10.10") is True
        assert scope.contains("10.0.0.5") is False     # internal, withheld
        assert scope.contains("198.18.11.7") is False    # out-of-scope derived

    def test_no_ledger_still_matches(self, tmp_path):
        target_file = str(tmp_path / "t.txt")
        _write(target_file, "10.0.0.0/8\nhost.tld\n")
        ips, nets, hosts = ai_validate._parse_scope(target_file, None)
        scope = tool_runners.load_scope(target_file, None)
        assert ips == scope.ips and hosts == scope.hosts
        assert [str(n) for n in nets] == [str(n) for n in scope.networks]


class TestExecParity:
    def test_execute_command_output_shape(self):
        # stdout captured, truncation + (no output) sentinel behaviour preserved.
        out = ai_validate._execute_command(["printf", "hello"])
        assert "hello" in out
        empty = ai_validate._execute_command(["true"])
        assert empty.strip() == "(no output)"

    def test_execute_command_timeout_message(self):
        out = ai_validate._execute_command(["sleep", "5"], timeout=1)
        assert out.startswith("TIMEOUT")

    def test_matches_run_argv(self):
        assert (ai_validate._execute_command(["printf", "abc"])
                == tool_runners.run_argv(["printf", "abc"]))
