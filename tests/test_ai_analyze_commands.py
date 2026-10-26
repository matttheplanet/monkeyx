"""Tests for ai_analyze fabricated-command detection.

ai_analyze's recommendation pass can hallucinate exploit scripts/binaries that
look real but don't exist (e.g. `python3 exploit_CVE-2024-1234.py`). The
post-filter flags those without touching commands that invoke real CLI tools.
"""

import os
import sys
import types
import importlib.util

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def _load_module():
    # Stub heavy deps so the module imports standalone (no AI/network/core deps).
    # Save/restore sys.modules so these stubs don't leak into other test modules
    # (which import the real core.* packages).
    stub_names = ["core", "core.credentials", "core.knowledge", "core.ai_provider", "core.utils"]
    saved = {name: sys.modules.get(name) for name in stub_names}
    try:
        for name in stub_names:
            sys.modules[name] = types.ModuleType(name)
        sys.modules["core.credentials"].get_ai_provider = lambda *a, **k: None
        sys.modules["core.ai_provider"].AIProvider = object
        sys.modules["core.ai_provider"].display_model_name = lambda *a, **k: "model"
        sys.modules["core.utils"].version_output_path = lambda *a, **k: None
        spec = importlib.util.spec_from_file_location(
            "ai_analyze_under_test",
            os.path.join(os.path.dirname(__file__), "..", "modules", "ai_analyze.py"),
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    finally:
        for name, prev in saved.items():
            if prev is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = prev


az = _load_module()


class TestCommandIsSuspect:
    def test_real_tools_not_flagged(self):
        for cmd in [
            "curl -sk https://H1/admin",
            "nmap --script ftp-anon -p21 H1",
            "hydra -l admin -P rockyou.txt ssh://H1",
            "sqlmap -u 'https://H1/x?id=1' --batch",
            "msfconsole -q -x 'use exploit/linux/http/foo; run'",
            "nuclei -u https://H1 -tags cve",
            'python3 -c "import socket"',
            "bash -c 'curl H1 | sh'",
        ]:
            assert az._command_is_suspect(cmd) is False, cmd

    def test_fabricated_artifacts_flagged(self):
        for cmd in [
            "python3 exploit_CVE-2024-1234.py --target H1",
            "./poc.sh H1 443",
            "ruby cve_2023_9999.rb H1",
            "./exploit",
            "perl smb_pwn.pl H1",
        ]:
            assert az._command_is_suspect(cmd) is True, cmd

    def test_empty_and_nonstring(self):
        assert az._command_is_suspect("") is False
        assert az._command_is_suspect(None) is False


class TestFlagFabricatedCommands:
    def test_prefixes_only_suspect_commands(self):
        result = {
            "quick_wins": [
                {"action": "x", "commands": [
                    "python3 exploit_CVE-2024-1234.py --target H1",
                    "curl -sk https://H1/",
                ]}
            ],
            "attack_chains": [],
            "requires_verification": [],
            "cve_research": [],
        }
        az._flag_fabricated_commands(result)
        cmds = result["quick_wins"][0]["commands"]
        assert cmds[0].startswith("[UNVERIFIED")
        assert "exploit_CVE-2024-1234.py" in cmds[0]
        assert cmds[1] == "curl -sk https://H1/"  # untouched

    def test_idempotent(self):
        result = {"quick_wins": [{"commands": ["./poc.sh H1"]}]}
        az._flag_fabricated_commands(result)
        az._flag_fabricated_commands(result)
        # Marker applied exactly once.
        assert result["quick_wins"][0]["commands"][0].count("[UNVERIFIED") == 1

    def test_handles_missing_or_malformed(self):
        # Should not raise on odd shapes.
        az._flag_fabricated_commands({})
        az._flag_fabricated_commands({"quick_wins": [{"commands": None}]})
        az._flag_fabricated_commands({"quick_wins": ["not-a-dict"]})
