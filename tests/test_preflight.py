"""`monkeyx --check` preflight: validate -t/-d/-url format, credentials, config
BEFORE a run — so e.g. masscan's 'invalid IP address on line #1' (a BOM / stray
char / hostname in a -t file) is caught up front, not after the fleet spins up.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core import preflight


def _w(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return str(p)


# --- targets (-t) ----------------------------------------------------------

def test_targets_valid_pass(tmp_path):
    r = preflight.Report()
    preflight.check_targets(_w(tmp_path, "t", "1.2.3.4\n10.0.0.0/24\nhost.example.com\n"), r)
    assert r.ok  # hostname is a note, not an error

def test_targets_bom_is_the_masscan_bug(tmp_path):
    r = preflight.Report()
    preflight.check_targets(_w(tmp_path, "t", "﻿1.2.3.4\n"), r)
    assert not r.ok
    assert any("BOM" in e and "masscan" in e for e in r.errors)

def test_targets_malformed_ip_flagged(tmp_path):
    r = preflight.Report()
    preflight.check_targets(_w(tmp_path, "t", "999.1.1.1\n10.0.0.256\n1.2.3\n"), r)
    assert len(r.errors) == 3
    assert all("malformed IP" in e for e in r.errors)

def test_targets_url_and_bad_cidr_flagged(tmp_path):
    r = preflight.Report()
    preflight.check_targets(_w(tmp_path, "t", "http://x.com/y\n10.0.0.0/99\n"), r)
    assert len(r.errors) == 2

def test_targets_comments_and_blanks_skipped(tmp_path):
    r = preflight.Report()
    preflight.check_targets(_w(tmp_path, "t", "# comment\n\n1.2.3.4\n"), r)
    assert r.ok


# --- domains (-d) ----------------------------------------------------------

def test_domains_reject_ip_and_url(tmp_path):
    r = preflight.Report()
    preflight.check_domains(_w(tmp_path, "d", "example.com\n8.8.8.8\nhttps://x.com\n"), r)
    assert len(r.errors) == 2  # the IP and the URL; the bare domain is fine


# --- urls (-url) -----------------------------------------------------------

def test_urls_require_http_scheme_and_host(tmp_path):
    r = preflight.Report()
    preflight.check_urls(_w(tmp_path, "u", "https://a.com/x\nftp://nope\nnotaurl\n"), r)
    assert len(r.errors) == 2


# --- credentials -----------------------------------------------------------

def test_credentials_placeholder_ai_key_errors_when_ai_required(monkeypatch):
    from core import credentials
    monkeypatch.setattr(credentials, "load_credentials",
                        lambda: {"ai": {"default_provider": "anthropic",
                                        "anthropic": {"api_key": "sk-ant-YOUR-KEY-HERE"}}})
    monkeypatch.setattr(credentials, "get_enrichment_key", lambda s: None)
    monkeypatch.delenv("MONKEYX_AI_API_KEY", raising=False)
    monkeypatch.delenv("MONKEYX_AI_PROVIDER", raising=False)
    r = preflight.Report()
    preflight.check_credentials(r, ai_required=True)
    assert any("PLACEHOLDER" in e for e in r.errors)

def test_credentials_placeholder_ai_key_ok_when_ai_not_selected(monkeypatch):
    # AI is opt-in: a placeholder/missing AI key must NOT fail --check for a run
    # that selects no AI modules (the common case).
    from core import credentials
    monkeypatch.setattr(credentials, "load_credentials",
                        lambda: {"ai": {"default_provider": "anthropic",
                                        "anthropic": {"api_key": "sk-ant-YOUR-KEY-HERE"}}})
    monkeypatch.setattr(credentials, "get_enrichment_key", lambda s: None)
    monkeypatch.delenv("MONKEYX_AI_API_KEY", raising=False)
    monkeypatch.delenv("MONKEYX_AI_PROVIDER", raising=False)
    r = preflight.Report()
    preflight.check_credentials(r, ai_required=False)
    assert r.ok  # placeholder is informational, not an error, when no AI selected

def test_credentials_claude_code_autodetect_no_false_fail(monkeypatch):
    # No AI provider configured but the `claude` CLI is on PATH: the engine
    # auto-selects claude-code (no key needed), so preflight must not false-fail
    # even when an AI module IS selected.
    from core import credentials
    monkeypatch.setattr(credentials, "load_credentials", lambda: {"ai": {}})
    monkeypatch.setattr(credentials, "get_enrichment_key", lambda s: None)
    monkeypatch.setattr(credentials.shutil, "which", lambda name: "/usr/bin/claude")
    monkeypatch.delenv("MONKEYX_AI_API_KEY", raising=False)
    monkeypatch.delenv("MONKEYX_AI_PROVIDER", raising=False)
    r = preflight.Report()
    preflight.check_credentials(r, ai_required=True)
    assert r.ok  # claude-code auto-detected -> needs no key
    assert any("claude-code" in n for n in r.notes)

def test_credentials_no_provider_no_cli_errors_only_when_ai_required(monkeypatch):
    from core import credentials
    monkeypatch.setattr(credentials, "load_credentials", lambda: {"ai": {}})
    monkeypatch.setattr(credentials, "get_enrichment_key", lambda s: None)
    monkeypatch.setattr(credentials.shutil, "which", lambda name: None)
    monkeypatch.delenv("MONKEYX_AI_API_KEY", raising=False)
    monkeypatch.delenv("MONKEYX_AI_PROVIDER", raising=False)
    # AI selected -> no provider is a real problem -> error
    r1 = preflight.Report()
    preflight.check_credentials(r1, ai_required=True)
    assert not r1.ok
    # AI not selected -> informational, check still passes
    r2 = preflight.Report()
    preflight.check_credentials(r2, ai_required=False)
    assert r2.ok

def test_credentials_real_ai_key_ok(monkeypatch):
    from core import credentials
    monkeypatch.setattr(credentials, "load_credentials",
                        lambda: {"ai": {"default_provider": "anthropic",
                                        "anthropic": {"api_key": "sk-ant-areallkeyvalue123"}}})
    monkeypatch.setattr(credentials, "get_enrichment_key", lambda s: None)
    monkeypatch.delenv("MONKEYX_AI_API_KEY", raising=False)
    monkeypatch.delenv("MONKEYX_AI_PROVIDER", raising=False)
    r = preflight.Report()
    preflight.check_credentials(r)
    assert r.ok

def test_credentials_ollama_needs_no_key(monkeypatch):
    from core import credentials
    monkeypatch.setattr(credentials, "load_credentials",
                        lambda: {"ai": {"default_provider": "ollama", "ollama": {}}})
    monkeypatch.setattr(credentials, "get_enrichment_key", lambda s: None)
    monkeypatch.delenv("MONKEYX_AI_PROVIDER", raising=False)
    r = preflight.Report()
    preflight.check_credentials(r)
    assert r.ok

def test_placeholder_detection():
    assert preflight._is_placeholder("sk-ant-YOUR-KEY-HERE")
    assert preflight._is_placeholder("YOUR-SHODAN-KEY")
    assert preflight._is_placeholder("<set me>")
    assert not preflight._is_placeholder("sk-ant-abc123realkey")
    assert not preflight._is_placeholder("")


# --- disk space -----------------------------------------------------------

def test_disk_error_below_hard_floor(tmp_path, monkeypatch):
    # Simulate ~2 GB free -> hard error (ENOSPC almost certain).
    import os as _os
    fake = _os.statvfs_result = type("S", (), {"f_bavail": 2, "f_frsize": 1024 ** 3})()
    monkeypatch.setattr(preflight.os, "statvfs", lambda p: fake)
    r = preflight.Report()
    preflight.check_disk_space(str(tmp_path), r)
    assert not r.ok
    assert any("No space left" in e or "GB free" in e for e in r.errors)


def test_disk_warn_below_soft_floor(tmp_path, monkeypatch):
    # ~12 GB free -> warn (between 5 and 20), not an error.
    fake = type("S", (), {"f_bavail": 12, "f_frsize": 1024 ** 3})()
    monkeypatch.setattr(preflight.os, "statvfs", lambda p: fake)
    r = preflight.Report()
    preflight.check_disk_space(str(tmp_path), r)
    assert r.ok and r.warnings


def test_disk_ample_is_a_note(tmp_path, monkeypatch):
    fake = type("S", (), {"f_bavail": 500, "f_frsize": 1024 ** 3})()
    monkeypatch.setattr(preflight.os, "statvfs", lambda p: fake)
    r = preflight.Report()
    preflight.check_disk_space(str(tmp_path), r)
    assert r.ok and not r.warnings and r.notes


def test_disk_probes_existing_ancestor_when_dir_absent(tmp_path, monkeypatch):
    # Output dir doesn't exist yet -> must statvfs an existing ancestor, not crash.
    seen = {}
    fake = type("S", (), {"f_bavail": 500, "f_frsize": 1024 ** 3})()
    def _sv(p):
        seen["path"] = p
        return fake
    monkeypatch.setattr(preflight.os, "statvfs", _sv)
    missing = str(tmp_path / "does" / "not" / "exist")
    r = preflight.Report()
    preflight.check_disk_space(missing, r)
    assert os.path.exists(seen["path"])  # resolved to a real ancestor


def test_disk_failure_is_a_warning_not_a_crash(tmp_path, monkeypatch):
    def _boom(p):
        raise OSError("statvfs blew up")
    monkeypatch.setattr(preflight.os, "statvfs", _boom)
    r = preflight.Report()
    preflight.check_disk_space(str(tmp_path), r)
    assert r.ok and any("could not determine free space" in w for w in r.warnings)


# ---- axiom / nMap_Merger presence (the DO-root 127 class) ----
def _fake_axiom(tmp_path, with_merger=True, executable=True):
    import core.config as cfg
    ax = tmp_path / ".axiom"
    (ax / "interact").mkdir(parents=True)
    if with_merger:
        m = ax / "interact" / "nMap_Merger.py"
        m.write_text("#!/usr/bin/env python3\n")
        m.chmod(0o755 if executable else 0o644)
    return ax


def test_axiom_missing_dir_warns(tmp_path, monkeypatch):
    import core.config as cfg
    monkeypatch.setattr(cfg, "AXIOM_PATH", str(tmp_path / "nope" / ".axiom"))
    r = preflight.Report()
    preflight.check_axiom(r)
    assert r.ok and any("not found" in w and "ax" in w.lower() for w in r.warnings)


def test_axiom_missing_merger_warns(tmp_path, monkeypatch):
    import core.config as cfg
    ax = _fake_axiom(tmp_path, with_merger=False)
    monkeypatch.setattr(cfg, "AXIOM_PATH", str(ax))
    r = preflight.Report()
    preflight.check_axiom(r)
    assert r.ok and any("nMap_Merger.py missing" in w or "127" in w for w in r.warnings)


def test_axiom_merger_not_executable_warns(tmp_path, monkeypatch):
    import core.config as cfg
    ax = _fake_axiom(tmp_path, executable=False)
    monkeypatch.setattr(cfg, "AXIOM_PATH", str(ax))
    r = preflight.Report()
    preflight.check_axiom(r)
    assert r.ok and any("not executable" in w for w in r.warnings)


def test_axiom_ok_notes_no_warning(tmp_path, monkeypatch):
    import core.config as cfg
    ax = _fake_axiom(tmp_path)
    monkeypatch.setattr(cfg, "AXIOM_PATH", str(ax))
    r = preflight.Report()
    preflight.check_axiom(r)
    assert r.ok and not r.warnings and any("OK" in n for n in r.notes)
