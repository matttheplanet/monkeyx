"""Axiom account resolution: --ax-account flag > AXIOM_ACCOUNT env > monkeyx.config.

The account can now be set once in monkeyx.config under `fleet.account`, instead
of exporting AXIOM_ACCOUNT or passing --ax-account every run. The flag and env
var still take precedence.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core import config, fleet


def _reset_fleet_cache():
    config._fleet_config_cache = None


def test_get_axiom_account_reads_fleet_account(monkeypatch):
    _reset_fleet_cache()
    monkeypatch.setattr(config, "load_fleet_config", lambda: {"account": "cfg-acct"})
    assert config.get_axiom_account() == "cfg-acct"


def test_get_axiom_account_none_when_unset(monkeypatch):
    monkeypatch.setattr(config, "load_fleet_config", lambda: {})
    assert config.get_axiom_account() is None


def test_iauth_uses_config_when_no_flag_or_env(monkeypatch):
    monkeypatch.delenv("AXIOM_ACCOUNT", raising=False)
    monkeypatch.setattr(config, "get_axiom_account", lambda: "cfg-acct")
    captured = {}

    def _fake_run(argv, **kwargs):
        captured["argv"] = argv
        class _R:  # noqa: E301
            returncode = 0
            stderr = ""
        return _R()

    monkeypatch.setattr("subprocess.run", _fake_run)
    fleet.iauth(None)
    # The config account reached the `ax account '<name>'` command.
    assert "cfg-acct" in captured["argv"][-1]


def test_env_beats_config(monkeypatch):
    monkeypatch.setenv("AXIOM_ACCOUNT", "env-acct")
    monkeypatch.setattr(config, "get_axiom_account", lambda: "cfg-acct")
    captured = {}

    def _fake_run(argv, **kwargs):
        captured["argv"] = argv
        class _R:  # noqa: E301
            returncode = 0
            stderr = ""
        return _R()

    monkeypatch.setattr("subprocess.run", _fake_run)
    fleet.iauth(None)
    assert "env-acct" in captured["argv"][-1]
    assert "cfg-acct" not in captured["argv"][-1]


def test_flag_beats_env_and_config(monkeypatch):
    monkeypatch.setenv("AXIOM_ACCOUNT", "env-acct")
    monkeypatch.setattr(config, "get_axiom_account", lambda: "cfg-acct")
    captured = {}

    def _fake_run(argv, **kwargs):
        captured["argv"] = argv
        class _R:  # noqa: E301
            returncode = 0
            stderr = ""
        return _R()

    monkeypatch.setattr("subprocess.run", _fake_run)
    fleet.iauth("flag-acct")
    assert "flag-acct" in captured["argv"][-1]
