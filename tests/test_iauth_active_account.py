"""Teardown re-auth must work even when no account was explicitly configured.

Orphaned-fleet cause: a long run's cloud session (e.g. IBM Cloud IAM token)
expires; on Ctrl-C teardown, kill_fleet re-auths via iauth and retries `ax rm`.
iauth runs `ax account <name>`, which re-runs the provider login (for IBM,
`ibmcloud login --apikey`). But if no account was set (--ax-account / AXIOM_ACCOUNT
/ fleet.account), iauth used to skip entirely → the expired session was never
refreshed → orphaned, billing instances. Now iauth falls back to the account
currently selected in ~/.axiom (the one that created the fleet).
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core import fleet


def _make_axiom(tmp_path, account="myacct"):
    """Build a fake ~/.axiom with axiom.json -> accounts/<account>.json."""
    ax = tmp_path / ".axiom"
    (ax / "accounts").mkdir(parents=True)
    (ax / "accounts" / f"{account}.json").write_text("{}")
    os.symlink(ax / "accounts" / f"{account}.json", ax / "axiom.json")
    return str(ax)


def test_active_account_resolved_from_symlink(tmp_path, monkeypatch):
    monkeypatch.setenv("AXIOM_PATH", _make_axiom(tmp_path, "ibmvpc"))
    assert fleet._active_axiom_account() == "ibmvpc"


def test_active_account_none_when_not_symlink(tmp_path, monkeypatch):
    ax = tmp_path / ".axiom"
    ax.mkdir()
    (ax / "axiom.json").write_text("{}")  # plain file, not a symlink to accounts/
    monkeypatch.setenv("AXIOM_PATH", str(ax))
    assert fleet._active_axiom_account() is None


def test_active_account_none_when_missing(tmp_path, monkeypatch):
    monkeypatch.setenv("AXIOM_PATH", str(tmp_path / "nope"))
    assert fleet._active_axiom_account() is None


def test_iauth_falls_back_to_active_account(tmp_path, monkeypatch):
    # No explicit account anywhere, but an active account is selected in ~/.axiom.
    monkeypatch.setenv("AXIOM_PATH", _make_axiom(tmp_path, "ibmvpc"))
    monkeypatch.delenv("AXIOM_ACCOUNT", raising=False)
    monkeypatch.setattr("core.config.get_axiom_account", lambda: None, raising=False)

    calls = []

    class _R:
        returncode = 0
        stderr = ""
    monkeypatch.setattr("subprocess.run", lambda *a, **k: calls.append(a[0]) or _R())

    fleet.iauth()  # account=None -> should resolve to the active account

    # It ran `ax account 'ibmvpc'` to refresh the session.
    assert any("ax account 'ibmvpc'" in " ".join(c) for c in calls), calls
