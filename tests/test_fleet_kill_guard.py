"""kill_fleet interpolates the fleet name into a shell command; it must refuse
an unsafe name rather than run it (defense-in-depth, round-2 review)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core import fleet


def test_kill_fleet_rejects_unsafe_name(monkeypatch):
    calls = []
    monkeypatch.setattr(fleet, "bash_command", lambda *a, **k: calls.append(a))
    fleet.kill_fleet("evil'; rm -rf / #")
    assert calls == []  # never reached the shell


class _R:
    def __init__(self, rc=0, out="", err=""):
        self.returncode, self.stdout, self.stderr = rc, out, err


def _install_fake_ax(monkeypatch, ls_sequence):
    """Route bash_command: `ax rm` -> ok; `ax ls` -> next _R from ls_sequence.
    Records the commands run. Also spies iauth (real iauth shells out)."""
    cmds, reauths = [], []
    seq = list(ls_sequence)

    def _run(cmd, **k):
        cmds.append(cmd)
        if cmd.strip().startswith("ax ls"):
            return seq.pop(0) if seq else _R(0, "")
        return _R(0)                       # ax rm and anything else: success

    monkeypatch.setattr(fleet, "bash_command", _run)
    monkeypatch.setattr(fleet, "iauth", lambda account=None: reauths.append(account))
    return cmds, reauths


def test_kill_fleet_runs_for_safe_name(monkeypatch):
    cmds, reauths = _install_fake_ax(monkeypatch, [_R(0, "")])  # ls empty -> verified
    assert fleet.kill_fleet("monkeyx-a7f3") is True
    assert any("ax rm 'monkeyx-a7f3*'" in c for c in cmds)
    assert reauths == []                    # clean kill needs no reauth


def test_kill_fleet_verified_clean(monkeypatch):
    cmds, reauths = _install_fake_ax(monkeypatch, [_R(0, "")])
    assert fleet.kill_fleet("monkeyx-aa11", account="acct") is True


def test_kill_fleet_dead_auth_reauths_then_reports_unconfirmed(monkeypatch):
    # `ax ls` keeps failing (expired auth): reauth + retry once, then return
    # False (never a false "success") so the caller can flag an orphan.
    cmds, reauths = _install_fake_ax(monkeypatch,
                                     [_R(1, "", "not logged in"),
                                      _R(1, "", "unauthorized")])
    assert fleet.kill_fleet("monkeyx-bb22", account="acct") is False
    assert reauths == ["acct"]              # reauthed once, with the account
    assert sum(1 for c in cmds if c.startswith("ax rm")) == 2   # retried the kill


def test_kill_fleet_instances_remain_then_clean(monkeypatch):
    # First ls shows a straggler, retry clears it -> confirmed True.
    cmds, reauths = _install_fake_ax(monkeypatch,
                                     [_R(0, "monkeyx-cc33-01  running"),
                                      _R(0, "")])
    assert fleet.kill_fleet("monkeyx-cc33", account="acct") is True
    assert reauths == ["acct"]              # reauthed before the retry


def test_kill_fleet_instances_persist_reports_unconfirmed(monkeypatch):
    cmds, reauths = _install_fake_ax(monkeypatch,
                                     [_R(0, "monkeyx-dd44-01  running"),
                                      _R(0, "monkeyx-dd44-01  running")])
    assert fleet.kill_fleet("monkeyx-dd44") is False


def test_ax_ls_auth_error_detected(monkeypatch):
    monkeypatch.setattr(fleet, "bash_command",
                        lambda *a, **k: _R(0, "", "IAM token expired"))
    ok, _ = fleet._ax_ls()
    assert ok is False                      # auth error in stderr != empty fleet


# --- fleet reuse: a benign `ax ls` listing must not read as "absent" ----------

def test_fleet_exists_matches_despite_auth_substrings_in_listing(monkeypatch):
    # Regression: an `ax ls` listing containing substrings like "iam"/"token"
    # (IBM provider output, instance names) previously tripped the auth-error
    # heuristic -> fleet_exists said absent -> a DUPLICATE fleet got created.
    listing = ("mattvpc01   198.18.7.10   ibm-iam   running\n"
               "mattvpc02   198.18.7.11   ibm-iam   running\n")
    monkeypatch.setattr(fleet, "bash_command",
                        lambda *a, **k: _R(0, listing, ""))
    exists, count = fleet.fleet_exists("mattvpc")
    assert exists is True and count == 2          # reused, not re-created


def test_fleet_exists_false_when_absent(monkeypatch):
    monkeypatch.setattr(fleet, "bash_command",
                        lambda *a, **k: _R(0, "othervpc01  1.2.3.4  running\n", ""))
    assert fleet.fleet_exists("mattvpc") == (False, 0)


def test_fleet_exists_false_when_ax_ls_auth_fails(monkeypatch):
    monkeypatch.setattr(fleet, "bash_command",
                        lambda *a, **k: _R(1, "", "Error: not logged in"))
    assert fleet.fleet_exists("mattvpc") == (False, 0)


def test_ax_ls_not_fooled_by_stdout_substrings(monkeypatch):
    # stdout contains auth-ish words but the command succeeded (rc 0, no stderr).
    monkeypatch.setattr(fleet, "bash_command",
                        lambda *a, **k: _R(0, "sessionhost01  iam  token  running\n", ""))
    ok, lines = fleet._ax_ls()
    assert ok is True and len(lines) == 1


def test_initialize_fleet_translates_spinup_failure(monkeypatch, tmp_path):
    """`ax fleet` non-zero exit -> FleetSpinupError with remediation, not a bare
    CalledProcessError traceback (expired cloud session / missing Axiom image)."""
    import subprocess

    def boom(cmd, *a, **k):
        raise subprocess.CalledProcessError(1, cmd)

    monkeypatch.setattr(fleet, "bash_command", boom)
    import pytest
    with pytest.raises(fleet.FleetSpinupError) as ei:
        fleet.initialize_fleet("monkeyx-abcd", "1", str(tmp_path / "p"), False)
    msg = str(ei.value)
    assert "ax fleet" in msg and "axiom-images" in msg and "ibmcloud" in msg
    # the original CalledProcessError is chained for debugging
    assert isinstance(ei.value.__cause__, subprocess.CalledProcessError)
