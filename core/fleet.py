"""Fleet management functions for MonkeyX."""

import logging
import math
import os
import secrets
import subprocess
import threading

from .utils import bash_command

logger = logging.getLogger("monkeyx.core.fleet")

# IPs and URLs have very different per-node throughput: a "target" IP means a
# full nmap (slow, ~60 IPs/node with the 4x DOS-safety margin), while a URL is a
# single nuclei/httpx pass (much lighter). Sizing URL-driven steps by the IP
# ratio would either wildly under-provision (few IPs, thousands of URLs — the
# real bug this fixes) or, if reused directly, over-provision. So URL-consuming
# steps get their own, higher ratio. Both are overridable via monkeyx.config
# `fleet.targets_per_node` / `fleet.urls_per_node`.
TARGETS_PER_NODE = 60
URLS_PER_NODE = 150

# Fleet sizing counts a CIDR by the hosts it covers, but CAPPED at this many per
# range — so a /16 sizes a bigger fleet than a single IP without demanding one
# node per address for mostly-empty space (common for ISP ranges). The hard
# `--max-nodes` cap still bounds the total. 0 disables (a CIDR counts as 1 entry,
# the legacy behavior). Overridable via monkeyx.config `fleet.cidr_host_cap`.
CIDR_HOST_CAP = 1024


def _cidr_host_cap() -> int:
    try:
        from core.config import load_fleet_config
        cap = load_fleet_config().get("cidr_host_cap")
        return int(cap) if cap is not None else CIDR_HOST_CAP
    except Exception:
        return CIDR_HOST_CAP


# Seconds to wait for `ax account <name>` (which re-runs the slow provider login,
# e.g. `ibmcloud login`). 60s proved too short — IBM Cloud login can exceed a
# minute, and a premature kill leaves the account un-switched. Tunable via
# MONKEYX_AX_AUTH_TIMEOUT; 0/blank/invalid => no timeout (wait indefinitely).
AX_AUTH_TIMEOUT = 300


def _ax_auth_timeout():
    raw = os.environ.get("MONKEYX_AX_AUTH_TIMEOUT")
    if raw is None:
        return AX_AUTH_TIMEOUT
    try:
        val = int(raw)
    except ValueError:
        return AX_AUTH_TIMEOUT
    return val if val > 0 else None   # 0 => no timeout


def count_ip_workload(ip_entries, cidr_host_cap: int | None = None) -> int:
    """Host-equivalent count for a set of IP/CIDR strings, for fleet sizing.

    A bare IP counts 1; a CIDR counts min(hosts_in_range, cap) so large ranges
    size a proportionally bigger (but bounded) fleet. Unparseable entries count
    1. cap<=0 (or legacy callers) → every entry counts 1.
    """
    import ipaddress
    cap = _cidr_host_cap() if cidr_host_cap is None else cidr_host_cap
    total = 0
    for entry in ip_entries:
        s = str(entry)
        if "/" in s:
            try:
                hosts = ipaddress.ip_network(s, strict=False).num_addresses
            except ValueError:
                total += 1
                continue
            total += min(hosts, cap) if cap and cap > 0 else 1
        else:
            total += 1
    return total


def _per_node_ratios() -> tuple[int, int]:
    """(targets_per_node, urls_per_node), config-overridable, with safe fallbacks."""
    tpn, upn = TARGETS_PER_NODE, URLS_PER_NODE
    try:
        from core.config import load_fleet_config
        cfg = load_fleet_config()
        tpn = int(cfg.get("targets_per_node") or tpn) or tpn
        upn = int(cfg.get("urls_per_node") or upn) or upn
    except Exception:
        pass
    return tpn, upn


def _active_axiom_account():
    """The Axiom account currently selected in ~/.axiom, or None.

    axiom switches accounts by symlinking ~/.axiom/axiom.json ->
    accounts/<name>.json, so the active account name is the resolved target's
    basename. Honors $AXIOM_PATH. Returns None if it can't be resolved to a real
    accounts/<name>.json (e.g. axiom.json is a plain file, not the symlink), so
    callers skip auth rather than running `ax account axiom`."""
    import os
    axiom_path = os.environ.get('AXIOM_PATH') or os.path.expanduser('~/.axiom')
    link = os.path.join(axiom_path, 'axiom.json')
    try:
        target = os.path.realpath(link)
    except OSError:
        return None
    parent, fn = os.path.split(target)
    if os.path.basename(parent) != 'accounts' or not fn.endswith('.json'):
        return None
    name = fn[:-len('.json')]
    return name or None


def iauth(account=None):
    """Initialize Axiom Authentication.

    Args:
        account: Axiom account name (the --ax-account flag). If None, falls back
                 to the AXIOM_ACCOUNT env var, then to monkeyx.config's
                 ``fleet.account``, then to the active account selected in
                 ~/.axiom (so teardown re-auth can refresh the session that
                 created the fleet). If still None, auth is skipped.
    """
    import logging
    import os
    import re
    import subprocess

    logger = logging.getLogger('monkeyx.core.fleet')
    # Resolution order (highest wins): --ax-account flag (passed in) > AXIOM_ACCOUNT
    # env var > monkeyx.config fleet.account. Env beats file, matching the rest of
    # MonkeyX's config precedence.
    account = account or os.environ.get('AXIOM_ACCOUNT')
    if not account:
        try:
            from core.config import get_axiom_account
            account = get_axiom_account()
        except Exception:  # pragma: no cover - config is best-effort
            account = None
    if not account:
        # Last resort: the account currently SELECTED in ~/.axiom (the one that
        # created this fleet). `ax account <name>` re-runs the provider login
        # (e.g. `ibmcloud login --apikey` for IBM), so this lets teardown refresh
        # an expired cloud session — the common orphaned-fleet cause — even when
        # nothing was explicitly configured (no --ax-account/env/fleet.account).
        account = _active_axiom_account()
        if account:
            logger.info("Axiom auth: no explicit account; using the active "
                        "account '%s' (from ~/.axiom/axiom.json)", account)
    if not account:
        print('[*] No Axiom account specified (set AXIOM_ACCOUNT, pass --ax-account, or set fleet.account in monkeyx.config). Skipping auth.')
        logger.info("Axiom auth skipped — no account specified")
        return
    # Validate: account names are simple identifiers. This also guards the
    # AXIOM_ACCOUNT env-var path, which does not pass through argparse's
    # shell_safe_str validator.
    if not re.fullmatch(r'[A-Za-z0-9_.\-]{1,100}', account):
        logger.error("Invalid Axiom account name %r — skipping auth", account)
        print(f"[!] Invalid Axiom account name {account!r} — skipping auth")
        return
    # `ax account <name>` re-runs the PROVIDER LOGIN (e.g. `ibmcloud login
    # --apikey`), which can be slow — IBM Cloud login routinely exceeds a minute.
    # If this times out, the account switch DOESN'T happen and the run continues
    # on the wrong/previous account, so `ax fleet` then fails with a confusing
    # "imageid ... not found". Hence a generous default (300s), tunable via
    # MONKEYX_AX_AUTH_TIMEOUT (seconds; 0/blank = no timeout).
    timeout = _ax_auth_timeout()
    print(f'Authenticating Axiom (account: {account})')
    try:
        result = subprocess.run(
            ['/bin/bash', '-c', f"ax account '{account}'"],
            capture_output=True, text=True, timeout=timeout,
            # Close stdin: a scan is non-interactive, so if the provider login
            # (`ibmcloud login`) tries to PROMPT (region/account/re-auth), it must
            # get EOF and fail fast — NOT block forever waiting on a tty. The login
            # has to be non-interactive (set IBMCLOUD_API_KEY + a default region).
            stdin=subprocess.DEVNULL,
        )
        if result.returncode != 0:
            logger.error("Axiom auth failed (exit %d) for account '%s': %s",
                         result.returncode, account, result.stderr.strip())
            print(f"[!] Axiom auth failed (exit {result.returncode}): {result.stderr.strip()}")
        else:
            logger.info("Axiom auth successful for account '%s'", account)
    except subprocess.TimeoutExpired:
        # The account switch + provider login didn't finish in time. We continue
        # on whatever session is already active, but if the account wasn't
        # actually switched the fleet step will likely fail with "imageid not
        # found" — so point the operator at the real remedy. WARNING, not ERROR.
        logger.warning("Axiom auth (`ax account %s`) timed out after %ss — the "
                       "account may not have switched; continuing on the active "
                       "session", account, timeout)
        print(f"[*] Axiom auth (`ax account {account}`) timed out after {timeout}s — "
              f"the account may NOT have switched.\n"
              f"    If the fleet step fails with 'imageid not found', the login was "
              f"just slow: run `ax account {account}` once by hand, or raise "
              f"MONKEYX_AX_AUTH_TIMEOUT (seconds).")
    except Exception as e:
        logger.error("Axiom auth raised exception for account '%s': %s", account, e)
        print(f"[!] Axiom auth error: {e}")


class FleetSpinupError(Exception):
    """`ax fleet` spin-up failed — almost always an ax/cloud-provider problem
    (expired cloud session, no region targeted, or a missing/stale Axiom image),
    NOT a MonkeyX bug. Carries an operator-facing remediation message so the CLI
    can print guidance instead of a raw traceback."""


_FLEET_SPINUP_HELP = (
    "[!] Axiom fleet spin-up failed (`ax fleet`). This is almost always an\n"
    "    ax / cloud-provider issue, not MonkeyX — see the `ax` error printed\n"
    "    just above for the specific cause. Common fixes:\n"
    "\n"
    "    • Expired cloud session / no region targeted:\n"
    "        ibmcloud login --apikey \"$IBMCLOUD_API_KEY\" -r <region>\n"
    "        ibmcloud target            # confirm a region is shown\n"
    "      (Set IBMCLOUD_API_KEY in the environment so the session doesn't\n"
    "       expire mid-run.)\n"
    "\n"
    "    • Missing/stale Axiom image (`imageid ... not found`):\n"
    "        axiom-images ls                               # what exists\n"
    "        axiom-images select axiom-<provisioner>-<ts>  # point axiom.json at it\n"
    "        axiom-build --setup                           # or rebuild one\n"
)


def initialize_fleet(fleet, nodes, prefix, wait):
    """Initialize and spin up an Axiom fleet.

    Args:
        fleet: Unique name for the Axiom fleet
        nodes: Number of scan nodes to spin up
        prefix: Output name prefix for files
        wait: Whether to wait for user confirmation before proceeding

    Raises:
        FleetSpinupError: if `ax fleet` exits non-zero (expired cloud session,
            missing Axiom image, …) — carries operator remediation guidance.
    """
    # Spin up fleet
    spinup = f"ax fleet '{fleet}' -i '{nodes}'"
    try:
        bash_command(spinup)
    except subprocess.CalledProcessError as e:
        # `ax fleet` already streamed its own error above; translate the non-zero
        # exit into a clear, actionable failure rather than a bare traceback.
        raise FleetSpinupError(_FLEET_SPINUP_HELP) from e

    get_source_ips = f"ax ls | grep -i '{fleet}' | tr -s ' ' | cut -d ' ' -f 2 | tee '{prefix}-axiom-source-ips.txt'"
    bash_command(get_source_ips)
    print("Axiom scan ips written to axiom-source-ips.txt")

    if wait:
        try:
            input("Axiom scan ready. Press Enter to continue, or Ctrl+C to abort: ")
        except KeyboardInterrupt:
            print("\nAborted.")
            raise



# Substrings that mean an `ax` command failed on AUTHENTICATION rather than
# returning a genuine (possibly empty) result. On a long run the cloud session
# can expire; without this, a dead-auth `ax ls` looks like "fleet is gone" and a
# dead-auth `ax rm` looks like "kill succeeded" — silently orphaning instances.
# Specific auth-FAILURE phrases only. Deliberately NOT bare substrings like
# "token"/"session"/"iam"/"auth"/"401"/"403": those appear in normal `ax ls`
# listings (IBM "iam", instance/VPC names, …) and would false-positive — which
# previously broke fleet REUSE (fleet_exists treated a benign listing as a failed
# command and reported the fleet absent, spinning up a duplicate).
_AUTH_ERROR_MARKERS = (
    "not logged in", "not authenticated", "please log in", "please login",
    "login required", "unauthorized", "unauthenticated", "authentication failed",
    "auth failed", "token expired", "expired token", "session expired",
    "invalid credentials", "credentials not", "access denied",
    "permission denied", "reauthenticate", "re-authenticate",
)


def _looks_like_auth_error(text: str) -> bool:
    low = (text or "").lower()
    return any(m in low for m in _AUTH_ERROR_MARKERS)


def _ax_ls():
    """Run `ax ls` and return (ok, lines).

    ``ok`` is False when the command itself failed (non-zero exit or an
    auth-error signature) — distinct from a successful run that lists nothing.
    Callers must NOT treat ``ok=False`` as "no instances": under expired auth
    `ax ls` returns nothing, which would otherwise read as an empty fleet.
    """
    result = bash_command("ax ls", capture_output=True, check=False)
    if result is None:
        return (False, [])
    rc = getattr(result, "returncode", 0) or 0
    out = getattr(result, "stdout", "") or ""
    err = getattr(result, "stderr", "") or ""
    # Auth failures surface on STDERR (or a non-zero exit); do NOT scan stdout —
    # the listing is data, and auth-phrase substrings legitimately appear in
    # instance/provider names and would false-positive.
    if rc != 0 or _looks_like_auth_error(err):
        return (False, out.splitlines())
    return (True, [l for l in out.splitlines() if l.strip()])


def fleet_exists(fleet_name):
    """Check if a fleet with the given name is running.

    Returns (exists, node_count). NOTE: a failed `ax ls` (e.g. expired auth) is
    reported as (False, 0) for back-compat, but a warning is logged — callers
    that must not orphan instances should use kill_fleet (which reauths + verifies)
    rather than trusting this alone.
    """
    ok, lines = _ax_ls()
    # A name match in the listing means the fleet EXISTS — trust it regardless of
    # the ok flag (so a benign listing never reads as "absent" and triggers a
    # duplicate spin-up). Only when nothing matches AND the command failed do we
    # warn that we couldn't confirm.
    matched = [l for l in lines if fleet_name.lower() in l.lower()]
    if matched:
        return (True, len(matched))
    if not ok:
        logger.warning("fleet_exists: `ax ls` failed (auth/command error) — "
                       "cannot confirm state of '%s'", fleet_name)
    return (False, 0)


def _remaining_instances(fleet: str):
    """(ok, count) of instances still matching ``fleet``. ok=False = `ax ls`
    itself failed (don't trust the count)."""
    ok, lines = _ax_ls()
    if not ok:
        return (False, 0)
    return (True, len([l for l in lines if fleet.lower() in l.lower()]))


def _is_no_cloud_fleet(fleet) -> bool:
    """True when `fleet` is the sentinel for a run with NO cloud fleet.

    "local" is used throughout MonkeyX (monkeyx.py, workflows.py) to mean "run
    tools on the local box, no Axiom cloud fleet". A local-only run has no cloud
    instances, so tearing it down with `ax rm 'local*'` is wrong (and alarming in
    the logs). Empty/None means the same. Matches the guard the early-kill and
    CLI fleet-init paths already apply, so teardown honors the same invariant.
    """
    return not fleet or str(fleet).strip().lower() == "local"


def kill_fleet(fleet, account=None, verify=True) -> bool:
    """Kill an Axiom fleet and VERIFY it's gone. Returns True iff confirmed empty.

    Hardened against the silent-orphan failure mode: a plain `ax rm` swallowed
    all errors and reported success even when auth had expired, leaving live
    (billing) instances behind. Now:
      * after `ax rm`, we verify via `ax ls`;
      * if verification fails (auth/command error) or instances remain, we
        re-auth (``iauth``) and retry the kill ONCE;
      * if it still can't be confirmed, we WARN loudly with the manual command
        and return False, so the caller can surface an orphaned-fleet warning
        instead of a false "killed successfully".
    """
    # No cloud fleet to tear down (local-only / no-fleet run) — never `ax rm`
    # the "local" sentinel. Return True: nothing to kill IS a confirmed-empty
    # teardown.
    if _is_no_cloud_fleet(fleet):
        logger.info("kill_fleet: no cloud fleet (%r) — nothing to tear down", fleet)
        return True

    print("Killing Axiom fleet")
    # Defense-in-depth: `fleet` is interpolated into a shell command. Callers are
    # expected to pass a validated name (the API/CLI do), but guard here too — a
    # value with a single quote or other shell metachar could otherwise break out
    # of the quotes. Rejecting rather than sanitizing keeps the contract obvious.
    import re
    if not fleet or not re.fullmatch(r'[A-Za-z0-9_.\-]{1,100}', str(fleet)):
        print(f"[!] Refusing fleet cleanup for unsafe name: {fleet!r}")
        logger.error("kill_fleet: refusing unsafe fleet name %r", fleet)
        return False

    def _rm():
        try:
            bash_command(f"ax rm '{fleet}*' -f", check=False)
        except Exception as e:  # noqa: BLE001
            logger.warning("kill_fleet: `ax rm` raised for '%s': %s", fleet, e)

    for attempt in (1, 2):
        _rm()
        if not verify:
            return True
        ok, remaining = _remaining_instances(fleet)
        if ok and remaining == 0:
            print(f"[+] Fleet '{fleet}' teardown verified — no instances remain")
            logger.info("Fleet '%s' teardown verified empty", fleet)
            return True
        # Either `ax ls` failed (likely dead auth) or instances still remain.
        if attempt == 1:
            why = "could not verify (ax ls failed — auth?)" if not ok \
                  else f"{remaining} instance(s) still present"
            logger.warning("kill_fleet: '%s' %s after rm — re-authing and retrying",
                            fleet, why)
            print(f"[*] Fleet '{fleet}' teardown unconfirmed ({why}) — re-authing and retrying")
            iauth(account)   # refresh the (possibly expired) cloud session

    # Second attempt still didn't confirm removal — surface loudly, don't lie.
    msg = (f"[!] ORPHANED FLEET RISK: could not confirm teardown of '{fleet}'. "
           f"Instances may still be running and billing. Re-auth and run manually: "
           f"ax rm '{fleet}*' -f")
    print(msg)
    logger.error("kill_fleet: unconfirmed teardown of '%s' — possible orphaned instances", fleet)
    return False


def kill_fleet_with_retries(fleet, expected_nodes=None, max_seconds=900, poll_seconds=30):
    """Kill an Axiom fleet, polling long enough to catch instances still provisioning.

    Cloud instances take 300+ seconds to fully come up. If Ctrl+C fires during
    fleet init, some instances may not yet appear in `ax ls` — a single `ax rm`
    will miss them and they'll finish provisioning afterward.

    Algorithm (two phases):

      Phase A (settle): wait for the fleet to finish provisioning before
        attempting the kill. If `expected_nodes` is provided, wait until
        `ax ls` shows that many instances. Otherwise wait until the visible
        count stays stable (no growth) across several consecutive polls.

      Phase B (drain): issue `ax rm`, then poll until the fleet stays empty
        across a streak of consecutive checks. Re-issues kill any time
        stragglers reappear.

    A second Ctrl+C during either phase aborts and prints the manual
    cleanup command.

    Args:
        fleet: Fleet name prefix
        expected_nodes: Number of nodes originally requested, if known. Lets
            Phase A finish as soon as all are visible, and lets Phase B trust
            an empty reading sooner (2 consecutive empties).
        max_seconds: Hard cap on total time spent (default 900s = 15 min)
        poll_seconds: Sleep between polls (default 30s)
    """
    import time
    import logging
    logger = logging.getLogger("monkeyx.core.fleet")

    if _is_no_cloud_fleet(fleet):
        logger.info("kill_fleet_with_retries: no cloud fleet (%r) — nothing to tear down", fleet)
        return

    start = time.monotonic()

    print(f"[*] Polling for up to {max_seconds}s to safely tear down fleet '{fleet}'.")
    if expected_nodes:
        print(f"[*] Will wait for {expected_nodes} nodes to become visible before issuing kill.")
    print(f"[*] Press Ctrl+C again to abort polling (you'll need to run 'ax rm \"{fleet}*\" -f' manually).")

    try:
        # ---- Phase A: wait for spin-up to settle ----
        last_count = -1
        plateau_polls = 0
        plateau_threshold = 3   # 3 polls × 30s = 90s of no growth → assume done provisioning
        phase_a_max = 480       # 8 min cap on settle wait

        while time.monotonic() - start < min(phase_a_max, max_seconds):
            exists, count = fleet_exists(fleet)
            elapsed = int(time.monotonic() - start)

            if expected_nodes and count >= expected_nodes:
                print(f"[*] Settle phase: all {count}/{expected_nodes} nodes visible after {elapsed}s — proceeding to kill")
                logger.info("Fleet '%s' settled with all %d nodes visible after %ds",
                            fleet, count, elapsed)
                break

            if count == last_count and count > 0:
                plateau_polls += 1
                tag = f"{count}/{expected_nodes}" if expected_nodes else str(count)
                print(f"[*] Settle phase ({elapsed}s): {tag} nodes visible — stable {plateau_polls}/{plateau_threshold}")
                if plateau_polls >= plateau_threshold:
                    print(f"[*] Settle phase: count stable at {count} for {plateau_polls * poll_seconds}s — proceeding to kill")
                    logger.info("Fleet '%s' plateaued at %d nodes after %ds", fleet, count, elapsed)
                    break
            else:
                plateau_polls = 0
                last_count = count
                tag = f"{count}/{expected_nodes}" if expected_nodes else str(count)
                print(f"[*] Settle phase ({elapsed}s): {tag} nodes visible — waiting for spin-up")

            time.sleep(poll_seconds)
        else:
            print(f"[*] Settle phase reached time cap — proceeding to kill")
            logger.warning("Fleet '%s' settle phase hit %ds cap", fleet, phase_a_max)

        # ---- Phase B: kill, then drain ----
        kill_fleet(fleet)

        # If we knew the expected count, we can trust empty readings sooner.
        # Otherwise be more paranoid in case a straggler shows up later.
        stable_empty_checks = 2 if expected_nodes else 6
        empty_streak = 0
        poll_num = 0

        while time.monotonic() - start < max_seconds:
            time.sleep(poll_seconds)
            poll_num += 1
            exists, count = fleet_exists(fleet)
            elapsed = int(time.monotonic() - start)

            if exists:
                empty_streak = 0
                print(f"[*] Drain poll {poll_num} ({elapsed}s): {count} instances visible — re-issuing kill")
                logger.warning("Fleet '%s' still has %d instances after %ds — re-killing",
                               fleet, count, elapsed)
                kill_fleet(fleet)
            else:
                empty_streak += 1
                print(f"[*] Drain poll {poll_num} ({elapsed}s): empty ({empty_streak}/{stable_empty_checks} stable)")
                logger.info("Fleet '%s' empty after %ds (streak %d/%d)",
                            fleet, elapsed, empty_streak, stable_empty_checks)
                if empty_streak >= stable_empty_checks:
                    print(f"[+] Fleet '{fleet}' confirmed empty for {empty_streak} consecutive checks — done")
                    logger.info("Fleet '%s' confirmed empty after %ds", fleet, elapsed)
                    return
    except KeyboardInterrupt:
        print(f"\n[!] Polling aborted by user.")
        print(f"[!] If instances are still visible, run: ax rm \"{fleet}*\" -f")
        logger.warning("Fleet kill polling aborted by user for '%s'", fleet)
        return

    exists, count = fleet_exists(fleet)
    if exists:
        print(f"[!] Warning: Fleet '{fleet}' still shows {count} instances after {max_seconds}s of polling.")
        print(f"[!] Run manually: ax rm \"{fleet}*\" -f")
        logger.error("Fleet '%s' still has %d instances after %ds of polling",
                     fleet, count, max_seconds)
    else:
        print(f"[+] Fleet '{fleet}' empty at end of polling window")


def compute_optimal_nodes(target_count: int, min_nodes: int = 1,
                          per_node: int = TARGETS_PER_NODE) -> int:
    """Compute optimal fleet size from a workload count.

    Formula: ceil(count / per_node), clamped to [min_nodes, ∞). per_node
    accounts for per-node thread concurrency and a safety margin to avoid DOS;
    pass URLS_PER_NODE for URL-driven steps, TARGETS_PER_NODE (default) for IPs.
    """
    if target_count <= 0:
        return min_nodes
    return max(min_nodes, math.ceil(target_count / max(1, per_node)))


def compute_initial_nodes(target_file: str | None = None,
                          domain_file: str | None = None,
                          url_file: str | None = None,
                          exclusion_file: str | None = None,
                          ip_scope: str = "provenance",
                          existing_ledger_dir: str | None = None,
                          max_nodes: int = 10) -> int:
    """Size the *initial* fleet from the known workload, before any step runs.

    Mirrors FleetScaler's between-step sizing so the opening fleet is already
    close to right, instead of booting at 1 node and only growing on step 2.

    Workload source (whichever applies):
      - ``existing_ledger_dir`` (continue / resume): load the on-disk
        ``discovery-ledger.jsonl`` — it already holds resolved, in-scope targets.
      - otherwise (fresh run): seed a THROWAWAY ledger in a temp dir (never the
        real output dir) from the user's -t/-d/-url files, honoring exclusions,
        exactly as ``--confirm-scope`` does.

    Counts use the same ledger semantics as the between-step scaler, so initial
    and later sizing share one yardstick. Returns a node count in [1, max_nodes].

    Caveat: for a domain-only (-d) fresh run the in-scope IP count is 0 until
    subfinder/dnsx resolve names, so sizing falls back to the seeded domain/URL
    count; the between-step scaler grows the fleet after resolution.
    """
    import shutil
    import tempfile
    from core.target_ledger import TargetLedger

    tpn, upn = _per_node_ratios()
    tmp_dir = None
    ledger = None
    try:
        if existing_ledger_dir and os.path.exists(
                os.path.join(existing_ledger_dir, "discovery-ledger.jsonl")):
            # Continue/resume: load the prior run's ledger. NOTE load_from_disk
            # ends in sync_scope_to_db — it WRITES resolved scope back to the real
            # scan.db — so seed persisted exclusions FIRST, or that sync would
            # transiently mark excluded targets in-scope. We own this connection
            # and close it in finally (run_modules opens its own afterward).
            ledger = TargetLedger(existing_ledger_dir)
            ledger.set_ip_scope_mode(ip_scope)
            ledger.seed_persisted_exclusions()
            ledger.load_from_disk()
        else:
            # Fresh run: size from the seeded inputs in a THROWAWAY ledger (temp
            # dir — never the real output dir).
            tmp_dir = tempfile.mkdtemp(prefix="mx-initsize-")
            ledger = TargetLedger(tmp_dir)
            ledger.set_ip_scope_mode(ip_scope)
            ledger.seed_user_inputs(target_file, domain_file, url_file)
            if exclusion_file:
                ledger.seed_exclusions(exclusion_file)
        snap = ledger.snapshot()
    finally:
        # Release the scan.db connection we opened (checkpoints WAL + closes), so
        # it never lingers alongside run_modules' own connection, and the temp
        # dir can be removed cleanly.
        if ledger is not None:
            try:
                ledger.close()
            except Exception:
                pass
        if tmp_dir:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    # Hosts to port-scan: explicit in-scope IPs plus names that resolve ~1:1 to a
    # scannable host. URL-driven steps size by the in-scope URL count.
    # CIDR-aware: a /16 in `-t` sizes a bigger opening fleet than a single IP
    # (count_ip_workload sums capped host-equivalents), instead of counting the
    # range as one target. Domains stay 1 each (resolved later).
    ip_workload = count_ip_workload(snap.in_scope_ips) + len(snap.in_scope_domains)
    url_workload = len(snap.in_scope_urls)
    optimal = max(compute_optimal_nodes(ip_workload, per_node=tpn),
                  compute_optimal_nodes(url_workload, per_node=upn))
    return max(1, min(optimal, max_nodes))


class FleetScaler:
    """Manages automatic fleet scaling between pipeline steps.

    Monitors ledger target count and resizes the fleet when the workload
    diverges significantly from current capacity. Uses parallel transition:
    new fleet spins up under a fresh name while old fleet is killed in a
    background thread.

    Workload sizing is input-aware: IP-scanning steps size by in-scope IP count
    (TARGETS_PER_NODE), URL-scanning steps (nuclei/gowitness/ffuf/...) by URL
    count (URLS_PER_NODE) — a scan with few IPs but thousands of URLs would
    otherwise stay tiny through the web-scan steps. Mixed parallel groups take
    the max of the two.

    Scaling triggers:
      - Scale UP:   optimal_nodes > current_nodes * 1.5
      - Scale DOWN: optimal_nodes < current_nodes * 0.5

    The scaler is opt-in via --auto-scale and respects --max-nodes.
    """

    def __init__(self, initial_fleet: str, initial_nodes: int, max_nodes: int = 10,
                 logs_prefix: str = "", cost_tracker=None, account=None):
        self.current_fleet = initial_fleet
        self.current_nodes = initial_nodes
        self.max_nodes = max_nodes
        self.logs_prefix = logs_prefix
        # Axiom account for re-auth before kills (long runs can outlive the
        # cloud session). None falls back to AXIOM_ACCOUNT / config in iauth.
        self.account = account
        # When provided, each scale transition is recorded so run cost/usage
        # stats sum node-hours across every fleet generation, not just the first.
        self.cost_tracker = cost_tracker
        # Set by run_modules once the ProgressTracker exists (created later than
        # the scaler); when present, scale transitions are emitted to
        # progress.jsonl / scan.db alongside step progress.
        self.progress_tracker = None
        self._retired_fleets: list[str] = []
        self._kill_threads: list[threading.Thread] = []

    @property
    def fleet(self) -> str:
        return self.current_fleet

    @property
    def nodes(self) -> int:
        return self.current_nodes

    def check_and_scale(self, ip_count: int, url_count: int = 0,
                        has_url_step: bool = False) -> bool:
        """Evaluate whether to scale for the upcoming step and execute if needed.

        Args:
            ip_count: in-scope IP count (workload for nmap-class steps).
            url_count: in-scope URL count (workload for URL-scanning steps).
            has_url_step: whether the upcoming step/group scans URLs — only then
                does the URL count drive sizing (else a big historical URL set
                would inflate an IP-only step).

        Returns:
            True if a scale event occurred, False otherwise.
        """
        tpn, upn = _per_node_ratios()
        optimal_ip = compute_optimal_nodes(ip_count, per_node=tpn)
        optimal_url = (compute_optimal_nodes(url_count, per_node=upn)
                       if has_url_step else 0)
        optimal = min(max(optimal_ip, optimal_url), self.max_nodes)

        driver = ("urls" if optimal_url >= optimal_ip and has_url_step else "targets")
        count = url_count if driver == "urls" else ip_count

        if optimal > self.current_nodes * 1.5:
            self._scale(optimal, reason=f"{driver} grew to {count}")
            return True
        elif optimal < self.current_nodes * 0.5 and optimal >= 1:
            self._scale(optimal, reason=f"{driver} reduced to {count}")
            return True

        return False

    def _scale(self, new_nodes: int, reason: str):
        """Execute a fleet transition: create new fleet, kill old in background."""
        old_fleet = self.current_fleet
        old_nodes = self.current_nodes
        new_fleet = f"monkeyx-{secrets.token_hex(2)}"

        print(f"\n{'='*60}")
        print(f"[*] Auto-scale: {self.current_nodes} → {new_nodes} nodes ({reason})")
        print(f"    Old fleet: {old_fleet}")
        print(f"    New fleet: {new_fleet}")
        print(f"{'='*60}\n")

        logger.info("Auto-scale: %d -> %d nodes (%s). Old=%s New=%s",
                    self.current_nodes, new_nodes, reason, old_fleet, new_fleet)

        # Register the NEW fleet for teardown BEFORE creating it: `ax fleet -i N`
        # may begin provisioning (billing) instances before initialize_fleet
        # returns or raises, and the new name is a random monkeyx-<hex> that
        # nothing else tracks — so if we don't record it here, a failed/partial
        # spin-up orphans those instances past cleanup(). Idempotent at teardown
        # (cleanup() checks for remaining instances before killing).
        self._retired_fleets.append(new_fleet)

        # Create the new fleet FIRST (blocks until ready). We do NOT touch the old
        # fleet until the new one is confirmed up — so a scale-up failure leaves
        # the old fleet intact and safe to keep running on (never revert onto a
        # fleet that's already being torn down).
        try:
            initialize_fleet(new_fleet, str(new_nodes), self.logs_prefix, False)
            self.current_fleet = new_fleet
            self.current_nodes = new_nodes

            # New fleet is up — NOW retire the old one in the background.
            kill_thread = threading.Thread(
                target=self._background_kill, args=(old_fleet, self.account),
                name=f"kill-{old_fleet}", daemon=True,
            )
            kill_thread.start()
            self._kill_threads.append(kill_thread)
            self._retired_fleets.append(old_fleet)

            # Record the transition so run cost/usage node-hours reflect the new
            # generation (name + node count), not just the initial fleet.
            if self.cost_tracker is not None:
                try:
                    self.cost_tracker.fleet_scaled(new_fleet, new_nodes)
                except Exception as e:  # never let accounting break a scan
                    logger.warning("cost_tracker.fleet_scaled failed: %s", e)
            # Emit to the event stream (progress.jsonl + scan.db) so scaling is
            # trackable alongside step progress, not just in the logs.
            if self.progress_tracker is not None:
                try:
                    self.progress_tracker.fleet_scaled(
                        from_nodes=old_nodes, to_nodes=new_nodes, reason=reason,
                        old_fleet=old_fleet, new_fleet=new_fleet)
                except Exception as e:  # never let tracking break a scan
                    logger.warning("progress fleet_scaled failed: %s", e)
            print(f"[+] New fleet '{new_fleet}' ready ({new_nodes} nodes)")
            logger.info("New fleet '%s' initialized with %d nodes", new_fleet, new_nodes)
        except Exception as e:
            # New fleet failed to come up. It's already registered in
            # _retired_fleets (above), so cleanup() will sweep any stragglers it
            # began provisioning. The old fleet was NOT killed (we moved that into
            # the success path), so it's still alive — keep running on it.
            print(f"[!] Fleet scale-up failed: {e}")
            print(f"[!] Keeping the existing fleet '{old_fleet}'")
            logger.error("Fleet scale failed: %s. Staying on %s", e, old_fleet)
            self.current_fleet = old_fleet
            # Don't update node count — we failed

    @staticmethod
    def _background_kill(fleet_name: str, account=None):
        """Kill a retired fleet in the background (verified + reauth on failure)."""
        try:
            if kill_fleet(fleet_name, account=account):
                logger.info("Background kill of '%s' completed", fleet_name)
            else:
                logger.error("Background kill of '%s' UNCONFIRMED — possible orphan",
                             fleet_name)
        except Exception as e:
            logger.warning("Background kill of '%s' failed: %s", fleet_name, e)

    def cleanup(self, keep_current: bool = False):
        """Join background kills and force-remove any retired fleet still alive.

        keep_current (from --keep-fleet) spares ONLY the currently-active fleet:
        fleets scaled away from are genuinely retired and are still killed (you
        can't "keep" a fleet you moved off of, and leaving them idle bills). This
        matters because _scale registers the new (active) fleet in
        _retired_fleets up front for orphan-safety, so without this guard a scale
        under --keep-fleet would tear down the fleet the operator asked to keep.

        Returns the list of fleets that could NOT be confirmed torn down (empty =
        all clean) so the caller can surface an orphaned-instance warning."""
        for t in self._kill_threads:
            t.join(timeout=60)
        # Re-auth once before the final sweep — on a long run the session that was
        # valid when the background kills fired may have since expired.
        iauth(self.account)
        orphaned: list[str] = []
        for fleet in self._retired_fleets:
            if keep_current and fleet == self.current_fleet:
                logger.info("Keeping active fleet '%s' (--keep-fleet)", fleet)
                continue
            ok, count = _remaining_instances(fleet)
            if not ok or count > 0:
                logger.warning("Retired fleet '%s' still present (count=%s, verify_ok=%s) — killing",
                               fleet, count, ok)
                if not kill_fleet(fleet, account=self.account):
                    orphaned.append(fleet)
        return orphaned


class NoOpScaler:
    """Drop-in replacement when auto-scale is disabled."""

    def __init__(self, fleet: str, nodes: int):
        self.current_fleet = fleet
        self.current_nodes = nodes

    @property
    def fleet(self) -> str:
        return self.current_fleet

    @property
    def nodes(self) -> int:
        return self.current_nodes

    def check_and_scale(self, ip_count: int, url_count: int = 0,
                        has_url_step: bool = False) -> bool:
        return False

    def cleanup(self, keep_current: bool = False):
        return []