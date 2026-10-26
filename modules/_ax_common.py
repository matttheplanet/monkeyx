"""Shared helpers for fleet-distributed (ax) wrapper modules.

Most ax wrappers follow the same shape: validate an input file, build an
``ax scan`` command against a built-in ax module, run it via ``bash_command``,
and return the standard module result dict. This module factors that out so each
wrapper stays a few lines and the command construction / error handling is
consistent and tested in one place.

Security note: ``fleet`` and file paths are single-quote-wrapped in the command
string (bash_command runs ``/bin/bash -c``). The engine/API validate the fleet
name (``^[a-zA-Z0-9_-]{1,100}$``) and paths are engine-generated ledger files,
so no scan-derived / model-derived data reaches the shell here. Do not pass
untrusted values as ``extra_args``.
"""

import logging
import os
import subprocess

from core.config import get_module_defaults, load_fleet_config
from core.utils import ax_local_config, bash_command

logger = logging.getLogger("monkeyx.modules._ax_common")


def _count_lines(path: str) -> int:
    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            return sum(1 for line in fh if line.strip() and not line.startswith("#"))
    except OSError:
        return 0


def _resolve_timeout(module_name: str, explicit):
    """Resolve the per-command wall-clock timeout (seconds) for an ax run.

    Priority (highest wins): the ``explicit`` arg > ``modules.<name>.timeout``
    in monkeyx.config > the ``fleet.ax_timeout`` global default. Returns a
    positive number of seconds, or ``None`` (no limit — the historical
    default). Without a bound, a single hung fleet node (e.g. amass stalling on
    its local-DB migration) blocks the whole pipeline forever, because these
    modules run inside parallel groups the engine joins on. bash_command's
    timeout path SIGKILLs the entire process group, so the SSH children ``ax
    scan`` spawns are reaped too."""
    raw = explicit
    if raw is None:
        raw = get_module_defaults(module_name).get("timeout")
    if raw is None:
        raw = load_fleet_config().get("ax_timeout")
    if raw is None:
        return None
    try:
        secs = float(raw)
    except (TypeError, ValueError):
        logger.warning("%s: ignoring invalid timeout %r (not a number)",
                       module_name, raw)
        return None
    return secs if secs > 0 else None


def run_ax_module(
    *,
    module_name: str,
    ax_module: str,
    input_file: str,
    prefix: str,
    fleet: str,
    output_suffix: str,
    input_kind: str = "input",
    extra_args: str | None = None,
    local_config_tool: str | None = None,
    expand_cidr: bool = False,
    dont_split: bool = False,
    require_fleet: bool = True,
    timeout: float | int | None = None,
) -> dict:
    """Run a built-in ax module against ``input_file`` and return a result dict.

    Args:
        module_name:   MonkeyX module name (for result dict + logging).
        ax_module:     The built-in ax module to invoke (``-m <ax_module>``).
        input_file:    Path to the ledger-generated input (urls/domains/targets).
        prefix:        Output prefix (already resolved to data_prefix by caller).
        fleet:         Axiom fleet name (engine/API validated).
        output_suffix: Suffix appended to prefix for the ``-o`` output file,
                       e.g. ``"-testssl.txt"``.
        input_kind:    Human label for the missing-input error message.
        extra_args:    Optional value for ``--extra-args '<...>'`` (tool flags).
        local_config_tool: If set, append ``ax_local_config(tool)`` (pushes the
                       tool's local config file to fleet nodes).
        expand_cidr:   Add ``--expand-cidr`` (for IP/CIDR target inputs).
        dont_split:    Add ``--dont-split`` — upload the FULL input file to every
                       node instead of splitting it round-robin. Required for
                       tools that read the input as a file and error on an empty
                       chunk (e.g. amass ``-df``: when there are fewer inputs than
                       nodes, split nodes get an empty file and amass exits with
                       "error reading the first 512 bytes ... EOF"). Also the
                       correct semantics for whole-list enumeration where
                       splitting gives no benefit.
        require_fleet: If True, fail when no fleet is supplied.
        timeout:       Max wall-clock seconds for the ``ax scan`` before the
                       whole process group (incl. SSH children on the fleet) is
                       killed. ``None`` (default) resolves from
                       ``modules.<name>.timeout`` / ``fleet.ax_timeout`` in
                       monkeyx.config, else no limit. On timeout the step is
                       reported ``failed`` and the run continues.

    Returns:
        Standard module result dict.
    """
    if not input_file or not os.path.exists(input_file):
        msg = (f"{module_name}: required {input_kind} file '{input_file}' does not "
               f"exist. Run a producing module first or provide the input.")
        print(f"[!] {msg}")
        return {"module": module_name, "status": "failed",
                "output_files": [], "error": msg}

    if require_fleet and not fleet:
        msg = f"{module_name}: no fleet specified"
        print(f"[!] {msg}")
        return {"module": module_name, "status": "failed",
                "output_files": [], "error": msg}

    count = _count_lines(input_file)
    if count == 0:
        # Nothing to scan is a skip, not a failure — keeps the pipeline honest.
        print(f"[*] {module_name}: input file empty, skipping")
        return {"module": module_name, "status": "skipped",
                "output_files": [], "warning": "empty input"}

    output_file = f"{prefix}{output_suffix}"
    parts = [f"ax scan '{input_file}' --fleet '{fleet}'"]
    if expand_cidr:
        parts.append("--expand-cidr")
    if dont_split:
        parts.append("--dont-split")
    parts.append(f"-m {ax_module} -o '{output_file}'")
    if extra_args:
        parts.append(f"--extra-args '{extra_args}'")
    cmd = " ".join(parts)
    if local_config_tool:
        cmd += ax_local_config(local_config_tool)

    timeout_s = _resolve_timeout(module_name, timeout)
    print(f"[*] Running {module_name}: {count} inputs across fleet '{fleet}'"
          + (f" (timeout {timeout_s:.0f}s)" if timeout_s else ""))
    try:
        bash_command(cmd, timeout=timeout_s)
    except subprocess.TimeoutExpired:
        # A hung node (e.g. amass stuck migrating its local DB) would otherwise
        # block the parallel group forever. Kill it, fail the step, let the run
        # continue — mirrors how any other step failure is handled.
        msg = (f"{module_name}: timed out after {timeout_s:.0f}s and was killed "
               f"(hung fleet node?)")
        logger.error(msg)
        print(f"[!] {msg}")
        return {"module": module_name, "status": "failed",
                "output_files": [], "error": msg}
    except Exception as e:  # noqa: BLE001 - surface any failure as a failed step
        logger.error("%s failed: %s", module_name, e)
        print(f"[!] {module_name} failed: {e}")
        return {"module": module_name, "status": "failed",
                "output_files": [], "error": str(e)}

    # Empty/missing output is downgraded success->warning centrally in
    # workflows.run_module (single source of truth), so it isn't re-checked here.
    result_lines = _count_lines(output_file) if os.path.exists(output_file) else 0
    print(f"[+] {module_name} complete: {result_lines} output lines")
    return {"module": module_name, "status": "success",
            "output_files": [output_file]}
