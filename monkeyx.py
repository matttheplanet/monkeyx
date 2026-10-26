#!/usr/bin/env python3

# Tool: MonkeyX
# Description: Tool to perform external pentesting workflows using Attack Surge Ax.
# By: Matt Dunn & Nadia Sharifi

import argparse
from datetime import datetime
import glob
import os
import secrets
import shutil
import signal
import sys
import logging
import zipfile
from core import (
    iauth,
    initialize_fleet,
    validate_file,
    get_current_date,
    setup_logging,
    shell_safe_str,
    fleet_exists,
)
from core.checkpoint import (
    Checkpoint, deserialize_steps,
    EXIT_CODE_OK, EXIT_CODE_FATAL, EXIT_CODE_STEP_FAILURES, EXIT_CODE_PAUSED,
)
from core.cost_tracker import CostTracker
from core.fleet import FleetScaler, NoOpScaler, compute_initial_nodes, FleetSpinupError


import re as _re

_FLEET_NAME_RE = _re.compile(r'^[a-z][a-z0-9](?:[a-z0-9-]*[a-z0-9])?$')

# Prior-run snapshot files written by core.merge_outputs' versioning
# (report.run2.html, summary.run1.md, ai-analysis.run1.json) — a ".run<N>"
# segment immediately before the extension. Excluded from the results zip as
# historical duplicates the current report/summary supersede.
_PRIOR_RUN_SNAPSHOT_RE = _re.compile(r'\.run\d+\.[^.]+$')


def _is_prior_run_snapshot(name: str) -> bool:
    return bool(_PRIOR_RUN_SNAPSHOT_RE.search(name))


def sanitize_fleet_name(name: str) -> str:
    """Normalize and validate a fleet name for cross-provider compatibility.

    Rules (IBM Cloud VPC compute): 2-63 chars, starts with letter,
    lowercase alphanumeric + hyphens only, no consecutive hyphens,
    cannot end with hyphen.
    """
    name = name.strip().lower()
    name = name.replace('_', '-')
    name = _re.sub(r'-{2,}', '-', name)
    name = name.strip('-')
    if len(name) < 2 or len(name) > 63:
        raise argparse.ArgumentTypeError(
            f"Fleet name must be 2-63 characters, got {len(name)}: '{name}'")
    if not _FLEET_NAME_RE.fullmatch(name):
        raise argparse.ArgumentTypeError(
            f"Fleet name must start with a letter and contain only lowercase letters, "
            f"numbers, and hyphens (no consecutive hyphens): '{name}'")
    return name


def shell_safe_file(arg):
    """Combined validator: file must exist AND its path must be shell-safe."""
    path = validate_file(arg)
    shell_safe_str(str(path))
    return path


def target_input(arg):
    """Accept a file path, single target, or comma-separated list.

    If `arg` is an existing file, return its path. Otherwise treat it as
    inline targets (single value or comma/semicolon/newline separated) and
    return the raw string for later resolution to a temp file.
    """
    if arg is None:
        return None
    shell_safe_str(arg)
    from pathlib import Path
    if Path(arg).is_file():
        return str(Path(arg))
    return arg
from workflows import (
    AVAILABLE_MODULES,
    MODULE_REQUIREMENTS,
    WORKFLOWS,
    ModuleStep,
    ParallelGroup,
    run_workflow,
    run_modules,
    get_resolved_workflow_rich,
    get_resolved_workflows_rich,
    validate_module_inputs,
    _module_consumes_urls,
    _module_produces_nmap_xml,
    _NO_FLEET_MODULES,
)


def _resolve_target_arg(value, output_dir, name):
    """Resolve a target argument to a file path.

    If `value` is already a path to an existing file, return it unchanged.
    Otherwise treat it as inline targets (single value or comma/semicolon
    separated), write them to a file in `output_dir`, and return that path.
    """
    if value is None:
        return None
    from pathlib import Path
    if Path(value).is_file():
        return str(Path(value))
    # Inline value — split on comma, semicolon, or newline
    import re
    entries = [e.strip() for e in re.split(r'[,;\n]+', value) if e.strip()]
    # A single token that looks like a file path but does not exist is almost
    # certainly a typo'd/mislocated file argument, not inline data. Seeding it
    # as a target produces junk (e.g. "./targets/x" → host ".") and derails the
    # whole run — so fail loudly instead.
    if len(entries) == 1:
        tok = entries[0]
        # A CIDR ('140.95.0.0/16') or bare IP legitimately contains '/', so it
        # must never be mistaken for a path — check that first.
        import ipaddress
        try:
            ipaddress.ip_network(tok, strict=False)
            is_ip_or_cidr = True
        except ValueError:
            is_ip_or_cidr = False
        looks_like_path = (
            not is_ip_or_cidr
            and "://" not in tok and (
                tok.startswith(("./", "../", "~", "/"))
                or os.sep in tok
                or (os.altsep and os.altsep in tok)
                or tok.rsplit(".", 1)[-1].lower() in ("txt", "lst", "list", "csv")
            )
        )
        if looks_like_path:
            raise FileNotFoundError(
                f"--{name} argument {tok!r} looks like a file path but no such "
                f"file exists. Check the path (relative to the current working "
                f"directory), or pass inline {name}s directly.")
    if not entries:
        return None
    out_path = os.path.join(output_dir, f"input-{name}.txt")
    os.makedirs(output_dir, exist_ok=True)
    with open(out_path, 'w') as f:
        for entry in entries:
            f.write(entry + '\n')
    print(f"[*] Wrote {len(entries)} {name}(s) to {out_path}")
    return out_path


def _all_modules_local(module_names: list[str]) -> bool:
    """Return True if every module in the list can run without a fleet."""
    return all(m in _NO_FLEET_MODULES for m in module_names)



def parse_commands():
    """Parse command line arguments.
    
    Returns:
        Parsed arguments object
    """
    parser = argparse.ArgumentParser(
        prog="monkeyx",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Modules & Workflows:
  All modules (recon, port/web scanning, DNS, service audits, AI analysis/
  validation, reporting) and the three workflows — fast, standard (default),
  and deep — are auto-discovered. Run --list-plugins to see everything with its
  source, or see docs/MODULES.md.

Input channels (the channel IS the authorization level — see docs):
  -t/--target       - Fully-owned targets (IPs/CIDRs/hostnames) — host-level scanning, all ports
  -d/--domain-list  - In-scope domains/subdomains — name-safe testing + subdomain enumeration
  -url/--url-list   - In-scope web URLs (or bare hostnames) — name-safe web testing
  -od/--output-dir  - Required — output directory. Provide at least one of -t/-d/-url.

Examples:
  # Run standard workflow (default)
  %(prog)s -t targets.txt -f myfleet -od ./scan-results

  # Run fast workflow
  %(prog)s -t targets.txt -f myfleet -w fast -od ./output

  # Run deep workflow with subdomain enumeration
  %(prog)s -t targets.txt -d domains.txt -f myfleet -w deep -od ./output

  # Run specific modules only
  %(prog)s -t targets.txt -f myfleet -m ax_nmap_tcp ax_nuclei -od ./output

  # Run subfinder only (no fleet needed)
  %(prog)s -d domains.txt -od ./output -m subfinder

  # Run nuclei/gowitness with custom URL list
  %(prog)s -url urls.txt -f myfleet -m ax_nuclei ax_gowitness -od ./output

  # Combine custom URLs with scan results
  %(prog)s -t targets.txt -url additional-urls.txt -f myfleet -od ./output

  # Custom fleet size and output prefix
  %(prog)s -t targets.txt -f myfleet -n 50 -o client-2026 -od ./output

  # Use TCP Connect scan instead of SYN
  %(prog)s -t targets.txt -f myfleet -st sT -od ./output

  # Pause for confirmation before starting
  %(prog)s -t targets.txt -f myfleet -p -od ./output

  # Resume a paused scan from checkpoint (fleet name read from checkpoint)
  %(prog)s --resume ./output

  # Resume with explicit fleet name (overrides checkpoint)
  %(prog)s --resume ./output -f myfleet

  # Resume keeping fleet alive between pause/resume cycles
  %(prog)s --resume ./output --keep-fleet

  # Graceful pause mode (finish current step before checkpointing)
  %(prog)s -t targets.txt -f myfleet -od ./output --finish-step

For detailed module information, see docs/MODULES.md
        """,
        conflict_handler='resolve')
    
    parser.add_argument('-t', '--target', dest='target', required=False, type=target_input,
                        help='Target file, single IP/host, or comma-separated list of IPs/hosts/CIDRs.')
    parser.add_argument('-d', '--domain-list', dest='domainlist', required=False, type=target_input,
                        help='Domain file, single domain, or comma-separated list of domains/subdomains.')
    parser.add_argument('-url', '--url-list', dest='urllist', required=False, type=target_input,
                        help='Web hosts to scan: file, single entry, or comma-separated list. '
                             'Accepts full URLs (https://host:8443/path) or bare hostnames — a bare '
                             'hostname (host or host:port) is expanded to both http:// and https://.')
    parser.add_argument('-o', '--output', dest='output', default=f"{get_current_date()}", type=shell_safe_str,
                        help='Output name prefix for files, default is current date in YYYY-MM-DD format.')
    parser.add_argument('-od', '--output-dir', dest='output_dir', required=False, type=shell_safe_str,
                        help='Output directory for all files (logs, scans, results). Example: ./monkeyx-output or /path/to/results')
    parser.add_argument('-n', '--nodes', dest='nodes', type=shell_safe_str, default='1',
                        help='Number of scan nodes to spin up. Use caution, large fleets can cause DOS in some cases. Default is 1.')
    parser.add_argument('-f', '--fleet', dest='fleet', type=sanitize_fleet_name, required=False,
                        help='Unique name for Axiom fleet (auto-generated if not provided)')
    parser.add_argument('--ax-account', dest='ax_account', type=shell_safe_str, default=None,
                        help='Axiom account name for authentication. Falls back to AXIOM_ACCOUNT env var. If unset, auth is skipped.')
    parser.add_argument('-p', '--pause', dest='wait', default=False, action='store_true', 
                        help="Pause after fleet creation before starting scans (Default: starts immediately).")
    parser.add_argument('-st', '--scantype', dest='scan_type', type=str, default="sS", choices=["sS", "sT"], 
                        help="Choose TCP scan type: Connect (sT) or SYN (sS). Default is SYN.")
    parser.add_argument('-v', '--verbose', dest='verbose', action='store_true',
                        help="Enable verbose logging (DEBUG level)")
    
    # New module-based arguments
    parser.add_argument('-m', '--modules', dest='modules', nargs='+', 
                        choices=list(AVAILABLE_MODULES.keys()),
                        metavar='MODULE',
                        help=f'Specify individual modules to run. Available: {", ".join(AVAILABLE_MODULES.keys())}')
    parser.add_argument('-w', '--workflow', dest='workflow', nargs='+',
                        metavar='WORKFLOW',
                        help=f'Specify one or more predefined workflows to run (default: standard). '
                             f'Multiple workflows are concatenated in order, preserving each '
                             f'workflow\'s parallel groups and per-step args. '
                             f'Available: {", ".join(sorted(WORKFLOWS.keys()))}')

    # Legacy scope knobs. Superseded as the operator interface by the
    # input-channel model (-t/-d/-url + the host/name gate), but kept as hidden
    # power-user overrides: their internals are still load-bearing (the -t-range
    # check backs the ownership promotion). Hidden from --help via SUPPRESS so the
    # normal surface shows only the channel model; they still parse and work.
    parser.add_argument('--scope-filter', dest='scope_filter', type=str, default='strict',
                        choices=['none', 'warn', 'strict'],
                        help=argparse.SUPPRESS)
    parser.add_argument('--ip-scope', dest='ip_scope', type=str, default='provenance',
                        choices=['provenance', 'strict', 'strict-resolved'],
                        help=argparse.SUPPRESS)
    parser.add_argument('--url-prune', dest='url_prune', type=str, default='live',
                        choices=['off', 'live', 'interesting'],
                        help=('Feed heavy web scanners (nuclei/gowitness/ffuf/ferox) only '
                              'httpx-live URLs instead of every discovered/historical URL. '
                              '"live"=any httpx response (default), "interesting"=2xx/3xx/401/403, '
                              '"off"=full list. httpx is auto-injected if absent. Fail-open: '
                              'hosts httpx has not covered keep all their URLs.'))
    parser.add_argument('--url-max-per-host', dest='url_max_per_host', type=int, default=None,
                        help=('Optional cap on URLs kept per host:port (default: unlimited). '
                              'Bounds both the live-URL export to heavy web scanners AND how '
                              'many crawled (katana/gau) URLs are promoted to ledger targets / '
                              'web_dirs — stops a wildcard-scope crawl from exploding the '
                              'ledger/scan.db. To bound the crawl itself, set katana options '
                              '(depth/crawl_duration/field_scope) on the ax_katana step.'))
    parser.add_argument('--exclude', dest='exclusion_file', type=shell_safe_file, default=None,
                        help=('File listing targets to exclude (one per line). Supports '
                              'IPs, CIDRs, hostnames (matches itself + subdomains), '
                              '"*.domain" wildcards (subdomains only), and full URLs. '
                              'Exclusions always win — they override -t/-d/-url and '
                              'block parent-chain inheritance.'))
    parser.add_argument('--resume', dest='resume_dir', type=shell_safe_str, default=None,
                        help='Resume a paused scan from checkpoint (path to output directory)')
    parser.add_argument('--continue', dest='continue_dir', type=shell_safe_str, default=None,
                        help='Continue in an existing output directory — run new modules/workflows '
                             'using the existing target ledger. Requires -m and/or -w.')
    parser.add_argument('--keep-fleet', dest='keep_fleet', action='store_true', default=False,
                        help='Keep fleet alive after scan completes or pauses (skip fleet cleanup)')
    parser.add_argument('--finish-step', dest='finish_step', action='store_true', default=False,
                        help='When pausing, wait for the current step to finish before checkpointing (default: cancel mid-step immediately)')
    parser.add_argument('--dry-run', dest='dry_run', action='store_true', default=False,
                        help='Run the full orchestration pipeline with synthetic data (no fleet, no real tools). For testing.')
    parser.add_argument('--no-auto-discovery', dest='no_auto_discovery', action='store_true', default=False,
                        help='Disable auto-injection of ax_nmap_tcp (and dns_resolve when needed) before web modules that lack a port-scan source. Pipeline runs exactly as specified.')
    parser.add_argument('--no-subdomain-enum', dest='no_subdomain_enum', action='store_true', default=False,
                        help='Skip subdomain-enumeration modules (subfinder, amass, puredns bruteforce, bbot passive). Use when -d is a FIXED list to test — the provided names still get full name-safe testing, but no new subdomains are discovered. Explicitly selected enum modules are warn-and-skipped.')
    parser.add_argument('--confirm-scope', dest='confirm_scope', action='store_true', default=False,
                        help='Dry pass: seed inputs, resolve/classify scope, print what WOULD be scanned per authorization channel (host-full vs name-safe), then exit without spinning up a fleet or scanning. Use to confirm scope before an engagement.')
    parser.add_argument('--check', dest='check', action='store_true', default=False,
                        help='Preflight: validate input files (-t/-d/-url format), credentials.yaml (parses + the AI provider has a real, non-placeholder key), and monkeyx.config, then exit (no scan, no fleet, no output dir). Exit 0 = ok, 1 = errors.')
    parser.add_argument('--no-sweep', dest='no_sweep', action='store_true', default=False,
                        help='Disable sweep-then-verify: skip the masscan pre-sweep and scan nmap directly (top-1000) instead of only the swept-open ports. Overrides the workflow and monkeyx.config scan.sweep. Default: sweep enabled where the workflow uses it (e.g. standard).')
    parser.add_argument('--auto-scale', dest='auto_scale', action='store_true', default=False,
                        help='Enable automatic fleet scaling. Sizes the INITIAL fleet from the '
                             'workload (unless -n is set) and resizes between steps as the target '
                             'count grows/shrinks. Respects --max-nodes.')
    parser.add_argument('--max-nodes', dest='max_nodes', type=int, default=10,
                        help='Maximum fleet nodes when using --auto-scale (default: 10, safety cap)')
    parser.add_argument('--ai-depth', dest='ai_depth', type=str, default=None,
                        choices=['quick', 'standard', 'balanced', 'deep', 'unlimited'],
                        help='AI analysis depth — controls how many hosts/findings are analyzed '
                             '(max hosts: quick=20, standard=50, balanced=100, deep=150, '
                             'unlimited=all). Default: standard.')
    parser.add_argument('--allow-intrusive-validation', dest='allow_intrusive',
                        action='store_true', default=False,
                        help='[EXPERIMENTAL ai_validate] Permit ai_validate to run state-changing (Tier 2/3) protocol checks '
                             '(SMTP open-relay test, SNMP write, FTP upload). OFF by default — '
                             'validation is read-only/non-destructive unless you opt in. Only enable '
                             'with explicit authorization for active testing.')
    parser.add_argument('--multi-pass', dest='ai_multipass', action='store_true', default=False,
                        help='ai_analyze runs recommendations TWICE — a pure (no knowledge base) '
                             'pass and a KB-grounded pass — then reconciles them (cross-checks, '
                             'surfaces what both agree on). Roughly doubles ai_analyze cost — OFF '
                             'by default.')
    parser.add_argument('--rebuttal', dest='rebuttal', action='store_true', default=False,
                        help='[EXPERIMENTAL ai_validate] Run ai_validate\'s adversarial rebuttal pass: an independent second '
                             'agent tries to overturn each confirmed/refuted verdict from a fresh '
                             'context. A verdict only flips on evidence a rebuttal command actually '
                             'produced. Roughly doubles ai_validate cost — OFF by default.')
    parser.add_argument('--nessus', dest='nessus_file', type=shell_safe_file, default=None,
                        help='Import a Nessus .nessus XML export file. Adds nessus_import to the module list '
                             'and passes the file path. Use with --continue to enrich an existing scan.')
    parser.add_argument('--engagement-id', dest='engagement_id', type=str, default=None,
                        help='Stable identifier stamped into scan.db (meta.engagement_uuid) so a '
                             'future rollup can attribute this engagement to a project/run. Set once '
                             'on first run and preserved across --continue/--resume. If omitted, the '
                             'engine generates a UUID. The API passes its run_id here.')
    parser.add_argument('--sync-knowledge', dest='sync_knowledge', action='store_true',
                        help='Sync knowledge base sources (git pull, re-index) and exit. '
                             'Configure in ~/.monkeyx/knowledge.yaml.')
    parser.add_argument('--list-plugins', dest='list_plugins', action='store_true',
                        help='List all modules/workflows and their source (built-in vs plugin), then exit.')
    parser.add_argument('--webserver', dest='webserver_dir', type=str, default=None,
                        metavar='OUTPUT_DIR',
                        help='Serve a live web view of a run\'s scan.db (live during '
                             'a scan and after), then exit when stopped. Binds '
                             '127.0.0.1 by default. Example: --webserver ./engagement')
    parser.add_argument('--webserver-host', dest='webserver_host', type=str,
                        default='127.0.0.1',
                        help='Host/interface for --webserver to bind (default 127.0.0.1; '
                             'localhost-only unless you knowingly change it).')
    parser.add_argument('--webserver-port', dest='webserver_port', type=int,
                        default=8765, help='Port for --webserver (default 8765).')

    args = parser.parse_args()

    # --nessus implies nessus_import module
    if args.nessus_file:
        if not args.modules:
            args.modules = []
        if 'nessus_import' not in args.modules:
            args.modules.insert(0, 'nessus_import')

    # Apply fleet config as defaults (CLI flags override config)
    from core.config import load_fleet_config
    fleet_cfg = load_fleet_config()
    if fleet_cfg.get('auto_scale') and not args.auto_scale:
        args.auto_scale = True
    # Sentinel MUST match the --max-nodes argparse default above: it means
    # "user didn't pass the flag", so fleet.max_nodes config can take effect.
    if fleet_cfg.get('max_nodes') and args.max_nodes == 10:
        args.max_nodes = int(fleet_cfg['max_nodes'])

    return args


def _resume_from_checkpoint(args):
    """Resume a paused scan from a checkpoint file."""
    output_directory = args.resume_dir

    cp = Checkpoint(output_directory)
    errors = cp.validate()
    if errors:
        print("[!] Checkpoint validation failed:")
        for e in errors:
            print(f"    - {e}")
        sys.exit(1)

    data = Checkpoint.load(output_directory)
    resume_from = data['next_step_index']
    module_kwargs = data['kwargs']
    fleet_killed = data['fleet_killed']
    workflow_name = data.get('workflow')
    module_names = data['modules']

    fleet_name = args.fleet or module_kwargs.get('fleet')
    if not fleet_name or fleet_name == "local":
        fleet_name = f"monkeyx-{secrets.token_hex(2)}"
        print(f"[*] No fleet specified, auto-generating: {fleet_name}")
    elif not args.fleet and module_kwargs.get('fleet'):
        print(f"[*] Using fleet '{fleet_name}' from checkpoint")

    logs_dir = os.path.join(output_directory, "logs")
    os.makedirs(logs_dir, exist_ok=True)
    logger = setup_logging(
        os.path.basename(module_kwargs.get('prefix', 'resume')),
        verbose=args.verbose if hasattr(args, 'verbose') else False,
        output_dir=logs_dir,
    )
    logger.info(f"Resuming scan from checkpoint: step_index={resume_from}")

    print(f"\n{'='*60}")
    print(f"Resuming paused scan")
    print(f"  Output dir: {output_directory}")
    print(f"  Resuming from step: {resume_from + 1} of {data['total_steps']}")
    print(f"  Fleet: {fleet_name}")
    print(f"  Modules: {', '.join(module_names)}")
    print(f"{'='*60}\n")

    # Rebuild module_kwargs with fleet name (may have changed)
    module_kwargs['fleet'] = fleet_name

    # Build step list — use rich steps if available (preserves parallel groups + args)
    if 'steps' in data:
        final_modules = deserialize_steps(data['steps'])
    else:
        final_modules = [ModuleStep(name=m) for m in module_names]

    finish_step = getattr(args, 'finish_step', False)

    if finish_step:
        _install_pause_handler(output_directory)

    fleet_cleanup_needed = True
    fleet_init_interrupted = False
    cost_tracker = CostTracker()

    # Initialize before the try so every code path (kept-alive fleet, reused
    # fleet, or an early exception) has these defined. Previously they were only
    # assigned inside the fleet-reinit branch, so resuming a kept-alive fleet
    # raised UnboundLocalError (swallowed by the generic except → silent failure).
    results = []
    exit_code = EXIT_CODE_OK
    nodes = args.nodes if args.nodes != '1' else module_kwargs.get('nodes', args.nodes)
    logs_prefix = os.path.join(logs_dir, os.path.basename(module_kwargs.get('prefix', 'resume')))

    try:
        # Reinitialize fleet if it was killed on pause
        if fleet_killed:
            exists, node_count = fleet_exists(fleet_name)
            if exists:
                msg = f"Reusing existing fleet '{fleet_name}' ({node_count} nodes). Fleet was not created by this run."
                logger.warning(msg)
                print(f"[!] {msg}")
                cost_tracker.fleet_started(fleet_name, node_count)
            else:
                logger.info("Fleet was killed on pause — reinitializing")
                print("[*] Reinitializing fleet...")
                # Size the reinit fleet from the existing ledger when auto-scaling
                # and -n was left at the default. An explicit -n always wins.
                if args.auto_scale and args.nodes == '1':
                    try:
                        sized = compute_initial_nodes(
                            existing_ledger_dir=output_directory,
                            ip_scope=getattr(args, 'ip_scope', 'provenance'),
                            max_nodes=args.max_nodes)
                        if sized > 1:
                            nodes = str(sized)
                            print(f"[*] Auto-scale: sized fleet to {nodes} nodes from the ledger")
                            logger.info("Auto-scale initial sizing (resume): %s nodes", nodes)
                    except Exception as e:
                        logger.warning("Initial fleet sizing failed; using nodes=%s (%s)", nodes, e)
                iauth(args.ax_account)
                fleet_init_interrupted = True
                try:
                    initialize_fleet(fleet_name, nodes, logs_prefix, False)
                    fleet_init_interrupted = False
                except KeyboardInterrupt:
                    logger.warning("Ctrl+C during fleet init — instances may still be provisioning")
                    print("\n[!] Ctrl+C during fleet reinit. Will retry teardown to catch stragglers.")
                    raise
                print(f"[+] Fleet '{fleet_name}' reinitialized ({nodes} nodes)")
                cost_tracker.fleet_started(fleet_name, int(nodes) if nodes else 0)
        else:
            logger.info("Fleet was kept alive — skipping initialization")
            print(f"[*] Using existing fleet '{fleet_name}'")

        if args.auto_scale and fleet_name != "local":
            scaler = FleetScaler(
                initial_fleet=fleet_name,
                initial_nodes=int(nodes) if nodes else 1,
                max_nodes=args.max_nodes,
                logs_prefix=logs_prefix,
                cost_tracker=cost_tracker,
                account=args.ax_account,
            )
        else:
            scaler = NoOpScaler(fleet=fleet_name, nodes=int(nodes) if nodes else 1)

        results = run_modules(
            final_modules, cleanup=False,
            resume_from=resume_from, finish_step=finish_step,
            scaler=scaler,
            output_dir=output_directory,
            workflow_name=workflow_name,
            keep_fleet=args.keep_fleet,
            **module_kwargs,
        )

        _print_results_summary(
            results,
            header="Execution Complete (resumed scan)",
            output_directory=output_directory,
        )
        exit_code = _completion_exit_code(results)

    except SystemExit as e:
        if e.code == EXIT_CODE_PAUSED:
            logger.info("Scan paused again during resume")
            _handle_pause_exit(fleet_name, keep_fleet=args.keep_fleet,
                               output_directory=output_directory,
                               account=args.ax_account)
            fleet_cleanup_needed = False
            exit_code = EXIT_CODE_PAUSED
        else:
            raise

    except KeyboardInterrupt:
        logger.warning("Resume interrupted by user")
        print("\n[!] Interrupted. Cleaning up...")
        exit_code = 130

    except Exception as e:
        logger.error(f"Error during resume: {e}", exc_info=True)
        print(f"\n[!] Error: {e}")
        exit_code = EXIT_CODE_FATAL

    finally:
        if fleet_cleanup_needed:
            cost_tracker.fleet_stopped()
            expected = _safe_int(nodes) or _safe_int(module_kwargs.get('nodes'))
            _fleet_cleanup(fleet_name, keep_fleet=args.keep_fleet,
                           fleet_init_interrupted=fleet_init_interrupted,
                           account=args.ax_account,
                           expected_nodes=expected)

        for r in (results or []):
            if isinstance(r, dict) and r.get("ai_usage"):
                cost_tracker.record_ai_usage(r["ai_usage"])
        cost_tracker.write(os.path.join(logs_dir, f"costs-{datetime.now().strftime('%Y%m%d-%H%M%S')}.txt"))

        _run_finalizers(output_directory, results)

        # Rebuild the results archive so a resumed run refreshes the deliverable.
        _create_results_archive(
            output_directory, os.path.basename(module_kwargs.get('prefix', 'resume')))

    sys.exit(exit_code)


def _completion_exit_code(results):
    """Map a completed run's results to a process exit code.

    EXIT_CODE_STEP_FAILURES if any step failed (partial coverage), else
    EXIT_CODE_OK. Step failures don't abort the run — the engine logs them and
    continues — so this is the only place a partially-failed run is surfaced to
    the exit code that CI/Docker/the API key off of.
    """
    for r in (results or []):
        if isinstance(r, dict) and r.get("status") == "failed":
            return EXIT_CODE_STEP_FAILURES
    return EXIT_CODE_OK


def _safe_int(value):
    """Best-effort int conversion. Returns None if value can't be coerced."""
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _module_succeeded(results, module_name):
    """True if `module_name` already ran AND succeeded as an explicit step.

    The end-of-run finalizers (summary, html_report) always run automatically
    with the correct output_directory. If the user also lists one via -m/-w it
    would otherwise run twice, versioning the first output into a spurious
    .run<N> file — so we skip the finalizer when the explicit step succeeded.

    We require success (not merely presence): the explicit module step derives
    its output dir from the prefix kwarg and can produce nothing (status
    'warning'/'failed'), in which case the finalizer MUST still run so a report
    is actually generated.
    """
    for r in (results or []):
        if (isinstance(r, dict) and r.get("module") == module_name
                and r.get("status") == "success"):
            return True
    return False


def _create_results_archive(output_directory, output_prefix):
    """Build (or rebuild) {output_prefix}-results.zip in output_directory.

    Overwrites any existing archive so the zip always reflects the latest run —
    called from the main, --resume, and --continue paths so every run type
    refreshes the deliverable. Best-effort: a failure is logged, never fatal.

    Includes: top-level files in output_directory, top-level files in data/
    (no subdirs like data/runs/), and the entire reports/ and logs/ trees.
    Prior-run snapshots (report.run2.html, *.run1.*) are skipped, and the
    standalone viewer is bundled so a recipient with only the zip can browse
    scan.db.
    """
    logger = logging.getLogger("monkeyx")
    try:
        zip_path = os.path.join(output_directory, f"{output_prefix}-results.zip")
        logger.info(f"Creating results archive: {zip_path}")
        print(f"\n[*] Creating results archive: {zip_path}")
        with zipfile.ZipFile(zip_path, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            for item in os.scandir(output_directory):
                # Skip scan.db's transient WAL/SHM sidecars: a checkpointed
                # scan.db is self-contained, and bundling a live sidecar makes a
                # read-only unzip fail to open the (WAL-mode) db.
                if item.is_file() and item.path != zip_path \
                        and item.name not in ("scan.db-wal", "scan.db-shm") \
                        and not _is_prior_run_snapshot(item.name):
                    archive.write(item.path, arcname=item.name)

            data_path = os.path.join(output_directory, "data")
            if os.path.isdir(data_path):
                for item in os.scandir(data_path):
                    if item.is_file() and not _is_prior_run_snapshot(item.name):
                        archive.write(item.path, arcname=os.path.join("data", item.name))

            # The exported ledger-*.txt list files now live in data/ledger/ — a
            # subdir, so the data/ top-level scan above skips them. Include it so
            # the target/port/URL/domain lists stay in the deliverable.
            ledger_path = os.path.join(data_path, "ledger")
            if os.path.isdir(ledger_path):
                for item in os.scandir(ledger_path):
                    if item.is_file() and not _is_prior_run_snapshot(item.name):
                        archive.write(item.path,
                                      arcname=os.path.join("data", "ledger", item.name))

            reports_path = os.path.join(output_directory, "reports")
            if os.path.isdir(reports_path):
                for root, dirs, files in os.walk(reports_path):
                    for fname in files:
                        # Skip prior-run snapshots (report.run2.html,
                        # summary.run1.md, ai-analysis.run1.json) — they're
                        # historical duplicates that clutter the deliverable;
                        # the current report/summary supersede them.
                        if _is_prior_run_snapshot(fname):
                            continue
                        fpath = os.path.join(root, fname)
                        arcname = os.path.relpath(fpath, output_directory)
                        archive.write(fpath, arcname=arcname)

            logs_path = os.path.join(output_directory, "logs")
            if os.path.isdir(logs_path):
                for root, dirs, files in os.walk(logs_path):
                    for fname in files:
                        fpath = os.path.join(root, fname)
                        arcname = os.path.relpath(fpath, output_directory)
                        archive.write(fpath, arcname=arcname)

            # Bundle the standalone viewer so a recipient with only this zip
            # can browse scan.db (same as API-produced zips). Best-effort.
            try:
                from viewer.bundle import bundle_viewer
                bundle_viewer(archive)
            except Exception as exc:
                logger.warning(f"Viewer bundling skipped: {exc}")
        logger.info(f"Results archive created: {zip_path}")
        print(f"[+] Results archive: {zip_path}")
    except Exception as e:
        logger.error(f"Error creating results archive: {e}", exc_info=True)
        print(f"[!] Error creating results archive: {e}")


def _run_finalizers(output_directory, results):
    """Generate the end-of-run summary + HTML report.

    Always runs unless the same module already ran successfully as an explicit
    step (avoids a duplicate that would version the report into report.run<N>).
    """
    # `logger` in this module is a per-call local created by setup_logging(); as
    # a module-level function we fetch the same configured 'monkeyx' logger by
    # name (setup_logging configures it) rather than relying on a global.
    logger = logging.getLogger("monkeyx")

    if not _module_succeeded(results, "summary"):
        try:
            from modules.summary import generate_summary
            generate_summary(output_directory, results or [])
        except Exception as e:
            logger.warning(f"Summary generation failed: {e}")

    report_path = None
    if not _module_succeeded(results, "html_report"):
        try:
            from modules.html_report import generate_html_report
            report_path = generate_html_report(output_directory)
        except Exception as e:
            logger.warning(f"HTML report generation failed: {e}")
    else:
        # html_report ran as an explicit step — surface its known output path.
        for r in (results or []):
            if isinstance(r, dict) and r.get("module") == "html_report":
                files = r.get("output_files") or []
                report_path = files[0] if files else None
                break

    # Print a prominent, unambiguous pointer to the report at the very end of the
    # run (or say clearly when none was produced), so it isn't lost in scan noise.
    if report_path:
        print(f"\n[+] HTML report generated: {report_path}")
        logger.info("HTML report generated: %s", report_path)
    else:
        print("\n[!] No HTML report generated (no markdown reports found in reports/).")
        logger.info("No HTML report generated for %s", output_directory)


def _install_pause_handler(output_directory):
    """Install SIGINT handler for --finish-step (graceful pause) mode.

    First Ctrl+C sets the pause sentinel; second Ctrl+C raises KeyboardInterrupt.
    """
    pause_requested = False
    _original_sigint = signal.getsignal(signal.SIGINT)

    def _handler(signum, frame):
        nonlocal pause_requested
        if pause_requested:
            signal.signal(signal.SIGINT, _original_sigint)
            print("\n[!] Force exit requested.")
            raise KeyboardInterrupt
        pause_requested = True
        print("\n[!] Pause requested. Current step will complete, then checkpoint will be written.")
        Checkpoint(output_directory).request_pause()

    signal.signal(signal.SIGINT, _handler)


def _fleet_cleanup(fleet_name, *, keep_fleet, fleet_init_interrupted,
                   expected_nodes=None, account=None):
    """Kill fleet with appropriate strategy. Called in finally blocks."""
    if keep_fleet:
        print(f"[*] Fleet '{fleet_name}' kept alive (--keep-fleet)")
        return
    from core.fleet import kill_fleet, kill_fleet_with_retries, iauth, _is_no_cloud_fleet
    # Local-only / no-fleet run: no cloud instances exist, so skip teardown
    # entirely (and the needless re-auth). "local" is the no-cloud sentinel.
    if _is_no_cloud_fleet(fleet_name):
        return
    # Re-auth before teardown: a long run can outlive the cloud session, and an
    # unauthenticated `ax rm` silently orphans (billing) instances. iauth falls
    # back to AXIOM_ACCOUNT/config when account is None.
    iauth(account)
    try:
        if fleet_init_interrupted:
            kill_fleet_with_retries(fleet_name, expected_nodes=expected_nodes)
        elif not kill_fleet(fleet_name, account=account):
            print(f"[!] Fleet '{fleet_name}' teardown UNCONFIRMED — may still be "
                  f"billing. Re-auth and run: ax rm '{fleet_name}*' -f")
    except Exception as e:
        print(f"[!] Error killing fleet: {e}")
        print(f"[!] Manual cleanup: ax rm '{fleet_name}*' -f")


def _handle_pause_exit(fleet_name, *, keep_fleet, output_directory, account=None):
    """Handle SystemExit(42) — pause. Kill fleet unless --keep-fleet."""
    print(f"\n[*] Scan paused. Resume with:")
    print(f"    python3 monkeyx.py --resume {output_directory} -f {fleet_name}")
    if not keep_fleet:
        from core.fleet import kill_fleet, iauth, _is_no_cloud_fleet
        if _is_no_cloud_fleet(fleet_name):
            return
        iauth(account)
        try:
            if not kill_fleet(fleet_name, account=account):
                print(f"[!] Fleet '{fleet_name}' teardown UNCONFIRMED — may still be "
                      f"billing. Re-auth and run: ax rm '{fleet_name}*' -f")
        except Exception:
            print(f"[!] Manual cleanup: ax rm '{fleet_name}*' -f")
    else:
        print(f"[*] Fleet '{fleet_name}' kept alive")


def _detect_output_prefix(data_dir):
    """Detect the output prefix from existing files in the data directory.

    Looks at non-directory files and finds the longest common prefix that ends
    before a hyphen (the separator between prefix and module suffix).
    Returns None if no files or no common prefix found.
    """
    try:
        files = [f for f in os.listdir(data_dir)
                 if os.path.isfile(os.path.join(data_dir, f))
                 and not f.startswith('.')]
    except OSError:
        return None

    if not files:
        return None

    # Files are named {prefix}-{suffix}.ext — find the common prefix up to the
    # first hyphen-separated boundary shared by all files.
    prefixes = set()
    for name in files:
        # Skip ledger/step-snapshot/progress files that don't follow prefix convention
        if name.startswith('ledger-') or name.startswith('step-'):
            continue
        # Extract everything before the first hyphen that starts a module suffix
        # e.g. "2026-06-01-nuclei.jsonl" -> try progressively longer hyphen-delimited segments
        parts = name.split('-')
        # Build candidate prefixes from left: "2026", "2026-06", "2026-06-01", etc.
        for i in range(1, len(parts)):
            prefixes.add('-'.join(parts[:i]))

    if not prefixes:
        return None

    # Find the longest prefix that matches ALL non-special files
    candidate_files = [f for f in files
                       if not f.startswith('ledger-') and not f.startswith('step-')]
    if not candidate_files:
        return None

    best = None
    for prefix in sorted(prefixes, key=len, reverse=True):
        # The prefix must be followed by a hyphen in all candidate files
        dash_prefix = prefix + '-'
        if all(f.startswith(dash_prefix) for f in candidate_files):
            best = prefix
            break

    return best


# Modules whose raw output `normalize` consumes into findings/JSONL. If a
# --continue run includes any of these but NOT `normalize`, the scanner output
# is produced but never turned into findings/scan.db rows — exactly the gap that
# silently dropped 8916 nuclei results in one real engagement (ax_nuclei ran in a
# --continue that omitted normalize). Keep in sync with normalize.py's input
# globs (nuclei/httpx/nmap/subfinder/ffuf/feroxbuster/bbot/dns_security).
_SCANNER_MODULES_NEEDING_NORMALIZE = frozenset({
    "ax_nuclei", "ax_nmap_tcp", "ax_nmap_udp", "ax_httpx", "ax_ffuf",
    "ax_feroxbuster", "ax_gowitness", "subfinder", "dns_resolve",
    "dnsx_resolve", "ax_puredns_bruteforce",
    "bbot_scan", "bbot_recon", "bbot_subdomain",
})


def _warn_if_normalize_missing(flat_names, data_dir):
    """Warn when a --continue run would leave scanner output un-normalized.

    Two independent checks:
    1. Run-plan: the run includes scanner module(s) but not `normalize`, so their
       output won't become findings / reach scan.db / the report this run.
    2. Staleness: raw scanner output already on disk post-dates the newest
       `*-normalized.jsonl`, meaning a PRIOR run left output un-normalized.

    Warn-only (never blocks): the operator may deliberately be re-running one
    step. Prints the exact recovery command.
    """
    run_set = set(flat_names)
    scanners_in_run = sorted(run_set & _SCANNER_MODULES_NEEDING_NORMALIZE)
    normalize_in_run = "normalize" in run_set

    if scanners_in_run and not normalize_in_run:
        print("\n[!] WARNING: this --continue runs scanner module(s) "
              f"({', '.join(scanners_in_run)}) but NOT `normalize`.")
        print("    Their output will be written to disk but NOT turned into "
              "findings / scan.db / the report this run.")
        print("    Add `normalize` (and `jsonl_to_csv`) to the run, e.g.:")
        print(f"      -m {' '.join(scanners_in_run)} normalize jsonl_to_csv\n")
        return

    # Staleness check only matters when we're NOT already normalizing this run.
    if normalize_in_run:
        return
    try:
        raw_globs = ("*-nuclei.jsonl", "*-httpx.jsonl", "*.xml",
                     "*-ffuf.jsonl", "*-bbot-*.jsonl")
        raw_mtime = 0.0
        for pat in raw_globs:
            for p in glob.glob(os.path.join(data_dir, pat)):
                raw_mtime = max(raw_mtime, os.path.getmtime(p))
        norm_mtime = 0.0
        for p in glob.glob(os.path.join(data_dir, "*-normalized.jsonl")):
            norm_mtime = max(norm_mtime, os.path.getmtime(p))
        if raw_mtime > 0 and raw_mtime > norm_mtime:
            print("\n[!] WARNING: raw scanner output in data/ is newer than the "
                  "last `normalize` run — findings/scan.db may be stale.")
            print("    Re-run `normalize jsonl_to_csv` to fold it in:")
            print("      --continue <dir> -m normalize jsonl_to_csv analyze\n")
    except OSError:
        pass


def _continue_in_directory(args):
    """Run additional modules/workflows in an existing output directory."""
    output_directory = args.continue_dir

    ledger_path = os.path.join(output_directory, 'discovery-ledger.jsonl')
    if not os.path.exists(ledger_path):
        print("[!] Error: No discovery-ledger.jsonl found in output directory.")
        print(f"    Path checked: {ledger_path}")
        print("    --continue requires a directory from a previous run.")
        sys.exit(1)

    if not args.modules and not args.workflow:
        print("[!] Error: --continue requires -m (modules) and/or -w (workflow) to specify what to run.")
        sys.exit(1)

    data_dir = os.path.join(output_directory, "data")
    reports_dir = os.path.join(output_directory, "reports")
    logs_dir = os.path.join(output_directory, "logs")
    input_dir = os.path.join(output_directory, "input")
    os.makedirs(data_dir, exist_ok=True)
    os.makedirs(reports_dir, exist_ok=True)
    os.makedirs(logs_dir, exist_ok=True)

    # Resolve target args — accept file paths, single values, or comma-separated lists
    try:
        args.target = _resolve_target_arg(args.target, input_dir, "targets")
        args.domainlist = _resolve_target_arg(args.domainlist, input_dir, "domains")
        args.urllist = _resolve_target_arg(args.urllist, input_dir, "urls")
    except FileNotFoundError as e:
        print(f"[!] Error: {e}")
        sys.exit(1)

    # Copy original input files into logs/ for reference
    for src in (args.target, args.domainlist, args.urllist):
        if src and os.path.isfile(src):
            shutil.copy2(src, logs_dir)

    # Auto-detect the output prefix from existing files when -o wasn't explicitly
    # provided (i.e. args.output is just today's date default).
    user_specified_output = '-o' in sys.argv or '--output' in sys.argv
    if user_specified_output:
        output_prefix = args.output
    else:
        detected = _detect_output_prefix(data_dir)
        if detected:
            # Re-validate: the detected prefix is interpolated into ax/nmap shell
            # commands. It derives from existing (already-sanitized) filenames, so
            # this is defense-in-depth against a hand-crafted data dir.
            output_prefix = shell_safe_str(detected)
            print(f"[*] Auto-detected output prefix: {detected}")
        else:
            output_prefix = args.output

    logger = setup_logging(output_prefix, verbose=args.verbose, output_dir=logs_dir)
    logger.info("Continue mode: running additional modules in %s", output_directory)

    workflow_names = args.workflow if args.workflow else None
    workflow_name = ",".join(workflow_names) if workflow_names else None
    modules_to_run = args.modules if args.modules else None

    # Clean error (not a traceback) for a mistyped workflow name.
    if workflow_names:
        unknown_workflows = [w for w in workflow_names if w not in WORKFLOWS]
        if unknown_workflows:
            print(f"[!] Error: Unknown workflow(s): {', '.join(unknown_workflows)}")
            print(f"    Available workflows: {', '.join(sorted(WORKFLOWS.keys()))}")
            print("    Run 'monkeyx --list-plugins' for details.")
            sys.exit(1)

    final_modules = []
    if modules_to_run and workflow_names:
        workflow_steps = get_resolved_workflows_rich(workflow_names)
        workflow_set = set(_flatten_step_names(workflow_steps))
        final_modules = list(workflow_steps)
        additional = [ModuleStep(name=m) for m in modules_to_run if m not in workflow_set]
        final_modules.extend(additional)
    elif modules_to_run:
        final_modules = modules_to_run
    elif workflow_names:
        final_modules = get_resolved_workflows_rich(workflow_names)

    # Auto-inject ax_nmap_tcp (web ports, light version detection) and
    # dns_resolve when needed before web modules that lack a URL source.
    # In continue mode the existing ledger may already have URLs from a
    # prior run — treat presence of any prior URL entries as an existing
    # URL source so we don't over-inject.
    ledger_has_urls = False
    try:
        ledger_path = os.path.join(output_directory, "discovery-ledger.jsonl")
        if os.path.exists(ledger_path):
            with open(ledger_path) as _lf:
                for _line in _lf:
                    if '"type": "url"' in _line:
                        ledger_has_urls = True
                        break
    except Exception:
        pass

    final_modules, _sweep_off = _apply_sweep_toggle(final_modules, _sweep_enabled(args))
    if _sweep_off:
        print("[*] Sweep-then-verify disabled — masscan sweep skipped; nmap scans top-1000 directly")

    if getattr(args, "no_subdomain_enum", False):
        final_modules, skipped_enum = _filter_subdomain_enum(final_modules)
        for m in skipped_enum:
            logger.warning("%s skipped — --no-subdomain-enum is set", m)
            print(f"[!] {m} skipped — --no-subdomain-enum is set "
                  f"(enum module suppressed)")

    if not args.no_auto_discovery and not ledger_has_urls:
        final_modules, injected = _auto_inject_web_discovery(
            final_modules,
            has_targets=bool(args.target),
            has_domains=bool(args.domainlist),
            has_urls=bool(args.urllist),
        )
        if injected:
            logger.info("Auto-injected modules: %s", ", ".join(injected))
            print(f"[i] Auto-injected modules: {', '.join(injected)} "
                  f"(use --no-auto-discovery to disable)\n")

    # When --url-prune is on, ensure ax_httpx runs before the heavy web scanners
    # so the live-URL prune has liveness data (else it fail-opens to the full list).
    if not args.no_auto_discovery and getattr(args, "url_prune", "off") != "off":
        final_modules, injected_httpx = _auto_inject_httpx_for_prune(final_modules)
        if injected_httpx:
            logger.info("Auto-injected for --url-prune: %s", ", ".join(injected_httpx))
            print(f"[i] Auto-injected for --url-prune={args.url_prune}: "
                  f"{', '.join(injected_httpx)} (use --no-auto-discovery to disable)\n")

    flat_names = _flatten_step_names(final_modules)

    invalid = [m for m in flat_names if m not in AVAILABLE_MODULES]
    if invalid:
        print(f"[!] Error: Unknown modules: {', '.join(invalid)}")
        sys.exit(1)

    # Warn (don't block) if this continue would leave scanner output
    # un-normalized — the gap that silently dropped nuclei results before.
    _warn_if_normalize_missing(flat_names, data_dir)

    local_only = _all_modules_local(flat_names)
    if not args.fleet and not args.dry_run and not local_only:
        args.fleet = f"monkeyx-{secrets.token_hex(2)}"
        print(f"[*] No fleet specified, auto-generating: {args.fleet}")
    if not args.fleet:
        args.fleet = "local"

    print(f"\n{'='*60}")
    print(f"Continue mode")
    print(f"  Output dir: {output_directory}")
    print(f"  Fleet: {args.fleet}")
    print(f"  Modules: {', '.join(flat_names)}")
    print(f"{'='*60}\n")

    full_prefix = os.path.join(output_directory, output_prefix)
    logs_prefix = os.path.join(logs_dir, output_prefix)
    fleet_initialized = False
    fleet_cleanup_needed = False
    fleet_init_interrupted = False
    results = []
    exit_code = EXIT_CODE_OK
    cost_tracker = CostTracker()

    module_kwargs = {
        'prefix': os.path.join(output_directory, output_prefix),
        'data_prefix': os.path.join(data_dir, output_prefix),
        'reports_prefix': os.path.join(reports_dir, output_prefix),
        'fleet': args.fleet,
        'scan_type': args.scan_type,
        'scope_filter': args.scope_filter,
        'ip_scope': args.ip_scope,
        'url_prune': getattr(args, 'url_prune', 'live'),
        'url_max_per_host': getattr(args, 'url_max_per_host', None),
        'nodes': args.nodes,
        'continue_mode': True,
    }
    if args.engagement_id:
        module_kwargs['engagement_id'] = args.engagement_id
    if args.exclusion_file:
        module_kwargs['exclusion_file'] = str(args.exclusion_file)
    if args.nessus_file:
        module_kwargs['nessus_file'] = str(args.nessus_file)
    if args.ai_depth:
        module_kwargs['ai_depth'] = args.ai_depth
    module_kwargs['allow_intrusive'] = args.allow_intrusive
    module_kwargs['rebuttal'] = args.rebuttal
    module_kwargs['ai_multipass'] = args.ai_multipass

    if args.target:
        module_kwargs['target'] = args.target
    if args.domainlist:
        module_kwargs['domainlist'] = args.domainlist
    if args.urllist:
        module_kwargs['user_url_file'] = args.urllist
    if args.dry_run:
        module_kwargs['dry_run'] = True

    if args.finish_step:
        _install_pause_handler(output_directory)

    try:
        # Node count for the fleet + scaler. Defaults to -n; when --auto-scale is
        # on and -n was left at its default, the reinit fleet is sized from the
        # existing on-disk ledger (resolved, in-scope targets from the prior run).
        fleet_nodes = args.nodes
        scaler_nodes = _safe_int(args.nodes) or 1
        if args.dry_run:
            print("[DRY-RUN] Skipping fleet initialization")
        elif local_only:
            print("[*] All modules are local — no fleet required")
        else:
            exists, node_count = fleet_exists(args.fleet)
            if exists:
                logger.warning("Reusing existing fleet '%s' (%s nodes)", args.fleet, node_count)
                print(f"[*] Reusing existing fleet '{args.fleet}' ({node_count} nodes)")
                fleet_cleanup_needed = True
                scaler_nodes = node_count
                cost_tracker.fleet_started(args.fleet, node_count)
            else:
                # Size the fleet from the existing ledger when auto-scaling and -n
                # was left at the default. An explicit -n always wins.
                if args.auto_scale and args.nodes == '1':
                    try:
                        sized = compute_initial_nodes(
                            existing_ledger_dir=output_directory,
                            ip_scope=getattr(args, 'ip_scope', 'provenance'),
                            max_nodes=args.max_nodes)
                        if sized > 1:
                            fleet_nodes = str(sized)
                            scaler_nodes = sized
                            print(f"[*] Auto-scale: sized fleet to {fleet_nodes} nodes from the ledger")
                            logger.info("Auto-scale initial sizing (continue): %s nodes", fleet_nodes)
                    except Exception as e:
                        logger.warning("Initial fleet sizing failed; using -n=%s (%s)", args.nodes, e)
                logger.info("Initializing fleet")
                iauth(args.ax_account)
                fleet_cleanup_needed = True
                fleet_init_interrupted = True
                try:
                    initialize_fleet(args.fleet, fleet_nodes, logs_prefix, args.wait)
                    fleet_init_interrupted = False
                except KeyboardInterrupt:
                    logger.warning("Ctrl+C during fleet init — instances may still be provisioning")
                    print("\n[!] Ctrl+C during fleet init. Will retry teardown to catch stragglers.")
                    raise
                print(f"[+] Fleet '{args.fleet}' initialized ({fleet_nodes} nodes)")
                cost_tracker.fleet_started(args.fleet, int(fleet_nodes))
            fleet_initialized = True

        if args.auto_scale and not local_only and not args.dry_run:
            scaler = FleetScaler(
                initial_fleet=args.fleet,
                initial_nodes=scaler_nodes,
                max_nodes=args.max_nodes,
                logs_prefix=logs_prefix,
                cost_tracker=cost_tracker,
                account=args.ax_account,
            )
        else:
            scaler = NoOpScaler(fleet=args.fleet, nodes=scaler_nodes)

        results = run_modules(
            final_modules, cleanup=False,
            resume_from=0, finish_step=args.finish_step,
            scaler=scaler,
            output_dir=output_directory,
            workflow_name=workflow_name,
            keep_fleet=args.keep_fleet,
            **module_kwargs,
        )

        _print_results_summary(
            results,
            header="Continue Execution Complete",
            output_directory=output_directory,
        )
        exit_code = _completion_exit_code(results)

    except SystemExit as e:
        if e.code == EXIT_CODE_PAUSED:
            _handle_pause_exit(args.fleet, keep_fleet=args.keep_fleet,
                               output_directory=output_directory,
                               account=args.ax_account)
            fleet_cleanup_needed = False
            exit_code = EXIT_CODE_PAUSED
        else:
            raise

    except KeyboardInterrupt:
        logger.warning("Continue run interrupted")
        print("\n[!] Interrupted.")
        exit_code = 130

    except Exception as e:
        logger.error(f"Error during continue: {e}", exc_info=True)
        print(f"\n[!] Error: {e}")
        exit_code = EXIT_CODE_FATAL

    finally:
        if fleet_cleanup_needed:
            cost_tracker.fleet_stopped()
            _fleet_cleanup(args.fleet, keep_fleet=args.keep_fleet,
                           fleet_init_interrupted=fleet_init_interrupted,
                           account=args.ax_account,
                           expected_nodes=scaler_nodes)

        for r in (results or []):
            if isinstance(r, dict) and r.get("ai_usage"):
                cost_tracker.record_ai_usage(r["ai_usage"])
        cost_tracker.write(os.path.join(logs_dir, f"costs-{datetime.now().strftime('%Y%m%d-%H%M%S')}.txt"))

        _run_finalizers(output_directory, results)

        # Rebuild the results archive so a --continue run overwrites the old one
        # with the now-fuller results (uses the detected/original output prefix).
        _create_results_archive(output_directory, output_prefix)

    sys.exit(exit_code)


def _print_results_summary(results: list, header: str = "Execution Complete",
                            output_directory: str | None = None,
                            log_path: str | None = None):
    """Print a uniform success/failure summary for a completed run.

    Reads each result dict's `status` and `error` fields. Failed modules are
    listed by name with the error message (truncated to one line).
    """
    import logging
    log = logging.getLogger("monkeyx")

    total = len(results)
    failed = [r for r in results if isinstance(r, dict) and r.get('status') == 'failed']
    succeeded = total - len(failed)

    log.info("=" * 60)
    log.info(header)
    log.info("Total modules executed: %d (succeeded: %d, failed: %d)",
             total, succeeded, len(failed))
    for r in failed:
        err = (r.get('error') or '').splitlines()[0] if r.get('error') else 'no error message'
        log.info("  Failed: %s — %s", r.get('module', '?'), err)

    print(f"\n{'='*60}")
    print(header)
    print(f"{'='*60}")
    print(f"Total modules executed: {total}")
    print(f"  Succeeded: {succeeded}")
    print(f"  Failed:    {len(failed)}")
    for r in failed:
        err = (r.get('error') or 'no error message').splitlines()[0]
        if len(err) > 100:
            err = err[:97] + "..."
        print(f"    - {r.get('module', '?')}: {err}")
    if output_directory:
        print(f"Output directory: {output_directory}")
    if log_path:
        print(f"Log files: {log_path}")
    print(f"{'='*60}\n")


def _flatten_step_names(items) -> list[str]:
    """Walk a list of strings, ModuleStep, ParallelGroup and return flat names in order."""
    names = []
    for item in items:
        if isinstance(item, str):
            names.append(item)
        elif isinstance(item, ModuleStep):
            names.append(item.name)
        elif isinstance(item, ParallelGroup):
            names.extend(s.name for s in item.steps)
    return names


def _format_step_display(items) -> list[str]:
    """Format step items for user-facing display (parallel groups shown as [parallel: ...])."""
    display = []
    for item in items:
        if isinstance(item, str):
            display.append(item)
        elif isinstance(item, ModuleStep):
            display.append(item.name)
        elif isinstance(item, ParallelGroup):
            names = [s.name for s in item.steps]
            display.append(f"[parallel: {', '.join(names)}]")
    return display


def _confirm_scope_and_exit(args, data_dir):
    """Dry pass for --confirm-scope: seed + resolve + classify + print, then exit.

    Spins up NO fleet and runs no scanning. Seeds the ledger from -t/-d/-url,
    seeds exclusions, runs a LOCAL dns resolution so -d/-url names classify
    against the -t ranges (surfacing the ownership promotion), prints the scope
    echo, and exits 0. This is the artifact to confirm scope before an engagement.
    """
    from core.target_ledger import TargetLedger
    from workflows import format_scope_echo, run_module

    os.makedirs(data_dir, exist_ok=True)
    ledger = TargetLedger(os.path.dirname(data_dir) or ".")
    ledger.set_ip_scope_mode(getattr(args, "ip_scope", "provenance"))
    ledger.seed_user_inputs(args.target, args.domainlist, args.urllist)
    if getattr(args, "exclusion_file", None):
        ledger.seed_exclusions(args.exclusion_file)

    # Best-effort local resolution so names map to IPs and classify against -t.
    # dns_resolve is local (no fleet); failures are non-fatal for a preview.
    try:
        tgt = os.path.join(data_dir, "confirm-targets.txt")
        n = ledger.export_targets(tgt, "strict")
        if n and (args.target or args.domainlist):
            run_module("dns_resolve", target=tgt,
                       prefix=os.path.join(data_dir, "confirm"),
                       data_prefix=os.path.join(data_dir, "confirm"),
                       fleet="local", _dry_run=False)
    except Exception as e:
        print(f"[i] (scope preview: local resolution skipped: {e})")

    print(f"\n{'='*60}")
    print("SCOPE CONFIRMATION (dry pass — no fleet, no scanning)")
    print(f"{'='*60}")
    print(format_scope_echo(ledger))
    print(f"{'='*60}")
    print("Host-full assets are scanned on all ports. Name-safe assets are tested")
    print("by hostname only (Host/SNI) — safe on shared infra. Leads are reported,")
    print("not scanned. Re-run without --confirm-scope to execute.")
    print(f"{'='*60}\n")
    sys.exit(0)


_SWEEP_OFF_PORTS = "top-1000"   # what an nmap `ports: open` step scans when sweep is off


def _sweep_enabled(args) -> bool:
    """Resolve the sweep-then-verify toggle: --no-sweep (CLI) wins; else
    monkeyx.config scan.sweep (default True)."""
    if getattr(args, "no_sweep", False):
        return False
    try:
        from core.config import load_scan_config
        return bool(load_scan_config().get("sweep", True))
    except Exception:
        return True


def _apply_sweep_toggle(items, enabled: bool):
    """When sweep-then-verify is DISABLED, drop masscan pre-sweep steps and turn
    any nmap `ports: open` step into a direct scan (top-1000). A global override
    on top of whatever the workflow chose. Returns (items, changed)."""
    if enabled:
        return items, False
    changed = False

    def _fix(ms):
        nonlocal changed
        if ms.name == "ax_nmap_tcp" and (ms.args or {}).get("ports") == "open":
            changed = True
            return ModuleStep(name=ms.name, args={**ms.args, "ports": _SWEEP_OFF_PORTS})
        return ms

    out = []
    for item in items:
        if isinstance(item, ModuleStep):
            if item.name == "ax_masscan":
                changed = True
                continue
            out.append(_fix(item))
        elif isinstance(item, ParallelGroup):
            members = [_fix(m) for m in item.steps if m.name != "ax_masscan"]
            if len(members) != len(item.steps):
                changed = True
            if members:
                out.append(ParallelGroup(steps=members))
        else:
            out.append(item)
    return out, changed


def _filter_subdomain_enum(items):
    """Remove subdomain-enumeration modules from the pipeline (--no-subdomain-enum).

    Enum modules are tagged in core.scope_classes.ENUM_MODULES. When the operator
    explicitly selected one, we WARN and skip it (rather than error) so the
    contradictory intent is visible in the log. -d names still get full
    name-safe testing; only new-subdomain DISCOVERY is suppressed.

    Returns (filtered_items, list_of_skipped_module_names).
    """
    from core import scope_classes

    skipped: list[str] = []

    def _keep(name: str) -> bool:
        if scope_classes.is_enum_module(name):
            skipped.append(name)
            return False
        return True

    filtered = []
    for item in items:
        if isinstance(item, str):
            if _keep(item):
                filtered.append(item)
        elif isinstance(item, ModuleStep):
            if _keep(item.name):
                filtered.append(item)
        elif isinstance(item, ParallelGroup):
            kept_steps = [s for s in item.steps if _keep(s.name)]
            if kept_steps:
                filtered.append(ParallelGroup(steps=kept_steps))
            # an all-enum parallel group collapses to nothing (dropped)
        else:
            filtered.append(item)
    return filtered, skipped


def _auto_inject_web_discovery(items, has_targets: bool, has_domains: bool,
                                has_urls: bool):
    """Inject ax_nmap_tcp (web ports, light version) and dns_resolve when
    needed before web modules in `items` if no URL-producing module precedes them.

    A web module is one declaring `CONSUMES_URLS = True`. URL-producing
    sources are: explicit `-url` input, any module declaring
    `PRODUCES["nmap_xml"]`, or `subfinder` (which feeds dns_resolve which
    feeds the discovery scan).

    Skip nmap injection when:
      - The user passed `--no-auto-discovery`
      - The pipeline already has a URL source before the web module
      - There are no targets, domains, or URLs to scan from at all
      - There are no -t targets (domains-only run): the host-class nmap would be
        scope-gated to nothing, so name-safe URL synthesis handles it instead.

    Returns: (new_items_list, list_of_injected_module_names_for_logging).
    """
    if has_urls:
        return list(items), []

    # Don't inject if the user has nothing to give us to scan from
    if not (has_targets or has_domains):
        return list(items), []

    new_items = []
    injected: list[str] = []
    nmap_tcp_already_seen = False
    nmap_xml_already_seen = False
    dns_resolve_already_seen = False

    for item in items:
        names = []
        if isinstance(item, str):
            names = [item]
        elif isinstance(item, ModuleStep):
            names = [item.name]
        elif isinstance(item, ParallelGroup):
            names = [s.name for s in item.steps]

        # If this step contains a web module and no URL source has been seen
        # yet, ensure it has one. For -t targets we inject a host-class nmap web
        # scan (discovers real open web ports on owned hosts — richer). For a
        # domains-only run (no -t), that nmap would be scope-gated to nothing and
        # would waste a fleet, so we DON'T inject it: name-safe URL synthesis
        # (ledger.synthesize_name_urls, run during target-file regeneration)
        # seeds http/https URLs for the -d hosts, which the web module probes by
        # hostname (Host/SNI) — the option-A safe path on shared infra.
        if any(_module_consumes_urls(n) for n in names):
            if has_targets and not (nmap_tcp_already_seen or nmap_xml_already_seen):
                # Inject dns_resolve first if we have domains but it hasn't run
                if has_domains and not dns_resolve_already_seen:
                    new_items.append(ModuleStep(name="dns_resolve"))
                    injected.append("dns_resolve")
                    dns_resolve_already_seen = True
                new_items.append(ModuleStep(
                    name="ax_nmap_tcp",
                    args={"ports": "web", "version": "light", "scripts": False},
                ))
                injected.append("ax_nmap_tcp")
                nmap_tcp_already_seen = True
                nmap_xml_already_seen = True

        new_items.append(item)

        # Track what's now in the pipeline for subsequent web-module checks
        _hardcoded_nmap_producers = {
            "ax_nmap_tcp", "ax_nmap_udp",
        }
        for n in names:
            if n == "ax_nmap_tcp":
                nmap_tcp_already_seen = True
                nmap_xml_already_seen = True
            elif n == "dns_resolve":
                dns_resolve_already_seen = True
            elif n in _hardcoded_nmap_producers or _module_produces_nmap_xml(n):
                nmap_xml_already_seen = True

    return new_items, injected


def _auto_inject_httpx_for_prune(items):
    """Ensure ax_httpx runs before the first heavy web scanner so --url-prune has
    liveness data. No-op if httpx already precedes them (or shares their group).

    Returns (new_items_list, injected_names).
    """
    from workflows import _LIVE_URL_SCANNERS

    def _names(item):
        if isinstance(item, str):
            return [item]
        if isinstance(item, ModuleStep):
            return [item.name]
        if isinstance(item, ParallelGroup):
            return [s.name for s in item.steps]
        return []

    new_items, injected = [], []
    httpx_seen = False
    for item in items:
        names = _names(item)
        has_httpx = "ax_httpx" in names
        if (not httpx_seen and not has_httpx
                and any(n in _LIVE_URL_SCANNERS for n in names)):
            new_items.append(ModuleStep(name="ax_httpx"))
            injected.append("ax_httpx")
            httpx_seen = True
        new_items.append(item)
        if has_httpx:
            httpx_seen = True
    return new_items, injected


BANNER = r"""
███╗   ███╗ ██████╗ ███╗   ██╗██╗  ██╗███████╗██╗   ██╗██╗  ██╗
████╗ ████║██╔═══██╗████╗  ██║██║ ██╔╝██╔════╝╚██╗ ██╔╝╚██╗██╔╝
██╔████╔██║██║   ██║██╔██╗ ██║█████╔╝ █████╗   ╚████╔╝  ╚███╔╝
██║╚██╔╝██║██║   ██║██║╚██╗██║██╔═██╗ ██╔══╝    ╚██╔╝   ██╔██╗
██║ ╚═╝ ██║╚██████╔╝██║ ╚████║██║  ██╗███████╗   ██║   ██╔╝ ██╗
╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝

            Human-Led Offensive Automation
                  Version 1.0.0
"""


def main():
    """Main entry point for MonkeyX."""
    print(BANNER)
    args = parse_commands()

    if args.webserver_dir:
        from webserver import serve
        serve(args.webserver_dir, host=args.webserver_host,
              port=args.webserver_port)
        sys.exit(0)

    if getattr(args, "check", False):
        # Preflight: validate inputs/creds/config and exit — no run dir, no fleet.
        # Resolve -t/-d/-url (file paths OR inline lists) into temp files using the
        # same logic a real run would, so what we validate is what a run would use.
        import tempfile
        from core.preflight import run_preflight
        # AI is opt-in: only gate the AI-key check on it when the selected
        # modules/workflows actually include an AI module. Flatten workflows
        # (e.g. `deep` pulls in ai_analyze) best-effort — a bad workflow name
        # surfaces in a real run, so don't crash --check over it.
        selected = list(args.modules or [])
        if args.workflow:
            from workflows import get_resolved_workflow
            for wf in args.workflow:
                try:
                    selected += get_resolved_workflow(wf)
                except Exception:  # noqa: BLE001
                    pass
        ai_required = any(str(m).startswith("ai_") for m in selected)
        tmp = tempfile.mkdtemp(prefix="monkeyx-check-")
        try:
            t = _resolve_target_arg(args.target, tmp, "targets")
            d = _resolve_target_arg(args.domainlist, tmp, "domains")
            u = _resolve_target_arg(args.urllist, tmp, "urls")
            sys.exit(run_preflight(target=t, domainlist=d, urllist=u,
                                   output_dir=args.output_dir,
                                   ai_required=ai_required))
        except FileNotFoundError as e:
            print(f"[!] Error: {e}")
            sys.exit(1)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    if args.sync_knowledge:
        from core.knowledge import sync_sources, index_sources, load_config
        config = load_config()
        if not config.get("sources"):
            print("[!] No knowledge sources configured.")
            print("    Create ~/.monkeyx/knowledge.yaml (see knowledge.yaml.example)")
            sys.exit(1)
        print("[*] Syncing knowledge base sources...")
        sync_results = sync_sources()
        for name, status in sync_results.items():
            print(f"    {name}: {status}")
        print("[*] Indexing...")
        stats = index_sources()
        print(f"    {stats['sources']} source(s), {stats['files']} file(s), {stats['chunks']} chunk(s)")
        print("[+] Knowledge base ready.")
        sys.exit(0)

    if args.list_plugins:
        from core.plugin_loader import get_plugin_registry

        registry = get_plugin_registry()
        print("\nModules:")
        for name in sorted(AVAILABLE_MODULES.keys()):
            source = registry['modules'].get(name, 'built-in')
            print(f"  - {name:20} [{source}]")

        print("\nWorkflows:")
        for name in sorted(WORKFLOWS.keys()):
            source = registry['workflows'].get(name, 'built-in')
            raw_steps = WORKFLOWS[name]
            display_parts = []
            for s in raw_steps:
                if isinstance(s, str):
                    display_parts.append(s)
                elif isinstance(s, dict) and "workflow" in s:
                    display_parts.append(f"workflow:{s['workflow']}")
                elif isinstance(s, dict) and "parallel" in s:
                    inner = [i if isinstance(i, str) else i.get("name", str(i)) for i in s["parallel"]]
                    display_parts.append(f"[parallel: {', '.join(inner)}]")
                elif isinstance(s, dict) and "name" in s:
                    label = s["name"]
                    if s.get("args"):
                        label += f"({s['args']})"
                    display_parts.append(label)
                else:
                    display_parts.append(str(s))
            print(f"  - {name:20} [{source}] -> {', '.join(display_parts)}")
        print()
        return

    # Resume mode — bypass normal validation, load state from checkpoint
    if args.resume_dir:
        _resume_from_checkpoint(args)
        return

    # Continue mode — run new modules/workflows in existing output directory
    if args.continue_dir:
        _continue_in_directory(args)
        return

    if not args.output_dir:
        print("[!] Error: -od/--output-dir is required for scan execution")
        exit(1)

    # Validate that at least one input source is provided
    if not args.target and not args.domainlist and not args.urllist:
        print("[!] Error: At least one input source is required:")
        print("    -t/--target       (target file with IPs/hosts/domains)")
        print("    -d/--domain-list (domains/subdomains for subfinder)")
        print("    -url/--url-list    (web hosts for nuclei/gowitness/feroxbuster: full URLs or bare hostnames)")
        print("\nUse -h for help and examples.")
        exit(1)
    
    # Use the required output directory
    output_directory = args.output_dir
    
    # Create output directory and subdirectories
    os.makedirs(output_directory, exist_ok=True)
    data_dir = os.path.join(output_directory, "data")
    reports_dir = os.path.join(output_directory, "reports")
    logs_dir = os.path.join(output_directory, "logs")
    input_dir = os.path.join(output_directory, "input")
    os.makedirs(data_dir, exist_ok=True)
    os.makedirs(reports_dir, exist_ok=True)
    os.makedirs(logs_dir, exist_ok=True)

    # Resolve target args — accept file paths, single values, or comma-separated lists
    try:
        args.target = _resolve_target_arg(args.target, input_dir, "targets")
        args.domainlist = _resolve_target_arg(args.domainlist, input_dir, "domains")
        args.urllist = _resolve_target_arg(args.urllist, input_dir, "urls")
    except FileNotFoundError as e:
        print(f"[!] Error: {e}")
        sys.exit(1)

    # Copy original input files into logs/ for reference
    for src in (args.target, args.domainlist, args.urllist):
        if src and os.path.isfile(src):
            shutil.copy2(src, logs_dir)

    if getattr(args, "confirm_scope", False):
        _confirm_scope_and_exit(args, data_dir)

    # Initialize logging
    logger = setup_logging(args.output, verbose=args.verbose, output_dir=logs_dir)
    logger.info("MonkeyX started")
    logger.info(f"Output directory: {output_directory}")
    logger.debug(f"Command line arguments: {vars(args)}")
    
    # Determine what will be run. args.workflow is a list (nargs='+') or None.
    workflow_names = args.workflow if args.workflow else (None if args.modules else ['standard'])
    modules_to_run = args.modules if args.modules else None
    # Comma-joined display/metadata name (checkpoint + logging).
    workflow_name = ",".join(workflow_names) if workflow_names else None

    # Validate workflow names up front so a typo yields a clean message + the
    # available list, not an unhandled ValueError from the rich resolver below.
    if workflow_names:
        unknown_workflows = [w for w in workflow_names if w not in WORKFLOWS]
        if unknown_workflows:
            print(f"[!] Error: Unknown workflow(s): {', '.join(unknown_workflows)}")
            print(f"    Available workflows: {', '.join(sorted(WORKFLOWS.keys()))}")
            print("    Run 'monkeyx --list-plugins' for details.")
            sys.exit(1)

    logger.info(f"Workflow: {workflow_name}")
    if modules_to_run:
        logger.info(f"Custom modules specified: {', '.join(modules_to_run)}")

    # Calculate final module list for display and validation
    if modules_to_run and workflow_names:
        rich_steps = get_resolved_workflows_rich(workflow_names)
        workflow_set = set(_flatten_step_names(rich_steps))
        additional = [m for m in modules_to_run if m not in workflow_set]
        flat_module_names = _flatten_step_names(rich_steps) + additional
        display_modules = _format_step_display(rich_steps) + additional
        display_mode = f"Combined (modules + {workflow_name} workflow)"
    elif modules_to_run:
        flat_module_names = modules_to_run
        display_modules = modules_to_run
        display_mode = "Custom modules"
    else:
        rich_steps = get_resolved_workflows_rich(workflow_names)
        flat_module_names = _flatten_step_names(rich_steps)
        display_modules = _format_step_display(rich_steps)
        display_mode = f"Workflow: {workflow_name}"

    # Auto-injection of ax_nmap_tcp makes the url_file requirement
    # satisfiable when there are targets/domains but no URL source. Tell
    # validation to consider that case unless the user opted out.
    auto_discovery_active = (
        not args.no_auto_discovery
        and (bool(args.target) or bool(args.domainlist))
    )

    validation_errors = validate_module_inputs(
        flat_module_names,
        has_targets=bool(args.target),
        has_urls=bool(args.urllist),
        has_domains=bool(args.domainlist),
        auto_discovery_active=auto_discovery_active,
    )
    if validation_errors:
        print("[!] Warning: Some modules may not have required inputs at launch:")
        for err in validation_errors:
            print(f"    - {err}")
        print("\n    Modules without required inputs will be skipped at runtime.")
        print("    (Earlier pipeline steps may produce the needed inputs.)")
        try:
            resp = input("\n    Press Enter to continue, or Ctrl+C to abort: ")
        except KeyboardInterrupt:
            print("\nAborted.")
            sys.exit(1)

    # Check if fleet is required based on modules being run
    local_only = _all_modules_local(flat_module_names)
    if not args.fleet and not args.dry_run and not local_only:
        args.fleet = f"monkeyx-{secrets.token_hex(2)}"
        print(f"[*] No fleet specified, auto-generating: {args.fleet}")
    if not args.fleet:
        args.fleet = "local"

    # Sanity check to ensure proper scan flags are used before initializing fleet
    if args.wait:
        print(f"\n{'='*60}")
        print("Axiom Scan Summary")
        print(f"{'='*60}")
        print(f"  Fleet: {args.fleet} ({args.nodes} nodes)")
        print(f"  Output prefix: {args.output}")
        print(f"  Target file: {args.target}")
        print(f"  TCP scan type: {args.scan_type}")

        if args.domainlist:
            print(f"  Domain list: {args.domainlist}")

        if args.urllist:
            print(f"  URL list: {args.urllist} (will merge with parsed-weburls.txt if exists)")

        print(f"  Mode: {display_mode}")
        print(f"  Modules: {', '.join(display_modules)}")

        print(f"{'='*60}")
        try:
            input("\nPress Enter to continue, or Ctrl+C to abort: ")
        except KeyboardInterrupt:
            print("\nAborted.")
            sys.exit(1)
    
    # Initialize fleet (or reuse existing one)
    full_prefix = os.path.join(output_directory, args.output)
    logs_prefix = os.path.join(logs_dir, args.output)
    fleet_initialized = False
    fleet_cleanup_needed = False
    fleet_init_interrupted = False
    results = []
    exit_code = EXIT_CODE_OK
    cost_tracker = CostTracker()

    if args.finish_step:
        _install_pause_handler(output_directory)

    try:
        # Node count for the fleet + scaler. Defaults to -n; when --auto-scale is
        # on and -n was left at its default, the initial fleet is sized from the
        # workload below so it doesn't boot at 1 node and scale up on step 2.
        # _safe_int keeps the finally-block teardown valid even for a bad -n.
        fleet_nodes = args.nodes
        scaler_nodes = _safe_int(args.nodes) or 1
        if args.dry_run:
            print("[DRY-RUN] Skipping fleet initialization")
            logger.info("Dry-run mode — skipping fleet init")
        elif local_only:
            print("[*] All modules are local — no fleet required")
            logger.info("Local-only modules — skipping fleet init")
        else:
            exists, node_count = fleet_exists(args.fleet)
            if exists:
                msg = f"Reusing existing fleet '{args.fleet}' ({node_count} nodes). Fleet was not created by this run."
                logger.warning(msg)
                print(f"\n{'='*60}")
                print(f"[!] {msg}")
                print(f"{'='*60}\n")
                scaler_nodes = node_count
                from core.utils import bash_command
                bash_command(
                    f"ax ls | grep -i '{args.fleet}' | tr -s ' ' | cut -d ' ' -f 2 | tee '{logs_prefix}-axiom-source-ips.txt'",
                    check=False,
                )
                cost_tracker.fleet_started(args.fleet, node_count)
            else:
                # Size the opening fleet from the workload when auto-scaling and
                # -n was left at the default, so step 1 isn't stuck on one node.
                # An explicit -n always wins.
                if args.auto_scale and args.nodes == '1':
                    try:
                        sized = compute_initial_nodes(
                            target_file=args.target, domain_file=args.domainlist,
                            url_file=args.urllist, exclusion_file=args.exclusion_file,
                            ip_scope=getattr(args, 'ip_scope', 'provenance'),
                            max_nodes=args.max_nodes)
                        if sized > 1:
                            fleet_nodes = str(sized)
                            scaler_nodes = sized
                            print(f"[*] Auto-scale: sized initial fleet to {fleet_nodes} nodes from inputs")
                            logger.info("Auto-scale initial sizing: %s nodes", fleet_nodes)
                    except Exception as e:
                        logger.warning("Initial fleet sizing failed; using -n=%s (%s)", args.nodes, e)
                logger.info("Initializing Axiom authentication and fleet")
                iauth(args.ax_account)
                fleet_cleanup_needed = True
                fleet_init_interrupted = True
                try:
                    initialize_fleet(args.fleet, fleet_nodes, logs_prefix, args.wait)
                    fleet_init_interrupted = False
                    logger.info(f"Fleet '{args.fleet}' initialized with {fleet_nodes} nodes")
                except KeyboardInterrupt:
                    logger.warning("Ctrl+C during fleet init — instances may still be provisioning")
                    print("\n[!] Ctrl+C during fleet init. Instances may still be coming up in the cloud.")
                    print("[!] Will retry fleet teardown to catch stragglers.")
                    raise
                cost_tracker.fleet_started(args.fleet, int(fleet_nodes))
            fleet_initialized = True
            if not fleet_cleanup_needed:
                fleet_cleanup_needed = True
        # Prepare module arguments
        module_kwargs = {
            'prefix': os.path.join(output_directory, args.output),
            'data_prefix': os.path.join(data_dir, args.output),
            'reports_prefix': os.path.join(reports_dir, args.output),
            'fleet': args.fleet,
            'scan_type': args.scan_type,
        }

        if args.target:
            module_kwargs['target'] = args.target
        
        # Add domain list if provided
        if args.domainlist:
            module_kwargs['domainlist'] = args.domainlist
        
        # Pass user URL list to workflows - it will be merged with discovered URLs dynamically
        if args.urllist:
            logger.info(f"User-provided URL list: {args.urllist}")
            module_kwargs['user_url_file'] = args.urllist
            logger.info("User URLs will be seeded into ledger and audit trail")
            print(f"[*] User-provided URLs will be seeded into the target ledger")

        module_kwargs['scope_filter'] = args.scope_filter
        module_kwargs['ip_scope'] = args.ip_scope
        module_kwargs['url_prune'] = getattr(args, 'url_prune', 'live')
        module_kwargs['url_max_per_host'] = getattr(args, 'url_max_per_host', None)
        module_kwargs['nodes'] = args.nodes
        if args.engagement_id:
            module_kwargs['engagement_id'] = args.engagement_id
        if args.exclusion_file:
            module_kwargs['exclusion_file'] = str(args.exclusion_file)
        if args.nessus_file:
            module_kwargs['nessus_file'] = str(args.nessus_file)
        if args.ai_depth:
            module_kwargs['ai_depth'] = args.ai_depth
        module_kwargs['allow_intrusive'] = args.allow_intrusive
        module_kwargs['rebuttal'] = args.rebuttal
        module_kwargs['ai_multipass'] = args.ai_multipass
        if args.dry_run:
            module_kwargs['dry_run'] = True

        # Determine which modules to execute (with deduplication)
        final_modules = []
        
        if modules_to_run and workflow_names:
            workflow_steps = get_resolved_workflows_rich(workflow_names)
            workflow_set = set(_flatten_step_names(workflow_steps))
            final_modules = list(workflow_steps)
            additional_modules = [m for m in modules_to_run if m not in workflow_set]
            final_modules.extend([ModuleStep(name=m) for m in additional_modules])

            ignored_modules = [m for m in modules_to_run if m in workflow_set]
            flat_display = _format_step_display(final_modules)
            logger.info(f"Running workflow '{workflow_name}': {', '.join(flat_display)}")
            print(f"\n[i] Running workflow '{workflow_name}' in specified order")
            if ignored_modules:
                print(f"[i] Ignored (already in workflow): {', '.join(ignored_modules)}")
            if additional_modules:
                print(f"[i] Additional modules: {', '.join(additional_modules)}")
            print(f"[i] Final execution order: {', '.join(flat_display)}\n")
        elif modules_to_run:
            final_modules = modules_to_run
        else:
            final_modules = get_resolved_workflows_rich(workflow_names)

        final_modules, _sweep_off = _apply_sweep_toggle(final_modules, _sweep_enabled(args))
        if _sweep_off:
            print("[*] Sweep-then-verify disabled — masscan sweep skipped; nmap scans top-1000 directly")

        if getattr(args, "no_subdomain_enum", False):
            final_modules, skipped_enum = _filter_subdomain_enum(final_modules)
            for m in skipped_enum:
                logger.warning("%s skipped — --no-subdomain-enum is set", m)
                print(f"[!] {m} skipped — --no-subdomain-enum is set "
                      f"(enum module suppressed)")

        # Auto-inject ax_nmap_tcp (and dns_resolve when needed) before
        # web modules that lack a URL source in the pipeline.
        if not args.no_auto_discovery:
            final_modules, injected = _auto_inject_web_discovery(
                final_modules,
                has_targets=bool(args.target),
                has_domains=bool(args.domainlist),
                has_urls=bool(args.urllist),
            )
            if injected:
                logger.info("Auto-injected modules: %s", ", ".join(injected))
                print(f"[i] Auto-injected modules: {', '.join(injected)} "
                      f"(use --no-auto-discovery to disable)\n")

        # Create fleet scaler
        if args.auto_scale and not local_only and not args.dry_run:
            scaler = FleetScaler(
                initial_fleet=args.fleet,
                initial_nodes=scaler_nodes,
                max_nodes=args.max_nodes,
                logs_prefix=logs_prefix,
                cost_tracker=cost_tracker,
                account=args.ax_account,
            )
            print(f"[*] Auto-scale enabled (max {args.max_nodes} nodes)")
        else:
            scaler = NoOpScaler(fleet=args.fleet, nodes=scaler_nodes)

        # Execute the final list of modules
        logger.info(f"Executing {len(final_modules)} steps")
        results = run_modules(final_modules, cleanup=False,
                              resume_from=0, finish_step=args.finish_step,
                              scaler=scaler,
                              output_dir=output_directory,
                              workflow_name=workflow_name,
                              keep_fleet=args.keep_fleet,
                              **module_kwargs)

        # Print summary
        _print_results_summary(
            results,
            header="Execution Complete",
            output_directory=output_directory,
            log_path=f"{os.path.join(output_directory, args.output)}-monkeyx.log",
        )
        exit_code = _completion_exit_code(results)

    except SystemExit as e:
        if e.code == EXIT_CODE_PAUSED:
            logger.info("Scan paused by user — checkpoint written")
            _handle_pause_exit(args.fleet, keep_fleet=args.keep_fleet,
                               output_directory=output_directory,
                               account=args.ax_account)
            fleet_cleanup_needed = False
            exit_code = EXIT_CODE_PAUSED
        else:
            raise

    except KeyboardInterrupt:
        logger.warning("Execution interrupted by user (Ctrl+C)")
        print("\n[!] Execution interrupted by user. Cleaning up...")
        exit_code = 130
    except FleetSpinupError as e:
        # Expected ax/cloud failure, not a MonkeyX bug — print the remediation
        # guidance cleanly (no traceback) and still run the finally cleanup.
        logger.error("Fleet spin-up failed (ax/cloud): %s", e)
        print(f"\n{e}")
        exit_code = EXIT_CODE_FATAL
    except Exception as e:
        logger.error(f"Unexpected error during execution: {e}", exc_info=True)
        print(f"\n[!] Error during execution: {e}")
        exit_code = EXIT_CODE_FATAL

    finally:
        if fleet_cleanup_needed:
            cost_tracker.fleet_stopped()
            _fleet_cleanup(args.fleet, keep_fleet=args.keep_fleet,
                           fleet_init_interrupted=fleet_init_interrupted,
                           account=args.ax_account,
                           expected_nodes=scaler_nodes)

        # Collect AI usage from module results and write cost summary
        for r in results:
            if isinstance(r, dict) and r.get("ai_usage"):
                cost_tracker.record_ai_usage(r["ai_usage"])
        cost_tracker.write(os.path.join(logs_dir, f"costs-{datetime.now().strftime('%Y%m%d-%H%M%S')}.txt"))

        # End-of-run debrief (skips summary/html_report if they ran explicitly)
        _run_finalizers(output_directory, results)

        # Build the results archive (also done on --resume/--continue).
        _create_results_archive(output_directory, args.output)

    sys.exit(exit_code)


if __name__ == '__main__':
    main()
