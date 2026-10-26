"""Unified TCP nmap scan module.

Configurable port selection, service detection, and script execution.
Replaces ax_tcp_baseline, ax_tcp_full, ax_nmaptop1000tcp, and ax_nmap_quick_web.

Outputs:
    {prefix}-tcpscan.xml            merged nmap XML
    {prefix}-tcpscan-weburls.txt    discovered web URLs
    {prefix}-tcpscan-alive-hosts.txt alive host IPs
"""

import glob
import logging
import os
import shutil

import re

from core.utils import bash_command, validate_port_spec
from core.scanning import (
    merge_nmap_folder, uncovered_ip_targets, hosts_up_without_open_ports,
    hosts_scan_truncated)
from core.nmap_service_parse import nmap_to_tcphosts

logger = logging.getLogger("monkeyx.modules.ax_nmap_tcp")

REQUIRED_INPUTS = frozenset({"target"})
PRODUCES = {"nmap_xml": "{prefix}-tcpscan.xml"}

DEFAULT_PORTS = "top-1000"
DEFAULT_SCRIPTS = True
DEFAULT_VERSION = "full"
DEFAULT_SCAN_TYPE = "sS"
# Tuning defaults. vuln scripts (vulners) are OFF by default — slow, noisy,
# network-dependent banner-CVE dumps; opt in via vuln_scripts=true. Version
# intensity 5 is a speed/detail middle-ground (nmap default is 7). max_retries
# below nmap's -T4 default (~10) cuts time on filtered ports.
DEFAULT_VERSION_INTENSITY = 5
DEFAULT_VULN_SCRIPTS = False
DEFAULT_MAX_RETRIES = 3
# 60m per-host cap. A slow/SYN-filtering host can push a full-port -sV+scripts
# scan past 30m and get cut off with ZERO ports collected (observed on a real
# run) — reads downstream as a clean, closed host. 60m gives it room; a host
# that still truncates is flagged (see hosts_scan_truncated). Lower it on large
# scopes where per-host runtime x host count matters.
DEFAULT_HOST_TIMEOUT = "60m"
DEFAULT_TIMING = "T4"
# Connect-scan (-sT) fallback for hosts a SYN scan reports as up-but-0-ports
# (SYN filtering / rate-limiting / lost raw-socket privilege). OFF by default —
# opt in via modules.ax_nmap_tcp.connect_fallback. Bounded so a large scope of
# genuinely-empty hosts can't trigger a slow full-connect sweep.
DEFAULT_CONNECT_FALLBACK = False
DEFAULT_CONNECT_FALLBACK_MAX_HOSTS = 32

# The `ports: web` quick profile. Despite the historical "web" name this is a
# common web + web-ADJACENT service/admin port set: alongside HTTP(S) it includes
# ports that frequently front web admin UIs or are high-value to fingerprint on a
# fast pass — SMB (445), MSSQL (1433/1434), Oracle (1521), MySQL (3306), Postgres
# (5432), VNC (5800-5802), app servers (7001/7002, 3000), proxies (1080/3128), etc.
# Not exhaustive and not purely HTTP; for full coverage use `ports: all`. No
# default workflow selects this — it's an operator-optional profile.
COMMON_SERVICE_PORTS = "66,80,81,443,445,457,1080,1100,1241,1352,1433,1434,1521,1944,2301,3000,3128,3306,4000,4001,4002,4100,5000,5432,5800,5801,5802,6346,6347,7001,7002,8000,8080,8443,8888,30821"

# Every tuning value below is interpolated into the shell `ax scan …` command, and
# monkeyx.config / workflow YAML args reach here UNVALIDATED — so each is strictly
# validated/allowlisted before use to prevent command injection (mirrors the
# scan_type allowlist and validate_port_spec already used here).
_TIMEOUT_RE = re.compile(r'^\d+(?:ms|s|m|h)?$')


def _as_bool(value, default=False):
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    return str(value).strip().lower() not in ('false', '0', 'no', 'off', '', 'none')


def _validate_int(value, lo, hi, name):
    try:
        n = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"invalid {name} {value!r}: must be an integer")
    return max(lo, min(hi, n))


def _validate_timeout(value, name="host_timeout"):
    s = str(value).strip()
    if not _TIMEOUT_RE.match(s):
        raise ValueError(f"invalid {name} {value!r}: expected e.g. 30m, 600s, 1h")
    return s


def _validate_timing(value):
    s = str(value).strip().lstrip('-')
    if s not in ('T0', 'T1', 'T2', 'T3', 'T4', 'T5'):
        raise ValueError(f"invalid timing {value!r}: must be T0..T5")
    return s


def _read_swept_ports(path) -> str:
    """Read a ledger-exported open-ports list (one port per line) into an
    nmap `-p` value ('22,80,443'). Returns '' if the file is missing/empty or
    has no valid ports. Each line is int-validated — the file is interpolated
    into the nmap command, so nothing non-numeric reaches the shell."""
    if not path or not os.path.exists(path):
        return ""
    ports = set()
    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                s = line.strip()
                if s.isdigit() and 0 < int(s) <= 65535:
                    ports.add(int(s))
    except OSError:
        return ""
    return ",".join(str(p) for p in sorted(ports))


def run_ax_nmap_tcp(target, prefix, fleet, **kwargs):
    """Run TCP nmap scan with configurable depth.

    Args:
        target:    Target file containing hosts/IPs
        prefix:    Output file prefix
        fleet:     Axiom fleet name
        **kwargs:
            data_prefix: Override for output prefix
            ports:       Port selection (default: top-1000)
                         "all"       -> -p-
                         "top-N"     -> --top-ports N
                         "web"       -> curated web/management port list
                         "22,80,443" -> -p 22,80,443
            scripts:     Run NSE scripts (default: true)
                         true  -> --script=default,'vuln and safe',reverse-index
                         false -> no scripts
            version:     Service version detection (default: full)
                         "full"  -> -sV --version-intensity <version_intensity>
                         "light" -> -sV --version-light
                         "none"  -> no -sV
            version_intensity: -sV probe depth 0-9 (default: 5; nmap's own default is 7)
            vuln_scripts: add the slow/noisy 'vuln and safe' (vulners) set (default: false)
            max_retries: nmap --max-retries (default: 3; nmap's -T4 default is ~10)
            min_rate:    nmap --min-rate packets/sec (default: unset/adaptive)
            timing:      nmap timing template T0-T5 (default: T4)
            host_timeout: nmap --host-timeout, e.g. 30m/600s/1h (default: 60m)
            scan_type:   TCP scan type — sS or sT (default: sS)
            connect_fallback: re-scan up-but-0-port hosts with -sT (default: false),
                         over the SAME ports as the primary scan (the `ports`
                         selection, default top-1000). Recovers ports on hosts that
                         filter/rate-limit SYN scans (or when the fleet nmap lost
                         raw-socket privilege).
            connect_fallback_max_hosts: cap on hosts the fallback will re-scan
                         (default: 32) so a large empty scope can't trigger a slow
                         full-connect sweep.
    """
    prefix = kwargs.get('data_prefix', prefix)
    # 'open' is a sweep-then-verify sentinel resolved below from the ledger's
    # swept-open-ports list (set by the workflow); everything else is a static
    # spec validated against injection here.
    ports_arg = kwargs.get('ports', DEFAULT_PORTS)
    ports = ports_arg if ports_arg == 'open' else validate_port_spec(ports_arg)
    scripts = kwargs.get('scripts', DEFAULT_SCRIPTS)
    version = str(kwargs.get('version', DEFAULT_VERSION))
    # scan_type is interpolated UNQUOTED into the nmap command (`-{scan_type}`).
    # The CLI constrains it via argparse choices, but monkeyx.config / workflow
    # YAML args reach here unvalidated — so allowlist strictly against the two
    # supported TCP scan flags to prevent shell injection via a config value.
    scan_type = kwargs.get('scan_type', DEFAULT_SCAN_TYPE)
    if scan_type not in ('sS', 'sT'):
        raise ValueError(
            f"invalid scan_type {scan_type!r}: must be 'sS' or 'sT'")
    connect_fallback = _as_bool(kwargs.get('connect_fallback', DEFAULT_CONNECT_FALLBACK))
    connect_fallback_max_hosts = _validate_int(
        kwargs.get('connect_fallback_max_hosts', DEFAULT_CONNECT_FALLBACK_MAX_HOSTS),
        1, 4096, 'connect_fallback_max_hosts')

    # Normalize scripts to bool
    if isinstance(scripts, str):
        scripts = scripts.lower() not in ('false', '0', 'no', 'off')

    # Port flag
    if ports == 'open':
        # Sweep-then-verify: scan only the UNION of ports a prior masscan/naabu
        # sweep found open (ledger-exported, one per line). nmap then runs its
        # full -sV/NSE command on a tiny port set per host instead of all 65k.
        swept = _read_swept_ports(kwargs.get('open_ports_list_file'))
        if not swept:
            print("[*] ax_nmap_tcp: ports=open — the sweep found no open ports to "
                  "verify; skipping")
            return {"module": "ax_nmap_tcp", "status": "skipped", "output_files": [],
                    "warning": "ports=open but no swept-open ports were available"}
        port_flag = f'-p {swept}'
        port_desc = f'{len(swept.split(","))} swept-open port(s)'
    elif ports == 'all':
        port_flag = '-p-'
        port_desc = 'all ports'
    elif ports == 'web':
        port_flag = f'-p {COMMON_SERVICE_PORTS}'
        port_desc = 'common web/service ports'
    elif ports.startswith('top-'):
        n = ports.split('-', 1)[1]
        port_flag = f'--top-ports {n}'
        port_desc = f'top {n} ports'
    else:
        port_flag = f'-p {ports}'
        port_desc = f'{len(ports.split(","))} ports'

    # Version detection flag
    version_intensity = _validate_int(
        kwargs.get('version_intensity', DEFAULT_VERSION_INTENSITY), 0, 9,
        'version_intensity')
    if version == 'none':
        version_flag = ''
    elif version == 'light':
        version_flag = '-sV --version-light'
    else:  # 'full' / default — bounded probe depth instead of nmap's full 7
        version_flag = f'-sV --version-intensity {version_intensity}'

    # Scripts flag. Baseline is nmap's `default` (-sC) set + reverse-index; the
    # slow/noisy 'vuln and safe' (vulners) set is opt-in via vuln_scripts.
    vuln_scripts = _as_bool(kwargs.get('vuln_scripts', DEFAULT_VULN_SCRIPTS))
    if scripts:
        script_set = ("default,'vuln and safe',reverse-index" if vuln_scripts
                      else "default,reverse-index")
        scripts_flag = (
            f"--script={script_set} "
            "--script-args http.useragent='Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko' "
            "--script-timeout 20m"
        )
    else:
        scripts_flag = ''

    parts = [port_desc]
    if version != 'none':
        parts.append(f'version={version}')
    if scripts:
        parts.append('scripts')
    print(f'[*] Running TCP scan ({", ".join(parts)})')

    cmd_parts = [
        f"ax scan '{target}' --fleet '{fleet}' --expand-cidr",
        f"-oA '{prefix}-tcpscan' -m nmapx -Pn --open -{scan_type}",
        port_flag,
    ]
    if version_flag:
        cmd_parts.append(version_flag)
    max_retries = _validate_int(
        kwargs.get('max_retries', DEFAULT_MAX_RETRIES), 0, 10, 'max_retries')
    host_timeout = _validate_timeout(kwargs.get('host_timeout', DEFAULT_HOST_TIMEOUT))
    timing = _validate_timing(kwargs.get('timing', DEFAULT_TIMING))
    timing_flags = [f'-{timing} --defeat-rst-ratelimit',
                    f'--max-retries {max_retries}',
                    f'--host-timeout {host_timeout}']
    min_rate = kwargs.get('min_rate')
    if min_rate not in (None, '', 0, '0'):
        timing_flags.append(f'--min-rate {_validate_int(min_rate, 1, 100000, "min_rate")}')
    cmd_parts.append(' '.join(timing_flags))
    if scripts_flag:
        cmd_parts.append(scripts_flag)

    cmd = ' '.join(cmd_parts)

    # ax scan can exit non-zero from a cosmetic cleanup step (e.g. `tput init`
    # failing in a non-TTY subprocess) even when the scan + result download fully
    # succeeded. So DON'T discard results on the exit code alone — capture the
    # error, merge whatever landed, and decide success on actual output presence.
    scan_error = None
    try:
        bash_command(cmd)
    except Exception as e:
        scan_error = str(e)
        print(f'[!] TCP scan command returned an error (verifying output anyway): {e}')

    print('[*] Merging nmap TCP results')
    merged_xml = f"{prefix}-tcpscan.xml"
    try:
        merge_info = merge_nmap_folder(prefix, "tcpscan", "TCP Scan")
    except Exception as merge_error:
        merge_info = {}
        print(f'[!] TCP merge step errored: {merge_error}')

    has_output = os.path.exists(merged_xml) and os.path.getsize(merged_xml) > 0

    # Only a real failure if the command errored AND no results landed. If the
    # command errored but hosts came back, treat it as the cosmetic-exit case.
    if scan_error and not has_output:
        print('[!] TCP scan failed: command errored and produced no output')
        return {
            'module': 'ax_nmap_tcp',
            'status': 'failed',
            'output_files': [],
            'error': scan_error,
        }

    try:
        nmap_to_tcphosts(merged_xml, prefix, "tcpscan")
    except Exception as parse_error:
        print(f"[!] TCP scan parsing failed: {parse_error}")

    # Optional connect-scan (-sT) fallback (opt-in). A SYN scan silently
    # under-reports hosts that filter/rate-limit SYN probes (or when the fleet
    # nmap lost raw-socket privilege): they come back "up" with zero open ports.
    # Re-scan ONLY those hosts with a full TCP connect() and fold the results
    # into the merged XML, so recovered ports reach the ledger AND the downstream
    # service modules (ssh_audit/smtp) in the SAME run (ax_nmap_tcp finishes
    # before that parallel group launches). Bounded by connect_fallback_max_hosts.
    if connect_fallback and scan_type == 'sS' and has_output:
        try:
            candidates = hosts_up_without_open_ports(merged_xml)
            if candidates and len(candidates) <= connect_fallback_max_hosts:
                print(f"[*] Connect-scan fallback: re-scanning {len(candidates)} "
                      f"up-but-0-port host(s) with -sT")
                retry_targets = f"{prefix}-tcpscan-retry-targets.txt"
                with open(retry_targets, 'w', encoding='utf-8') as fh:
                    fh.write("\n".join(candidates) + "\n")
                retry_parts = [
                    f"ax scan '{retry_targets}' --fleet '{fleet}' --expand-cidr",
                    f"-oA '{prefix}-tcpscan-retry' -m nmapx -Pn --open -sT",
                    port_flag,
                ]
                if version_flag:
                    retry_parts.append(version_flag)
                retry_parts.append(' '.join(timing_flags))
                if scripts_flag:
                    retry_parts.append(scripts_flag)
                try:
                    bash_command(' '.join(retry_parts))
                except Exception as e:
                    print(f"[!] Connect-scan fallback command errored "
                          f"(folding in whatever landed): {e}")
                # Fold retry per-host XMLs into the primary folder (prefixed so
                # they never clobber the SYN results), then re-merge + re-parse.
                # nMap_Merger merges by host IP, so the -sT ports join the record.
                retry_folder = f"{prefix}-tcpscan-retry"
                main_folder = f"{prefix}-tcpscan"
                if os.path.isdir(retry_folder):
                    os.makedirs(main_folder, exist_ok=True)
                    for xmlf in glob.glob(os.path.join(retry_folder, "*.xml")):
                        shutil.copy(xmlf, os.path.join(
                            main_folder, "retry-" + os.path.basename(xmlf)))
                    merge_nmap_folder(prefix, "tcpscan", "TCP Scan")
                    nmap_to_tcphosts(merged_xml, prefix, "tcpscan")
                    still_empty = set(hosts_up_without_open_ports(merged_xml))
                    recovered = [h for h in candidates if h not in still_empty]
                    if recovered:
                        print(f"[+] Connect-scan fallback recovered ports on "
                              f"{len(recovered)} host(s): {', '.join(recovered)}")
            elif candidates:
                print(f"[*] Connect-scan fallback skipped: {len(candidates)} "
                      f"up-but-0-port host(s) exceeds connect_fallback_max_hosts "
                      f"({connect_fallback_max_hosts})")
        except Exception as e:  # never let the fallback break the run
            logger.warning("connect-scan fallback failed: %s", e)

    result = {
        'module': 'ax_nmap_tcp',
        'status': 'success',
        'output_files': [f"{prefix}-tcpscan.xml"],
        'parsed_urls': f"{prefix}-tcpscan-weburls.txt",
    }
    if scan_error:
        # Non-fatal: results were present despite the non-zero exit. Surface it so
        # the (recoverable) exit-code leak is visible without failing the run.
        result['status'] = 'warning'
        result['warning'] = (
            "ax_nmap_tcp: the ax scan command exited non-zero but results were "
            f"collected, so they were kept (not discarded): {scan_error}")
    # Coverage check: any in-scope IP target that produced no host entry in the
    # merged output was never scanned/collected (dead fleet instance, failed
    # result pull, or a merge drop). ax reports success regardless, so verify at
    # this seam — those targets' ports never reach the ledger and every
    # downstream module silently misses them. Report honestly, don't assume clean.
    uncovered = uncovered_ip_targets(target, f"{prefix}-tcpscan.xml", f"{prefix}-tcpscan")
    if uncovered:
        dropped = set((merge_info or {}).get('dropped_hosts') or [])
        merge_lost = [ip for ip in uncovered if ip in dropped]
        cause = (" (some were lost in the nmap merge)" if merge_lost else "")
        result['status'] = 'warning'
        result['warning'] = (
            f"ax_nmap_tcp: {len(uncovered)} in-scope target(s) produced no results "
            f"and may not have been scanned/collected{cause}: {', '.join(uncovered)}. "
            f"Their ports/services are NOT in the ledger — verify before assuming "
            f"they are clean."
        )
        result['uncovered_targets'] = uncovered

    # Degraded-scan check: the uncovered check above only catches hosts MISSING
    # from the XML. It misses the worse, silent failure where hosts ARE present
    # ("up") but the port-scan phase collected ~nothing (broken/blocked fleet
    # nmap) — e.g. 1000 hosts up, 2 open ports. That reads downstream as a clean,
    # closed network. Detect it and flag loudly, and stamp scan.db so the reports
    # (analyze/summary) can banner it instead of presenting zero ports as fact.
    from core.scanning import port_scan_health, port_scan_degraded
    health = port_scan_health(f"{prefix}-tcpscan.xml")
    degraded, reason = port_scan_degraded(health)
    if degraded:
        result['status'] = 'warning'
        # This is the more important signal — lead with it.
        result['warning'] = f"ax_nmap_tcp: {reason}" + (
            "  " + result.get('warning', '') if result.get('warning') else "")
        result['port_scan_degraded'] = True
        result['port_scan_health'] = health
        print(f"\n{'!'*60}\n[!] {reason}\n{'!'*60}\n")
        try:
            from core import scan_db
            data_dir = os.path.dirname(prefix) or "."
            db = scan_db.open_db(data_dir)
            if db is not None:
                db.set_meta("port_scan_degraded", "1")
                db.set_meta("port_scan_health",
                            f"{health['hosts_with_open_ports']}/{health['hosts_up']} "
                            f"hosts have open ports; {health['open_ports']} open total")
                db.close()
        except Exception as e:  # never let a health note break the run
            logger.warning("could not stamp port_scan_degraded to scan.db: %s", e)

    # Per-host scan truncation: a host that's "up" but has NO ports AND NO
    # <extraports> summary was cut off (host-timeout) before its ports were
    # tallied — ZERO data collected for it, which otherwise reads as a clean,
    # empty host. Flag the specific hosts (and recommend the remedies) rather
    # than letting a timed-out host masquerade as closed. These are also the
    # connect-fallback candidate set, so enabling that recovers them.
    truncated = hosts_scan_truncated(f"{prefix}-tcpscan.xml")
    if truncated:
        msg = (f"ax_nmap_tcp: port scan was TRUNCATED (hit --host-timeout) on "
               f"{len(truncated)} host(s) — NO ports collected, so they are NOT "
               f"closed/clean, just un-enumerated: {', '.join(truncated)}. Raise "
               f"host_timeout (default 60m), or enable connect_fallback (-sT), "
               f"and re-scan before trusting a zero-port result for them.")
        result['status'] = 'warning'
        result['warning'] = msg + (
            "  " + result['warning'] if result.get('warning') else "")
        result['truncated_targets'] = truncated
        print(f"\n{'!'*60}\n[!] {msg}\n{'!'*60}\n")
        try:
            from core import scan_db
            db = scan_db.open_db(os.path.dirname(prefix) or ".")
            if db is not None:
                db.set_meta("port_scan_truncated_hosts", ", ".join(truncated))
                db.close()
        except Exception as e:  # never let a health note break the run
            logger.warning("could not stamp port_scan_truncated to scan.db: %s", e)
    return result
