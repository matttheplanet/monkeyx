"""Workflow definitions and orchestration for MonkeyX.

Workflows are combinations of enumeration modules executed in sequence.
Users can run individual modules or predefined workflows.
"""

import concurrent.futures
import importlib
import inspect
import json
import logging
import os
import pkgutil
import re
import shutil
import sys
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Union
from urllib.parse import urlparse
from core.plugin_loader import discover_plugins
from core.fleet import kill_fleet, count_ip_workload
from core.checkpoint import Checkpoint, EXIT_CODE_PAUSED
from core.progress import ProgressTracker, NO_OP_TRACKER, HeartbeatPrinter
from core.target_ledger import TargetLedger, NO_OP_LEDGER, LedgerSnapshot, TYPE_IP, TYPE_DOMAIN, TYPE_URL, TYPE_SUBDOMAIN, TYPE_PORT, _PRIVATE_FILTER_ENABLED, _is_private_ip
from core.merge_outputs import (
    should_version as _merge_should_version,
    archive_existing_output as _merge_archive_existing,
    version_and_merge as _merge_version_and_merge,
)
from core import scope_classes
from core.output_layout import ledger_file

logger = logging.getLogger('monkeyx.workflows')


@dataclass
class ModuleStep:
    name: str
    args: dict = field(default_factory=dict)


@dataclass
class ParallelGroup:
    steps: list[ModuleStep] = field(default_factory=list)


@dataclass
class WaitStep:
    name: str


StepItem = Union[ModuleStep, ParallelGroup, WaitStep]


# Modules whose import raised during discovery. A broken module (e.g. a
# defusedxml Element misuse, a syntax error, a missing dependency) otherwise
# vanishes SILENTLY from AVAILABLE_MODULES: discovery runs at import time before
# the CLI configures logging, so the warning goes nowhere, and a later request
# for it looks identical to a typo. We record the reason so it can be surfaced
# loudly here and again if the module is requested.
FAILED_MODULE_IMPORTS: dict[str, str] = {}


def _discover_modules() -> tuple[dict, dict]:
    """Auto-discover modules by scanning the modules package.

    Finds every run_<name> function in modules/*.py and registers it
    as module name -> callable.  Also picks up each module's
    REQUIRED_INPUTS constant (defaults to empty frozenset if absent).

    Returns:
        Tuple of (name -> callable, name -> frozenset of required input categories)
    """
    import modules as modules_pkg

    discovered = {}
    requirements = {}
    for finder, module_name, is_pkg in pkgutil.iter_modules(modules_pkg.__path__):
        if module_name.startswith("_"):
            continue
        try:
            mod = importlib.import_module(f"modules.{module_name}")
        except Exception as e:
            FAILED_MODULE_IMPORTS[module_name] = f"{type(e).__name__}: {e}"
            logger.warning(f"Failed to import modules.{module_name}: {e}")
            # Logging isn't configured yet at import time, so also warn on stderr
            # — a scanning module dropping out of the registry is not something to
            # discover only when a scan silently skips it.
            print(f"[!] WARNING: module 'modules.{module_name}' failed to load and "
                  f"is UNAVAILABLE: {type(e).__name__}: {e}", file=sys.stderr)
            continue

        mod_reqs = getattr(mod, "REQUIRED_INPUTS", frozenset())
        if not isinstance(mod_reqs, (set, frozenset)):
            logger.warning("modules.%s.REQUIRED_INPUTS is not a set, ignoring", module_name)
            mod_reqs = frozenset()

        for attr_name, attr_val in inspect.getmembers(mod, inspect.isfunction):
            if attr_name.startswith("run_") and attr_name != "run_":
                # Only register functions DEFINED in this module. Shared helpers
                # imported into a module (run_ax_module from _ax_common,
                # run_bbot_flags/run_bbot_modules from _bbot_common) are also
                # `run_*` functions, and getmembers surfaces them — without this
                # guard they leak into AVAILABLE_MODULES as fake modules
                # (ax_module, bbot_flags, bbot_modules) a user could try to select.
                if getattr(attr_val, "__module__", None) != mod.__name__:
                    continue
                key = attr_name[4:]  # strip "run_" prefix
                discovered[key] = attr_val
                requirements[key] = frozenset(mod_reqs)
                logger.debug(f"Discovered module: {key} -> {mod.__name__}.{attr_name} (requires: {mod_reqs or 'none'})")

    return discovered, requirements


def _module_produces_nmap_xml(module_name: str) -> bool:
    """Check whether a module declares it produces nmap XML output.

    Looks for a module-level `PRODUCES = {"nmap_xml": "..."}` attribute on
    the discovered module object. Modules that produce nmap XML are eligible
    for cross-run hostname URL synthesis after the step completes.
    """
    mod = AVAILABLE_MODULES.get(module_name)
    if mod is None:
        return False
    func = mod
    module_obj = getattr(func, "__module__", None)
    if module_obj is None:
        return False
    try:
        m = sys.modules.get(module_obj)
        if m is None:
            return False
        produces = getattr(m, "PRODUCES", None)
        return bool(produces and "nmap_xml" in produces)
    except Exception:
        return False


def _module_consumes_urls(module_name: str) -> bool:
    """Check whether a module consumes a URL list.

    Web modules declare `CONSUMES_URLS = True` to indicate that they need
    `url_file`. Used by the auto-injection logic in monkeyx.py to decide
    whether `ax_nmap_tcp` should be prepended to the pipeline.
    """
    mod = AVAILABLE_MODULES.get(module_name)
    if mod is None:
        return False
    module_obj = getattr(mod, "__module__", None)
    if module_obj is None:
        return False
    try:
        m = sys.modules.get(module_obj)
        if m is None:
            return False
        return bool(getattr(m, "CONSUMES_URLS", False))
    except Exception:
        return False


def _synthesize_urls_from_weburls(weburls_path: str, ledger, source: str = "url_synthesis_nmap"):
    """Cross-reference an already-parsed weburls.txt with the ledger's
    hostname↔IP map. For each IP-form URL, emit corresponding hostname URLs
    with the same scheme+port. Each hostname URL is parented at the hostname
    so scope inheritance behaves correctly.
    """
    if not weburls_path or not os.path.exists(weburls_path):
        return 0

    try:
        ip_to_hostnames = ledger.get_ip_to_hostnames()
    except Exception:
        return 0
    if not ip_to_hostnames:
        return 0

    synthesized = 0
    try:
        with open(weburls_path) as f:
            for line in f:
                url = line.strip()
                if not url or url.startswith("#"):
                    continue
                try:
                    parsed = urlparse(url)
                except Exception:
                    continue
                scheme = parsed.scheme
                ip = parsed.hostname
                if not ip or scheme not in ("http", "https"):
                    continue
                hostnames = ip_to_hostnames.get(ip)
                if not hostnames:
                    continue
                port_suffix = ""
                if parsed.port and parsed.port not in (80, 443):
                    port_suffix = f":{parsed.port}"
                for host in hostnames:
                    new_url = f"{scheme}://{host}{port_suffix}"
                    ledger.log_discovery(new_url, TYPE_URL, source, parent=host)
                    synthesized += 1
    except Exception as e:
        logger.warning("URL synthesis from %s failed: %s", weburls_path, e)
        return 0
    if synthesized:
        logger.info("Synthesized %d hostname URLs from %s", synthesized, weburls_path)
    return synthesized


def _extract_discoveries(result: dict | None, module_name: str, ledger, data_prefix: str,
                         kwargs: dict | None = None):
    """Extract discovered targets from module output and log to the ledger."""
    if not result or not isinstance(result, dict):
        return
    # Ingest on "warning" as well as "success": a warning means results WERE
    # collected but with a caveat (e.g. an nmap scan that found open ports yet
    # left some in-scope hosts uncovered, or a cosmetic non-zero exit). Dropping
    # the ports/IPs/URLs it DID find would silently starve every downstream
    # module (httpx -> nuclei/gowitness, ssh_audit, ...) of real targets. Only
    # "failed"/"skipped" (no trustworthy output) are skipped here.
    if result.get("status") not in ("success", "warning"):
        return

    # Nmap-based modules: extract alive IPs, discovered URLs, and open ports
    if module_name in ("ax_nmap_tcp", "ax_nmap_udp", "ax_live_host_discovery") \
            or _module_produces_nmap_xml(module_name):
        target_file = kwargs.get("target") if kwargs else None
        output_files = result.get("output_files", [])
        for f in output_files:
            if f.endswith(".xml"):
                # Alive-hosts file shares the XML basename: {prefix}-{id}-alive-hosts.txt
                xml_base = os.path.splitext(f)[0]
                hosts_path = f"{xml_base}-alive-hosts.txt"
                if os.path.exists(hosts_path):
                    _log_ips_from_file(hosts_path, module_name, ledger, parent=target_file)
                # Log open ports with service info from nmap XML
                if os.path.exists(f):
                    _log_ports_from_nmap_xml(f, module_name, ledger)

        # URLs from parsed_urls key
        parsed_urls = result.get("parsed_urls")
        if parsed_urls and os.path.exists(parsed_urls):
            _log_urls_from_file(parsed_urls, module_name, ledger)
            # Cross-reference IP-form URLs with ledger hostnames to emit
            # hostname URLs with nmap-classified schemes.
            _synthesize_urls_from_weburls(parsed_urls, ledger)

    # Masscan: extract alive IPs and open ports (no service info).
    # ax emits greppable (-oG) output as `{prefix}-masscan.txt`.
    elif module_name == "ax_masscan":
        output_files = result.get("output_files", [])
        stats = {"ingested": 0, "tarpits": 0, "hosts": 0}
        parsed_any = False
        for f in output_files:
            if f.endswith(".txt") and os.path.exists(f):
                s = _log_ports_from_masscan_grep(f, module_name, ledger) or {}
                parsed_any = True
                for k in stats:
                    stats[k] += int(s.get(k, 0))
        # Honesty: a sweep that found hosts but no usable open ports (the whole
        # scope is a tarpit/SYN-proxy, or every host was dropped by the cap) must
        # not read as a clean run — the nmap verify step will have nothing to
        # scan and the TCP side silently produces nothing. Escalate the masscan
        # step to a warning (runs sequentially, so this propagates to the
        # recorded step status -> completed_with_warnings). A partial tarpit
        # (some ports kept, some hosts dropped) also warns, since ports were lost.
        if parsed_any and isinstance(result, dict) and result.get("status") == "success":
            if stats["hosts"] and stats["ingested"] == 0:
                msg = (f"masscan swept {stats['hosts']} host(s) but ingested 0 usable "
                       f"open ports ({stats['tarpits']} flagged tarpit/SYN-proxy and "
                       f"dropped) — the TCP verify (nmap) will have nothing to scan. "
                       f"This scope may be a tarpit; verify rather than assume no open ports.")
                logger.warning(msg)
                print(f"[!] {msg}")
                result["status"] = "warning"
                result.setdefault("warning", msg)
            elif stats["tarpits"]:
                msg = (f"masscan: {stats['tarpits']} of {stats['hosts']} host(s) flagged "
                       f"tarpit/SYN-proxy and dropped; {stats['ingested']} usable open "
                       f"ports ingested from the rest.")
                logger.warning(msg)
                print(f"[!] {msg}")
                result["status"] = "warning"
                result.setdefault("warning", msg)

    # Naabu: extract live hosts
    elif module_name == "ax_naabu":
        target_file = kwargs.get("target") if kwargs else None
        live_hosts = result.get("live_hosts")
        if live_hosts and os.path.exists(live_hosts):
            _log_ips_from_file(live_hosts, module_name, ledger, parent=target_file)

    # Subfinder / Amass: extract subdomains
    elif module_name in ("subfinder", "ax_subfinder", "ax_amass"):
        hosts_file = result.get("discovered_hosts_file")
        if hosts_file and os.path.exists(hosts_file):
            _log_subdomains_from_file(hosts_file, module_name, ledger)
        for f in result.get("output_files", []):
            if os.path.exists(f):
                _log_subdomains_from_file(f, module_name, ledger)

    # dns_resolve / dnsx_resolve: extract resolved IPs from the resolve report.
    # Both produce the same -resolve-report.jsonl shape, so one parser works.
    elif module_name in ("dns_resolve", "dnsx_resolve"):
        output_files = result.get("output_files", [])
        report_file = None
        for f in output_files:
            if f.endswith("-resolve-report.jsonl") and os.path.exists(f):
                report_file = f
                break
        if report_file:
            _log_ips_from_resolve_report(report_file, module_name, ledger)
        else:
            resolved_file = result.get("resolved_target_file")
            if resolved_file and os.path.exists(resolved_file):
                _log_ips_from_file(resolved_file, module_name, ledger)

    # ax_puredns_bruteforce: extract discovered subdomains from plaintext output.
    elif module_name == "ax_puredns_bruteforce":
        hosts_file = result.get("discovered_hosts_file")
        if hosts_file and os.path.exists(hosts_file):
            _log_subdomains_from_file(hosts_file, module_name, ledger)

    # nessus_import: extract alive hosts and ports from the imported data
    elif module_name == "nessus_import":
        output_files = result.get("output_files", [])
        nessus_file = kwargs.get("nessus_file") if kwargs else None
        for f in output_files:
            if f.endswith("-nessus-alive-hosts.txt") and os.path.exists(f):
                _log_ips_from_file(f, module_name, ledger, parent=nessus_file)
            elif f.endswith("-nessus-normalized.jsonl") and os.path.exists(f):
                _log_ports_from_nessus_jsonl(f, module_name, ledger)

    # ffuf/feroxbuster: extract discovered URLs (new paths on existing targets)
    elif module_name in ("ax_ffuf", "ax_feroxbuster"):
        output_files = result.get("output_files", [])
        for f in output_files:
            if f.endswith(".jsonl") and os.path.exists(f):
                _log_urls_from_ffuf_jsonl(f, module_name, ledger)
            elif f.endswith(".txt") and os.path.exists(f):
                _log_urls_from_dirbrute_txt(f, module_name, ledger)

    # httpx: extract discovered URLs (including redirect targets / new hostnames)
    elif module_name == "ax_httpx":
        output_files = result.get("output_files", [])
        for f in output_files:
            if f.endswith(".jsonl") and os.path.exists(f):
                _log_discoveries_from_httpx_jsonl(f, module_name, ledger)

    # katana / gau / subjs / arjun: crawled, historical, JS, and parameterized
    # URLs -> ledger (feeds nuclei/ffuf/dalfox/etc.)
    elif module_name in ("ax_katana", "ax_gau", "ax_subjs", "ax_arjun"):
        urls_file = result.get("discovered_urls_file")
        if urls_file and os.path.exists(urls_file):
            _log_urls_from_file(urls_file, module_name, ledger,
                                max_per_host=(kwargs.get("url_max_per_host") if kwargs else None))

    # linkfinder: JS endpoint extraction. Output is a DIRECTORY of per-target
    # files whose lines mix absolute URLs and relative paths. Ingest only the
    # absolute http(s) URLs (scannable); relative endpoints need a base URL we
    # can't reliably attribute, so they stay in the raw -linkfinder/ output.
    elif module_name == "ax_linkfinder":
        for f in result.get("output_files", []):
            if f and os.path.isdir(f):
                _log_urls_from_linkfinder_dir(f, module_name, ledger)

    # shodan_enrich: IPs surfaced by pivot searches -> ledger as DERIVED. They
    # are not authorized to scan by virtue of being found (authorization is -t);
    # scope filtering / --ip-scope decides whether they're exported to scanners.
    elif module_name == "shodan_enrich":
        hosts_file = result.get("discovered_hosts_file")
        if hosts_file and os.path.exists(hosts_file):
            _log_ips_from_file(hosts_file, module_name, ledger)

    # bbot modules: extract DNS_NAME, IP_ADDRESS, URL events from output JSONL
    elif module_name.startswith("bbot_"):
        output_files = result.get("output_files", [])
        for f in output_files:
            if f.endswith(".jsonl") and os.path.exists(f):
                _log_discoveries_from_bbot_jsonl(f, module_name, ledger)


def _coverage_host_key(value: str) -> str:
    """Normalize a target/url/host to a bare comparable host key.

    Coverage `fed` rows store whatever was in the input file (a URL for web
    tools, an IP/host for scanners); tool output reports a bare host. Reduce both
    sides to host (lowercased, no scheme/port/path) so a reached-set membership
    test lines up. Returns '' if nothing host-like is found.
    """
    v = (value or "").strip().lower()
    if not v:
        return ""
    if "://" in v:
        try:
            v = urlparse(v).hostname or ""
        except ValueError:
            return ""
    else:
        v = v.split("/", 1)[0]            # strip any path
        if v.count(":") == 1:              # host:port (not IPv6)
            v = v.split(":", 1)[0]
    return v.rstrip(".")


def _reached_hosts_from_output(result: dict, module_name: str) -> set | None:
    """Bare host keys a tool actually REACHED, or None if we can't tell for it.

    None means "no reached-extractor for this module" — the caller then leaves
    rows as 'fed' rather than guessing (never marks no_response on a tool we
    can't read). Extractors added incrementally; starting with the high-value
    web/scan tools. All keys normalized via _coverage_host_key.
    """
    import json as _json
    files = result.get("output_files", []) or []

    # nuclei: JSONL with a per-hit 'host' (or 'matched-at'). A host appearing =
    # nuclei got a response worth matching against — proof of reach.
    if module_name == "ax_nuclei":
        hosts = set()
        for f in files:
            if not f.endswith(".jsonl") or not os.path.exists(f):
                continue
            with open(f, encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = _json.loads(line)
                    except ValueError:
                        continue
                    h = rec.get("host") or rec.get("matched-at")
                    k = _coverage_host_key(h) if h else ""
                    if k:
                        hosts.add(k)
        return hosts

    # httpx: JSONL (-oJ) of live web services. A record present = the host
    # responded. Field precedence matches normalize._mint_web_endpoints.
    if module_name == "ax_httpx":
        hosts = set()
        for f in files:
            if not f.endswith(".jsonl") or not os.path.exists(f):
                continue
            with open(f, encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = _json.loads(line)
                    except ValueError:
                        continue
                    h = rec.get("host") or rec.get("input") or rec.get("url")
                    k = _coverage_host_key(h) if h else ""
                    if k:
                        hosts.add(k)
        return hosts

    # nmap: alive-hosts file (shares the XML basename) lists hosts that answered.
    if module_name in ("ax_nmap_tcp", "ax_nmap_udp") or _module_produces_nmap_xml(module_name):
        hosts = set()
        for f in files:
            if f.endswith(".xml"):
                hosts_path = f"{os.path.splitext(f)[0]}-alive-hosts.txt"
                if os.path.exists(hosts_path):
                    with open(hosts_path, encoding="utf-8", errors="ignore") as fh:
                        for line in fh:
                            k = _coverage_host_key(line)
                            if k:
                                hosts.add(k)
        return hosts

    return None  # no extractor -> leave rows 'fed'


def _reconcile_step_coverage(result: dict | None, module_name: str,
                             step_index: int, ledger):
    """Upgrade this step's coverage rows from 'fed' to their outcome.

    Failure -> step_failed (always knowable). Success -> if we have a reached-set
    for this tool, mark reached / no_response (the gap = "fed, finished, absent
    from output" = maybe-missed); if not, leave 'fed'. Best-effort.
    """
    if not isinstance(result, dict):
        return
    if result.get("status") == "failed":
        ledger.reconcile_coverage(module_name, step_index, all_failed=True)
        return
    reached = _reached_hosts_from_output(result, module_name)
    if reached is None:
        return  # no extractor for this tool — honest: rows stay 'fed'
    # Compare on host keys: the reconcile matches by raw target, so hand it the
    # ORIGINAL fed targets whose host-key is in the reached set. The DB method
    # re-reads its fed rows and marks the rest no_response.
    ledger.reconcile_coverage(module_name, step_index,
                              reached=_reached_targets_for(ledger, module_name,
                                                           step_index, reached))


def _reached_targets_for(ledger, module_name, step_index, reached_keys):
    """Map reached host-KEYS back to the raw fed target strings for this step.

    The coverage rows store raw targets (URLs/hosts); the reached set is host
    keys. Pull this step's fed targets from the DB and return those whose
    normalized key is reached, so the DB update matches on the exact stored value.
    """
    db = getattr(ledger, "_db", None)
    if db is None:
        return []
    try:
        run_seq = db.current_run_seq()
        fed = db.fed_coverage_targets(module_name, run_seq, step_index)
        return [t for t in fed if _coverage_host_key(t) in reached_keys]
    except Exception:
        return []


def _extract_host_from_url(url: str) -> str | None:
    """Extract hostname (with port if non-standard) from a URL."""
    try:
        parsed = urlparse(url)
        host = parsed.hostname
        if not host:
            return None
        port = parsed.port
        if port and port not in (80, 443):
            return f"{host}:{port}"
        return host
    except Exception:
        return None


def _extract_base_url(url: str) -> str | None:
    """Extract scheme://host(:port) from a URL (the base target being fuzzed)."""
    try:
        parsed = urlparse(url)
        if not parsed.hostname:
            return None
        port_suffix = ""
        if parsed.port and parsed.port not in (80, 443):
            port_suffix = f":{parsed.port}"
        return f"{parsed.scheme}://{parsed.hostname}{port_suffix}"
    except Exception:
        return None


def _infer_parent_domain(subdomain: str) -> str | None:
    """Infer the parent domain from a subdomain (e.g. foo.bar.example.com → example.com)."""
    parts = subdomain.split(".")
    if len(parts) >= 3:
        return ".".join(parts[-2:])
    return None


def _log_ips_from_resolve_report(path: str, module_name: str, ledger):
    """Read dns_resolve report JSONL and log IPs with their hostname as parent.

    Also processes PTR records: logs PTR hostnames as subdomains and re-logs the
    IP with the PTR hostname as parent, so get_ip_to_hostnames() includes PTR
    names and URL synthesis emits hostname URLs for downstream modules.

    PTR hostnames are filtered to only include those related to the target's
    domains — CDN/infra PTRs (akamai, cloudfront, etc.) are dropped to prevent
    scope pollution.
    """
    # Build set of in-scope root domains to filter PTR hostnames against
    scope_domains = set()
    for d in ledger._explicit_domains:
        scope_domains.add(d.lower())
    for d in ledger._in_scope_domains:
        parts = d.lower().split(".")
        if len(parts) >= 2:
            scope_domains.add(".".join(parts[-2:]))

    ptr_logged = 0
    ptr_skipped = 0

    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue

                status = record.get("status", "")
                hostname = record.get("hostname", "")
                ip = record.get("ip", "")

                # Forward resolution: log IP with hostname as parent
                if status == "resolved":
                    if ip and hostname:
                        ledger.log_discovery(ip, TYPE_IP, module_name, parent=hostname)
                    elif ip:
                        ledger.log_discovery(ip, TYPE_IP, module_name)

                # MX records: log the domain's mail infrastructure. dnsx requests
                # -mx and write_resolve_outputs preserves it, but nothing logged
                # it — so ledger-mx-domains.txt and scan.db.mx_domains stayed
                # empty. Filter out blank placeholders ([""] on no_answer).
                mx_hosts = [m.strip().rstrip(".") for m in (record.get("mx") or [])
                            if m and m.strip()]
                if hostname and mx_hosts:
                    ledger.log_mx_domain(hostname, mx_hosts)

                # PTR records: only log hostnames that are subdomains of
                # target domains. This prevents CDN/infra PTRs (akamai,
                # cloudfront, incapsula, etc.) from polluting scope.
                ptr_hostnames = record.get("ptr_hostnames", [])
                if ip and ptr_hostnames:
                    for ptr_name in ptr_hostnames:
                        if not ptr_name:
                            continue
                        if not _ptr_matches_scope(ptr_name, scope_domains):
                            ptr_skipped += 1
                            continue
                        ledger.log_discovery(
                            ptr_name, TYPE_SUBDOMAIN, module_name, parent=ip
                        )
                        ledger.log_discovery(
                            ip, TYPE_IP, module_name, parent=ptr_name
                        )
                        ptr_logged += 1
    except Exception as e:
        logger.warning(f"Failed to read resolve report from {path}: {e}")

    if ptr_skipped:
        logger.info("PTR filtering: logged %d, skipped %d out-of-scope", ptr_logged, ptr_skipped)
        print(f"[*] PTR hostnames: {ptr_logged} in-scope, {ptr_skipped} skipped (unrelated domains)")


def _ptr_matches_scope(ptr_name: str, scope_domains: set) -> bool:
    """Check if a PTR hostname belongs to any of the target's domains."""
    ptr_lower = ptr_name.lower().rstrip(".")
    parts = ptr_lower.split(".")
    if len(parts) < 2:
        return False
    ptr_apex = ".".join(parts[-2:])
    if ptr_apex in scope_domains:
        return True
    for domain in scope_domains:
        if ptr_lower.endswith("." + domain) or ptr_lower == domain:
            return True
    return False


def _log_ips_from_file(path: str, module_name: str, ledger, parent: str | None = None):
    """Read one-IP-per-line file and log each to the ledger."""
    try:
        with open(path) as f:
            for line in f:
                ip = line.strip()
                if ip and not ip.startswith("#"):
                    ledger.log_discovery(ip, TYPE_IP, module_name, parent=parent)
    except Exception as e:
        logger.warning(f"Failed to read IPs from {path}: {e}")



def _log_urls_from_file(path: str, module_name: str, ledger, max_per_host: int | None = None):
    """Read one-URL-per-line file and log each to the ledger.

    `max_per_host` (opt-in `--url-max-per-host`) caps how many URLs per host:port
    are promoted to ledger targets. A crawler (katana/gau) on a wildcard scope can
    emit ~1M URLs; without a cap each becomes a derived target, exploding the
    ledger / web_dirs / module_coverage and the scan.db. First-N per host:port in
    file order (crawl order surfaces shallower URLs first). The raw file is left
    intact for audit — only promotion to a scannable target is capped.
    """
    from core.target_ledger import _url_cov_key
    per_host: dict = {} if (max_per_host and max_per_host > 0) else None
    try:
        with open(path) as f:
            for line in f:
                url = line.strip()
                if not url or url.startswith("#"):
                    continue
                if per_host is not None:
                    key = _url_cov_key(url) or url
                    if per_host.get(key, 0) >= max_per_host:
                        continue
                    per_host[key] = per_host.get(key, 0) + 1
                parent = _extract_host_from_url(url)
                ledger.log_discovery(url, TYPE_URL, module_name, parent=parent)
    except Exception as e:
        logger.warning(f"Failed to read URLs from {path}: {e}")


_ABS_URL_RE = re.compile(r"https?://[^\s'\"<>()\]]+")


def _log_urls_from_linkfinder_dir(dir_path: str, module_name: str, ledger):
    """Walk LinkFinder's per-target output directory and log the ABSOLUTE http(s)
    URLs it extracted to the ledger. Relative endpoints (e.g. `/api/v1/x`) are
    skipped — they aren't scannable without a base URL we can attribute. Deduped."""
    seen: set[str] = set()
    try:
        for root, _dirs, files in os.walk(dir_path):
            for name in files:
                fpath = os.path.join(root, name)
                try:
                    with open(fpath, encoding="utf-8", errors="ignore") as fh:
                        for line in fh:
                            for url in _ABS_URL_RE.findall(line):
                                url = url.rstrip(".,;")
                                if url in seen:
                                    continue
                                seen.add(url)
                                ledger.log_discovery(
                                    url, TYPE_URL, module_name,
                                    parent=_extract_host_from_url(url))
                except OSError:
                    continue
    except Exception as e:
        logger.warning(f"Failed to read linkfinder output {dir_path}: {e}")
    if seen:
        logger.info("Logged %d absolute URL(s) from linkfinder %s",
                    len(seen), dir_path)


def _log_subdomains_from_file(path: str, module_name: str, ledger):
    """Read subfinder output (plain text or JSONL) and log subdomains."""
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # JSONL format from subfinder -oJ
                if line.startswith("{"):
                    try:
                        record = json.loads(line)
                        host = record.get("host", "")
                        parent = record.get("input", "") or _infer_parent_domain(host)
                        if host:
                            ledger.log_discovery(host, TYPE_SUBDOMAIN, module_name, parent=parent or None)
                    except json.JSONDecodeError:
                        pass
                else:
                    # Plain text, one subdomain per line
                    parent = _infer_parent_domain(line)
                    ledger.log_discovery(line, TYPE_SUBDOMAIN, module_name, parent=parent)
    except Exception as e:
        logger.warning(f"Failed to read subdomains from {path}: {e}")


def _log_urls_from_ffuf_jsonl(path: str, module_name: str, ledger):
    """Extract URLs from ffuf JSONL output."""
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                    url = record.get("url", "")
                    if url:
                        parent = record.get("input", {}).get("FUZZ", "") if isinstance(record.get("input"), dict) else ""
                        if not parent:
                            parent = _extract_base_url(url)
                        ledger.log_discovery(url, TYPE_URL, module_name, parent=parent or None)
                except json.JSONDecodeError:
                    pass
    except Exception as e:
        logger.warning(f"Failed to read ffuf URLs from {path}: {e}")


def _log_urls_from_dirbrute_txt(path: str, module_name: str, ledger):
    """Extract URLs from feroxbuster/ffuf plain text output."""
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                # feroxbuster lines: STATUS  METHOD  LINES  WORDS  CHARS  URL
                parts = line.split()
                for part in parts:
                    if part.startswith("http://") or part.startswith("https://"):
                        parent = _extract_base_url(part)
                        ledger.log_discovery(part, TYPE_URL, module_name, parent=parent or None)
                        break
    except Exception as e:
        logger.warning(f"Failed to read URLs from {path}: {e}")


def _log_discoveries_from_bbot_jsonl(path: str, module_name: str, ledger):
    """Extract targets from bbot JSON output and log to the ledger."""
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue

                etype = event.get('type', '')
                data = event.get('data', '')

                # Honor bbot's own wildcard determination: it tags DNS_NAME/URL
                # events that resolved only via a wildcard/catch-all record. These
                # are phantom hosts (random labels that differ run-to-run) — logging
                # them wastes crawl/scan time and pollutes findings. IP_ADDRESS is
                # kept (the underlying shared IP is real and may be in scope).
                tags = event.get('tags') or []
                is_wildcard = isinstance(tags, list) and 'wildcard' in tags

                if etype == 'DNS_NAME' and isinstance(data, str) and data:
                    if is_wildcard:
                        continue
                    ledger.log_discovery(data, TYPE_SUBDOMAIN, module_name)
                elif etype == 'IP_ADDRESS' and isinstance(data, str) and data:
                    ledger.log_discovery(data, TYPE_IP, module_name)
                elif etype == 'URL' and isinstance(data, str) and data:
                    if is_wildcard:
                        continue
                    ledger.log_discovery(data, TYPE_URL, module_name)
    except Exception as e:
        logger.warning(f"Failed to parse bbot output from {path}: {e}")


def _log_discoveries_from_httpx_jsonl(path: str, module_name: str, ledger):
    """Extract URLs and redirect-discovered hostnames from httpx JSONL output."""
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue

                # Log the probed URL
                url = record.get('url', '')
                if url:
                    ledger.log_discovery(url, TYPE_URL, module_name)
                    # Record liveness for --url-prune (a response = live; keep the
                    # status so the "interesting" policy can filter 2xx/3xx/401/403).
                    ledger.record_httpx_result(url, record.get('status_code'))

                # Log redirect target (may reveal new hostnames)
                final_url = record.get('final_url') or record.get('location', '')
                if final_url and final_url != url:
                    ledger.log_discovery(final_url, TYPE_URL, module_name, parent=url)
    except Exception as e:
        logger.warning(f"Failed to parse httpx output from {path}: {e}")


def _log_ports_from_nmap_xml(path: str, module_name: str, ledger):
    """Parse nmap XML and log open ports with service info to the ledger."""
    import defusedxml.ElementTree as ET

    try:
        tree = ET.parse(path)
        root = tree.getroot()
    except Exception as e:
        logger.warning("Failed to parse nmap XML for ports from %s: %s", path, e)
        return

    count = 0
    for host in root.findall(".//host"):
        addr_el = host.find("address")
        if addr_el is None:
            continue
        ip = addr_el.get("addr", "")
        if not ip:
            continue

        ports_el = host.find("ports")
        if ports_el is None:
            continue

        for port_el in ports_el.findall("port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue

            port_num = int(port_el.get("portid", 0))
            proto = port_el.get("protocol", "tcp")
            reason = state_el.get("reason", "")

            from core.nmap_service_parse import clean_service_name
            svc_el = port_el.find("service")
            service = clean_service_name(svc_el.get("name", "")) if svc_el is not None else ""
            product = svc_el.get("product", "") if svc_el is not None else ""
            version = svc_el.get("version", "") if svc_el is not None else ""
            extra = svc_el.get("extrainfo", "") if svc_el is not None else ""
            tunnel = svc_el.get("tunnel", "") if svc_el is not None else ""
            method = svc_el.get("method", "") if svc_el is not None else ""
            confidence = svc_el.get("conf", "") if svc_el is not None else ""
            banner_parts = [p for p in (product, version, extra) if p]
            banner = " ".join(banner_parts)

            ledger.log_port(
                host=ip, port=port_num, proto=proto,
                source_module=module_name,
                service=service, product=product,
                version=version, banner=banner,
                tunnel=tunnel, reason=reason, method=method,
                confidence=confidence, extra=extra,
            )
            count += 1

    if count:
        logger.info("Logged %d open ports from %s (%s)", count, path, module_name)


# A host that SYN-ACKs far more ports than any real server has is a tarpit /
# SYN-proxy (or a firewall that answers everything). masscan faithfully reports
# all of them as "open", which (a) bloats the raw output and (b) would poison
# the nmap `ports: open` verify step with thousands of fake ports. Above this
# many open ports on one host we treat it as a tarpit: log it alive but ingest
# NO ports, and warn. Real hosts never approach this. Overridable via
# monkeyx.config `scan.masscan_tarpit_port_cap`; 0 (or negative) disables.
_MASSCAN_TARPIT_PORT_CAP = 500


def _masscan_tarpit_port_cap() -> int:
    try:
        from core.config import load_scan_config
        cap = load_scan_config().get("masscan_tarpit_port_cap")
        return int(cap) if cap is not None else _MASSCAN_TARPIT_PORT_CAP
    except Exception:
        return _MASSCAN_TARPIT_PORT_CAP


def _log_ports_from_masscan_grep(path: str, module_name: str, ledger):
    """Stream masscan greppable (-oG) output and log open ports to the ledger.

    masscan -oG is tab-separated fields, one line per open port, and the line
    STARTS WITH the timestamp field (not Host:):
        Timestamp: 1792527276\\tHost: 1.2.3.4 ()\\tPorts: 80/open/tcp//http//
    Streamed line-by-line (no DOM load — the file can be large) and guarded by a
    per-host tarpit cap (see _MASSCAN_TARPIT_PORT_CAP). No service info.

    Returns a stats dict {"ingested", "tarpits", "hosts"} so the caller can
    surface a mass-tarpit / empty sweep as a run-level warning (a sweep that
    yields no usable ports must not read as a clean run).
    """
    cap = _masscan_tarpit_port_cap()   # <=0 disables the tarpit guard

    # Accumulate per host so the tarpit cap can drop a host's ports wholesale.
    # Bounded memory: once a host crosses the cap we stop tracking its ports.
    host_ports = {}      # ip -> set((port, proto))
    tarpits = set()      # ips flagged as tarpit/SYN-proxy
    alive = set()        # every ip seen (logged alive regardless of cap)

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                # Fields are tab-separated and the line may be prefixed with a
                # "Timestamp:" field, so locate Host:/Ports: by field, not by
                # line position. A line without a Ports: field (host-discovery
                # only) is ignored.
                if "Host:" not in line or "Ports:" not in line:
                    continue
                ip = None
                ports_part = None
                for field in line.split("\t"):
                    field = field.strip()
                    if field.startswith("Host:"):
                        ip = field[len("Host:"):].strip().split(" ", 1)[0].strip()
                    elif field.startswith("Ports:"):
                        ports_part = field[len("Ports:"):].strip()
                if not ip or ports_part is None:
                    continue
                alive.add(ip)
                if ip in tarpits:
                    continue

                for spec in ports_part.split(","):
                    fields = spec.strip().split("/")
                    if len(fields) < 3 or fields[1] != "open":
                        continue
                    try:
                        port_num = int(fields[0])
                    except ValueError:
                        continue
                    proto = fields[2] or "tcp"

                    seen = host_ports.setdefault(ip, set())
                    if cap > 0 and len(seen) >= cap:
                        # Over the cap — this host is a tarpit. Drop everything
                        # we accumulated for it and ignore the rest of its ports.
                        tarpits.add(ip)
                        host_ports.pop(ip, None)
                        break
                    seen.add((port_num, proto))
    except Exception as e:
        logger.warning("Failed to parse masscan greppable output from %s: %s", path, e)
        return {"ingested": 0, "tarpits": 0, "hosts": 0}

    count = 0
    for ip, ports in host_ports.items():
        for port_num, proto in ports:
            ledger.log_port(
                host=ip, port=port_num, proto=proto,
                source_module=module_name,
            )
            count += 1

    # Log every responsive IP as alive — including tarpits (they're up, just not
    # usefully port-scannable), so coverage/ledger stay honest.
    for ip in alive:
        ledger.log_discovery(ip, TYPE_IP, module_name)

    for ip in sorted(tarpits):
        logger.warning(
            "masscan: host %s exceeded %d open ports — treating as tarpit/"
            "SYN-proxy; ports NOT ingested (would poison nmap verify)",
            ip, cap,
        )

    if count:
        logger.info("Logged %d open ports from masscan %s", count, path)

    return {"ingested": count, "tarpits": len(tarpits), "hosts": len(alive)}


def _log_ports_from_nessus_jsonl(path: str, module_name: str, ledger):
    """Parse nessus-normalized JSONL and log unique open ports to the ledger."""
    import json

    seen = set()
    count = 0

    try:
        with open(path) as f:
            for line in f:
                record = json.loads(line)
                host = record.get('host', '')
                port = record.get('port')
                proto = record.get('proto', 'tcp')
                service = record.get('service') or ''

                if not host or not port:
                    continue

                key = (host, port, proto)
                if key in seen:
                    continue
                seen.add(key)

                ledger.log_port(
                    host=host, port=port, proto=proto,
                    service=service,
                    source_module=module_name,
                )
                count += 1
    except Exception as e:
        logger.warning("Failed to parse nessus JSONL for ports from %s: %s", path, e)
        return

    if count:
        logger.info("Logged %d open ports from nessus import %s", count, path)


# Available enumeration modules — auto-discovered from modules/*.py
AVAILABLE_MODULES, MODULE_REQUIREMENTS = _discover_modules()


# Predefined workflows — loaded from workflows/*.yaml via plugin_loader
WORKFLOWS = {}


# Merge external plugin-provided modules/workflows into built-ins.
# Later discovered plugins override earlier names.
_PLUGIN_MODULES, _PLUGIN_WORKFLOWS = discover_plugins()
AVAILABLE_MODULES.update(_PLUGIN_MODULES)
WORKFLOWS.update(_PLUGIN_WORKFLOWS)

for _name in _PLUGIN_MODULES:
    if _name not in MODULE_REQUIREMENTS:
        MODULE_REQUIREMENTS[_name] = frozenset()



def get_resolved_workflow(workflow_name: str) -> list[str]:
    """Get the flat, resolved module list for a workflow.

    Derives the flat list from the rich resolver (single source of truth).
    Deduplicates while preserving order.
    """
    steps = get_resolved_workflow_rich(workflow_name)
    flat: list[str] = []
    for item in steps:
        if isinstance(item, ModuleStep):
            flat.append(item.name)
        elif isinstance(item, ParallelGroup):
            flat.extend(m.name for m in item.steps)
        elif isinstance(item, WaitStep):
            pass
    return flat


_TARGET_PRODUCING_MODULES = frozenset({
    "dns_resolve", "dnsx_resolve",
})

_DOMAIN_PRODUCING_MODULES = frozenset({
    "subfinder", "ax_subfinder", "ax_puredns_bruteforce",
})


def validate_module_inputs(
    module_names: list[str],
    has_targets: bool,
    has_urls: bool,
    has_domains: bool,
    auto_discovery_active: bool = False,
) -> list[str]:
    """Check that all required inputs are provided for the given modules.

    The url_file requirement is satisfied if any of:
      - has_urls is True
      - a target-scanning module (ax_nmap_tcp, ax_naabu,
        ax_nmap_udp) appears earlier in module_names
      - auto_discovery_active is True (ax_nmap_tcp will be injected)

    The target requirement is satisfied if any of:
      - has_targets is True
      - a target-producing module (dns_resolve, dnsx_resolve) appears
        earlier in the pipeline — these resolve hostnames/subdomains to IPs
        which land in the ledger as targets

    Returns:
        List of human-readable error strings (empty if validation passes).
    """
    errors = []
    target_module_seen = False
    target_will_be_produced = False
    domain_will_be_produced = False

    for name in module_names:
        reqs = MODULE_REQUIREMENTS.get(name, frozenset())

        if reqs:
            if "target" in reqs:
                if not has_targets and not target_will_be_produced:
                    errors.append(
                        f"Module '{name}' requires targets but none were provided "
                        f"and no target-producing module (dns_resolve, dnsx_resolve) "
                        f"appears before it in the pipeline."
                    )
                else:
                    target_module_seen = True

            if "url_file" in reqs:
                if not (has_urls or target_module_seen or auto_discovery_active):
                    errors.append(
                        f"Module '{name}' requires URLs but none were provided "
                        f"and no target-scanning module appears before it in the pipeline."
                    )

            if "domainlist" in reqs:
                if not has_domains and not domain_will_be_produced:
                    errors.append(
                        f"Module '{name}' requires domains but none were provided."
                    )

        if name in _TARGET_PRODUCING_MODULES:
            target_will_be_produced = True
        if name in _DOMAIN_PRODUCING_MODULES:
            domain_will_be_produced = True

    return errors


def _check_runtime_inputs(reqs: frozenset, kwargs: dict) -> list[str]:
    """Check if a module's required inputs are actually available at runtime.

    Unlike validate_module_inputs (pre-run, pipeline-aware), this checks the
    actual files right before execution. Returns list of missing input names.
    """
    missing = []
    if "target" in reqs:
        target = kwargs.get('target')
        if not target or not os.path.exists(target) or os.path.getsize(target) == 0:
            missing.append("targets")
    if "url_file" in reqs:
        url_file = kwargs.get('url_file')
        if not url_file or not os.path.exists(url_file) or os.path.getsize(url_file) == 0:
            missing.append("urls")
    if "domainlist" in reqs:
        domainlist = kwargs.get('domainlist')
        if not domainlist or not os.path.exists(domainlist) or os.path.getsize(domainlist) == 0:
            missing.append("domains")
    return missing


def _resolve_step(step, all_workflows: dict, _seen: set) -> list[StepItem]:
    if isinstance(step, str):
        return [ModuleStep(name=step)]

    if not isinstance(step, dict):
        logger.warning("Ignoring unrecognized step: %r", step)
        return []

    if "workflow" in step:
        return resolve_workflow_steps_rich(step["workflow"], all_workflows, _seen)

    if "name" in step:
        args = step.get("args", {})
        if not isinstance(args, dict):
            args = {}
        return [ModuleStep(name=step["name"], args=args)]

    if "wait" in step:
        return [WaitStep(name=step["wait"])]

    if "parallel" in step:
        inner_steps: list[ModuleStep] = []
        for inner in step["parallel"]:
            if isinstance(inner, str):
                inner_steps.append(ModuleStep(name=inner))
            elif isinstance(inner, dict) and "name" in inner:
                args = inner.get("args", {})
                if not isinstance(args, dict):
                    args = {}
                inner_steps.append(ModuleStep(name=inner["name"], args=args))
            else:
                logger.warning("Ignoring non-module step inside parallel block: %r", inner)
        if inner_steps:
            return [ParallelGroup(steps=inner_steps)]
        return []

    logger.warning("Ignoring unrecognized step: %r", step)
    return []


def resolve_workflow_steps_rich(
    workflow_name: str,
    all_workflows: dict | None = None,
    _seen: set | None = None,
) -> list[StepItem]:
    """Resolve a workflow into a rich step list preserving parallel groups and args."""
    if all_workflows is None:
        all_workflows = WORKFLOWS
    if _seen is None:
        _seen = set()

    if workflow_name in _seen:
        cycle = " -> ".join(list(_seen) + [workflow_name])
        raise ValueError(f"Circular workflow reference: {cycle}")

    if workflow_name not in all_workflows:
        raise ValueError(f"Unknown workflow '{workflow_name}'")

    _seen = _seen | {workflow_name}
    raw_steps = all_workflows[workflow_name]
    resolved: list[StepItem] = []

    for step in raw_steps:
        resolved.extend(_resolve_step(step, all_workflows, _seen))

    return resolved


# Idempotent modules that MAY legitimately run at several points in one workflow
# (e.g. `normalize` mid-run to mint scan.db findings progressively instead of
# only at the end). The dedup below never suppresses these, so every occurrence
# executes. Safe because they overwrite their outputs and upsert by finding_id.
_REPEATABLE_STEPS = frozenset({"normalize"})


def _dedup_rich_steps(steps: list[StepItem]) -> list[StepItem]:
    """Deduplicate a rich step list by module name (first occurrence wins),
    EXCEPT for _REPEATABLE_STEPS which are kept at every occurrence.

    Parallel group members are deduped against everything seen so far; a group
    that collapses to a single unique member becomes a sequential step.
    """
    seen: set[str] = set()
    deduped: list[StepItem] = []

    for item in steps:
        if isinstance(item, ModuleStep):
            if item.name in _REPEATABLE_STEPS or item.name not in seen:
                deduped.append(item)
                seen.add(item.name)
        elif isinstance(item, ParallelGroup):
            unique_inner = [ms for ms in item.steps
                            if ms.name in _REPEATABLE_STEPS or ms.name not in seen]
            for ms in unique_inner:
                seen.add(ms.name)
            if len(unique_inner) == 1:
                deduped.append(unique_inner[0])
            elif unique_inner:
                deduped.append(ParallelGroup(steps=unique_inner))
        else:
            # WaitStep or other structural items pass through unchanged.
            deduped.append(item)

    return deduped


def get_resolved_workflow_rich(workflow_name: str) -> list[StepItem]:
    """Get resolved step list preserving parallel groups and per-step args.

    Deduplicates sequential steps. Parallel group of 1 collapses to sequential.
    """
    return _dedup_rich_steps(resolve_workflow_steps_rich(workflow_name))


def get_resolved_workflows_rich(workflow_names: list[str]) -> list[StepItem]:
    """Resolve multiple workflows into a single rich step list, in order.

    Concatenates each workflow's rich steps (preserving parallel groups and
    per-step args) and deduplicates across the combined list, so selecting
    several workflows keeps their structure instead of flattening to bare
    module names.
    """
    combined: list[StepItem] = []
    for name in workflow_names:
        combined.extend(resolve_workflow_steps_rich(name))
    return _dedup_rich_steps(combined)


def _outputs_all_empty(output_files) -> bool:
    """True when a module declared output paths but every one is missing or holds
    zero bytes (a directory counts the bytes of all files it contains,
    recursively). Returns as soon as any non-empty byte is found. An empty/absent
    output_files list returns False — there is nothing to measure, so such a
    module is left as-is rather than flagged."""
    if not output_files:
        return False
    saw_path = False
    for path in output_files:
        if not isinstance(path, str) or not path:
            continue
        saw_path = True
        try:
            if os.path.isdir(path):
                for root, _dirs, files in os.walk(path):
                    for fn in files:
                        try:
                            if os.path.getsize(os.path.join(root, fn)) > 0:
                                return False
                        except OSError:
                            continue
            elif os.path.exists(path) and os.path.getsize(path) > 0:
                return False
        except OSError:
            continue
    return saw_path


def run_module(module_name, _dry_run: bool = False, **kwargs):
    """Run a single enumeration module.

    Args:
        module_name: Name of the module to run
        _dry_run: If True, generate synthetic output instead of running real tools
        **kwargs: Arguments to pass to the module (target, prefix, fleet, etc.)

    Returns:
        dict: Results from the module execution
    """
    if module_name not in AVAILABLE_MODULES:
        # Distinguish a module that FAILED TO IMPORT (a real, fixable bug) from a
        # genuinely unknown name (a typo). The former silently disappears from
        # AVAILABLE_MODULES otherwise, so a requested-but-broken module looked
        # identical to a misspelling.
        load_err = FAILED_MODULE_IMPORTS.get(module_name)
        if load_err:
            error_msg = (f"Module '{module_name}' exists but FAILED TO LOAD "
                         f"({load_err}) — fix the module, not the name")
        else:
            error_msg = f"Unknown module '{module_name}'"
        logger.error(error_msg)
        print(f"[!] Error: {error_msg}")
        print(f"[i] Available modules: {', '.join(AVAILABLE_MODULES.keys())}")
        raise ValueError(error_msg)

    logger.info(f"Starting module: {module_name}")
    logger.debug(f"Module kwargs: {kwargs}")

    if _dry_run and module_name not in _PASSTHROUGH_DRY_RUN:
        from core.dry_run import generate_synthetic_output
        result = generate_synthetic_output(module_name, **kwargs)
    else:
        module_func = AVAILABLE_MODULES[module_name]
        result = module_func(**kwargs)

    # Zero-byte output honesty (single source of truth for every module): a step
    # that returns success but wrote nothing — all declared output files missing
    # or empty, or an empty output directory — almost always means the tool
    # didn't reach/collect its targets, not a clean "found nothing". Downgrade to
    # warning so partial coverage never hides as success. Skipped under dry-run
    # (synthetic fixtures may not write real files); modules that declare no
    # output_files are left untouched (nothing to measure).
    if (not _dry_run and isinstance(result, dict)
            and result.get('status') == 'success'
            and _outputs_all_empty(result.get('output_files'))):
        msg = (f"{module_name}: ran but produced no output (all declared output "
               f"files are missing or empty) — the fleet may not have reached the "
               f"targets or results weren't collected. Verify rather than assume "
               f"zero findings.")
        print(f"[!] {msg}")
        result['status'] = 'warning'
        result.setdefault('warning', msg)

    status = result.get('status') if isinstance(result, dict) else None
    if status == 'failed':
        logger.warning(f"Module '{module_name}' returned failed: {result.get('error', 'unknown')}")
    elif status == 'warning':
        logger.warning(f"Module '{module_name}' completed with warning: {result.get('warning', 'unknown')}")
    else:
        logger.info(f"Module '{module_name}' completed successfully")
    logger.debug(f"Module result: {result}")
    return result


# Modules that RUN FOR REAL under --dry-run instead of being replaced by a
# synthetic fixture. The rule is strict: a module may passthrough ONLY if it is
# a purely-local file transform that makes NO external network call. These read
# the synthetic scan files produced upstream and generate reports/CSVs locally,
# so a dry-run still exercises the real normalize -> analyze -> report path.
#
# Modules that reach an external service (the AI providers: ai_analyze,
# ai_analyze_gowitness, ai_validate; and shodan_enrich, which sends
# client IPs to the Shodan API) are DELIBERATELY EXCLUDED. --dry-run must mean
# "no external calls" — including no scan data (IPs, titles, screenshots) leaving
# the host to a third party. Excluded modules fall through to
# core.dry_run.generate_synthetic_output, whose _gen_generic returns a clean
# empty success with zero egress.
_PASSTHROUGH_DRY_RUN = frozenset({"normalize", "analyze", "focus", "jsonl_to_csv", "nmap_converter", "summary"})

_NO_FLEET_MODULES = frozenset({
    "normalize", "analyze", "ai_analyze", "ai_analyze_gowitness",
    "ai_validate", "focus",
    "jsonl_to_csv", "nmap_converter", "dns_resolve", "dnsx_resolve",
    "subfinder", "nessus_import",
    "bbot_cloud", "bbot_takeover", "bbot_passive", "bbot_code", "bbot_dast", "bbot_recon",
    "dns_security", "html_report", "summary", "shodan_enrich",
    "ssh_audit_scan", "snmp_sweep", "smtp_security",
})

_BACKGROUND_MODULES = frozenset()

_BRUTEFORCE_MODULES = frozenset({"ax_puredns_bruteforce"})


def _last_fleet_step_index(steps: list) -> int:
    """Return the index of the last step that requires a fleet, or -1 if none."""
    last = -1
    idx = 0
    for step in steps:
        if isinstance(step, WaitStep):
            continue
        elif isinstance(step, ParallelGroup):
            if any(s.name not in _NO_FLEET_MODULES for s in step.steps):
                last = idx
            idx += len(step.steps)
        else:
            if step.name not in _NO_FLEET_MODULES:
                last = idx
            idx += 1
    return last


def run_workflow(workflow_name, cleanup=True, **kwargs):
    """Run a predefined workflow.

    Args:
        workflow_name: Name of the workflow to run
        cleanup: Whether to kill the fleet after completion (default: True)
        **kwargs: Arguments to pass to modules (target, prefix, fleet, etc.)

    Returns:
        list: Results from all modules in the workflow
    """
    if workflow_name not in WORKFLOWS:
        error_msg = f"Unknown workflow '{workflow_name}'"
        logger.error(error_msg)
        print(f"[!] Error: {error_msg}")
        print(f"[i] Available workflows: {', '.join(WORKFLOWS.keys())}")
        return []

    try:
        steps = get_resolved_workflow_rich(workflow_name)
    except ValueError as e:
        logger.error(str(e))
        print(f"[!] Error resolving workflow: {e}")
        return []

    return run_modules(steps, cleanup=cleanup, **kwargs)


def _merge_kwargs(base_kwargs: dict, step_args: dict, module_name: str = "") -> dict:
    merged = dict(base_kwargs)
    if module_name:
        from core.config import get_module_defaults
        config_defaults = get_module_defaults(module_name)
        if config_defaults:
            merged.update(config_defaults)
    if step_args:
        merged.update(step_args)
    return merged


def _regenerate_target_files(ledger, base_kwargs: dict, data_dir: str,
                             scope_filter: str = "strict",
                             snapshot: LedgerSnapshot | None = None):
    """Regenerate target files from the ledger before a module step.

    Writes deduplicated, scope-filtered files (into the data/ledger/ subdir via
    core.output_layout.ledger_file) and updates base_kwargs in-place:
      - target -> {data_dir}/ledger/ledger-targets.txt
      - url_file -> {data_dir}/ledger/ledger-urls.txt
      - domainlist -> {data_dir}/ledger/ledger-domains.txt

    Only overrides a kwarg if the ledger has entries of that type.
    """
    os.makedirs(data_dir, exist_ok=True)

    if snapshot:
        # Use snapshot sets directly (for parallel group consistency)
        _export_snapshot(snapshot, data_dir, scope_filter, base_kwargs, ledger=ledger)
        return

    # Name-safe web discovery (option A): seed http/https URLs for name-safe
    # (-d/-url) in-scope hosts so NAME-class web modules can probe them by
    # hostname (Host/SNI) — the safe substitute for a host-class port scan that
    # is gated away for these hosts. Idempotent (deduped in the ledger). -t hosts
    # are left to the richer nmap-driven URL discovery. Best-effort.
    if ledger is not NO_OP_LEDGER:
        try:
            from core.target_ledger import CHANNEL_DOMAIN, CHANNEL_URL
            seeded = ledger.synthesize_name_urls(
                only_channels=(CHANNEL_DOMAIN, CHANNEL_URL))
            if seeded:
                logger.debug("Seeded %d name-safe URLs for web modules", seeded)
        except Exception as e:
            logger.warning("Name-safe URL synthesis failed: %s", e)

    targets_path = ledger_file(data_dir, "ledger-targets.txt")
    count = ledger.export_targets(targets_path, scope_filter)
    if count > 0:
        base_kwargs['target'] = targets_path
        logger.debug("Regenerated %d targets -> %s", count, targets_path)

    target_ips_path = ledger_file(data_dir, "ledger-target-ips.txt")
    ip_count = ledger.export_target_ips(target_ips_path, scope_filter)
    if ip_count > 0:
        base_kwargs['target_ips_file'] = target_ips_path
        logger.debug("Regenerated %d target IPs -> %s", ip_count, target_ips_path)

    # Host-scoped variants for HOST-class modules (port sweeps, name-blind
    # service probes): same files, but restricted to -t-authorized assets. A
    # dl/ul-only name or IP (name-safe surface on shared infra) is dropped. The
    # per-module remap (_host_scoped_kwargs) points host-class modules at these.
    _regenerate_host_variants(ledger, data_dir, scope_filter)

    urls_path = ledger_file(data_dir, "ledger-urls.txt")
    count = ledger.export_urls(urls_path, scope_filter)
    _export_live_urls(ledger, data_dir, scope_filter, base_kwargs)
    if count > 0:
        base_kwargs['url_file'] = urls_path
        logger.debug("Regenerated %d URLs -> %s", count, urls_path)

    domains_path = ledger_file(data_dir, "ledger-domains.txt")
    count = ledger.export_domains(domains_path, scope_filter)
    if count > 0:
        base_kwargs['domainlist'] = domains_path
        logger.debug("Regenerated %d domains -> %s", count, domains_path)

    mx_path = ledger_file(data_dir, "ledger-mx-domains.txt")
    mx_count = ledger.export_mx_domains(mx_path, scope_filter)
    if mx_count > 0:
        base_kwargs['mx_domains_file'] = mx_path
        logger.debug("Regenerated %d MX domains -> %s", mx_count, mx_path)

    ports_path = ledger_file(data_dir, "ledger-open-ports.txt")
    ports_count = ledger.export_open_ports(ports_path, scope_filter)
    if ports_count > 0:
        base_kwargs['open_ports_file'] = ports_path
        logger.debug("Regenerated open ports for %d hosts -> %s", ports_count, ports_path)

    # UDP open ports as a separate file — the per-host list is proto-less, and
    # the TCP file above excludes UDP, so snmp_sweep (UDP/161) reads this one.
    udp_ports_path = ledger_file(data_dir, "ledger-open-ports-udp.txt")
    udp_ports_count = ledger.export_open_ports(udp_ports_path, scope_filter, proto_filter="udp")
    if udp_ports_count > 0:
        base_kwargs['udp_open_ports_file'] = udp_ports_path
        logger.debug("Regenerated UDP open ports for %d hosts -> %s", udp_ports_count, udp_ports_path)


# Kwargs that point at the target-family files a HOST-class module scans, and
# the host-scoped variant each should be remapped to. url_file/domainlist are
# NAME-safe by nature (addressed by Host/SNI) and are never remapped.
_HOST_SCOPED_FILES = {
    "target": "ledger-targets.host.txt",
    "target_ips_file": "ledger-target-ips.host.txt",
    "open_ports_file": "ledger-open-ports.host.txt",
    "udp_open_ports_file": "ledger-open-ports-udp.host.txt",
}


def format_scope_echo(ledger) -> str:
    """Render the operator-facing scope summary (see ledger.scope_summary()).

    Shows what will be host-scanned (-t) vs tested name-safe (-d/-url), plus
    exclusion and lead counts, so intent is visible before a fleet spins up.
    """
    if ledger is NO_OP_LEDGER:
        return ""
    s = ledger.scope_summary()
    hf, ns = s["host_full"], s["name_safe"]
    lines = [
        "Scope summary (authorization by input channel):",
        f"  Host-full (-t, all ports):   "
        f"{hf['ips']} IPs, {hf['hosts']} hosts, {hf['urls']} URLs",
        f"  Name-safe (-d/-url, by name): "
        f"{ns['ips']} IPs, {ns['hosts']} hosts, {ns['urls']} URLs",
        f"  Excluded: {s['excluded']}    Discovered leads (not scanned): {s['leads']}",
    ]
    return "\n".join(lines)


def _regenerate_host_variants(ledger, data_dir: str, scope_filter: str,
                              snapshot: LedgerSnapshot | None = None):
    """Write the -t-authorized-only variants of the target-family files.

    These mirror the normal ledger-*.txt files but pass host_only=True, so a
    dl/ul-only name/IP (name-safe on shared infra) is excluded. HOST-class
    modules are remapped onto these by _host_scoped_kwargs.
    """
    if ledger is NO_OP_LEDGER:
        return
    ips_all = set(snapshot.ips) if snapshot else None
    ips_in = set(snapshot.in_scope_ips) if snapshot else None

    # HOST-class port scanners get UNIQUE IPs (collapsed), not one line per
    # hostname — a shared IP that many in-scope names resolve to is scanned once,
    # not once per name. NAME/web modules still read the name-expanded
    # ledger-targets.txt. See TargetLedger.export_host_targets.
    ledger.export_host_targets(ledger_file(data_dir, _HOST_SCOPED_FILES["target"]),
                               scope_filter, all_set=ips_all, in_scope_set=ips_in)
    ledger.export_target_ips(ledger_file(data_dir, _HOST_SCOPED_FILES["target_ips_file"]),
                             scope_filter, all_set=ips_all, in_scope_set=ips_in,
                             host_only=True)
    # Port files read the live _ports index (not snapshot-overridable), so they
    # are written once per regeneration regardless of the snapshot path.
    ledger.export_open_ports(ledger_file(data_dir, _HOST_SCOPED_FILES["open_ports_file"]),
                             scope_filter, host_only=True)
    ledger.export_open_ports(ledger_file(data_dir, _HOST_SCOPED_FILES["udp_open_ports_file"]),
                             scope_filter, host_only=True, proto_filter="udp")


# Heavy web scanners that should consume the httpx-live URL subset (not the full
# list) when --url-prune is on. Probers (ax_httpx) and discovery modules
# (katana/gau/subjs/arjun/linkfinder/amass) are NOT here — they need every URL.
# bbot_dast is here because it's the invasive fuzzer — it must hit only live
# endpoints, never dead/historical URLs. wafw00f/testssl also live-filter (and
# are additionally collapsed to one root per host via _BASE_URL_SCANNERS).
_LIVE_URL_SCANNERS = frozenset({
    "ax_nuclei", "ax_gowitness", "ax_ffuf", "ax_feroxbuster",
    "ax_dalfox", "ax_corsy", "ax_mantra", "ax_wpscan",
    "ax_wafw00f", "ax_testssl", "bbot_dast",
})


def _export_live_urls(ledger, data_dir: str, scope_filter: str, base_kwargs: dict,
                      snapshot=None):
    """Write ledger-urls-live.txt (httpx-live subset) when --url-prune is on, and
    stash its path in base_kwargs['url_file_live'] for _live_url_kwargs to pick up.
    No-op (and no file) when pruning is off."""
    if getattr(ledger, "_url_prune_policy", "off") not in ("live", "interesting"):
        return
    live_path = ledger_file(data_dir, "ledger-urls-live.txt")
    kw = {}
    if snapshot is not None:
        kw = {"all_set": set(snapshot.urls), "in_scope_set": set(snapshot.in_scope_urls)}
    ledger.export_urls_live(live_path, scope_filter,
                            policy=ledger._url_prune_policy,
                            max_per_host=ledger._url_prune_max_per_host, **kw)
    base_kwargs['url_file_live'] = live_path


def _live_url_kwargs(module_name: str, kwargs: dict) -> dict:
    """Remap a heavy web scanner's url_file to the httpx-live subset when
    available. NAME-class, so it can't ride on _host_scoped_kwargs (which only
    touches HOST modules) — applied as a sibling step."""
    if module_name not in _LIVE_URL_SCANNERS:
        return kwargs
    live = kwargs.get("url_file_live")
    if live and kwargs.get("url_file") and os.path.exists(live):
        remapped = dict(kwargs)
        remapped["url_file"] = live
        return remapped
    return kwargs


# Tools that act on a SITE / host:port, not per-path — feed them ONE root per
# scheme://host:port instead of the full deep-path inventory (every URL from
# gau/katana/httpx, often thousands):
#   - ax_feroxbuster: recursive dir brute-force — recursion finds the tree, so
#     one root per host; the full list makes it brute-force each path (melts the
#     fleet).
#   - ax_ffuf: wordlist fuzzer with no FUZZ keyword → fuzzes the wordlist under
#     every input URL; base roots keep it to one pass per host.
#   - ax_wpscan: fingerprints/enumerates a whole WordPress site — identical per
#     path, so one scan per host.
#   - ax_wafw00f: WAF fingerprint is per host — one probe per host, not per URL.
#   - ax_testssl: TLS config is a host:port property — one (slow) audit per
#     host:port, not per path.
_BASE_URL_SCANNERS = frozenset({
    "ax_feroxbuster", "ax_ffuf", "ax_wpscan", "ax_wafw00f", "ax_testssl",
})


def _base_url_kwargs(module_name: str, kwargs: dict, data_dir: str) -> dict:
    """Collapse a recursive scanner's url_file to deduplicated base URLs.

    Applied AFTER _live_url_kwargs, so it collapses whatever URL set the module
    would otherwise read (full list, or the httpx-live subset when --url-prune is
    on) down to unique scheme://host:port roots. Writes
    ledger-urls-ferox-base.txt and remaps url_file to it. Fail-open: if the input
    file is missing/empty/unreadable or yields no base URLs, kwargs are unchanged
    (the module falls back to its original input rather than getting starved)."""
    if module_name not in _BASE_URL_SCANNERS:
        return kwargs
    src = kwargs.get("url_file")
    if not src or not os.path.exists(src):
        return kwargs
    bases: dict[str, None] = {}  # ordered set
    try:
        with open(src, encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                base = _extract_base_url(line)
                if base:
                    bases.setdefault(base, None)
    except OSError:
        return kwargs
    if not bases:
        return kwargs
    out_path = ledger_file(data_dir, "ledger-urls-ferox-base.txt")
    try:
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(bases) + "\n")
    except OSError:
        return kwargs
    remapped = dict(kwargs)
    remapped["url_file"] = out_path
    return remapped


def _host_scoped_kwargs(module_name: str, kwargs: dict, data_dir: str) -> dict:
    """Return kwargs remapped for the module's scope class.

    HOST-class modules get the -t-authorized-only target-family files; NAME and
    PASSIVE modules are unchanged (they address by name/URL, safe on shared
    infra, or touch no target). Only remaps a kwarg the module already has set
    and whose host variant exists on disk — so a module reading no target file
    is untouched.
    """
    # ai_validate is HOST fail-safe at the module level, but it legitimately runs
    # BOTH name-safe tools (curl/nuclei — must see the full name surface) and
    # host-touching tools (nmap/nc/snmp — must be -t-only). It enforces that
    # split itself per-command (see modules/ai_validate.py), so we do NOT remap
    # its target files here — that would wrongly starve its name-safe validation.
    if module_name == "ai_validate":
        return kwargs
    if scope_classes.scope_class(module_name) != scope_classes.SCOPE_HOST:
        return kwargs
    remapped = dict(kwargs)
    for key, host_name in _HOST_SCOPED_FILES.items():
        if not kwargs.get(key):
            continue
        host_path = ledger_file(data_dir, host_name)
        if os.path.exists(host_path):
            remapped[key] = host_path
    return remapped


def _member_kwargs(step, base_kwargs: dict, data_dir, ledger=None) -> dict:
    """The exact kwargs a step runs with: base + per-step args, then the
    HOST-scope and live-URL (url-prune) remaps, plus dns_security's root-domain
    scoping. Used to BOTH run a parallel-group member and snapshot/record what it
    was fed — so the forensic step-snapshot reflects reality, not the pre-remap
    group kwargs."""
    merged = _merge_kwargs(base_kwargs, step.args, module_name=step.name)
    if data_dir:
        merged = _host_scoped_kwargs(step.name, merged, data_dir)
        merged = _live_url_kwargs(step.name, merged)
        merged = _base_url_kwargs(step.name, merged, data_dir)
        if ledger is not None and ledger is not NO_OP_LEDGER:
            # Bruteforce modules target user-provided root domains only, not the
            # full ledger (which includes their own prior discoveries). This must
            # mirror the sequential path — without it, puredns in a parallel group
            # re-bruteforces every discovered subdomain (wordlist × discoveries).
            if step.name in _BRUTEFORCE_MODULES:
                root_domains_path = ledger_file(data_dir, "ledger-root-domains.txt")
                if ledger.export_root_domains(root_domains_path) > 0:
                    merged['domainlist'] = root_domains_path
            if step.name == "dns_security":
                root_domains_path = ledger_file(data_dir, "ledger-root-domains.txt")
                ledger.export_root_domains(root_domains_path)
                merged['root_domains_file'] = root_domains_path
            # Sweep-then-verify: an ax_nmap_tcp step with ports:open scans only the
            # ports a prior masscan/naabu sweep found open, on only the live hosts.
            # Point it at the swept-open union + the responsive-host list so nmap's
            # heavy -sV/NSE command runs on a tiny port set per host, not all 65k.
            if step.name == "ax_nmap_tcp" and (step.args or {}).get("ports") == "open":
                scope_filter = base_kwargs.get("scope_filter", "strict")
                ports_list = ledger_file(data_dir, "ledger-open-ports-list.txt")
                if ledger.export_port_list(ports_list, proto="tcp",
                                           scope_filter=scope_filter, host_only=True) > 0:
                    merged["open_ports_list_file"] = ports_list
                live_hosts = ledger_file(data_dir, "ledger-live-hosts.host.txt")
                if ledger.export_live_host_targets(live_hosts, proto="tcp",
                                                   scope_filter=scope_filter, host_only=True) > 0:
                    merged["target"] = live_hosts
    return merged


def _export_snapshot(snapshot: LedgerSnapshot, data_dir: str,
                     scope_filter: str, base_kwargs: dict, ledger=None):
    """Export a frozen snapshot to target files (used for parallel groups).

    Delegates to the ledger's own export functions, passing the snapshot's
    frozen sets as overrides — so parallel groups apply the IDENTICAL
    exclusion / CIDR-carve-out / private-address / ip_scope policy as sequential
    steps. (Previously this reimplemented that policy and drifted, letting
    excluded IPs inside a CIDR and private URL hosts leak into parallel modules.)
    """
    if ledger is None or ledger is NO_OP_LEDGER:
        return

    targets_path = ledger_file(data_dir, "ledger-targets.txt")
    if ledger.export_targets(targets_path, scope_filter,
                             all_set=set(snapshot.ips),
                             in_scope_set=set(snapshot.in_scope_ips)):
        base_kwargs['target'] = targets_path

    target_ips_path = ledger_file(data_dir, "ledger-target-ips.txt")
    if ledger.export_target_ips(target_ips_path, scope_filter,
                                all_set=set(snapshot.ips),
                                in_scope_set=set(snapshot.in_scope_ips)):
        base_kwargs['target_ips_file'] = target_ips_path

    urls_path = ledger_file(data_dir, "ledger-urls.txt")
    if ledger.export_urls(urls_path, scope_filter,
                          all_set=set(snapshot.urls),
                          in_scope_set=set(snapshot.in_scope_urls)):
        base_kwargs['url_file'] = urls_path
    _export_live_urls(ledger, data_dir, scope_filter, base_kwargs, snapshot=snapshot)

    domains_path = ledger_file(data_dir, "ledger-domains.txt")
    if ledger.export_domains(domains_path, scope_filter,
                             all_set=set(snapshot.domains),
                             in_scope_set=set(snapshot.in_scope_domains)):
        base_kwargs['domainlist'] = domains_path

    # Open-ports kwargs, mirroring the sequential path (_regenerate_target_files).
    # Without this, HOST-class port consumers in a parallel group (ax_nuclei,
    # ssh_audit_scan, smtp_security) never get open_ports_file seeded into
    # base_kwargs — and _host_scoped_kwargs only remaps a kwarg that is ALREADY
    # set, so they'd silently skip with "no in-scope open ports" even when ports
    # exist. Port files read the live _ports index (not snapshot-overridable), so
    # seeding them here is consistent with _regenerate_host_variants below.
    ports_path = ledger_file(data_dir, "ledger-open-ports.txt")
    if ledger.export_open_ports(ports_path, scope_filter):
        base_kwargs['open_ports_file'] = ports_path
    udp_ports_path = ledger_file(data_dir, "ledger-open-ports-udp.txt")
    if ledger.export_open_ports(udp_ports_path, scope_filter, proto_filter="udp"):
        base_kwargs['udp_open_ports_file'] = udp_ports_path

    # Host-scoped variants so a parallel group's HOST-class members (e.g.
    # ax_nmap_tcp running alongside name-class bbot_recon) gate identically to
    # the sequential path.
    _regenerate_host_variants(ledger, data_dir, scope_filter, snapshot=snapshot)


def _get_max_snapshot_index(data_dir: str) -> int:
    """Find the highest step index in existing step-snapshots to avoid collisions."""
    snapshot_dir = os.path.join(data_dir, "step-snapshots")
    if not os.path.isdir(snapshot_dir):
        return 0
    import re
    max_idx = 0
    for fname in os.listdir(snapshot_dir):
        m = re.match(r'step-(\d+)-', fname)
        if m:
            max_idx = max(max_idx, int(m.group(1)))
    return max_idx


# Input-file kwarg -> snapshot filename label.
_INPUT_FILE_LABELS = {
    "target": "target",
    "url_file": "urls",
    "domainlist": "domains",
    "target_ips_file": "target-ips",
    "open_ports_file": "open-ports",
    "udp_open_ports_file": "open-ports-udp",
    "root_domains_file": "root-domains",
}

# Modules whose real inputs aren't the standard target/url/domain (they have
# empty REQUIRED_INPUTS and read a port/IP/root-domain file instead). Listed here
# so the step snapshot captures EXACTLY what the tool scanned, not the target/url
# files it ignores. Keys are the kwargs each reads (in preference order).
_MODULE_EXTRA_INPUTS = {
    "snmp_sweep":     ["udp_open_ports_file", "open_ports_file"],
    "smtp_security":  ["open_ports_file"],
    "ssh_audit_scan": ["open_ports_file"],
    # ax_nuclei scans both the URL list and the -t-authorized IP:port endpoints.
    "ax_nuclei":      ["url_file", "open_ports_file"],
    "shodan_enrich":  ["target_ips_file"],
    "dns_security":   ["root_domains_file"],
}


def _snapshot_module_inputs(data_dir: str, step_index: int, module_name: str,
                             base_kwargs: dict):
    """Save a copy of the input files this module was ACTUALLY fed — post
    host-scope + url-prune remap, so the record matches what the tool scanned.

    Writes to {data_dir}/step-snapshots/step-{N:03d}-{module}-{label}.txt.
    - PASSIVE modules (no target contact) snapshot nothing.
    - Modules in `_MODULE_EXTRA_INPUTS` snapshot exactly their declared inputs
      (open-ports / UDP / target-ips / root-domains).
    - Everything else snapshots target/url/domain gated by REQUIRED_INPUTS
      (empty = all three; CONSUMES_URLS also pulls in the URL file).
    """
    if scope_classes.scope_class(module_name) == scope_classes.SCOPE_PASSIVE:
        return  # passive modules process files, they don't scan a target set

    snapshot_dir = os.path.join(data_dir, "step-snapshots")
    try:
        os.makedirs(snapshot_dir, exist_ok=True)
    except OSError as e:
        logger.warning("Could not create step snapshot dir: %s", e)
        return

    extra = _MODULE_EXTRA_INPUTS.get(module_name)
    if extra is not None:
        keys = list(extra)
    else:
        reqs = MODULE_REQUIREMENTS.get(module_name, frozenset())
        if not reqs:
            keys = ["target", "url_file", "domainlist"]
        else:
            keys = []
            if "target" in reqs:
                keys.append("target")
            if "url_file" in reqs or _module_consumes_urls(module_name):
                keys.append("url_file")
            if "domainlist" in reqs:
                keys.append("domainlist")

    for key in keys:
        src = base_kwargs.get(key)
        if not src or not os.path.exists(str(src)):
            continue
        label = _INPUT_FILE_LABELS.get(key, key)
        dest = os.path.join(
            snapshot_dir,
            f"step-{step_index:03d}-{module_name}-{label}.txt",
        )
        try:
            shutil.copy2(str(src), dest)
        except Exception as e:
            logger.warning("Step snapshot copy failed for %s: %s", dest, e)


def _run_sequential_step(step: ModuleStep, base_kwargs: dict, results: list,
                         step_index: int = 0,
                         ledger=NO_OP_LEDGER, scope_filter: str = "strict",
                         data_dir: str | None = None, dry_run: bool = False):
    print(f"\n{'-'*60}")
    print(f"Module: {step.name}")
    if step.args:
        print(f"  Custom args: {step.args}")
    print(f"{'-'*60}")

    # Regenerate target files from ledger before running module
    if data_dir:
        _regenerate_target_files(ledger, base_kwargs, data_dir, scope_filter)

    data_prefix = base_kwargs.get('data_prefix', base_kwargs.get('prefix', ''))
    continue_mode = base_kwargs.get('_continue_mode', False)

    if continue_mode and data_prefix and _merge_should_version(step.name):
        try:
            _merge_archive_existing(step.name, data_prefix)
        except Exception as e:
            logger.warning("Pre-step archive failed for %s: %s", step.name, e)

    # Build the exact kwargs the module runs with: merge + HOST-scope + live-URL
    # + base-URL + bruteforce/dns_security root-domain remaps. Shared with the
    # parallel path (_member_kwargs), so both snapshot and run with IDENTICAL
    # inputs — and all remaps happen BEFORE the snapshot/coverage below, so the
    # forensic record reflects what the module actually scanned (previously the
    # root-domain remaps ran after the snapshot, mis-recording puredns/dns_security).
    merged_kwargs = _member_kwargs(step, base_kwargs, data_dir, ledger)
    if data_dir:
        _snapshot_module_inputs(data_dir, step_index, step.name, merged_kwargs)
        # Record coverage (module <- targets fed) into scan.db from the same
        # post-remap inputs. Intent only; Phase 2 reconciliation adds reach.
        ledger.record_coverage(step.name, merged_kwargs, step_index)

    # Runtime input check: skip module if its required inputs aren't available
    reqs = MODULE_REQUIREMENTS.get(step.name, frozenset())
    if reqs:
        missing = _check_runtime_inputs(reqs, merged_kwargs)
        if missing:
            logger.info("Skipping '%s' — missing inputs: %s", step.name, ', '.join(missing))
            print(f"[*] Skipping '{step.name}' — required inputs not available: {', '.join(missing)}")
            skip_result = {'module': step.name, 'status': 'skipped', 'output_files': [],
                           'error': f"Missing inputs: {', '.join(missing)}"}
            results.append(skip_result)
            return skip_result

    result = run_module(step.name, _dry_run=dry_run, **merged_kwargs)
    results.append(result)
    _extract_discoveries(result, step.name, ledger, data_prefix, kwargs=base_kwargs)
    _reconcile_step_coverage(result, step.name, step_index, ledger)

    if (continue_mode and data_prefix
            and _merge_should_version(step.name)
            and result.get('status') == 'success'):
        try:
            _merge_version_and_merge(step.name, data_prefix)
        except Exception as e:
            logger.warning("Post-step merge failed for %s: %s", step.name, e)

    return result


def _run_parallel_group(group: ParallelGroup, base_kwargs: dict, results: list,
                        step_index: int = 0,
                        tracker=NO_OP_TRACKER,
                        ledger=NO_OP_LEDGER, scope_filter: str = "strict",
                        data_dir: str | None = None, dry_run: bool = False):
    module_names = [s.name for s in group.steps]

    print(f"\n{'='*60}")
    print(f"Parallel group: {', '.join(module_names)}")
    print(f"{'='*60}")

    # Per-member kwargs, computed once so the snapshot/coverage record and the
    # actual run can't diverge (id(step) -> kwargs).
    member_kwargs: dict = {}
    # Snapshot ledger and regenerate files ONCE for the whole group
    if data_dir:
        snap = ledger.snapshot()
        _regenerate_target_files(ledger, base_kwargs, data_dir, scope_filter, snapshot=snap)
        # Snapshot inputs for each member from the SAME remapped kwargs it will
        # run with (post host-scope + url-prune), so the forensic snapshot and
        # coverage reflect what the tool was actually fed — not the group kwargs.
        for offset, step in enumerate(group.steps):
            mk = _member_kwargs(step, base_kwargs, data_dir, ledger)
            member_kwargs[id(step)] = mk
            _snapshot_module_inputs(data_dir, step_index + offset, step.name, mk)
            ledger.record_coverage(step.name, mk, step_index + offset)

    data_prefix = base_kwargs.get('data_prefix', base_kwargs.get('prefix', ''))
    continue_mode = base_kwargs.get('_continue_mode', False)

    if continue_mode and data_prefix:
        for step in group.steps:
            if _merge_should_version(step.name):
                try:
                    _merge_archive_existing(step.name, data_prefix)
                except Exception as e:
                    logger.warning("Pre-step archive failed for %s: %s", step.name, e)

    group_started = tracker.parallel_group_started(module_names)
    group_results: list[tuple[ModuleStep, dict]] = []
    started_times: dict = {}

    def _tracked_run(step):
        started = tracker.step_started(step.name, parallel_group=True)
        started_times[step.name] = started
        # Reuse the kwargs the snapshot/coverage recorded (computed above), so the
        # module runs with EXACTLY what was recorded. Fall back to computing when
        # there's no data_dir (no snapshot pass ran).
        merged_kwargs = member_kwargs.get(id(step))
        if merged_kwargs is None:
            merged_kwargs = _member_kwargs(step, base_kwargs, data_dir, ledger)

        reqs = MODULE_REQUIREMENTS.get(step.name, frozenset())
        if reqs:
            missing = _check_runtime_inputs(reqs, merged_kwargs)
            if missing:
                logger.info("Skipping '%s' — missing inputs: %s", step.name, ', '.join(missing))
                print(f"[*] Skipping '{step.name}' — required inputs not available: {', '.join(missing)}")
                result = {'module': step.name, 'status': 'skipped', 'output_files': [],
                          'error': f"Missing inputs: {', '.join(missing)}"}
                tracker.step_completed(step.name, started, result)
                return result

        try:
            result = run_module(step.name, _dry_run=dry_run, **merged_kwargs)
            if isinstance(result, dict) and result.get('status') == 'failed':
                tracker.step_failed(step.name, started,
                                    result.get('error', 'module returned failed'))
            else:
                tracker.step_completed(step.name, started, result)
            return result
        except Exception as e:
            tracker.step_failed(step.name, started, str(e))
            # MUST carry status='failed': _completion_exit_code / the summary key
            # off it, so without it a crashed parallel member exits 0 ("clean").
            return {'module': step.name, 'status': 'failed', 'error': str(e)}

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(group.steps)) as executor:
            future_to_step = {}
            for step in group.steps:
                future = executor.submit(_tracked_run, step)
                future_to_step[future] = step

            for future in concurrent.futures.as_completed(future_to_step):
                step = future_to_step[future]
                result = future.result()
                group_results.append((step, result))
    except KeyboardInterrupt:
        # Ctrl+C only interrupts the MAIN thread, but worker threads keep running
        # to completion (the executor waits on exit) — so a worker whose tool
        # exited 0 on the signal may already have recorded step_completed(success).
        # The group is incomplete and re-runs atomically on resume, so override
        # every member to failed: an interrupted step must never report success.
        for step in group.steps:
            tracker.step_failed(step.name,
                                started_times.get(step.name, group_started),
                                "Interrupted (Ctrl+C) — parallel group incomplete, re-runs on resume")
        raise

    _step_offsets = {id(s): i for i, s in enumerate(group.steps)}
    for step, result in group_results:
        results.append(result)
        _extract_discoveries(result, step.name, ledger, data_prefix, kwargs=base_kwargs)
        _reconcile_step_coverage(result, step.name,
                                 step_index + _step_offsets.get(id(step), 0), ledger)

        if (continue_mode and data_prefix
                and _merge_should_version(step.name)
                and result.get('status') == 'success'):
            try:
                _merge_version_and_merge(step.name, data_prefix)
            except Exception as e:
                logger.warning("Post-step merge failed for %s: %s", step.name, e)

    tracker.parallel_group_completed(group_started)

    print(f"\n{'='*60}")
    print(f"Parallel group complete: {', '.join(module_names)}")
    print(f"{'='*60}")


def run_modules(module_list, cleanup=True, resume_from: int = 0, finish_step: bool = False,
                scaler=None, **kwargs):
    """Run a list of modules, supporting parallel groups and per-step args.

    Args:
        module_list: List of module names (str), ModuleStep, or ParallelGroup objects
        cleanup: Whether to kill the fleet after completion (default: True)
        resume_from: Step index to resume from (0 = start from beginning)
        finish_step: If True, pause waits for current step to complete (graceful).
                     If False (default), KeyboardInterrupt cancels mid-step and
                     checkpoint points at the interrupted step for re-run on resume.
        scaler: FleetScaler or NoOpScaler instance for auto-scaling (optional)
        **kwargs: Base arguments passed to all modules (target, prefix, fleet, etc.)
            output_dir: Output directory for progress tracking (optional)
            scope_filter: "strict" (default), "warn", or "none"

    Returns:
        list: Results from all modules
    """
    steps: list[StepItem] = []
    for item in module_list:
        if isinstance(item, str):
            steps.append(ModuleStep(name=item))
        elif isinstance(item, (ModuleStep, ParallelGroup, WaitStep)):
            steps.append(item)
        else:
            logger.warning("Ignoring unrecognized item in module list: %r", item)

    total = sum(
        len(s.steps) if isinstance(s, ParallelGroup) else (0 if isinstance(s, WaitStep) else 1)
        for s in steps
    )

    output_dir = kwargs.pop('output_dir', None)
    keep_fleet = kwargs.pop('keep_fleet', False)
    scope_filter = kwargs.pop('scope_filter', 'strict')
    kwargs['scope_filter'] = scope_filter
    ip_scope = kwargs.pop('ip_scope', 'provenance')
    url_prune = kwargs.pop('url_prune', 'off')
    url_max_per_host = kwargs.pop('url_max_per_host', None)
    # Re-inject (like scope_filter) so it reaches per-module kwargs: the
    # ingestion cap in _extract_discoveries (crawled URLs -> ledger targets) and
    # the web_dirs cap in normalize both read kwargs['url_max_per_host'], not just
    # the export's set_url_prune below.
    kwargs['url_max_per_host'] = url_max_per_host
    dry_run = kwargs.pop('dry_run', False)
    engagement_id = kwargs.pop('engagement_id', None)
    if output_dir:
        tracker = ProgressTracker(output_dir, total, start_index=resume_from)
        ledger = TargetLedger(output_dir)
        ledger.set_ip_scope_mode(ip_scope)
        ledger.set_url_prune(url_prune, url_max_per_host)
        # Stamp durable engagement identity into scan.db meta (first-wins uuid,
        # stable across --continue/--resume; API can inject its run_id here).
        _prefix = kwargs.get('prefix')
        ledger.stamp_identity(
            engagement_uuid=engagement_id,
            output_prefix=os.path.basename(_prefix) if _prefix else None)
        checkpoint = Checkpoint(output_dir)
    else:
        tracker = NO_OP_TRACKER
        ledger = NO_OP_LEDGER
        checkpoint = None

    # Let the fleet scaler emit its up/down transitions into the same event
    # stream (progress.jsonl + scan.db). The scaler is constructed before the
    # tracker exists, so it's wired here. Harmless on NoOpScaler (never scales).
    if scaler is not None:
        scaler.progress_tracker = tracker

    # Determine data_dir for ledger-generated target files
    data_prefix = kwargs.get('data_prefix', kwargs.get('prefix', ''))
    data_dir: str | None = None
    if data_prefix:
        data_dir = os.path.dirname(data_prefix) if os.path.dirname(data_prefix) else None

    # Collect flat module names for checkpoint
    all_module_names: list[str] = []
    for s in steps:
        if isinstance(s, ParallelGroup):
            all_module_names.extend(m.name for m in s.steps)
        elif isinstance(s, WaitStep):
            continue
        else:
            all_module_names.append(s.name)

    # Record the ordered plan for THIS invocation so the live view can show the
    # modules queued but not yet started. Mirror the loop's resume skip so a
    # --resume plan only lists the steps that will actually run.
    _plan, _pi = [], 0
    for s in steps:
        if isinstance(s, WaitStep):
            continue
        cnt = len(s.steps) if isinstance(s, ParallelGroup) else 1
        if _pi + cnt <= resume_from:
            _pi += cnt
            continue
        _plan.append([m.name for m in s.steps] if isinstance(s, ParallelGroup) else s.name)
        _pi += cnt
    tracker.run_planned(_plan)

    workflow_name = kwargs.pop('workflow_name', None)

    logger.info(f"Running {total} modules in {len(steps)} steps (scope_filter={scope_filter})")

    print(f"\n{'='*60}")
    if resume_from > 0:
        print(f"Resuming from step {resume_from + 1} of {total} ({len(steps)} steps)")
    else:
        print(f"Running {total} modules in {len(steps)} steps")
    print(f"Scope filter: {scope_filter}")
    print(f"{'='*60}\n")

    continue_mode = kwargs.pop('continue_mode', False)
    kwargs['_continue_mode'] = continue_mode
    exclusion_file = kwargs.pop('exclusion_file', None)

    # Ledger initialization: continue loads existing then optionally seeds new inputs,
    # fresh run seeds from scratch, resume reloads from disk.
    if continue_mode:
        # Seed exclusions BEFORE load_from_disk so the scope fixpoint sees them:
        # (1) rules a prior run persisted to scan.db — honored even without a
        # re-passed --exclude (previously they silently vanished and excluded
        # targets re-entered scope), then (2) any newly passed --exclude.
        ledger.seed_persisted_exclusions()
        if exclusion_file:
            ledger.seed_exclusions(exclusion_file)
        ledger.load_from_disk()
        logger.info("Continue mode: loaded existing ledger from disk")

        new_target = kwargs.get('target')
        new_domains = kwargs.get('domainlist')
        new_urls = kwargs.get('user_url_file')
        if new_target or new_domains or new_urls:
            ledger.seed_user_inputs(new_target, new_domains, new_urls)
            logger.info("Continue mode: seeded additional user inputs into ledger")
            print("[*] Additional inputs seeded into existing target ledger")

    elif resume_from == 0:
        ledger.seed_user_inputs(
            kwargs.get('target'),
            kwargs.get('domainlist'),
            kwargs.get('user_url_file'),
        )
        if exclusion_file:
            ledger.seed_exclusions(exclusion_file)
    else:
        # Resume: same as continue — exclusions (persisted + any new) before the
        # fixpoint, so a resume without --exclude can't re-admit excluded targets.
        ledger.seed_persisted_exclusions()
        if exclusion_file:
            ledger.seed_exclusions(exclusion_file)
        ledger.load_from_disk()
        tracker.scan_resumed(resume_from)
        logger.info(f"Resuming from step index {resume_from}, ledger rebuilt from disk")

    # Prior ledger state is now loaded; flag the run in-progress so a mid-run
    # SIGKILL leaves scan.db 'dirty' and the next resume re-resolves scope
    # rather than trusting write-time in_scope flags. Cleared in the finally.
    ledger.mark_run_started()

    # Authorization boundary check: --ip-scope strict only enforces an IP
    # boundary when the run has explicit IP ranges (from -t). In a domain-only
    # run there is no boundary, so strict silently degrades to provenance and
    # ANY IP a discovered name resolves to (CDN, SaaS, third-party) becomes a
    # live scan target. Warn loudly so the operator doesn't trust a control
    # that isn't active. (Authorization can't be inferred from DNS/WHOIS — a
    # customer's own cloud VMs share their provider's org/ASN — so the tool
    # surfaces the ambiguity rather than guessing.)
    if ip_scope in ("strict", "strict-resolved") and ledger is not NO_OP_LEDGER \
            and not ledger._authorized_ip_networks():
        msg = (f"--ip-scope {ip_scope} has NO authorized IP ranges to enforce (no IP/CIDR "
               "targets via -t). Derived IPs will be scanned by provenance — including "
               "any third-party/CDN/SaaS IP a discovered name resolves to. To bound "
               "active IP scanning, pass the customer's in-scope ranges via -t (that is "
               "the authorization boundary), and/or list third parties in --exclude.")
        logger.warning(msg)
        print(f"\n[!] {msg}\n")

    # Start-of-run scope echo: show the operator what will be host-scanned vs
    # tested name-safe, so scope intent is confirmable before a fleet spins up.
    if ledger is not NO_OP_LEDGER:
        echo = format_scope_echo(ledger)
        if echo:
            print(f"\n{echo}\n")
            logger.info("Scope: %s", ledger.scope_summary())

    results = []
    step_index = 0
    fleet_killed_early = False
    last_fleet_idx = _last_fleet_step_index(steps)
    background_futures: dict[str, concurrent.futures.Future] = {}
    background_executor = concurrent.futures.ThreadPoolExecutor(max_workers=4)
    # Guards shared mutable state (`results`, `fleet_killed_early`) against
    # concurrent access from background-module threads and the main loop.
    _state_lock = threading.Lock()

    # Offset step numbering in continue mode to avoid overwriting prior snapshots
    step_offset = 0
    if continue_mode and data_dir:
        step_offset = _get_max_snapshot_index(data_dir)

    def _kill_fleet_early():
        """Kill the fleet once all fleet-requiring steps are done, so it doesn't
        idle (billing) through the trailing LOCAL steps (normalize/analyze/
        ai_analyze/ai_validate — minutes of AI round-trips on `deep`)."""
        nonlocal fleet_killed_early
        # Atomic check-and-set so a background thread and the main loop can't
        # both pass the guard and issue kill_fleet() twice.
        with _state_lock:
            # Gated on keep_fleet only — NOT on `cleanup`. Every CLI entry point
            # calls run_modules(cleanup=False) (the CLI does the final teardown),
            # so gating on `cleanup` disabled early-kill entirely and left the
            # fleet up for the whole local tail. The later CLI/`cleanup` teardown
            # is an idempotent, verified no-op once this has already killed it.
            if fleet_killed_early or keep_fleet:
                return
            fleet_name = kwargs.get('fleet', '')
            if not fleet_name or fleet_name == 'local':
                return
            fleet_killed_early = True
        logger.info("All fleet modules complete — killing fleet early")
        print(f"\n[*] All fleet modules complete — killing fleet '{fleet_name}' early")
        account = getattr(scaler, 'account', None) if scaler else None
        try:
            from core.fleet import iauth as _iauth
            _iauth(account)                       # refresh session before kill
            if not kill_fleet(fleet_name, account=account):
                # Couldn't confirm removal — re-arm so the final teardown retries
                # and surfaces the orphan rather than silently skipping it.
                with _state_lock:
                    fleet_killed_early = False
                logger.warning("Early fleet kill of '%s' unconfirmed — deferring to "
                               "final teardown", fleet_name)
        except Exception as e:
            logger.error(f"Early fleet kill failed: {e}", exc_info=True)
            print(f"[!] Error killing fleet: {e}")
            with _state_lock:
                fleet_killed_early = False

    def _run_background_module(step, step_idx):
        """Run a background module (e.g. nessus) in a thread."""
        started = tracker.step_started(step.name)
        # Collect into a private list so the concurrently-running main loop
        # never observes a half-written `results`, then merge under the lock.
        local_results: list = []
        try:
            result = _run_sequential_step(step, kwargs, local_results,
                                          step_index=step_idx,
                                          ledger=ledger, scope_filter=scope_filter,
                                          data_dir=data_dir, dry_run=dry_run)
            with _state_lock:
                results.extend(local_results)
            tracker.step_completed(step.name, started, result or {})
        except Exception as e:
            tracker.step_failed(step.name, started, str(e))
            logger.error("Background step '%s' failed: %s", step.name, e)
            print(f"\n[!] Background step '{step.name}' failed: {e}")
            with _state_lock:
                results.extend(local_results)
                results.append({'module': step.name, 'status': 'failed', 'error': str(e)})

    def _write_checkpoint_and_exit(at_index: int, cancelled_step: str = None) -> None:
        """Write checkpoint and exit with paused code."""
        if not checkpoint:
            return
        logger.info("Writing checkpoint at step_index=%d", at_index)
        print(f"\n[!] Writing checkpoint (will resume from step {at_index + 1})...")
        if cancelled_step:
            tracker.scan_cancelled(cancelled_step, at_index)
        else:
            tracker.scan_paused(at_index)
        checkpoint.write(
            next_step_index=at_index,
            total_steps=total,
            workflow=workflow_name,
            modules=all_module_names,
            kwargs=kwargs,
            fleet_killed=not keep_fleet,
            steps=steps,
        )
        checkpoint.clear_pause_request()
        sys.exit(EXIT_CODE_PAUSED)

    # Console heartbeat: prints a one-line run status every 15s (always on).
    # First line only after 15s, so fast runs / tests stay silent. Stopped in
    # the finally below on every exit path (completion, pause, exception).
    heartbeat = HeartbeatPrinter(tracker) if output_dir else None
    if heartbeat:
        heartbeat.start()

    try:
        for step in steps:
            if isinstance(step, WaitStep):
                future = background_futures.get(step.name)
                if future and not future.done():
                    print(f"\n[*] Waiting for background module '{step.name}' to complete...")
                    future.result()
                    print(f"[+] Background module '{step.name}' finished")
                elif not future:
                    logger.warning("wait: '%s' — no background module with that name was launched", step.name)
                continue

            # Count steps in this item for skip logic
            step_count = len(step.steps) if isinstance(step, ParallelGroup) else 1

            if step_index + step_count <= resume_from:
                step_index += step_count
                continue

            if isinstance(step, ModuleStep) and step.name in _BACKGROUND_MODULES:
                print(f"\n[*] Launching '{step.name}' in background — continuing pipeline...")
                future = background_executor.submit(_run_background_module, step, step_index + step_offset)
                background_futures[step.name] = future
                step_index += 1

                if step_index > last_fleet_idx and last_fleet_idx >= 0:
                    _kill_fleet_early()
                continue

            if isinstance(step, ModuleStep):
                # Auto-scale check before fleet-requiring steps. Size by the
                # workload the step actually drives: URL count for URL-scanning
                # modules, IP count otherwise (see FleetScaler.check_and_scale).
                if scaler and step.name not in _NO_FLEET_MODULES and not dry_run:
                    ip_count = count_ip_workload(ledger._all_ips) if hasattr(ledger, '_all_ips') else 0
                    url_count = len(ledger._all_urls) if hasattr(ledger, '_all_urls') else 0
                    has_url = _module_consumes_urls(step.name)
                    if scaler.check_and_scale(ip_count, url_count, has_url):
                        kwargs['fleet'] = scaler.fleet

                started = tracker.step_started(step.name)
                try:
                    # Use the returned result rather than results[-1]: a
                    # background module may append concurrently, so the tail of
                    # the shared list is not guaranteed to be this step's result.
                    last_result = _run_sequential_step(step, kwargs, results,
                                                       step_index=step_index + step_offset,
                                                       ledger=ledger, scope_filter=scope_filter,
                                                       data_dir=data_dir, dry_run=dry_run) or {}
                    if isinstance(last_result, dict) and last_result.get('status') == 'failed':
                        tracker.step_failed(step.name, started,
                                            last_result.get('error', 'module returned failed'))
                    else:
                        tracker.step_completed(step.name, started, last_result)
                except KeyboardInterrupt:
                    # Mid-step cancel (default): checkpoint at THIS step so resume re-runs it
                    tracker.step_failed(step.name, started, "Cancelled by user")
                    logger.warning("Step '%s' cancelled mid-execution", step.name)
                    print(f"\n[!] Step '{step.name}' cancelled.")
                    _write_checkpoint_and_exit(step_index, cancelled_step=step.name)
                    raise
                except Exception as e:
                    tracker.step_failed(step.name, started, str(e))
                    logger.error("Step '%s' failed: %s", step.name, e)
                    print(f"\n[!] Step '{step.name}' failed: {e}")
                    print(f"[*] Continuing to next step...")
                    results.append({'module': step.name, 'status': 'failed', 'error': str(e)})
                step_index += 1
            elif isinstance(step, ParallelGroup):
                # Auto-scale check before parallel groups (if any member requires
                # fleet). URL count drives sizing when any member scans URLs.
                if scaler and not dry_run:
                    has_fleet_step = any(s.name not in _NO_FLEET_MODULES for s in step.steps)
                    if has_fleet_step:
                        ip_count = count_ip_workload(ledger._all_ips) if hasattr(ledger, '_all_ips') else 0
                        url_count = len(ledger._all_urls) if hasattr(ledger, '_all_urls') else 0
                        has_url = any(_module_consumes_urls(s.name) for s in step.steps)
                        if scaler.check_and_scale(ip_count, url_count, has_url):
                            kwargs['fleet'] = scaler.fleet

                try:
                    _run_parallel_group(step, kwargs, results,
                                        step_index=step_index + step_offset, tracker=tracker,
                                        ledger=ledger, scope_filter=scope_filter,
                                        data_dir=data_dir, dry_run=dry_run)
                except KeyboardInterrupt:
                    # Mid-group cancel: checkpoint at this group so resume re-runs all of it
                    module_names = [s.name for s in step.steps]
                    group_label = ", ".join(module_names)
                    logger.warning("Parallel group cancelled mid-execution")
                    print(f"\n[!] Parallel group cancelled.")
                    _write_checkpoint_and_exit(step_index, cancelled_step=f"parallel[{group_label}]")
                    raise
                except Exception as e:
                    module_names = [s.name for s in step.steps]
                    logger.error("Parallel group [%s] failed: %s", ', '.join(module_names), e)
                    print(f"\n[!] Parallel group [{', '.join(module_names)}] failed: {e}")
                    print(f"[*] Continuing to next step...")
                    # Record a failed result so the group failure reaches the exit
                    # code / summary instead of being swallowed as a clean run.
                    results.append({'module': f"parallel[{','.join(module_names)}]",
                                    'status': 'failed', 'error': str(e)})
                step_index += step_count

            # Kill fleet early if we just finished the last fleet-requiring step
            if step_index > last_fleet_idx and last_fleet_idx >= 0:
                _kill_fleet_early()

            # Graceful pause: sentinel file check (--finish-step mode)
            if finish_step and checkpoint and checkpoint.is_pause_requested():
                _write_checkpoint_and_exit(step_index)

        # Wait for background modules to finish
        if background_futures:
            pending = [name for name, f in background_futures.items() if not f.done()]
            if pending:
                print(f"\n[*] Waiting for background module(s) to complete: {', '.join(pending)}")
            for future in concurrent.futures.as_completed(background_futures.values()):
                try:
                    future.result()
                except Exception as e:
                    logger.error("Background module error: %s", e)

        # Successful completion — remove any stale checkpoint
        if checkpoint:
            checkpoint.delete()

    finally:
        # Stop the console heartbeat first so it never prints after completion.
        if heartbeat:
            heartbeat.stop()
        # Cancel any background futures that never started, then detach without
        # blocking (a stuck background module must not hang cleanup / Ctrl+C).
        # Normal completion already drained them via as_completed above.
        for _f in background_futures.values():
            if not _f.done():
                _f.cancel()
        background_executor.shutdown(wait=False)
        # Account for re-auth before any teardown kill — a long run can outlive
        # the cloud session, and an unauthenticated `ax rm` silently orphans
        # (billing) instances. iauth() falls back to AXIOM_ACCOUNT/config.
        _ax_account = getattr(scaler, 'account', None) if scaler else None
        orphaned_fleets: list[str] = []
        if scaler:
            orphaned_fleets.extend(scaler.cleanup(keep_current=keep_fleet) or [])
        if cleanup and 'fleet' in kwargs and not fleet_killed_early:
            fleet_name = kwargs['fleet']
            logger.info(f"Cleaning up: Killing Axiom fleet '{fleet_name}'")
            print(f"\n{'='*60}")
            print(f"Cleaning up: Killing Axiom fleet '{fleet_name}'")
            print(f"{'='*60}")
            try:
                from core.fleet import iauth as _iauth
                _iauth(_ax_account)          # refresh a possibly-expired session
                if kill_fleet(fleet_name, account=_ax_account):
                    logger.info(f"Fleet '{fleet_name}' cleanup complete")
                else:
                    orphaned_fleets.append(fleet_name)
            except Exception as e:
                logger.error(f"Error killing fleet '{fleet_name}': {e}", exc_info=True)
                print(f"[!] Error killing fleet '{fleet_name}': {e}")
                print(f"[!] You may need to manually kill the fleet with: ax rm \"{fleet_name}*\" -f")
                orphaned_fleets.append(fleet_name)
        if orphaned_fleets:
            uniq = sorted(set(orphaned_fleets))
            logger.error("Teardown left %d fleet(s) UNCONFIRMED: %s", len(uniq), uniq)
            print(f"\n{'!'*60}")
            print(f"[!] WARNING: could not confirm teardown of {len(uniq)} fleet(s): "
                  f"{', '.join(uniq)}")
            print(f"[!] These may still be running and BILLING. Re-auth (ax account) "
                  f"and run: " + " ; ".join(f"ax rm '{f}*' -f" for f in uniq))
            print(f"{'!'*60}\n")

        # Finalize scan.db on EVERY exit path (normal, exception, and the
        # sys.exit pause/cancel below runs this finally too). sync_scope_to_db
        # persists the fixpoint-resolved in_scope flags; close() checkpoints the
        # WAL into scan.db so the archived file is self-contained.
        try:
            ledger.sync_scope_to_db()
            # Flags are now fixpoint-resolved and persisted; mark the run clean
            # so a later load_from_db() can trust them without re-resolving.
            ledger.mark_clean_shutdown()
        except Exception as e:  # pragma: no cover - defensive, never block cleanup
            logger.debug("ledger.sync_scope_to_db failed: %s", e)
        ledger.close()
        tracker.close()

    # Recon summary: if discovered names resolved to public IPs spread across
    # many networks, that's a signal of CDN/SaaS/third-party sprawl (not a small
    # set of customer hosts). Surface it so the operator can decide what's
    # actually in scope — the tool can't infer authorization from DNS/WHOIS.
    if ledger is not NO_OP_LEDGER:
        try:
            summ = ledger.derived_ip_network_summary()
            if summ["network_count"] >= 3:
                logger.info("Recon: %d derived IPs across %d /16 networks",
                            summ["ip_count"], summ["network_count"])
                print(f"\n[i] Recon: {summ['ip_count']} discovered IPs span "
                      f"{summ['network_count']} distinct /16 networks — likely "
                      f"CDN/SaaS/third-party infrastructure, not all customer-owned.")
                if not ledger._authorized_ip_networks():
                    print("    Confirm which IPs are in scope; pass in-scope ranges via -t "
                          "and/or third parties via --exclude before active IP scanning.")
        except Exception as e:
            logger.debug("derived_ip_network_summary failed: %s", e)

    logger.info("Module execution complete")
    return results
