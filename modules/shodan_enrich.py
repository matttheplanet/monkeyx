"""Shodan (and pluggable enrichment-provider) attack-surface enrichment.

Queries Shodan's *existing* database (read-only — never triggers an active
Shodan scan, so no scan credits are spent) to enrich the engagement:

  * Host lookups (``/shodan/host/{ip}``) for every in-scope IP — ports/banners
    and, crucially, the CVEs Shodan has already associated with the host. These
    do NOT consume query credits on paid plans, so they run by default.
  * Optional pivot searches (``/shodan/host/search``) using org / net / favicon
    hash / TLS cert filters to surface related or origin infrastructure. These
    DO consume query credits, so they are OFF by default (``searches: false``)
    and bounded by ``max_query_credits``.

Shodan ``vulns`` are version/CPE-inferred (banner -> CVE-DB match): they ignore
distro backports and tag every CVE ever associated with a version, so most are
false positives. To avoid flooding findings, only Shodan-``verified`` CVEs become
findings by default; the rest are surfaced as host_info context. Tune with the
``shodan_cve_findings`` option: ``verified`` (default) | ``all`` | ``none``.

Outputs ``{prefix}-shodan.jsonl`` — normalize-shaped records:
  * ``type: "vulnerability"`` (Shodan CVEs per ``shodan_cve_findings``) -> findings/scan.db
  * ``type: "host_info"`` (ports/banners + ``possible_cves`` context)   -> ai_analyze context
  * discovered IPs are also written to ``{prefix}-shodan-hosts.txt`` which the
    engine logs to the ledger as *derived* targets (scope filtering still
    decides whether they get scanned — authorization comes from ``-t``, never
    from Shodan org/ASN data; see monkeyx/CLAUDE.md scope model).

Config (``monkeyx.config`` ``modules.shodan_enrich`` or workflow step ``args``):
  searches            bool   run credit-spending pivot searches (default False)
  search_org          bool   org:"..." searches from domain apexes (default True when searches on)
  search_favicon      bool   http.favicon.hash pivots (default True when searches on)
  search_cert         bool   ssl.cert.subject.cn pivots (default True when searches on)
  history             bool   per-host ?history=true (default False)
  max_query_credits   int    hard cap on Search-API credits this run (default 50)
  shodan_cve_findings str    which Shodan CVEs become findings:
                             verified (default) | all | none
  providers           list   enrichment providers to use (default ["shodan"])

Inputs:  none required; no fleet. Uses ledger domains plus the ledger's
    scope/ip_scope-authorized bare-IP export (``target_ips_file`` →
    ``ledger-target-ips.txt``), so host lookups work on domain-only runs where
    the plain target file is hostname-collapsed. Falls back to any literal IPs
    in the target file.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import urllib.error
import urllib.parse
import urllib.request

from core.credentials import get_enrichment_config, get_enrichment_key

logger = logging.getLogger("monkeyx.modules.shodan_enrich")

REQUIRED_INPUTS = frozenset()

_SHODAN_API = "https://api.shodan.io"
_HTTP_TIMEOUT = 20


# --------------------------------------------------------------------------- #
# HTTP (injectable for tests — tests pass a fake _fetch via kwargs)
# --------------------------------------------------------------------------- #

def _default_fetch(url: str) -> dict | None:
    """GET a Shodan JSON endpoint. Returns parsed dict or None on any error.

    Read-only. Never raises — Shodan hiccups must not fail the run.
    """
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as resp:  # noqa: S310 - https only, host pinned below
            if resp.status != 200:
                return None
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as exc:
        # 401/403 = the API key is missing, invalid, or revoked. Surface it
        # loudly: otherwise every lookup silently 401s to None and the run looks
        # like "nothing in Shodan" rather than "bad key". 404 = no data for that
        # host (normal) — stays debug.
        if exc.code in (401, 403):
            logger.warning("shodan: API key rejected (HTTP %s) for %s — set a "
                           "valid enrichment.shodan.api_key / MONKEYX_SHODAN_API_KEY",
                           exc.code, url.split("?")[0])
        else:
            logger.debug("shodan fetch HTTP %s for %s", exc.code, url.split("?")[0])
        return None
    except Exception as exc:  # noqa: BLE001
        logger.debug("shodan fetch failed for %s: %s", url.split("?")[0], exc)
        return None


def _api_url(path: str, params: dict) -> str:
    return f"{_SHODAN_API}{path}?{urllib.parse.urlencode(params)}"


# --------------------------------------------------------------------------- #
# Input loading (scope-safe: only what the ledger already exported)
# --------------------------------------------------------------------------- #

def _load_lines(path: str | None) -> list[str]:
    if not path or not os.path.exists(path):
        return []
    out = []
    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                v = line.strip()
                if v and not v.startswith("#"):
                    out.append(v)
    except OSError:
        pass
    return out


def _split_ips(values: list[str]) -> list[str]:
    """Keep bare, public, non-CIDR IPs — host lookups take single addresses."""
    ips = []
    for v in values:
        if "/" in v:  # CIDR — skip (host lookup is per-IP; searches handle ranges)
            continue
        try:
            ip = ipaddress.ip_address(v)
        except ValueError:
            continue
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            continue
        ips.append(str(ip))
    return ips


def _load_target_ips(path: str | None) -> dict[str, str | None]:
    """Parse the ledger's bare-IP export into {ip: resolved_from_hostname|None}.

    Format is `ip` or `ip\thost1,host2` (see TargetLedger.export_target_ips) —
    already scope- and ip_scope-authorized, so these are exactly the IPs the
    scanners were allowed to hit. Only the first hostname is kept as provenance
    for record stamping. Non-IP/private lines are dropped by _split_ips.
    """
    out: dict[str, str | None] = {}
    for line in _load_lines(path):
        parts = line.split("\t", 1)
        addr = parts[0].strip()
        if not _split_ips([addr]):  # reuse the public/bare-IP validation
            continue
        hostname = None
        if len(parts) == 2 and parts[1].strip():
            hostname = parts[1].split(",")[0].strip() or None
        out[addr] = hostname
    return out


def _apex_domains(domains: list[str]) -> list[str]:
    """Reduce a domain/subdomain list to unique registrable-ish apexes."""
    apexes = set()
    for d in domains:
        d = d.strip().rstrip(".").lower()
        parts = d.split(".")
        if len(parts) >= 2:
            apexes.add(".".join(parts[-2:]))
    return sorted(apexes)


# --------------------------------------------------------------------------- #
# Record shaping
# --------------------------------------------------------------------------- #

def _finding_records_from_host(host_obj: dict, ip: str, source: str,
                               resolved_from: str | None = None,
                               cve_mode: str = "verified") -> list[dict]:
    """Turn a Shodan host object into normalize-shaped records.

    Emits one host_info record (context for ai_analyze) plus, depending on
    ``cve_mode``, findings for Shodan-tagged CVEs. Shodan ``vulns`` are
    version/CPE-inferred and mostly false positives, so:
      * ``verified`` (default): only CVEs Shodan marks ``verified`` become
        ``vulnerability`` findings; the rest are folded into host_info's
        ``possible_cves`` (context, not high-severity findings).
      * ``all``: every Shodan CVE becomes a finding (raw dump).
      * ``none``: no CVE findings; unverified/verified all listed as
        ``possible_cves`` context only.

    ``resolved_from`` is the in-scope ledger hostname this IP was resolved from
    (when the IP came via a name rather than a literal ``-t`` entry). It is
    stamped on every record so a reviewer can tell an origin from a shared CDN
    edge at triage time — a shared IP's Shodan data describes the edge/other
    tenants, not necessarily the authorized asset.
    """
    records: list[dict] = []
    hostnames = host_obj.get("hostnames") or []
    hostname = hostnames[0] if hostnames else resolved_from
    ports = host_obj.get("ports") or []
    org = host_obj.get("org") or ""

    vulns = host_obj.get("vulns")
    # vulns may be a list (older) or dict keyed by CVE (newer, with metadata).
    cve_iter: list[str] = []
    if isinstance(vulns, dict):
        cve_iter = list(vulns.keys())
    elif isinstance(vulns, list):
        cve_iter = [str(v) for v in vulns]

    def _meta_for(cve: str):
        if not isinstance(vulns, dict):
            return None
        return vulns.get(cve.lower()) or vulns.get(cve) or vulns.get(cve.upper())

    finding_cves: list[str] = []          # CVEs that become findings this run
    context_cves: list[str] = []          # CVEs surfaced as host_info context
    for raw_cve in cve_iter:
        cve = str(raw_cve).upper()
        meta = _meta_for(str(raw_cve))
        verified = bool(meta.get("verified")) if isinstance(meta, dict) else False
        emit = (cve_mode == "all") or (cve_mode == "verified" and verified)
        (finding_cves if emit else context_cves).append(cve)

    host_detail = f"ports={sorted(ports)} org={org} os={host_obj.get('os') or ''}"
    if context_cves:
        # Version-inferred CVEs Shodan associates with the banner — kept as
        # context (not findings) so a reviewer/ai_analyze sees them without the
        # false-positive flood. Deduped, stable order.
        host_detail += f" possible_cves={sorted(set(context_cves))}"
    host_rec = {
        "host": ip,
        "hostname": hostname,
        "resolved_from": resolved_from,
        "port": None,
        "proto": None,
        "tool": "shodan",
        "type": "host_info",
        "severity": "info",
        "title": f"[shodan_host] {ip} — {len(ports)} port(s)"
                 + (f", org={org}" if org else "")
                 + (f" (via {resolved_from})" if resolved_from else ""),
        "detail": host_detail,
        "shodan_claim": "host_info",
        "shodan_source": source,
        "source_file": "shodan",
    }
    if context_cves:
        host_rec["possible_cves"] = sorted(set(context_cves))
    records.append(host_rec)

    for cve in finding_cves:
        meta = _meta_for(cve)
        verified = bool(meta.get("verified")) if isinstance(meta, dict) else False
        cvss = meta.get("cvss") if isinstance(meta, dict) else None
        # Severity from CVSS when present, else default high.
        sev = "high"
        try:
            if cvss is not None and float(cvss) >= 9.0:
                sev = "critical"
            elif cvss is not None and float(cvss) < 4.0:
                sev = "medium"
        except (TypeError, ValueError):
            pass
        records.append({
            "host": ip,
            "hostname": hostname,
            "resolved_from": resolved_from,
            "port": None,
            "proto": None,
            "tool": "shodan",
            "type": "vulnerability",
            "severity": sev,
            "title": f"[{cve}] Shodan-reported vulnerability on {ip}"
                     + (" (verified)" if verified else ""),
            "detail": (meta.get("summary") if isinstance(meta, dict) and meta.get("summary")
                       else f"Shodan associates {cve} with {ip}"),
            "cve_id": cve,
            "shodan_claim": cve,
            "shodan_source": source,
            "source_file": "shodan",
        })
    return records


# --------------------------------------------------------------------------- #
# Caching (JSON file in the data dir — avoids re-billing credits on re-runs)
# --------------------------------------------------------------------------- #

def _load_cache(cache_path: str) -> dict:
    if os.path.exists(cache_path):
        try:
            with open(cache_path, encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, json.JSONDecodeError):
            pass
    return {"hosts": {}, "searches": {}}


def _save_cache(cache_path: str, cache: dict) -> None:
    try:
        with open(cache_path, "w", encoding="utf-8") as fh:
            json.dump(cache, fh)
    except OSError as exc:
        logger.warning("shodan cache write failed: %s", exc)


# --------------------------------------------------------------------------- #
# Provider seam — shodan implemented; others no-op cleanly when absent
# --------------------------------------------------------------------------- #

def _provider_available(name: str) -> bool:
    if name == "shodan":
        return bool(get_enrichment_key("shodan"))
    if name == "censys":
        cfg = get_enrichment_config("censys")
        return bool(cfg.get("api_id") and cfg.get("api_secret"))
    if name == "greynoise":
        return bool(get_enrichment_key("greynoise"))
    return False


def _bool_arg(kwargs: dict, key: str, default: bool) -> bool:
    v = kwargs.get(key, default)
    if isinstance(v, str):
        return v.strip().lower() not in ("false", "0", "no", "off", "")
    return bool(v)


def run_shodan_enrich(prefix=None, target=None, domainlist=None, **kwargs) -> dict:
    prefix = kwargs.get("data_prefix", prefix)
    fetch = kwargs.get("_fetch", _default_fetch)  # test seam

    providers = kwargs.get("providers") or ["shodan"]
    if isinstance(providers, str):
        providers = [p.strip() for p in providers.split(",") if p.strip()]

    do_searches = _bool_arg(kwargs, "searches", False)
    # Which Shodan-tagged CVEs become findings. Shodan `vulns` are version/CPE-
    # inferred (banner -> CVE-DB match), so they ignore distro backports and tag
    # every CVE ever associated with a version — mostly false positives. Default
    # 'verified' keeps only Shodan-confirmed CVEs as findings; the rest surface
    # as host_info context (possible_cves) instead of a HIGH-severity flood.
    cve_mode = str(kwargs.get("shodan_cve_findings", "verified")).strip().lower()
    if cve_mode not in ("verified", "all", "none"):
        cve_mode = "verified"
    search_org = _bool_arg(kwargs, "search_org", True)
    search_favicon = _bool_arg(kwargs, "search_favicon", True)
    search_cert = _bool_arg(kwargs, "search_cert", True)
    want_history = _bool_arg(kwargs, "history", False)
    try:
        max_credits = int(kwargs.get("max_query_credits", 50))
    except (TypeError, ValueError):
        max_credits = 50

    if "shodan" not in providers or not _provider_available("shodan"):
        # Note any requested-but-unavailable providers honestly, then skip.
        missing = [p for p in providers if not _provider_available(p)]
        msg = ("shodan_enrich: no usable enrichment provider "
               f"(requested={providers}, missing_keys={missing}). "
               "Set enrichment.shodan.api_key in ~/.monkeyx/credentials.yaml "
               "or MONKEYX_SHODAN_API_KEY.")
        print(f"[*] {msg}")
        return {"module": "shodan_enrich", "status": "skipped",
                "output_files": [], "warning": msg}

    other = [p for p in providers if p != "shodan"]
    for p in other:
        if _provider_available(p):
            logger.info("shodan_enrich: provider '%s' has a key but no client "
                        "is implemented yet — skipping (seam reserved).", p)
        else:
            logger.debug("shodan_enrich: provider '%s' skipped (no key).", p)

    key = get_enrichment_key("shodan")
    # Bare IPs the ledger already resolved from in-scope hostnames (with
    # provenance), plus any literal IPs in the target file. The target file is
    # hostname-collapsed for the scanners, so on domain-only runs it carries no
    # IPs — target_ips_file (ledger-target-ips.txt) is what makes host lookups
    # possible there. Both files are already scope/ip_scope-authorized.
    ip_hosts: dict[str, str | None] = _load_target_ips(kwargs.get("target_ips_file"))
    for ip in _split_ips(_load_lines(target)):
        ip_hosts.setdefault(ip, None)
    ips = sorted(ip_hosts)
    apexes = _apex_domains(_load_lines(domainlist))

    if not ips and not apexes:
        msg = "shodan_enrich: no in-scope IPs or domains to enrich"
        print(f"[*] {msg}")
        return {"module": "shodan_enrich", "status": "skipped",
                "output_files": [], "warning": msg}

    cache_path = f"{prefix}-shodan-cache.json"
    cache = _load_cache(cache_path)

    records: list[dict] = []
    discovered_ips: set[str] = set()
    credits_used = 0
    searches_skipped = 0
    hosts_looked_up = 0

    # --- host lookups (free, always) --------------------------------------- #
    for ip in ips:
        params = {"key": key}
        if want_history:
            params["history"] = "true"
        cache_key = f"{ip}|hist={want_history}"
        obj = cache["hosts"].get(cache_key)
        if obj is None:
            obj = fetch(_api_url(f"/shodan/host/{ip}", params))
            if obj is not None:
                cache["hosts"][cache_key] = obj
        if not obj:
            continue
        hosts_looked_up += 1
        records.extend(_finding_records_from_host(obj, ip, source="host_lookup",
                                                  resolved_from=ip_hosts.get(ip),
                                                  cve_mode=cve_mode))

    # --- pivot searches (opt-in, credit-bounded) --------------------------- #
    def _run_search(query: str, label: str) -> None:
        nonlocal credits_used, searches_skipped
        if credits_used >= max_credits:
            searches_skipped += 1
            return
        cached = cache["searches"].get(query)
        if cached is None:
            res = fetch(_api_url("/shodan/host/search",
                                 {"key": key, "query": query}))
            if res is None:
                return
            cache["searches"][query] = res
            credits_used += 1  # a filtered search page costs ~1 query credit
        else:
            res = cached
        for match in (res.get("matches") or []):
            ip = match.get("ip_str") or ""
            if ip:
                discovered_ips.add(ip)
            recs = _finding_records_from_host(match, ip or "unknown",
                                              source=f"search:{label}",
                                              cve_mode=cve_mode)
            records.extend(recs)

    if do_searches:
        for apex in apexes:
            if search_org:
                _run_search(f'hostname:"{apex}"', f"hostname:{apex}")
                _run_search(f'org:"{apex}"', f"org:{apex}")
            if search_cert:
                _run_search(f'ssl.cert.subject.CN:"{apex}"', f"cert:{apex}")
        # favicon pivots require a hash we don't compute here; reserved for a
        # future httpx-favicon-hash handoff. Logged so coverage is honest.
        if search_favicon:
            logger.info("shodan_enrich: favicon pivot needs a favicon hash "
                        "source (httpx) — not run this pass.")
    else:
        logger.info("shodan_enrich: pivot searches disabled (searches=false) — "
                    "host lookups only, zero query credits spent.")

    _save_cache(cache_path, cache)

    # --- write outputs ----------------------------------------------------- #
    out_jsonl = f"{prefix}-shodan.jsonl"
    try:
        with open(out_jsonl, "w", encoding="utf-8") as fh:
            for rec in records:
                fh.write(json.dumps(rec) + "\n")
    except OSError as exc:
        return {"module": "shodan_enrich", "status": "failed",
                "output_files": [], "error": str(exc)}

    output_files = [out_jsonl]
    hosts_file = f"{prefix}-shodan-hosts.txt"
    # Only new IPs (not already in the target file) are worth logging as derived.
    new_ips = sorted(discovered_ips - set(ips))
    if new_ips:
        try:
            with open(hosts_file, "w", encoding="utf-8") as fh:
                fh.write("\n".join(new_ips) + "\n")
            output_files.append(hosts_file)
        except OSError:
            hosts_file = None
    else:
        hosts_file = None

    findings = sum(1 for r in records if r.get("type") in ("finding", "vulnerability"))
    print(f"[+] shodan_enrich: {hosts_looked_up} hosts looked up, "
          f"{findings} finding(s), {len(new_ips)} new IP(s); "
          f"{credits_used} query credit(s) used"
          + (f", {searches_skipped} search(es) skipped (budget)" if searches_skipped else ""))

    # Honesty: an EMPTY result is not a clean success. _provider_available only
    # checks that a key EXISTS, so a present-but-invalid/placeholder key passes
    # the skip above and every lookup silently 401s to None — producing zero
    # records that look identical to "genuinely nothing in Shodan". Either way the
    # enrichment contributed nothing, so report `warning` (matching the engine's
    # "empty output -> warning" convention) rather than a green success. A run
    # that looked anything up OR surfaced a new IP is a real success.
    result = {
        "module": "shodan_enrich",
        "status": "success",
        "output_files": output_files,
        "findings": findings,
        "credits_used": credits_used,
        "searches_skipped": searches_skipped,
        "hosts_looked_up": hosts_looked_up,
    }
    if not records and not new_ips:
        result["status"] = "warning"
        result["warning"] = (
            "shodan_enrich produced no records — either no in-scope asset is in "
            "Shodan, or the API key was rejected (a present-but-invalid key looks "
            "exactly like empty results; check enrichment.shodan.api_key / "
            "MONKEYX_SHODAN_API_KEY and the log for HTTP 401/403).")
    if hosts_file:
        result["discovered_hosts_file"] = hosts_file
    return result
