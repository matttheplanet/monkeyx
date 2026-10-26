"""DNS security audit — SPF, DMARC, zone transfer, NS health, open recursion,
private-address leaks.

Two-phase approach:
  Phase 1: Parse existing dnsx JSONL for TXT/MX/NS/A/AAAA records (no network calls)
  Phase 2: Targeted dig queries for _dmarc records, AXFR attempts, NS resolution,
           and open-recursion probes against in-scope nameservers

Also flags RFC1918/ULA addresses published in public DNS answers (internal
topology leak) from the passive dnsx data.

Scope: audits the operator's EXPLICIT -d root domains (passed as
`root_domains_file` by the orchestrator), never registrable apexes collapsed
from discovered subdomains — that previously pulled in third-party providers
(e.g. amazonaws.com) and produced false positives. Also checks in-scope
subdomains that have MX records for SPF/DMARC — if it sends mail, it needs email
authentication regardless of being a subdomain.

Email-auth posture follows internet.nl guidance: SPF ~all (softfail) and -all
both pass (only +all/?all are flagged), and DMARC honors RFC 7489
organizational-domain inheritance — a subdomain with no _dmarc record inherits
the org domain's sp=/p=, so it isn't flagged "missing" when the org policy
already enforces (quarantine/reject). The organizational domain is the
registrable domain per the Public Suffix List (tldextract) — e.g.
`a.b.example.co.uk` -> `example.co.uk` — matching how a receiver resolves it,
not just the immediate parent; falls back to the in-scope apex if tldextract is
unavailable.

Inputs:  domainlist (fallback), root_domains_file (preferred scope)
Outputs: {prefix}-dns-security.jsonl
"""

import ipaddress
import json
import logging
import os
import re
import subprocess

from core.utils import version_output_path

logger = logging.getLogger('monkeyx.modules.dns_security')

REQUIRED_INPUTS = frozenset()

# Public Suffix List support for RFC 7489 organizational-domain resolution.
# Instantiated to use ONLY the snapshot bundled with the package (no network
# fetch at scan time) — deterministic/offline, fine for registrable-domain
# computation. If tldextract isn't installed we degrade to the in-scope apex.
try:
    import tldextract as _tldextract
    _TLD_EXTRACT = _tldextract.TLDExtract(suffix_list_urls=())
except Exception:  # pragma: no cover - optional dep; fallback keeps the module working
    _TLD_EXTRACT = None


def _load_apex_domains(domainlist):
    """Load domains from file, filtering to likely apex domains only."""
    domains = set()
    with open(domainlist, encoding="utf-8") as f:
        for line in f:
            d = line.strip().lower()
            if not d or d.startswith("#"):
                continue
            parts = d.split(".")
            if len(parts) <= 2:
                domains.add(d)
            elif len(parts) == 3 and parts[0] in ("www",):
                domains.add(".".join(parts[1:]))
            else:
                domains.add(".".join(parts[-2:]))
    return sorted(domains)


def _load_root_domains(root_domains_file):
    """Load the operator's explicit -d root domains (used AS-IS, no last-2-label
    collapsing). Returns None if the file is absent so the caller can fall back."""
    if not root_domains_file or not os.path.isfile(root_domains_file):
        return None
    domains = set()
    with open(root_domains_file, encoding="utf-8") as f:
        for line in f:
            d = line.strip().lower().rstrip(".")
            if d and not d.startswith("#"):
                domains.add(d)
    return sorted(domains)


def _find_dnsx_jsonl(prefix):
    """Find the dnsx resolve JSONL output from a prior step."""
    candidates = [
        f"{prefix}-dnsx-resolve.txt",
        f"{prefix}-dnsx-resolve.jsonl",
    ]
    for path in candidates:
        if os.path.isfile(path):
            return path
    data_dir = os.path.dirname(prefix)
    if data_dir:
        import glob
        matches = glob.glob(os.path.join(data_dir, "*-dnsx-resolve.txt"))
        if matches:
            return matches[0]
    return None


def _parse_dnsx_records(dnsx_path, filter_domains=None):
    """Extract TXT, MX, NS, SOA records from dnsx JSONL.

    Args:
        dnsx_path: Path to dnsx JSONL output
        filter_domains: If set, only return records for these domains.
                        If None, return all domains found.
    """
    domain_set = set(filter_domains) if filter_domains else None
    records = {}
    if not dnsx_path or not os.path.isfile(dnsx_path):
        return records

    with open(dnsx_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            host = (rec.get("host") or "").strip().lower()
            if not host:
                continue
            if domain_set and host not in domain_set:
                continue
            if host not in records:
                records[host] = {"txt": [], "mx": [], "ns": [], "soa": None,
                                 "a": [], "aaaa": []}
            for txt in (rec.get("txt") or []):
                records[host]["txt"].append(txt)
            for mx in (rec.get("mx") or []):
                records[host]["mx"].append(mx)
            for ns in (rec.get("ns") or []):
                records[host]["ns"].append(ns)
            for a in (rec.get("a") or []):
                records[host]["a"].append(a)
            for aaaa in (rec.get("aaaa") or []):
                records[host]["aaaa"].append(aaaa)
            if rec.get("soa"):
                records[host]["soa"] = rec["soa"]
    return records


def _dig(domain, record_type, server=None, timeout=10):
    """Run dig and return raw answer lines."""
    # A discovered name/NS beginning with '-' would be parsed by dig as an
    # option, not a hostname (argv, so no RCE — but a malformed/attacker query).
    if domain.startswith("-") or (server and str(server).startswith("-")):
        return []
    cmd = ["dig", "+short", "+time=5", "+tries=2", record_type, domain]
    if server:
        cmd.append(f"@{server}")
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        if result.returncode == 0:
            return [l.strip() for l in result.stdout.strip().split("\n") if l.strip()]
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return []


def _dig_answer_and_flags(name, server, timeout=10):
    """Recursive A query to `server`. Returns (has_a_answer, flags_set).

    ``flags_set`` is the dig header flags (``qr``/``aa``/``rd``/``ra``/…). Used to
    tell a genuine open resolver (recursed for an external name: an answer with
    ``ra`` set and ``aa`` ABSENT) apart from a server merely AUTHORITATIVE for the
    probe name (``aa`` set) — e.g. a Cloudflare NS answering ``one.one.one.one``
    (Cloudflare's own domain) authoritatively, which is NOT recursion.
    """
    if name.startswith("-") or str(server).startswith("-"):
        return (False, set())
    cmd = ["dig", "+time=5", "+tries=2", "A", name, f"@{server}"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return (False, set())
    out = result.stdout or ""
    m = re.search(r";; flags:\s*([a-z ]+?);", out)
    flags = set(m.group(1).split()) if m else set()
    has_a = bool(re.search(r"\bIN\s+A\s+\d{1,3}(\.\d{1,3}){3}\b", out))
    return (has_a, flags)


def _dig_axfr(domain, nameserver, timeout=15):
    """Attempt zone transfer. Returns True if transfer succeeded."""
    if domain.startswith("-") or str(nameserver).startswith("-"):
        return False
    cmd = ["dig", "+time=5", "+tries=1", "AXFR", domain, f"@{nameserver}"]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        if result.returncode == 0 and result.stdout:
            lines = [l for l in result.stdout.split("\n")
                     if l.strip() and not l.startswith(";")]
            return len(lines) > 2
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return False


def _soa_mname(domain):
    """The SOA primary master (MNAME) for a zone, or None. This is often the
    self-hosted authoritative NS even when the public NS set is a managed
    provider (Cloudflare) — and it's a prime AXFR target."""
    if domain.startswith("-"):
        return None
    soa = _dig(domain, "SOA")   # "mname rname serial refresh retry expire minttl"
    if soa and soa[0].split():
        return soa[0].split()[0].rstrip(".")
    return None


def _check_spf(domain, txt_records):
    """Analyze SPF records from TXT. Returns list of findings."""
    findings = []
    spf_records = [t for t in txt_records if "v=spf1" in t.lower()]

    if not spf_records:
        findings.append({
            "domain": domain,
            "check": "spf_missing",
            "severity": "MEDIUM",
            "detail": "No SPF record found — weakens sender authentication and "
                      "DMARC alignment (DMARC is the primary anti-spoofing control)",
            "evidence": "",
            "recommendation": "Add a TXT record with a valid SPF policy (v=spf1 ... -all)",
        })
        return findings

    if len(spf_records) > 1:
        findings.append({
            "domain": domain,
            "check": "spf_multiple",
            "severity": "MEDIUM",
            "detail": "Multiple SPF records found — RFC 7208 violation, behavior is undefined",
            "evidence": " | ".join(spf_records),
            "recommendation": "Merge into a single SPF record",
        })

    for spf in spf_records:
        spf_lower = spf.lower()
        if "+all" in spf_lower:
            findings.append({
                "domain": domain,
                "check": "spf_plus_all",
                "severity": "CRITICAL",
                "detail": "SPF uses +all — allows ANY server to send mail as this domain",
                "evidence": spf,
                "recommendation": "Change +all to -all immediately",
            })
        # NOTE: ~all (softfail) is NOT flagged. Both -all (hardfail) and ~all
        # (softfail) satisfy internet.nl's SPF requirement — softfail is a valid,
        # commonly-recommended posture (DMARC provides the enforcement), so
        # flagging it produced false positives. Only +all and ?all are issues.
        elif "?all" in spf_lower:
            findings.append({
                "domain": domain,
                "check": "spf_neutral",
                "severity": "MEDIUM",
                "detail": "SPF uses ?all (neutral) — effectively no protection",
                "evidence": spf,
                "recommendation": "Change ?all to -all",
            })

        includes = re.findall(r'include:(\S+)', spf_lower)
        if len(includes) > 8:
            findings.append({
                "domain": domain,
                "check": "spf_too_many_includes",
                "severity": "LOW",
                "detail": f"SPF has {len(includes)} includes — risk of exceeding 10-lookup limit",
                "evidence": spf,
                "recommendation": "Consolidate includes or use SPF flattening",
            })

    return findings


def _parse_dmarc(dmarc_txt):
    """Parse a DMARC TXT record. Returns None if absent/invalid, else a dict
    {p, sp, has_reporting, raw}. `p`/`sp` are the policy tokens (none/quarantine/
    reject) or None if the tag isn't set."""
    if not dmarc_txt:
        return None
    raw = " ".join(dmarc_txt)
    s = raw.lower()
    if "v=dmarc1" not in s:
        return None
    def _tag(name):
        m = re.search(rf'\b{name}\s*=\s*([a-z]+)', s)
        return m.group(1) if m else None
    return {"p": _tag("p"), "sp": _tag("sp"),
            "has_reporting": ("rua=" in s or "ruf=" in s), "raw": raw}


def _check_dmarc(domain, dmarc_txt):
    """Analyze a domain's OWN DMARC record. Returns list of findings.

    Used for org/apex domains and for subdomains that publish their own _dmarc
    record. Subdomains WITHOUT their own record are handled by
    `_check_dmarc_fallback` (RFC 7489 organizational-domain inheritance).
    """
    findings = []

    if not dmarc_txt:
        findings.append({
            "domain": domain,
            "check": "dmarc_missing",
            "severity": "MEDIUM",
            "detail": "No DMARC record found — no policy enforcement for spoofed mail",
            "evidence": f"No TXT record at _dmarc.{domain}",
            "recommendation": f"Add _dmarc TXT record: v=DMARC1; p=reject; rua=mailto:dmarc@{domain}",
        })
        return findings

    parsed = _parse_dmarc(dmarc_txt)
    if parsed is None:
        findings.append({
            "domain": domain,
            "check": "dmarc_invalid",
            "severity": "HIGH",
            "detail": "DMARC record exists but appears invalid (no v=DMARC1 tag)",
            "evidence": " ".join(dmarc_txt),
            "recommendation": "Fix DMARC record format: must start with v=DMARC1",
        })
        return findings

    p = parsed["p"]
    if p == "none":
        findings.append({
            "domain": domain,
            "check": "dmarc_none",
            "severity": "MEDIUM",
            "detail": "DMARC policy is p=none — monitoring only, no enforcement",
            "evidence": parsed["raw"],
            "recommendation": "Upgrade to p=quarantine or p=reject once reporting confirms legitimate senders",
        })
    elif p in ("quarantine", "reject"):
        pass  # enforced — internet.nl considers quarantine and reject sufficient
    else:
        findings.append({
            "domain": domain,
            "check": "dmarc_weak",
            "severity": "MEDIUM",
            "detail": "DMARC record present but no enforcing policy found (missing p= tag)",
            "evidence": parsed["raw"],
            "recommendation": "Ensure p= tag is set to quarantine or reject",
        })

    if not parsed["has_reporting"]:
        findings.append({
            "domain": domain,
            "check": "dmarc_no_reporting",
            "severity": "LOW",
            "detail": "DMARC has no reporting addresses (rua/ruf) — you won't see abuse data",
            "evidence": parsed["raw"],
            "recommendation": "Add rua=mailto:... to receive aggregate reports",
        })

    return findings


def _check_dmarc_fallback(subdomain, org_domain, org_dmarc_txt):
    """Evaluate a subdomain's INHERITED DMARC policy (RFC 7489 §6.6.3).

    A subdomain with no _dmarc record of its own is NOT unprotected: receivers
    fall back to the organizational domain's DMARC record and apply `sp=`
    (subdomain policy) if present, else `p=`. So we only flag a subdomain when
    that inherited policy is itself weak/absent — otherwise the earlier
    "missing DMARC on every subdomain" false positives fire.
    """
    findings = []
    parsed = _parse_dmarc(org_dmarc_txt)
    if parsed is None:
        # Org domain has no (valid) DMARC either → the subdomain really is
        # unprotected. Report once, attributed to the subdomain, pointing at org.
        findings.append({
            "domain": subdomain,
            "check": "dmarc_missing",
            "severity": "MEDIUM",
            "detail": f"No DMARC record on {subdomain} and none inherited from the "
                      f"organizational domain {org_domain} — spoofed mail is unenforced",
            "evidence": f"No TXT at _dmarc.{subdomain} or _dmarc.{org_domain}",
            "recommendation": f"Publish DMARC at the organizational domain: "
                              f"_dmarc.{org_domain} TXT v=DMARC1; p=reject; rua=mailto:...",
        })
        return findings

    # Effective policy for the subdomain: sp= wins, else p=.
    effective = parsed["sp"] or parsed["p"]
    if effective in ("quarantine", "reject"):
        return findings  # inherited enforcement is sufficient — no finding
    if effective == "none":
        findings.append({
            "domain": subdomain,
            "check": "dmarc_subdomain_none",
            "severity": "MEDIUM",
            "detail": f"Subdomain inherits DMARC from {org_domain}, whose "
                      f"{'sp=none' if parsed['sp'] else 'p=none'} leaves subdomains unenforced",
            "evidence": parsed["raw"],
            "recommendation": f"Set sp=quarantine or sp=reject on _dmarc.{org_domain} "
                              f"(or publish a dedicated _dmarc.{subdomain})",
        })
    return findings


def _org_domain_for(name, org_domains):
    """Return the in-scope organizational domain that `name` belongs to — the
    longest org domain it equals or is a subdomain of, or None.

    Used for SCOPE gating (only audit names under an in-scope apex). For the
    RFC 7489 DMARC org-domain *lookup target*, prefer `_registrable_domain`."""
    matches = [o for o in org_domains if name == o or name.endswith("." + o)]
    return max(matches, key=len) if matches else None


def _registrable_domain(name):
    """RFC 7489 'organizational domain' via the Public Suffix List: the
    registrable domain for `name` (e.g. `a.b.example.co.uk` -> `example.co.uk`).

    This is what a DMARC receiver resolves to when a subdomain has no `_dmarc`
    record — the registrable domain, NOT the immediate parent. Returns None when
    tldextract is unavailable or `name` has no registrable domain, so callers
    fall back to the in-scope apex (`_org_domain_for`)."""
    if _TLD_EXTRACT is None or not name:
        return None
    try:
        ext = _TLD_EXTRACT(name)
        # tldextract 5.x renamed `registered_domain` ->
        # `top_domain_under_public_suffix`; support both across the 5.x range.
        return (getattr(ext, "top_domain_under_public_suffix", "")
                or ext.registered_domain or None)
    except Exception:
        return None


def _dmarc_org_domain(subdomain, apex_domains):
    """The DMARC-fallback organizational domain for `subdomain`, CLAMPED to scope.

    RFC 7489 says a receiver falls back to the PSL registrable domain — so prefer
    that (`_registrable_domain`), but ONLY when the registrable domain is itself
    in scope. Otherwise a subdomain supplied as a root (e.g. `-d
    corp.example.com`) would make us query `_dmarc` against, and file findings on,
    the out-of-scope parent registrable (`example.com`). Fall back to the longest
    in-scope apex (also the behavior when tldextract is unavailable)."""
    apex = _org_domain_for(subdomain, apex_domains)
    psl = _registrable_domain(subdomain)
    if psl and (psl in set(apex_domains) or psl == apex
                or (apex and psl.endswith("." + apex))):
        return psl
    return apex


def _check_zone_transfer(domain, nameservers):
    """Attempt AXFR against each NS. Returns findings."""
    findings = []
    for ns in nameservers:
        ns_clean = ns.rstrip(".")
        if _dig_axfr(domain, ns_clean):
            findings.append({
                "domain": domain,
                "check": "axfr_allowed",
                "severity": "CRITICAL",
                "detail": f"Zone transfer (AXFR) allowed on {ns_clean} — full DNS zone exposed",
                "evidence": f"dig AXFR {domain} @{ns_clean} returned records",
                "recommendation": f"Restrict AXFR on {ns_clean} to authorized secondary nameservers only",
            })
    return findings


def _check_ns_health(domain, nameservers):
    """Check NS records for dangling/dead nameservers."""
    findings = []
    for ns in nameservers:
        ns_clean = ns.rstrip(".")
        a_records = _dig(ns_clean, "A")
        if not a_records:
            aaaa_records = _dig(ns_clean, "AAAA")
            if not aaaa_records:
                findings.append({
                    "domain": domain,
                    "check": "ns_nxdomain",
                    "severity": "MEDIUM",
                    "detail": f"NS record points to {ns_clean} which does not resolve — potential takeover vector (unverified)",
                    "evidence": f"dig A {ns_clean} returned no results",
                    "recommendation": "Investigate if the NS hostname is registrable; remove or replace the dangling delegation",
                })
    return findings


# External names an in-scope authoritative NS is NOT responsible for. If the
# server answers these for us (an off-net client), it is recursing on behalf of
# the internet — an open resolver (DNS-amplification DDoS reflector). Two probes
# so a single dead/renamed name doesn't yield a false negative.
_RECURSION_PROBES = ("a.root-servers.net", "one.one.one.one")


def _check_open_recursion(domain, nameservers):
    """Flag nameservers that recurse for external names (open resolvers).

    Recursion is confirmed ONLY when the NS returns an answer for the probe with
    the ``ra`` (recursion-available) flag set AND without ``aa`` (authoritative):
    a bare "got an A record" test false-positives on any NS that happens to be
    authoritative for the probe name (a Cloudflare NS answers ``one.one.one.one``
    authoritatively, not by recursing).
    """
    findings = []
    for ns in nameservers:
        ns_clean = ns.rstrip(".")
        for probe in _RECURSION_PROBES:
            has_a, flags = _dig_answer_and_flags(probe, ns_clean)
            if has_a and "ra" in flags and "aa" not in flags:
                findings.append({
                    "domain": domain,
                    "check": "dns_open_recursion",
                    "severity": "MEDIUM",
                    "detail": f"Nameserver {ns_clean} answers recursive queries for "
                              f"external domains — an open resolver usable for "
                              f"DNS-amplification DDoS reflection",
                    "evidence": f"dig A {probe} @{ns_clean}: answer present, "
                                f"flags={' '.join(sorted(flags))} (ra set, aa absent)",
                    "recommendation": f"Disable recursion on {ns_clean} (authoritative-"
                                      f"only) or restrict it to trusted client networks",
                })
                break  # one probe answering is enough; don't double-report the NS
    return findings


_PRIVATE_NETS = [ipaddress.ip_network(n) for n in
                 ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")]


def _check_private_dns(host, a_records, aaaa_records):
    """Flag RFC1918 / ULA addresses published in PUBLIC DNS answers.

    A public A/AAAA record pointing at 10/8, 172.16/12, 192.168/16 (or IPv6
    fc00::/7) leaks internal network topology to anyone who resolves the name —
    an information-disclosure finding, not a vuln in itself.
    """
    private = []
    for ip in list(a_records) + list(aaaa_records):
        try:
            addr = ipaddress.ip_address(str(ip).strip())
        except ValueError:
            continue
        if any(addr in net for net in _PRIVATE_NETS):
            private.append(str(ip).strip())
    if not private:
        return []
    return [{
        "domain": host,
        "check": "rfc1918_in_public_dns",
        "severity": "LOW",
        "detail": f"Public DNS for {host} resolves to private/internal address(es) "
                  f"({', '.join(sorted(set(private)))}) — leaks internal network "
                  f"topology and is unreachable from the internet",
        "evidence": ", ".join(sorted(set(private))),
        "recommendation": "Remove the internal records from public DNS (use split-"
                          "horizon/internal-only zones for private addresses)",
    }]


def run_dns_security(domainlist=None, prefix=None, **kwargs):
    """Run DNS security checks against apex domains.

    Args:
        domainlist: File containing domains
        prefix: Output file prefix
        **kwargs:
            data_prefix: Override for output prefix
            skip_axfr: Skip zone transfer checks (default: False)
            skip_dmarc: Skip DMARC lookups (default: False)
            skip_recursion: Skip open-recursion probes (default: False)
    """
    prefix = kwargs.get('data_prefix', prefix)
    skip_axfr = kwargs.get('skip_axfr', False)
    skip_dmarc = kwargs.get('skip_dmarc', False)
    skip_recursion = kwargs.get('skip_recursion', False)
    root_domains_file = kwargs.get('root_domains_file')

    print("\n[*] DNS Security Audit")

    # Scope: prefer the operator's EXPLICIT -d root domains (passed by the
    # orchestrator). This keeps the audit on domains the engagement actually owns
    # and stops it recursing into third-party registrable domains (e.g.
    # amazonaws.com) collapsed from discovered subdomains. Fall back to
    # apex-collapsing the domainlist only when run standalone with no roots file.
    apex_domains = _load_root_domains(root_domains_file)
    scoped_to_roots = apex_domains is not None
    if apex_domains is None:
        if not domainlist or not os.path.exists(domainlist):
            print("[!] dns_security: no domainlist available (yet)")
            return {'module': 'dns_security', 'status': 'skipped', 'output_files': [], 'findings': 0}
        apex_domains = _load_apex_domains(domainlist)

    if not apex_domains:
        msg = ("no explicit -d root domains in scope" if scoped_to_roots
               else "no apex domains found in domainlist")
        print(f"[!] dns_security: {msg} — nothing to audit")
        return {'module': 'dns_security', 'status': 'skipped', 'output_files': [], 'findings': 0}

    print(f"[+] Checking {len(apex_domains)} in-scope domain(s)")

    # Phase 1: Parse existing dnsx data (all domains, not just apex)
    dnsx_path = _find_dnsx_jsonl(prefix)
    all_dnsx_records = _parse_dnsx_records(dnsx_path)
    if all_dnsx_records:
        print(f"[+] Phase 1: Found existing DNS data for {len(all_dnsx_records)} domains")
    else:
        print("[*] Phase 1: No existing dnsx data found, will query apex records fresh")

    # Find subdomains with MX records — they send mail and need SPF/DMARC. Only
    # consider subdomains WITHIN an in-scope org domain, so discovered
    # third-party mail hosts (e.g. under amazonaws.com) are never audited.
    apex_set = set(apex_domains)
    mx_subdomains = []
    for host, data in all_dnsx_records.items():
        if host in apex_set or not data.get("mx"):
            continue
        if _org_domain_for(host, apex_domains):
            mx_subdomains.append(host)
    if mx_subdomains:
        print(f"[+] Found {len(mx_subdomains)} in-scope subdomains with MX records — will check email security")

    findings = []

    # Check apex domains (zone transfer + NS health always; SPF/DMARC only if MX exists)
    for domain in apex_domains:
        dns_data = all_dnsx_records.get(domain, {})
        txt_records = dns_data.get("txt", [])
        ns_records = dns_data.get("ns", [])
        mx_records = dns_data.get("mx", [])

        if not txt_records:
            txt_records = _dig(domain, "TXT")
        if not ns_records:
            ns_records = _dig(domain, "NS")
        if not mx_records:
            mx_records = _dig(domain, "MX")

        if mx_records:
            findings.extend(_check_spf(domain, txt_records))
            if not skip_dmarc:
                dmarc_txt = _dig(f"_dmarc.{domain}", "TXT")
                findings.extend(_check_dmarc(domain, dmarc_txt))

        a_records = dns_data.get("a", [])
        aaaa_records = dns_data.get("aaaa", [])
        if not a_records and not aaaa_records:
            a_records = _dig(domain, "A")
            aaaa_records = _dig(domain, "AAAA")
        findings.extend(_check_private_dns(domain, a_records, aaaa_records))

        if not skip_axfr and ns_records:
            # Include the SOA primary (MNAME) — often a self-hosted NS that allows
            # AXFR even when the delegated/public NS set refuses.
            mname = _soa_mname(domain)
            axfr_ns = list(dict.fromkeys(
                [n.rstrip(".") for n in ns_records] + ([mname] if mname else [])))
            findings.extend(_check_zone_transfer(domain, axfr_ns))
            if not skip_recursion:
                findings.extend(_check_open_recursion(domain, ns_records))

        if ns_records:
            findings.extend(_check_ns_health(domain, ns_records))

    # Follow delegation: a self-hosted subzone with its OWN NS delegation can
    # allow AXFR even when the apex is on a managed provider (Cloudflare) that
    # refuses — the apex loop above would miss it. Probe AXFR against each
    # in-scope delegated subzone's own NS + SOA primary. Scope-safe: only
    # subzones under an in-scope org domain (never third-party NS).
    if not skip_axfr:
        for host, data in all_dnsx_records.items():
            if host in apex_set or not _org_domain_for(host, apex_domains):
                continue
            sub_ns = data.get("ns") or _dig(host, "NS")
            if not sub_ns:
                continue  # not a delegation point
            mname = _soa_mname(host)
            axfr_ns = list(dict.fromkeys(
                [n.rstrip(".") for n in sub_ns] + ([mname] if mname else [])))
            findings.extend(_check_zone_transfer(host, axfr_ns))

    # Check subdomains that have MX records (email security only). DMARC honors
    # organizational-domain inheritance: a subdomain with no _dmarc record falls
    # back to the org domain's sp=/p= (RFC 7489), so we don't flag it as missing.
    org_dmarc_cache = {}  # org_domain -> dig result (query each org once)
    for subdomain in sorted(mx_subdomains):
        dns_data = all_dnsx_records.get(subdomain, {})
        txt_records = dns_data.get("txt", [])

        if not txt_records:
            txt_records = _dig(subdomain, "TXT")

        findings.extend(_check_spf(subdomain, txt_records))

        if not skip_dmarc:
            dmarc_txt = _dig(f"_dmarc.{subdomain}", "TXT")
            if dmarc_txt:
                findings.extend(_check_dmarc(subdomain, dmarc_txt))
            else:
                # RFC 7489 org-domain fallback, clamped to in-scope (see helper):
                # never query/report an out-of-scope parent registrable.
                org = _dmarc_org_domain(subdomain, apex_domains)
                if org not in org_dmarc_cache:
                    org_dmarc_cache[org] = _dig(f"_dmarc.{org}", "TXT")
                findings.extend(
                    _check_dmarc_fallback(subdomain, org, org_dmarc_cache[org]))

    # RFC1918/private addresses in PUBLIC DNS for in-scope subdomains (info
    # leak). Uses passive dnsx data only — no extra network calls — and stays on
    # in-scope org domains so third-party names a subdomain CNAMEs to are ignored.
    for host, data in all_dnsx_records.items():
        if host in apex_set:
            continue  # apexes were checked in the loop above
        if not _org_domain_for(host, apex_domains):
            continue
        findings.extend(_check_private_dns(host, data.get("a", []),
                                           data.get("aaaa", [])))

    # Write output
    output_file = version_output_path(f"{prefix}-dns-security.jsonl")
    with open(output_file, 'w', encoding="utf-8") as f:
        for finding in findings:
            f.write(json.dumps(finding) + "\n")

    # Print summary
    by_severity = {}
    for finding in findings:
        sev = finding["severity"]
        by_severity[sev] = by_severity.get(sev, 0) + 1

    print(f"\n[+] DNS Security Audit Complete: {len(findings)} findings")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        count = by_severity.get(sev, 0)
        if count:
            print(f"    {sev}: {count}")

    # Print critical/high findings inline
    for f in findings:
        if f["severity"] in ("CRITICAL", "HIGH"):
            print(f"    [{f['severity']}] {f['domain']}: {f['detail']}")

    return {
        'module': 'dns_security',
        'status': 'success',
        'output_files': [output_file],
        'findings': len(findings),
        'by_severity': by_severity,
    }
