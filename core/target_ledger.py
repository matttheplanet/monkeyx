"""Target discovery ledger — tracks all targets with source attribution and scope.

The ledger is the single source of truth for what gets scanned. Before each module
step, target files are regenerated from the ledger with deduplication and scope
filtering applied.

Scope inheritance via parent chain:
  - User-provided targets are "explicit" scope
  - A discovered target whose parent is in-scope inherits in-scope status
  - Example chain: example.com (explicit) → api.example.com (in-scope, parent is
    explicit) → 10.0.0.5 (in-scope, parent api.example.com is in-scope) →
    https://10.0.0.5:8080/admin (in-scope, host is in-scope IP)
  - The _in_scope_* sets accumulate as discoveries are logged, no re-walking needed

Scope filter modes (applied at export time only — all discoveries are always logged):
  - "strict" (default): only export in-scope targets to modules
  - "warn": export all targets, log warnings for out-of-scope entries
  - "none": export all targets without warnings
"""

import ipaddress
import json
import logging
import os
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlparse

from core import scan_db

logger = logging.getLogger("monkeyx.target_ledger")


class RunPredatesDbMigration(Exception):
    """Raised when a resume/continue targets a scan.db that predates the DB
    migration (no ``ledger_authoritative`` marker) — its ledger state can't be
    trusted as source of truth. Callers surface a clean message and exit."""


SCOPE_EXPLICIT = "explicit"
SCOPE_DERIVED = "derived"
SCOPE_EXCLUDED = "excluded"

# Authorization channel — WHICH input a target's authorization traces back to.
# This is the ceiling that gates host-class vs name-class module access
# (see core/scope_classes.py and the input-channel scope model):
#   CHANNEL_TARGET ("t")  — fully authorized: host-level scanning allowed.
#   CHANNEL_DOMAIN ("dl") — name-safe only: web/name modules, never port sweeps.
#   CHANNEL_URL ("ul")    — name-safe only: web surface addressed by URL.
#   None                  — a discovered lead that traces to no input channel.
# Precedence when a target is reachable from more than one channel: t > dl > ul.
# (Highest authorization wins — if any explicit -t path authorizes a host, it is
# fully in scope.)
CHANNEL_TARGET = "t"
CHANNEL_DOMAIN = "dl"
CHANNEL_URL = "ul"

_CHANNEL_RANK = {CHANNEL_TARGET: 3, CHANNEL_DOMAIN: 2, CHANNEL_URL: 1, None: 0}


def _channel_max(a: str | None, b: str | None) -> str | None:
    """Return the higher-authorization channel of the two (t > dl > ul > None)."""
    return a if _CHANNEL_RANK.get(a, 0) >= _CHANNEL_RANK.get(b, 0) else b

TYPE_IP = "ip"
TYPE_DOMAIN = "domain"
TYPE_PORT = "port"

# External-only scanning: filter out RFC1918 and other non-routable addresses
_PRIVATE_FILTER_ENABLED = True


# The address families we treat as private/non-routable for external scanning.
# Defined EXPLICITLY (not via Python's `.is_private`) so the filter is stable
# across Python versions: since 3.12.4, `ip_address(...).is_private` also returns
# True for RFC5737 documentation ranges (192.0.2/198.51.100/203.0.113) and other
# reserved blocks, which silently widens what gets filtered on a Python upgrade.
_PRIVATE_NETS = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",  # RFC1918
    "127.0.0.0/8",       # loopback
    "169.254.0.0/16",    # link-local
    "100.64.0.0/10",     # RFC6598 Carrier-Grade NAT
    "::1/128",           # IPv6 loopback
    "fe80::/10",         # IPv6 link-local
    "fc00::/7",          # IPv6 unique-local (ULA)
))


def _is_private_ip(addr_str: str) -> bool:
    """Check if an IP or CIDR is a private/non-routable address.

    Covers RFC1918, loopback, link-local, RFC6598 Carrier-Grade NAT, and the
    IPv6 equivalents (loopback/link-local/ULA). Deliberately does NOT delegate to
    `.is_private` so behavior can't drift with Python's evolving definition.
    """
    try:
        if "/" in addr_str:
            obj = ipaddress.ip_network(addr_str, strict=False)
            return any(obj.version == n.version and obj.subnet_of(n)
                       for n in _PRIVATE_NETS)
        addr = ipaddress.ip_address(addr_str)
        return any(addr.version == n.version and addr in n for n in _PRIVATE_NETS)
    except (ValueError, TypeError):
        return False


def _subtract_exclusions(target: str, excluded_networks: list) -> list[str]:
    """Return the exportable address strings for an IP/CIDR target after removing
    any excluded IPs/subnets that fall inside it.

    - A bare IP or /32 fully inside an exclusion -> [] (dropped).
    - A CIDR partially overlapping exclusions -> the CIDR split into the largest
      sub-networks that avoid the excluded ranges (via address_exclude).
    - A target that doesn't parse as an IP/network -> returned unchanged.

    Previously exclusions only dropped a CIDR when it was WHOLLY contained in an
    excluded network, so excluding a single IP left the surrounding in-scope
    CIDR fully exportable — an authorization-boundary hole for a pentest tool.
    """
    try:
        net = ipaddress.ip_network(target, strict=False)
    except ValueError:
        return [target]

    # Only exclusions of the same address family can overlap.
    relevant = [e for e in excluded_networks
                if e.version == net.version and (net.subnet_of(e) or e.subnet_of(net)
                                                 or net.overlaps(e))]
    if not relevant:
        return [target]

    remaining = [net]
    for excl in relevant:
        next_remaining = []
        for block in remaining:
            if block.subnet_of(excl):
                # Entire block excluded — drop it.
                continue
            if block.overlaps(excl):
                # Split block into sub-networks that avoid excl.
                try:
                    next_remaining.extend(block.address_exclude(excl))
                except ValueError:
                    # excl not a subnet of block (shouldn't happen after overlap
                    # check) — keep the block conservatively.
                    next_remaining.append(block)
            else:
                next_remaining.append(block)
        remaining = next_remaining
        if not remaining:
            break

    # Render: emit bare address for /32|/128, else CIDR string. Preserve the
    # original single-IP form when the input had no prefix.
    had_prefix = "/" in target
    out = []
    for block in remaining:
        if block.num_addresses == 1 and not had_prefix:
            out.append(str(block.network_address))
        else:
            out.append(str(block))
    return out


def _url_has_private_host(url: str) -> bool:
    """Check if a URL's hostname resolves to a private/non-routable IP."""
    from urllib.parse import urlparse
    import socket
    hostname = urlparse(url).hostname
    if not hostname:
        return False
    if _is_private_ip(hostname):
        return True
    try:
        resolved = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
        for _, _, _, _, sockaddr in resolved:
            if _is_private_ip(sockaddr[0]):
                return True
    except (socket.gaierror, OSError, UnicodeError):
        # UnicodeError: getaddrinfo IDNA-encodes the host; a malformed host
        # (e.g. an empty DNS label like ".") raises it, and it is NOT an
        # OSError — so without this it would escape and kill the whole step.
        pass
    return False


_DEFAULT_PORTS = {"http": 80, "https": 443}
# "interesting" liveness policy: real responses worth scanning — success,
# redirects, and auth-gated pages (401/403 often front the real app).
_INTERESTING_STATUSES = set(range(200, 400)) | {401, 403}


def _effective_port(scheme: str, port) -> int:
    if port:
        return int(port)
    return _DEFAULT_PORTS.get((scheme or "http").lower(), 80)


def _url_cov_key(url: str) -> str | None:
    """Coverage key (host:port) used to group a URL with its httpx probe result.
    Two URLs on the same host+port share a key regardless of path/scheme-default."""
    try:
        p = urlparse(url)
    except ValueError:
        return None
    if not p.hostname:
        return None
    return f"{p.hostname.lower()}:{_effective_port(p.scheme, p.port)}"


def _norm_url(url: str) -> str | None:
    """Canonical URL for matching httpx output against ledger URLs: lowercase
    host, explicit default port dropped, trailing slash stripped."""
    try:
        p = urlparse(url)
    except ValueError:
        return None
    if not p.hostname:
        return None
    scheme = (p.scheme or "http").lower()
    port = p.port
    netloc = p.hostname.lower()
    if port and port != _DEFAULT_PORTS.get(scheme):
        netloc += f":{port}"
    path = p.path.rstrip("/")
    tail = (f"?{p.query}" if p.query else "")
    return f"{scheme}://{netloc}{path}{tail}"


def _is_scannable_host(host: str | None) -> bool:
    """True if `host` is something we could actually address: an IP literal, or
    a hostname with no empty DNS labels and only valid label characters.

    Rejects junk that urlparse extracts from a non-URL string — e.g. a stray
    file path fed to -url yields host "." (an empty label), which later blows up
    socket/IDNA encoding. Better to never seed it than to crash downstream.
    """
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    if host.startswith(".") or host.endswith(".") or ".." in host:
        return False
    labels = host.split(".")
    for lbl in labels:
        if not lbl or len(lbl) > 63:
            return False
        if not all(c.isalnum() or c in "-_" for c in lbl):
            return False
    return True


def _is_wildcard_marker(target: str | None) -> bool:
    """True if `target` is bbot's synthetic wildcard-parent marker.

    bbot emits wildcard-catch-all parents as a DNS_NAME whose leftmost label is
    literally `_wildcard` (e.g. `_wildcard.example.com`). It is not a real host —
    it must never be scanned, resolved, or synthesized into a URL. Handles the
    bare name plus the URL form (`http://_wildcard.example.com/...`).
    """
    if not target:
        return False
    host = target
    if "://" in host:
        host = host.split("://", 1)[1]
    host = host.split("/", 1)[0].split("@")[-1].split(":", 1)[0]
    return any(lbl == "_wildcard" for lbl in host.split("."))


def normalize_user_url(line: str) -> list[str]:
    """Expand a user-supplied URL line into one or more normalized URLs.

    - "https://web.example.com" → ["https://web.example.com"]
    - "ftp://host" → ["ftp://host"] (other schemes left alone)
    - "web.example.com" → ["http://web.example.com", "https://web.example.com"]
    - "web.example.com:8443" → ["http://web.example.com:8443",
                                "https://web.example.com:8443"]

    Entries with no usable host (e.g. a file path fed to -url) are skipped with a
    warning rather than seeded as bogus targets.
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return []
    candidates = [line] if "://" in line else [f"http://{line}", f"https://{line}"]
    out = []
    for url in candidates:
        try:
            host = urlparse(url).hostname
        except ValueError:
            host = None
        if _is_scannable_host(host):
            out.append(url)
    if not out:
        logger.warning(
            "Skipping URL/host input %r: no valid host (looks like a file path "
            "or malformed entry, not a URL).", line)
    return out
TYPE_SUBDOMAIN = "subdomain"
TYPE_URL = "url"

# Identity/SSO/SaaS-login hosts that are the PROVIDER's asset, never the
# customer's — a redirect/crawl target here (e.g. an M365 SSO redirect) must not
# be actively scanned. Matched as an exact host or a dotted suffix. Deliberately
# narrow (login endpoints), not general CDN/storage — the cross-domain guard in
# _is_third_party_name covers the rest when explicit domains are listed.
_THIRD_PARTY_SUFFIXES = frozenset({
    "microsoftonline.com", "login.microsoftonline.com", "login.windows.net",
    "login.live.com", "sts.windows.net",
    "okta.com", "oktapreview.com", "onelogin.com", "auth0.com",
    "accounts.google.com", "pingidentity.com", "duosecurity.com",
    "signin.aws.amazon.com",
})


@dataclass(frozen=True)
class LedgerSnapshot:
    """Immutable point-in-time snapshot of ledger state for parallel groups."""

    ips: frozenset = field(default_factory=frozenset)
    urls: frozenset = field(default_factory=frozenset)
    domains: frozenset = field(default_factory=frozenset)
    in_scope_ips: frozenset = field(default_factory=frozenset)
    in_scope_urls: frozenset = field(default_factory=frozenset)
    in_scope_domains: frozenset = field(default_factory=frozenset)


class TargetLedger:
    """Append-only JSONL ledger tracking discovered targets with provenance.

    Each entry records what was found, what module found it, whether it was
    user-provided (explicit scope) or discovered during scanning (derived),
    and optionally what parent target led to its discovery.

    The ledger maintains in-memory sets for efficient export:
    - _all_* sets: every target by type (for none/warn export)
    - _in_scope_* sets: targets traceable to explicit scope (for strict export)

    Scope inheritance: when a target is logged with a parent that is already
    in-scope, the new target is also marked in-scope. This cascades through
    the discovery chain automatically.
    """

    def __init__(self, output_dir: str):
        self.path = os.path.join(output_dir, "discovery-ledger.jsonl")
        self._lock = threading.Lock()
        self._seen: set[str] = set()
        self._explicit_ips: set[str] = set()
        self._explicit_domains: set[str] = set()
        self._explicit_urls: set[str] = set()
        # All targets by type (for export)
        self._all_ips: set[str] = set()
        self._all_urls: set[str] = set()
        # Domains AND subdomains live together in _all_domains (DNS resolution,
        # parent chains, and exports treat them identically). _subdomain_targets
        # records which of those were logged as TYPE_SUBDOMAIN so sync_scope_to_db
        # can persist the faithful target_type to scan.db instead of forcing every
        # entry to TYPE_DOMAIN (which minted phantom duplicate 'domain' rows).
        self._all_domains: set[str] = set()
        self._subdomain_targets: set[str] = set()
        # In-scope subsets (explicit + derived-from-explicit via parent chain)
        self._in_scope_ips: set[str] = set()
        self._in_scope_urls: set[str] = set()
        self._in_scope_domains: set[str] = set()
        # Authorization channel per (target, type): CHANNEL_TARGET/DOMAIN/URL.
        # Set at seed time for explicit inputs; propagated to derived targets
        # via the parent chain (highest-authorization channel wins, t>dl>ul).
        # This is the ceiling host-class module gating reads (see scope_classes).
        self._channel_by_target: dict[tuple[str, str], str] = {}
        # Port/service index: {ip: {(port, proto): {service, product, version, ...}}}
        # Last-write-wins on load — later entries with more info supersede earlier ones.
        self._ports: dict[str, dict[tuple[int, str], dict]] = {}
        # Parents-by-(target,type) for accessors used by URL synthesis.
        # A target can have multiple parents (e.g., one IP resolved from
        # multiple hostnames). All parents are tracked here even though only
        # the first is recorded in the JSONL entry's `parent` field.
        self._parents_by_target: dict[tuple[str, str], set[str]] = {}
        # Provenance kept for faithful DB persistence (the in-memory sets don't
        # otherwise retain per-target source / first-seen). first-write-wins for
        # discovered_at (earliest); source is the discovering module or user_input.
        self._source_by_target: dict[tuple[str, str], str] = {}
        self._discovered_at_by_target: dict[tuple[str, str], str] = {}
        # Domains with MX records (have mail infrastructure)
        self._mx_domains: dict[str, list[str]] = {}
        # httpx liveness (feeds the --url-prune live-URL export):
        #   _httpx_live   normalized URL -> HTTP status code httpx observed
        #   _httpx_covered  host:port keys httpx got ANY response for; used for
        #                   fail-open pruning (a host httpx never answered on keeps
        #                   all its URLs, so pruning is never a no-op-that-starves).
        self._httpx_live: dict[str, int] = {}
        self._httpx_covered: set[str] = set()
        # --url-prune policy for the live-URL export (set once per run):
        #   "off"          — heavy scanners read the full URL list (default)
        #   "live"         — only URLs httpx answered on
        #   "interesting"  — only 2xx/3xx/401/403 responders
        self._url_prune_policy: str = "off"
        self._url_prune_max_per_host: int | None = None
        # Exclusion lists — entries here are filtered from all exports and
        # excluded from in-scope determination, even if they would otherwise
        # be in-scope via parent chain or explicit user input.
        self._excluded_ips: set[str] = set()
        self._excluded_networks: list = []  # list[ipaddress.IPv4Network|IPv6Network]
        # Plain-name domain exclusion: matches the domain itself AND any subdomain
        self._excluded_domains: set[str] = set()
        # Wildcard-only domain exclusion (from "*.foo.com"): matches subdomains
        # but NOT the bare domain itself
        self._excluded_domain_subs_only: set[str] = set()
        self._excluded_urls: set[str] = set()
        # IP-authorization mode (independent of scope_filter's traceability):
        #   "provenance" (default) — a derived IP is exportable if traceable to
        #       explicit scope, wherever it resolves (legacy behavior).
        #   "strict" — a derived BARE IP (no authorized hostname) is exportable
        #       only if it falls within the authorized IP ranges (the IP/CIDR
        #       entries from -t). Named targets are authorized by name and are
        #       unaffected. If no explicit IP ranges exist (e.g. domain-only
        #       runs), there is no IP boundary and this mode is a no-op.
        #   "strict-resolved" — everything strict does, PLUS a hostname/URL is
        #       exportable only if it resolves to IP(s) all within the authorized
        #       ranges. Fail-closed: a name with no resolved IP yet is dropped.
        #       Confines scanning to the -t IP ranges even when names are used.
        self._ip_scope_mode: str = "provenance"
        # Dual-write to the per-engagement scan.db. The JSONL above stays the
        # authoritative store; the DB mirrors targets/ports/mx for new consumers.
        # None if it can't be opened — mirroring is always non-fatal.
        self._db = scan_db.open_db(output_dir)

    _IP_SCOPE_MODES = ("provenance", "strict", "strict-resolved")

    def set_ip_scope_mode(self, mode: str) -> None:
        """Set IP-authorization mode: provenance | strict | strict-resolved."""
        if mode not in self._IP_SCOPE_MODES:
            raise ValueError(f"invalid ip_scope mode: {mode!r}")
        self._ip_scope_mode = mode

    def _authorized_ip_networks(self) -> list:
        """Explicit IP/CIDR entries from -t, as networks (the authorized ranges)."""
        nets = []
        for entry in self._explicit_ips:
            try:
                nets.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                continue
        return nets

    def _ip_authorized(self, ip: str, authorized_nets: list) -> bool:
        """Under strict/strict-resolved ip_scope, is a bare IP within the ranges?

        Returns True in provenance mode, or when no authorized ranges exist
        (no IP boundary -> fall back to provenance / traceability).
        """
        if self._ip_scope_mode == "provenance" or not authorized_nets:
            return True
        try:
            addr = ipaddress.ip_address(ip.split("/")[0])
        except ValueError:
            return True  # not a bare IP (shouldn't happen in this path)
        return any(addr.version == n.version and addr in n for n in authorized_nets)

    def _hostname_ip_authorized(self, host: str, authorized_nets: list,
                                host_to_ips: dict | None = None) -> bool:
        """Under strict-resolved, may a hostname be scanned given where it resolves?

        Only enforced in 'strict-resolved' with authorized ranges present. A name
        is authorized ONLY if it has at least one resolved IP AND every resolved
        IP falls within the authorized ranges (fail-closed: an unresolved name is
        NOT authorized). Other modes always return True (names authorized by
        name, per strict/provenance).
        """
        if self._ip_scope_mode != "strict-resolved" or not authorized_nets:
            return True
        if host_to_ips is None:
            host_to_ips = self.get_hostname_to_ips()
        ips = host_to_ips.get(host, [])
        if not ips:
            return False  # fail-closed: unresolved name is not confirmed in-range
        for ip in ips:
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                return False
            if not any(addr.version == n.version and addr in n for n in authorized_nets):
                return False  # any out-of-range resolved IP disqualifies the name
        return True

    def _url_ip_authorized(self, url: str, authorized_nets: list,
                           host_to_ips: dict | None = None) -> bool:
        """strict-resolved gate for a URL: authorize by its host.

        IP-host URLs are checked as a bare IP; hostname-host URLs via
        _hostname_ip_authorized (must resolve within the authorized ranges).
        """
        from urllib.parse import urlparse
        try:
            host = urlparse(url).hostname
        except ValueError:
            return False
        if not host:
            return False
        try:
            ipaddress.ip_address(host)
            return self._ip_authorized(host, authorized_nets)  # IP-host URL
        except ValueError:
            return self._hostname_ip_authorized(host, authorized_nets, host_to_ips)

    def _write_entry(self, entry: dict):
        with self._lock:
            with open(self.path, "a") as f:
                f.write(json.dumps(entry) + "\n")
        self._mirror_entry_to_db(entry)

    def _write_entry_unlocked(self, entry: dict):
        """Write entry without acquiring lock (caller must hold self._lock)."""
        with open(self.path, "a") as f:
            f.write(json.dumps(entry) + "\n")
        self._mirror_entry_to_db(entry)

    def _mirror_entry_to_db(self, entry: dict):
        """Mirror a JSONL entry into scan.db. Never fatal — JSONL is authoritative.

        Also records per-target provenance (source / discovered_at, first-write-
        wins) so it's centralized for every write path (seed, discovery, mx).
        For scannable targets we persist the authoritative in_scope flag computed
        at write time and the FULL parent set (target_parents side-table); the
        load-time fixpoint re-asserts in_scope for out-of-order parent chains on
        the next reload, and sync_scope_to_db() re-asserts at end of a live run.
        """
        etype = entry.get("type", "")
        if etype in (TYPE_IP, TYPE_DOMAIN, TYPE_SUBDOMAIN, TYPE_URL):
            self._record_provenance(entry["target"], etype,
                                    entry.get("source"), entry.get("discovered_at"))
        if self._db is None:
            return
        try:
            if etype == TYPE_PORT:
                self._db.upsert_port(
                    host=entry["target"], port=entry["port"],
                    proto=entry.get("proto", "tcp"), state=entry.get("state", "open"),
                    service=entry.get("service", ""), product=entry.get("product", ""),
                    version=entry.get("version", ""), banner=entry.get("banner", ""),
                    tunnel=entry.get("tunnel", ""), reason=entry.get("reason", ""),
                    method=entry.get("method", ""), confidence=entry.get("confidence", ""),
                    extra=entry.get("extra", ""), source=entry.get("source", ""))
            elif etype == "mx_domain":
                self._db.upsert_mx_domain(
                    entry["target"], json.dumps(entry.get("mx_hosts", [])))
            elif etype in (TYPE_IP, TYPE_DOMAIN, TYPE_SUBDOMAIN, TYPE_URL):
                target, ttype = entry["target"], etype
                self._db.upsert_target(
                    target=target, target_type=ttype,
                    source=self._source_by_target.get((target, ttype)),
                    scope=entry.get("scope"),
                    in_scope=self._is_in_scope(target, ttype),
                    channel=self.get_channel(target, ttype),
                    parent=entry.get("parent"),
                    discovered_at=self._discovered_at_by_target.get((target, ttype)))
                parents = self._parents_by_target.get((target, ttype))
                if parents:
                    self._db.replace_target_parents(target, ttype, parents)
        except Exception as exc:  # pragma: no cover - defensive, DB never aborts a run
            logger.warning("scan.db ledger mirror failed: %s", exc)

    def _key(self, target: str, target_type: str) -> str:
        return f"{target_type}:{target}"

    def _record_provenance(self, target: str, target_type: str,
                           source: str | None, discovered_at: str | None):
        """First-write-wins record of source + discovered_at for a target.

        Kept so sync_scope_to_db can persist faithful source/discovered_at to
        scan.db (the in-memory scope sets don't otherwise retain them).
        """
        tkey = (target, target_type)
        if source and tkey not in self._source_by_target:
            self._source_by_target[tkey] = source
        if discovered_at and tkey not in self._discovered_at_by_target:
            self._discovered_at_by_target[tkey] = discovered_at

    def _add_to_all(self, target: str, target_type: str):
        """Add target to the all-targets set for its type."""
        if target_type == TYPE_IP:
            self._all_ips.add(target)
        elif target_type == TYPE_URL:
            self._all_urls.add(target)
        elif target_type in (TYPE_DOMAIN, TYPE_SUBDOMAIN):
            self._all_domains.add(target)
            if target_type == TYPE_SUBDOMAIN:
                self._subdomain_targets.add(target)
            else:
                # A later explicit-domain log outranks an earlier subdomain guess.
                self._subdomain_targets.discard(target)

    def _add_to_in_scope(self, target: str, target_type: str):
        """Add target to the in-scope set for its type."""
        if target_type == TYPE_IP:
            self._in_scope_ips.add(target)
        elif target_type == TYPE_URL:
            self._in_scope_urls.add(target)
        elif target_type in (TYPE_DOMAIN, TYPE_SUBDOMAIN):
            self._in_scope_domains.add(target)

    def _set_channel(self, target: str, target_type: str, channel: str | None):
        """Record/upgrade the authorization channel for a target.

        Highest-authorization channel wins (t > dl > ul), so a host reachable
        from both an explicit -t path and a -d name is authorized at -t level.
        """
        if channel is None:
            return
        tkey = (target, target_type)
        self._channel_by_target[tkey] = _channel_max(
            self._channel_by_target.get(tkey), channel)

    def get_channel(self, target: str, target_type: str) -> str | None:
        """Return the authorization channel for a target, or None (a lead)."""
        return self._channel_by_target.get((target, target_type))

    def _best_channel(self, value: str | None) -> str | None:
        """Highest authorization channel recorded for a bare value across types.

        Targets are stored per (value, type); a value's channel may live under
        any type, so take the max (t > dl > ul).
        """
        if not value:
            return None
        best = None
        for ttype in (TYPE_IP, TYPE_DOMAIN, TYPE_SUBDOMAIN, TYPE_URL):
            best = _channel_max(best, self._channel_by_target.get((value, ttype)))
        return best

    def _channel_for_parent(self, parent: str | None) -> str | None:
        """Best channel recorded for a parent value (see _best_channel)."""
        return self._best_channel(parent)

    def _ip_in_t_range(self, ip: str) -> bool:
        """True if a bare IP falls within the explicit -t IP/CIDR ranges.

        Unconditional range check (independent of ip_scope mode) — used for the
        host-authorization promotion: a dl/ul-derived IP that lands inside a -t
        range is owned address space, so host-class scanning is authorized.
        """
        nets = self._authorized_ip_networks()
        if not nets:
            return False
        try:
            addr = ipaddress.ip_address(ip.split("/")[0])
        except ValueError:
            return False
        return any(addr.version == n.version and addr in n for n in nets)

    def _host_authorized_ip(self, ip: str) -> bool:
        """May a HOST-class module scan this bare IP?

        Yes if its authorization traces to -t (channel == t), or it falls inside
        a -t range (ownership promotion). A dl/ul-only IP on shared infra is NOT
        host-authorized — that is the whole point of the model.
        """
        if self._best_channel(ip) == CHANNEL_TARGET:
            return True
        return self._ip_in_t_range(ip)

    def _host_authorized_name(self, host: str,
                              host_to_ips: dict | None = None) -> bool:
        """May a HOST-class module scan this hostname?

        Yes if the name came in via -t (channel == t), or every IP it resolves to
        falls inside a -t range (ownership promotion). Fail-closed: a name that
        resolves to nothing known, or to any out-of-range IP, is not authorized.
        """
        if self._best_channel(host) == CHANNEL_TARGET:
            return True
        if host_to_ips is None:
            host_to_ips = self.get_hostname_to_ips()
        ips = host_to_ips.get(host, [])
        if not ips:
            return False
        return all(self._ip_in_t_range(ip) for ip in ips)

    def _authorization_channel(self, target: str, target_type: str,
                               host_to_ips: dict | None = None) -> str | None:
        """The scanning ceiling for a target, for display/audit (NOT a new gate).

        Returns CHANNEL_TARGET ("t") when a HOST-class module is authorized to
        scan this target — it came in via -t, or a -d/-url asset was ownership-
        promoted into a -t range. Otherwise the name-safe channel it traces to
        ("dl"/"ul"), or None for an unauthorized lead. Mirrors the export gate
        (_host_authorized_ip / _host_authorized_name) so the value the viewer
        shows matches what actually gets port-scanned, including promotion.
        """
        if target_type == TYPE_IP:
            if self._host_authorized_ip(target):
                return CHANNEL_TARGET
        elif target_type in (TYPE_DOMAIN, TYPE_SUBDOMAIN):
            if self._host_authorized_name(target, host_to_ips):
                return CHANNEL_TARGET
        return self._best_channel(target)

    def _is_in_scope(self, target: str, target_type: str) -> bool:
        """Membership check against the in-scope set for a target's type."""
        if target_type == TYPE_IP:
            return target in self._in_scope_ips
        if target_type == TYPE_URL:
            return target in self._in_scope_urls
        if target_type in (TYPE_DOMAIN, TYPE_SUBDOMAIN):
            return target in self._in_scope_domains
        return False

    def _is_parent_in_scope(self, parent: str | None) -> bool:
        """Check if a parent value is already in one of the in-scope sets.

        Excluded parents — even if explicit — never count as in-scope.
        """
        if not parent:
            return False
        # Determine likely type for exclusion check (heuristic — parent
        # could be an IP, domain, or URL string)
        if "://" in parent:
            ptype = TYPE_URL
        elif _classify_target(parent) == TYPE_IP:
            ptype = TYPE_IP
        else:
            ptype = TYPE_DOMAIN
        if self.is_excluded(parent, ptype):
            return False

        if parent in self._in_scope_ips:
            return True
        if parent in self._in_scope_domains:
            return True
        if parent in self._in_scope_urls:
            return True
        if parent in self._explicit_ips:
            return True
        if parent in self._explicit_domains:
            return True
        if parent in self._explicit_urls:
            return True
        return False

    def _is_third_party_name(self, target: str, target_type: str) -> bool:
        """A NAME target (URL host / domain / subdomain) that must not inherit
        ACTIVE-scan scope from a redirect/crawl parent.

        Two signals:
          #1  a known identity/SaaS provider host (_THIRD_PARTY_SUFFIXES) — never
              the customer's asset, e.g. login.microsoftonline.com; and
          #2  a host under NONE of the operator's explicit name anchors (the -t/-d
              domains AND the hosts of explicit -url targets, each owning itself +
              subdomains) — a cross-domain redirect/crawl target.
        Explicit targets are authorized earlier (this gate never sees them), and a
        run always has explicit scope, so #2 DEFAULT-DENIES: a derived NAME that
        matches no owned anchor is third-party even when no -d was given. (The old
        code failed OPEN with no -d — a redirect from a -url/-t-only run dragged an
        unlisted domain, e.g. *.facebook.com reached via a DNS record, into active
        scope and e.g. dns_security's DMARC checks.) IPs return False — their
        authorization is the ip_scope axis, not this.
        """
        if target_type == TYPE_IP:
            return False
        host = target
        if target_type == TYPE_URL:
            try:
                host = urlparse(target).hostname or ""
            except ValueError:
                return False
        host = (host or "").lower().rstrip(".")
        if not host:
            return False
        for suf in _THIRD_PARTY_SUFFIXES:
            if host == suf or host.endswith("." + suf):
                return True
        # Owned name anchors: explicit -d/-t domains + explicit -url hosts. A host
        # under any of them is ours; a host under none is third-party (default
        # deny), regardless of whether -d was supplied.
        for d in (self._explicit_domains | self._owned_url_hosts()):
            d = d.lower().rstrip(".")
            if host == d or host.endswith("." + d):
                return False
        return True

    def _owned_url_hosts(self) -> set:
        """Hostnames of explicit -url targets (lowercased). Owned name anchors for
        the third-party gate, so a -url-only run (no -d) still has a name boundary
        and a cross-domain redirect isn't auto-authorized. Each owns itself + its
        subdomains (see _is_third_party_name)."""
        hosts = set()
        for u in self._explicit_urls:
            try:
                h = (urlparse(u).hostname or "").lower().rstrip(".")
            except ValueError:
                continue
            if h:
                hosts.add(h)
        return hosts

    def _resolve_in_scope(self, target: str, target_type: str, parent: str | None) -> bool:
        """Determine if a target should be in-scope based on parent chain.

        A target is in-scope if:
        - It's explicitly provided by the user
        - Its parent is in-scope (cascading inheritance)
        - It's a subdomain of an explicit domain
        - It's a URL whose host is in-scope

        Exclusions always win — an excluded target is never in-scope, even if
        explicitly provided or inherited.
        """
        if self.is_excluded(target, target_type):
            return False

        # Explicit targets are always in scope
        if target_type == TYPE_IP and target in self._explicit_ips:
            return True
        # A discovered bare IP inside an explicit -t CIDR is owned address space
        # (e.g. a host found alive by scanning the range). Such IPs are logged
        # with the target-FILE path as their parent, which is not itself in-scope,
        # so without this they never enter _in_scope_ips and their open ports are
        # silently dropped from the strict host-only exports that feed the
        # service-audit modules (ssh_audit_scan/snmp_sweep/smtp_security) and
        # targeted port re-scans. _ip_in_t_range is the same -t membership check
        # _host_authorized_ip already uses to authorize scanning them.
        if target_type == TYPE_IP and self._ip_in_t_range(target):
            return True
        if target_type == TYPE_DOMAIN and target in self._explicit_domains:
            return True
        if target_type == TYPE_URL and target in self._explicit_urls:
            return True

        # Parent chain: if parent is in-scope, this target inherits — UNLESS the
        # target is a third-party NAME (an identity/SaaS provider host, or a host
        # under none of the explicit -t/-d domains). Such redirect/crawl targets
        # (e.g. an M365 SSO redirect from an in-scope host) are logged for audit
        # but NOT authorized for active scanning: authorization comes from -t/-d,
        # not from a redirect.
        # A DERIVED private/non-routable IP is never in-scope via inheritance: a
        # hostname resolving to an RFC1918/loopback/CGNAT address is internal-DNS
        # leakage / split-horizon, not an authorized external target, and the
        # target-file exports already strip private IPs (see _scoped_ip_set). An
        # explicit private -t IP is unaffected — it returned True above at
        # _explicit_ips / _ip_in_t_range before reaching here.
        if (target_type == TYPE_IP and _is_private_ip(target)):
            return False
        if self._is_parent_in_scope(parent) and not self._is_third_party_name(target, target_type):
            return True

        # Subdomain of explicit domain
        if target_type in (TYPE_DOMAIN, TYPE_SUBDOMAIN):
            for domain in self._explicit_domains:
                if target.endswith("." + domain):
                    return True

        # URL whose host is in-scope
        if target_type == TYPE_URL:
            try:
                host = urlparse(target).hostname
                if not host:
                    return False
                if (host in self._in_scope_ips or host in self._in_scope_domains
                        or host in self._explicit_ips or host in self._explicit_domains):
                    return True
                for domain in self._explicit_domains:
                    if host.endswith("." + domain):
                        return True
            except Exception:
                pass

        return False

    def seed_user_inputs(self, targets_file: str | None, domains_file: str | None,
                         urls_file: str | None):
        """Register user-provided inputs as explicit-scope targets."""
        now = datetime.now(timezone.utc).isoformat()

        if targets_file and os.path.exists(targets_file):
            with open(targets_file) as f:
                for line in f:
                    t = line.strip()
                    if not t or t.startswith("#"):
                        continue
                    ttype = _classify_target(t)
                    if ttype == TYPE_IP:
                        self._explicit_ips.add(t)
                    elif ttype == TYPE_DOMAIN:
                        self._explicit_domains.add(t)
                    key = self._key(t, ttype)
                    self._set_channel(t, ttype, CHANNEL_TARGET)
                    if key not in self._seen:
                        self._seen.add(key)
                        self._add_to_all(t, ttype)
                        self._add_to_in_scope(t, ttype)
                        self._write_entry({
                            "target": t,
                            "type": ttype,
                            "source": "user_input",
                            "scope": SCOPE_EXPLICIT,
                            "channel": CHANNEL_TARGET,
                            "discovered_at": now,
                            "parent": None,
                        })

        if domains_file and os.path.exists(domains_file):
            with open(domains_file) as f:
                for line in f:
                    d = line.strip()
                    if not d or d.startswith("#"):
                        continue
                    self._explicit_domains.add(d)
                    key = self._key(d, TYPE_DOMAIN)
                    self._set_channel(d, TYPE_DOMAIN, CHANNEL_DOMAIN)
                    if key not in self._seen:
                        self._seen.add(key)
                        self._add_to_all(d, TYPE_DOMAIN)
                        self._add_to_in_scope(d, TYPE_DOMAIN)
                        self._write_entry({
                            "target": d,
                            "type": TYPE_DOMAIN,
                            "source": "user_input",
                            "scope": SCOPE_EXPLICIT,
                            "channel": CHANNEL_DOMAIN,
                            "discovered_at": now,
                            "parent": None,
                        })

        if urls_file and os.path.exists(urls_file):
            with open(urls_file) as f:
                for line in f:
                    for u in normalize_user_url(line):
                        self._explicit_urls.add(u)
                        key = self._key(u, TYPE_URL)
                        self._set_channel(u, TYPE_URL, CHANNEL_URL)
                        if key not in self._seen:
                            self._seen.add(key)
                            self._add_to_all(u, TYPE_URL)
                            self._add_to_in_scope(u, TYPE_URL)
                            self._write_entry({
                                "target": u,
                                "type": TYPE_URL,
                                "source": "user_input",
                                "scope": SCOPE_EXPLICIT,
                                "channel": CHANNEL_URL,
                                "discovered_at": now,
                                "parent": None,
                            })

    def seed_exclusions(self, exclusions_file: str | None):
        """Load an exclusion file. Entries here are filtered from all
        exports and prevent in-scope status. Supported formats per line:

          - bare IP                  e.g. 10.0.0.5
          - CIDR                     e.g. 10.0.0.0/24
          - bare hostname/domain     e.g. legacy.example.com
                                     (matches itself AND any subdomain)
          - "*.domain"               e.g. *.staging.example.com
                                     (matches subdomains only, not the bare domain)
          - URL                      e.g. https://x.example.com/admin
                                     (exact match only)
          - blank lines and lines starting with # are ignored
        """
        if not exclusions_file or not os.path.exists(exclusions_file):
            return
        entries = []
        with open(exclusions_file) as f:
            for raw in f:
                entry = raw.strip()
                if entry and not entry.startswith("#"):
                    entries.append(entry)
        loaded = self._seed_exclusion_entries(entries, persist=True)
        if loaded:
            print(f"[*] Loaded {loaded} exclusions from {exclusions_file}")

    def seed_persisted_exclusions(self) -> int:
        """Re-seed exclusion rules a prior run persisted to scan.db, so a
        --continue/--resume honors them even when --exclude isn't re-passed.

        MUST run BEFORE load_from_disk() so the scope fixpoint sees the
        exclusions — otherwise previously-excluded targets re-enter scope.
        Returns the number of rules re-seeded.
        """
        if self._db is None:
            return 0
        try:
            entries = self._db.load_exclusions()
        except Exception as e:
            logger.warning("could not load persisted exclusions from scan.db: %s", e)
            return 0
        if not entries:
            return 0
        loaded = self._seed_exclusion_entries(entries, persist=False)
        if loaded:
            logger.info("Re-seeded %d persisted exclusion rule(s) from scan.db", loaded)
            print(f"[*] Re-seeded {loaded} exclusion rule(s) persisted by a prior run")
        return loaded

    def _seed_exclusion_entries(self, entries, *, persist: bool) -> int:
        """Parse raw --exclude rule lines into the exclusion sets, re-apply them
        to already-seeded entries (exclusions win), and — when ``persist`` —
        save them to scan.db so continue/resume can reload them."""
        import ipaddress

        loaded = 0
        for entry in entries:
            if not entry or entry.startswith("#"):
                continue

            # URL — exact match only
            if "://" in entry:
                self._excluded_urls.add(entry)
                loaded += 1
                continue

            # Wildcard hostname like *.foo.com — subdomains only
            if entry.startswith("*."):
                base = entry[2:]
                if base:
                    self._excluded_domain_subs_only.add(base)
                    loaded += 1
                continue

            # IP / CIDR
            if "/" in entry:
                try:
                    self._excluded_networks.append(ipaddress.ip_network(entry, strict=False))
                    loaded += 1
                    continue
                except ValueError:
                    pass

            ttype = _classify_target(entry)
            if ttype == TYPE_IP:
                self._excluded_ips.add(entry)
                try:
                    # Single IPs become /32 (or /128) networks for fast lookup
                    self._excluded_networks.append(ipaddress.ip_network(entry, strict=False))
                except ValueError:
                    pass
            else:
                # Plain domain — excludes the domain AND any subdomain
                self._excluded_domains.add(entry)
            loaded += 1

        # Persist the raw rules so --continue/--resume honor them without a
        # re-passed --exclude. Best-effort — DB issues must never break scope.
        if persist and self._db is not None and entries:
            try:
                self._db.save_exclusions(entries)
            except Exception as e:
                logger.warning("could not persist exclusions to scan.db: %s", e)

        if loaded:
            logger.info(
                "Seeded %d exclusions (ips=%d nets=%d domains=%d wildcards=%d urls=%d)",
                loaded,
                len(self._excluded_ips), len(self._excluded_networks),
                len(self._excluded_domains), len(self._excluded_domain_subs_only),
                len(self._excluded_urls),
            )

        # Exclusions win over user input: demote any already-seeded explicit
        # entries that now match the exclusion list.
        self._apply_exclusions_to_existing()
        return loaded

    def _apply_exclusions_to_existing(self):
        """Remove already-seeded entries from in-scope/explicit sets if they
        now match an exclusion. Called after seed_exclusions to handle the
        case where -t/--exclude were both passed and -t was processed first.
        """
        for ip in list(self._explicit_ips):
            if self.is_excluded(ip, TYPE_IP):
                self._in_scope_ips.discard(ip)
                logger.warning("Explicit IP %s is in exclusion list — excluded", ip)
                print(f"[!] Explicit IP {ip} matches an exclusion — skipping")

        for d in list(self._explicit_domains):
            if self.is_excluded(d, TYPE_DOMAIN):
                self._in_scope_domains.discard(d)
                logger.warning("Explicit domain %s is in exclusion list — excluded", d)
                print(f"[!] Explicit domain {d} matches an exclusion — skipping")

        for u in list(self._explicit_urls):
            if self.is_excluded(u, TYPE_URL):
                self._in_scope_urls.discard(u)
                logger.warning("Explicit URL %s is in exclusion list — excluded", u)
                print(f"[!] Explicit URL {u} matches an exclusion — skipping")

    def _demote_internal_only_hosts(self):
        """Drop DERIVED hostnames that resolve ONLY to private/non-routable IPs
        from the in-scope set.

        A subdomain of an explicit domain is name-safe in-scope by default. But
        if every IP it resolves to is RFC1918/loopback/CGNAT it is an
        internal-only name (split-horizon / internal-DNS leakage), not an
        external target: nothing external is ever scanned through it, so leaving
        it in-scope over-reports coverage (e.g. summary's "Subdomains In-Scope").
        The IP itself is already out of scope (see _resolve_in_scope); this is the
        NAME-level companion. Explicit -d domains are never demoted (the operator
        authorized them explicitly). A name with no resolved IPs yet is left
        alone. Runs at finalize (sync_scope_to_db), when the host->IP map is
        complete.
        """
        host_to_ips = self.get_hostname_to_ips()
        for host in list(self._in_scope_domains):
            if host in self._explicit_domains:
                continue
            ips = host_to_ips.get(host)
            if ips and all(_is_private_ip(ip) for ip in ips):
                self._in_scope_domains.discard(host)
                logger.info(
                    "host %s resolves only to private IP(s) %s — out of scope "
                    "(internal-only name)", host, ips)

    def is_excluded(self, target: str, target_type: str) -> bool:
        """Return True if the target matches any exclusion rule."""
        import ipaddress

        if target_type == TYPE_IP:
            if "/" in target:
                # CIDR — exclude only if the whole network is contained in
                # an excluded network. Conservative.
                try:
                    net = ipaddress.ip_network(target, strict=False)
                    for excl in self._excluded_networks:
                        # subnet_of raises TypeError across families; skip
                        # cross-family comparisons (a v4 net can't be in a v6 net).
                        if net.version == excl.version and net.subnet_of(excl):
                            return True
                except ValueError:
                    return False
                return False
            try:
                addr = ipaddress.ip_address(target)
                for excl in self._excluded_networks:
                    if addr.version == excl.version and addr in excl:
                        return True
            except ValueError:
                return False
            return False

        if target_type in (TYPE_DOMAIN, TYPE_SUBDOMAIN):
            t = target.lower()
            # Plain-name exclusion: matches itself AND any subdomain
            for d in self._excluded_domains:
                d = d.lower()
                if t == d or t.endswith("." + d):
                    return True
            # Wildcard exclusion: matches subdomains only
            for d in self._excluded_domain_subs_only:
                d = d.lower()
                if t.endswith("." + d):
                    return True
            return False

        if target_type == TYPE_URL:
            if target in self._excluded_urls:
                return True
            # Also exclude if the URL's host is excluded
            try:
                host = urlparse(target).hostname
                if host and self.is_excluded(host, TYPE_DOMAIN):
                    return True
                if host and self.is_excluded(host, TYPE_IP):
                    return True
            except Exception:
                pass
            return False

        return False

    def log_discovery(self, target: str, target_type: str, source_module: str,
                      parent: str | None = None):
        """Log a single discovered target. Deduplicates by target+type.

        Thread-safe: acquires lock for the entire operation to prevent races
        during parallel group execution.
        """
        # Drop bbot's synthetic `_wildcard.*` catch-all marker before it can enter
        # the domain sets — otherwise it propagates into every export (domains,
        # then a resolved IP->name mapping, then synthesized URLs) and scanners
        # waste effort on a host that does not exist.
        if _is_wildcard_marker(target):
            logger.debug("Skipping wildcard marker (%s): %s", target_type, target)
            return

        with self._lock:
            if parent:
                self._parents_by_target.setdefault(
                    (target, target_type), set()).add(parent)

            key = self._key(target, target_type)
            if key in self._seen:
                return
            self._seen.add(key)

            scope = self._classify_scope(target, target_type)
            self._add_to_all(target, target_type)

            in_scope = (not self.is_excluded(target, target_type) and
                        self._resolve_in_scope(target, target_type, parent))
            if in_scope:
                self._add_to_in_scope(target, target_type)
                # Inherit the parent's authorization channel. Explicit targets
                # already carry a channel from seed time (don't downgrade them);
                # a derived target takes its parent's channel. Leads (no in-scope
                # parent) get no channel and remain host-gated out.
                inherited = self._channel_for_parent(parent)
                if inherited is not None:
                    self._set_channel(target, target_type, inherited)

            # Provenance (source/discovered_at) is recorded centrally in
            # _mirror_entry_to_db, which every write funnels through.
            self._write_entry_unlocked({
                "target": target,
                "type": target_type,
                "source": source_module,
                "scope": scope,
                "channel": self.get_channel(target, target_type),
                "discovered_at": datetime.now(timezone.utc).isoformat(),
                "parent": parent,
            })

    def log_discoveries(self, targets: list[tuple[str, str]], source_module: str,
                        parent: str | None = None):
        """Log multiple discoveries. Each item is (target, target_type)."""
        for target, target_type in targets:
            self.log_discovery(target, target_type, source_module, parent)

    def _classify_scope(self, target: str, target_type: str) -> str:
        """Classify scope for the JSONL entry (audit trail)."""
        if self.is_excluded(target, target_type):
            return SCOPE_EXCLUDED
        if target_type == TYPE_IP and target in self._explicit_ips:
            return SCOPE_EXPLICIT
        if target_type == TYPE_DOMAIN and target in self._explicit_domains:
            return SCOPE_EXPLICIT
        if target_type == TYPE_URL and target in self._explicit_urls:
            return SCOPE_EXPLICIT
        return SCOPE_DERIVED

    def _scoped_ip_targets(self, scope_filter: str,
                           all_set: set | None = None,
                           in_scope_set: set | None = None) -> set:
        """Apply scope_filter + exclusion-carve + private-filter to the IP set.

        Shared by export_targets and export_target_ips so both run the IDENTICAL
        pre-authorization policy (no second implementation to drift). This does
        NOT apply ip_scope authorization — that decision differs per caller
        (hostname-collapse vs bare-IP) and is applied by the caller via
        _ip_authorized / _hostname_ip_authorized.
        """
        all_set = self._all_ips if all_set is None else all_set
        in_scope_set = self._in_scope_ips if in_scope_set is None else in_scope_set
        raw_targets = self._get_filtered_set(all_set, in_scope_set, scope_filter, "ip")
        # Subtract excluded IPs/subnets. Unlike a whole-network containment check,
        # this carves excluded addresses out of a larger in-scope CIDR (splitting
        # it into the surviving sub-networks) rather than exporting the CIDR whole.
        targets = set()
        for t in raw_targets:
            targets.update(_subtract_exclusions(t, self._excluded_networks))
        # Domain/URL-style exclusions can't be handled by network subtraction;
        # still honor a full match for non-IP-shaped entries.
        targets = {t for t in targets if not self.is_excluded(t, TYPE_IP)}
        if _PRIVATE_FILTER_ENABLED:
            private = {t for t in targets if _is_private_ip(t)}
            if private:
                logger.info("Excluded %d private/non-routable IPs from target list", len(private))
                targets -= private
                if not targets and raw_targets:
                    logger.warning(
                        "All %d scoped IP target(s) were private/non-routable and "
                        "filtered out — MonkeyX is external-only, so this run will "
                        "scan no IPs. Provide public targets or scan internally.",
                        len(private))
        return targets

    def export_targets(self, output_path: str, scope_filter: str = "strict",
                       all_set: set | None = None, in_scope_set: set | None = None,
                       host_only: bool = False) -> int:
        """Write IPs/CIDRs to a file, filtered by scope. Returns count written.

        Prefers hostnames over bare IPs where a hostname mapping exists, so that
        tools like nmap record the associated hostname in their output. IPs with
        multiple hostnames are expanded (one line per hostname). IPs with no known
        hostname are written as-is.

        `all_set`/`in_scope_set` override the live ledger sets — parallel-group
        snapshot export passes the frozen snapshot sets here so it runs the
        IDENTICAL exclusion/CIDR-carve/private-filter/ip_scope policy (no second
        implementation).

        `host_only` applies the input-channel gate for HOST-class modules
        (port sweeps, name-blind service probes): only assets authorized at -t
        level — or promoted into a -t range by ownership — survive. A dl/ul-only
        name or IP (name-safe surface on shared infra) is dropped. This layers on
        top of the existing scope_filter/ip_scope checks; it never widens them.
        """
        targets = self._scoped_ip_targets(scope_filter, all_set, in_scope_set)
        ip_to_hosts = self.get_ip_to_hostnames()
        authorized_nets = self._authorized_ip_networks()
        host_to_ips = self.get_hostname_to_ips()
        ip_unauthorized = 0
        channel_gated = 0
        private_named = 0
        output_lines = set()
        for t in targets:
            hostnames = ip_to_hosts.get(t)
            if hostnames:
                # Named target — authorized by name; export the hostname(s).
                # Under strict-resolved, also require the name to resolve within
                # the authorized ranges.
                for h in hostnames:
                    if self.is_excluded(h, TYPE_DOMAIN):
                        continue
                    if not self._hostname_ip_authorized(h, authorized_nets, host_to_ips):
                        continue
                    if host_only and not self._host_authorized_name(h, host_to_ips):
                        channel_gated += 1
                        continue
                    # External-only invariant: a name that resolves to a private/
                    # non-routable IP must not be scanned by name (the scanner
                    # re-resolves h and would hit the internal/metadata IP — the
                    # same reason bare private IPs are filtered). Fail-closed.
                    if _PRIVATE_FILTER_ENABLED and any(
                            _is_private_ip(ip) for ip in (host_to_ips.get(h) or [])):
                        private_named += 1
                        continue
                    output_lines.add(h)
            else:
                # Bare derived IP with no authorized hostname. Under strict
                # ip_scope it must fall within the authorized IP ranges (-t);
                # otherwise it's a traceable-but-unauthorized IP (e.g. shared
                # CDN behind an in-scope name) and must not be actively scanned.
                if not self._ip_authorized(t, authorized_nets):
                    ip_unauthorized += 1
                    continue
                if host_only and not self._host_authorized_ip(t):
                    channel_gated += 1
                    continue
                output_lines.add(t)
        if ip_unauthorized:
            logger.info(
                "ip_scope=strict: excluded %d derived IP(s) outside authorized "
                "ranges (-t) from the target list", ip_unauthorized)
        if channel_gated:
            logger.info(
                "host-scope gate: excluded %d name-safe (-d/-url) asset(s) from a "
                "host-class module's target list", channel_gated)
        if private_named:
            logger.info(
                "Excluded %d name(s) resolving to private/non-routable IPs from "
                "the target list", private_named)
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w") as f:
            for t in sorted(output_lines):
                f.write(t + "\n")
        return len(output_lines)

    def export_host_targets(self, output_path: str, scope_filter: str = "strict",
                            all_set: set | None = None,
                            in_scope_set: set | None = None) -> int:
        """Write the HOST-class scan target file as UNIQUE IPs (collapsed).

        A port scan's result set is a property of the IP, not the vhost, so a
        shared IP that many in-scope names resolve to should be scanned ONCE, not
        once per name. This is the target file fed to HOST-class port scanners
        (nmap/naabu/masscan/ssh_audit_scan/...); NAME/web modules keep reading the
        name-expanded ledger-targets.txt, so vhost/SNI coverage is unaffected.

        Differs from export_targets only in OUTPUT — it emits each authorized IP
        once instead of expanding it to one line per hostname. It applies the
        IDENTICAL scope_filter/exclusion/private/ip_scope + -t host-channel gating.

        Two rules keep the collapse from ever dropping authorized coverage:
          - Multi-IP names (round-robin/GeoDNS): every resolved IP is a distinct
            entry in the scoped IP set, so all are emitted (union) — never one.
          - Unresolved -t names (#1): a name that came in via -t (channel t) but
            has no resolved IP yet is emitted as the bare hostname so nmap still
            scans it (fail-open for owned scope). A name that DID resolve but
            whose IPs were dropped by ip_scope is NOT re-added by name — that
            would defeat strict's intent.
        """
        targets = self._scoped_ip_targets(scope_filter, all_set, in_scope_set)
        ip_to_hosts = self.get_ip_to_hostnames()
        authorized_nets = self._authorized_ip_networks()
        host_to_ips = self.get_hostname_to_ips()
        output_lines: set[str] = set()
        for t in targets:
            hostnames = ip_to_hosts.get(t)
            if hostnames:
                # Named IP — authorized by name. Keep the IP if any of its names
                # survives exclusion + strict-resolved + -t host authorization.
                if any(not self.is_excluded(h, TYPE_DOMAIN)
                       and self._hostname_ip_authorized(h, authorized_nets, host_to_ips)
                       and self._host_authorized_name(h, host_to_ips)
                       for h in hostnames):
                    output_lines.add(t)
            else:
                # Bare derived IP — must pass ip_scope AND -t host authorization.
                if self._ip_authorized(t, authorized_nets) and self._host_authorized_ip(t):
                    output_lines.add(t)

        # #1: unresolved -t names — scan by name so an explicitly-authorized asset
        # that hasn't resolved yet is not silently skipped. Snapshot the channel
        # map to avoid mutation-during-iteration on the parallel-group path.
        for (value, ttype), channel in list(self._channel_by_target.items()):
            if channel != CHANNEL_TARGET or ttype not in (TYPE_DOMAIN, TYPE_SUBDOMAIN):
                continue
            if self.is_excluded(value, ttype) or host_to_ips.get(value):
                continue
            output_lines.add(value)

        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w") as f:
            for t in sorted(output_lines):
                f.write(t + "\n")
        return len(output_lines)

    def export_target_ips(self, output_path: str, scope_filter: str = "strict",
                          all_set: set | None = None, in_scope_set: set | None = None,
                          host_only: bool = False) -> int:
        """Write authorized BARE IPs (for IP-native tools that can't resolve names).

        Sibling of export_targets: same scope_filter + exclusion-carve + private
        filter + ip_scope authorization, but emits the IP itself rather than
        collapsing it to its hostname(s). This is the surface a resolver-less
        enrichment tool (shodan_enrich) may look up — identical to what the
        scanners are authorized to hit, never a superset.

        Format: one line per IP, `ip\thost1,host2` when the ledger knows which
        hostname(s) resolved to it (provenance for record stamping), else `ip`.

        Authorization mirrors export_targets exactly:
          - a named IP is authorized by name (strict/provenance), or must resolve
            within -t ranges under strict-resolved (_hostname_ip_authorized);
          - a bare derived IP must pass _ip_authorized (within -t under strict).
        """
        targets = self._scoped_ip_targets(scope_filter, all_set, in_scope_set)
        ip_to_hosts = self.get_ip_to_hostnames()
        authorized_nets = self._authorized_ip_networks()
        host_to_ips = self.get_hostname_to_ips()
        ip_unauthorized = 0
        channel_gated = 0
        rows: dict[str, list[str]] = {}
        for t in targets:
            hostnames = ip_to_hosts.get(t)
            if hostnames:
                # Named IP — authorized by name (strict-resolved also requires the
                # name to resolve within -t). Keep the authorized names as provenance.
                authed = [h for h in hostnames
                          if not self.is_excluded(h, TYPE_DOMAIN)
                          and self._hostname_ip_authorized(h, authorized_nets, host_to_ips)]
                if host_only:
                    kept = [h for h in authed
                            if self._host_authorized_name(h, host_to_ips)]
                    if authed and not kept:
                        channel_gated += 1
                    authed = kept
                if authed:
                    rows[t] = sorted(authed)
            else:
                # Bare derived IP with no hostname — gate on -t ranges under strict.
                if not self._ip_authorized(t, authorized_nets):
                    ip_unauthorized += 1
                elif host_only and not self._host_authorized_ip(t):
                    channel_gated += 1
                else:
                    rows.setdefault(t, [])
        if ip_unauthorized:
            logger.info(
                "ip_scope=strict: excluded %d derived IP(s) outside authorized "
                "ranges (-t) from the target-IP list", ip_unauthorized)
        if channel_gated:
            logger.info(
                "host-scope gate: excluded %d name-safe (-d/-url) asset(s) from a "
                "host-class module's target-IP list", channel_gated)
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w") as f:
            for ip in sorted(rows):
                hosts = rows[ip]
                if hosts:
                    f.write(f"{ip}\t{','.join(hosts)}\n")
                else:
                    f.write(f"{ip}\n")
        return len(rows)

    def _scoped_url_set(self, scope_filter: str, all_set: set | None,
                        in_scope_set: set | None) -> set:
        """The in-scope URL set after scope_filter + exclusion + private +
        strict-resolved gating. Shared by export_urls and export_urls_live so the
        live file is always a subset of the scoped file (never a superset)."""
        all_set = self._all_urls if all_set is None else all_set
        in_scope_set = self._in_scope_urls if in_scope_set is None else in_scope_set
        targets = self._get_filtered_set(all_set, in_scope_set, scope_filter, "url")
        targets = {t for t in targets if not self.is_excluded(t, TYPE_URL)}
        if _PRIVATE_FILTER_ENABLED:
            private = {t for t in targets if _url_has_private_host(t)}
            if private:
                logger.info("Excluded %d URLs with private/non-routable hosts", len(private))
                targets -= private
        # strict-resolved: drop URLs whose hostname resolves outside -t ranges
        # (or isn't resolved yet). IP-host URLs are gated as bare IPs.
        if self._ip_scope_mode == "strict-resolved":
            authorized_nets = self._authorized_ip_networks()
            if authorized_nets:
                host_to_ips = self.get_hostname_to_ips()
                targets = {t for t in targets
                           if self._url_ip_authorized(t, authorized_nets, host_to_ips)}
        return targets

    def export_urls(self, output_path: str, scope_filter: str = "strict",
                    all_set: set | None = None, in_scope_set: set | None = None) -> int:
        """Write URLs to a file, filtered by scope. Returns count written.

        Applies private IP filtering to URL hostnames to prevent scanning
        internal/non-routable addresses via URL-consuming tools.

        `all_set`/`in_scope_set` override the live ledger sets (snapshot export).
        """
        targets = self._scoped_url_set(scope_filter, all_set, in_scope_set)
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w") as f:
            for t in sorted(targets):
                f.write(t + "\n")
        return len(targets)

    def set_url_prune(self, policy: str, max_per_host: int | None = None):
        """Configure the live-URL export (mirrors set_ip_scope_mode's run-scoped
        config). policy in {off, live, interesting}; invalid -> off."""
        self._url_prune_policy = policy if policy in ("live", "interesting") else "off"
        self._url_prune_max_per_host = max_per_host

    def record_httpx_result(self, url: str, status_code=None):
        """Record that httpx got a response for `url` (feeds --url-prune). Marks
        the URL live (with its status) and its host:port as covered.

        THREAD-SAFETY INVARIANT (load-bearing, undocumented until now): this and
        the export_* readers mutate/read _httpx_*/scope sets WITHOUT _lock. That
        is safe ONLY because every ledger write happens on the MAIN thread,
        serially — parallel-group workers (ThreadPoolExecutor) run tool
        subprocesses only, and _extract_discoveries/record_httpx_result/
        record_coverage/exports all run after `as_completed` on the main thread
        (_BACKGROUND_MODULES is empty, so no module runs in the background
        executor). If a module ever calls back into the ledger from a worker
        thread, or _BACKGROUND_MODULES is repopulated, this and the exporters
        must take _lock (as log_discovery/log_port/snapshot already do)."""
        key = _url_cov_key(url)
        if not key:
            return
        self._httpx_covered.add(key)
        norm = _norm_url(url)
        if norm:
            try:
                self._httpx_live[norm] = int(status_code) if status_code is not None else 0
            except (TypeError, ValueError):
                self._httpx_live[norm] = 0

    def export_urls_live(self, output_path: str, scope_filter: str = "strict",
                         policy: str = "live", max_per_host: int | None = None,
                         all_set: set | None = None, in_scope_set: set | None = None) -> int:
        """Write the httpx-live SUBSET of the scoped URLs — the list heavy web
        scanners (nuclei/gowitness/ffuf/feroxbuster) consume so they aren't fed
        thousands of dead historical/crawled URLs.

        Fail-open per host:port: a URL on a host httpx never answered on is KEPT
        (httpx hasn't covered it — unknown != dead). Only on a host:port httpx DID
        respond for do we drop the URLs it didn't confirm live. So with no httpx
        data the output equals export_urls; pruning only ever removes URLs proven
        dead-among-live-neighbours.

        policy: "live" keeps any httpx response; "interesting" keeps 2xx/3xx/401/403.
        max_per_host: optional cap on URLs emitted per host:port (highest-signal
        kept is not attempted — just a deterministic sorted slice).
        """
        targets = self._scoped_url_set(scope_filter, all_set, in_scope_set)

        def _keep(u: str) -> bool:
            key = _url_cov_key(u)
            if key is None or key not in self._httpx_covered:
                return True  # host:port not probed by httpx -> fail-open
            status = self._httpx_live.get(_norm_url(u))
            if status is None:
                return False  # host covered, this URL not among the live ones
            if policy == "interesting":
                return status in _INTERESTING_STATUSES
            return True  # "live": any recorded response

        kept = [u for u in targets if _keep(u)]

        if max_per_host and max_per_host > 0:
            per_host: dict[str, int] = {}
            capped = []
            for u in sorted(kept):
                key = _url_cov_key(u) or u
                if per_host.get(key, 0) >= max_per_host:
                    continue
                per_host[key] = per_host.get(key, 0) + 1
                capped.append(u)
            kept = capped

        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w") as f:
            for t in sorted(kept):
                f.write(t + "\n")
        return len(kept)

    def export_domains(self, output_path: str, scope_filter: str = "strict",
                       all_set: set | None = None, in_scope_set: set | None = None) -> int:
        """Write domains + subdomains to a file, filtered by scope. Returns count written.

        `all_set`/`in_scope_set` override the live ledger sets (snapshot export).
        """
        all_set = self._all_domains if all_set is None else all_set
        in_scope_set = self._in_scope_domains if in_scope_set is None else in_scope_set
        targets = self._get_filtered_set(all_set, in_scope_set, scope_filter, "domain")
        targets = {t for t in targets if not self.is_excluded(t, TYPE_DOMAIN)}
        # strict-resolved: drop DERIVED names that resolve outside -t ranges (or
        # aren't resolved yet). The domainlist feeds discovery/resolution modules
        # (subfinder, dnsx), not active scanners, so explicit user-provided
        # domains are kept (you still want to resolve/enumerate them); active-scan
        # confinement is enforced on the target/URL exports.
        if self._ip_scope_mode == "strict-resolved":
            authorized_nets = self._authorized_ip_networks()
            if authorized_nets:
                host_to_ips = self.get_hostname_to_ips()
                targets = {
                    t for t in targets
                    if t in self._explicit_domains
                    or self._hostname_ip_authorized(t, authorized_nets, host_to_ips)
                }
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w") as f:
            for t in sorted(targets):
                f.write(t + "\n")
        return len(targets)

    def export_root_domains(self, output_path: str) -> int:
        """Write only user-provided explicit domains (no discovered subdomains).

        Used by bruteforce modules (puredns) that should only target root domains,
        not feed their own output back as input.
        """
        targets = {d for d in self._explicit_domains if not self.is_excluded(d, TYPE_DOMAIN)}
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w") as f:
            for t in sorted(targets):
                f.write(t + "\n")
        return len(targets)

    def get_ip_to_hostnames(self) -> dict[str, list[str]]:
        """Return {ip: [hostname, ...]} derived from logged IP entries' parents.

        Built from `_parents_by_target` for IP entries whose parents are known
        domains or subdomains. Used by URL synthesis to know which hostnames
        map to a given IP.
        """
        result: dict[str, set[str]] = {}
        for (target, ttype), parents in self._parents_by_target.items():
            if ttype != TYPE_IP:
                continue
            for parent in parents:
                if parent in self._all_domains:
                    result.setdefault(target, set()).add(parent)
        return {ip: sorted(names) for ip, names in result.items()}

    def get_hostname_to_ips(self) -> dict[str, list[str]]:
        """Return {hostname: [ip, ...]} — symmetric inverse of get_ip_to_hostnames."""
        result: dict[str, set[str]] = {}
        for (target, ttype), parents in self._parents_by_target.items():
            if ttype != TYPE_IP:
                continue
            for parent in parents:
                if parent in self._all_domains:
                    result.setdefault(parent, set()).add(target)
        return {host: sorted(ips) for host, ips in result.items()}

    def get_url_hosts(self) -> set[str]:
        """Return the set of hosts (IPs and hostnames) that already have at
        least one URL entry in the ledger. Used to skip default-port synthesis
        for hostnames whose IPs already have nmap-derived URL data.
        """
        from urllib.parse import urlparse
        hosts = set()
        for url in self._all_urls:
            try:
                h = urlparse(url).hostname
                if h:
                    hosts.add(h)
            except Exception:
                continue
        return hosts

    def log_mx_domain(self, domain: str, mx_hosts: list[str]):
        """Record that a domain has MX records (mail infrastructure)."""
        if domain and mx_hosts and domain not in self._mx_domains:
            self._mx_domains[domain] = mx_hosts
            self._write_entry({
                "target": domain,
                "type": "mx_domain",
                "source": "dnsx",
                "scope": SCOPE_DERIVED,
                "discovered_at": datetime.now(timezone.utc).isoformat(),
                "parent": None,
                "mx_hosts": mx_hosts,
            })

    def get_mx_domains(self) -> dict[str, list[str]]:
        """Return {domain: [mx_host, ...]} for all domains with MX records."""
        return dict(self._mx_domains)

    def export_mx_domains(self, output_path: str, scope_filter: str = "strict") -> int:
        """Write domains with MX records to a file. Returns count written.

        Gated like every other exporter so ledger-mx-domains.txt (consumed by
        analyze._find_mx_domains and the SMTP modules) can never be a superset
        of what the scanners are allowed to touch:
        - exclusions ALWAYS win (the firm cross-exporter invariant);
        - under strict/warn, a domain that is affirmatively out of scope (known
          to the ledger but not in-scope) is dropped. A domain the ledger never
          tracked as a discovery has unknown scope and is kept (fail-open) — MX
          domains are logged straight from dnsx and may not appear in the domain
          sets, and dropping those would silently regress the analyze consumer.
        """
        def _keep(domain: str) -> bool:
            if self.is_excluded(domain, TYPE_DOMAIN):
                return False
            if scope_filter != "none" and domain in self._all_domains \
                    and domain not in self._in_scope_domains:
                return False
            return True

        domains = sorted(d for d in self._mx_domains if _keep(d))
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w") as f:
            for domain in domains:
                f.write(domain + "\n")
        return len(domains)

    # ------------------------------------------------------------------
    # Port / service tracking
    # ------------------------------------------------------------------

    def log_port(self, host: str, port: int, proto: str, source_module: str,
                 service: str = "", product: str = "", version: str = "",
                 banner: str = "", state: str = "open", tunnel: str = "",
                 reason: str = "", method: str = "", confidence: str = "",
                 extra: str = ""):
        """Log an open port with optional service info. Last-write-wins for service details.

        Dedup key is (host, port, proto). If an entry already exists and the new
        call provides more service detail (non-empty service/product/version), the
        in-memory record is updated and a new JSONL line is appended (for audit).

        Thread-safe: acquires lock for the entire operation.
        """
        port = int(port)
        with self._lock:
            key = (port, proto)
            host_ports = self._ports.setdefault(host, {})
            existing = host_ports.get(key)

            new_info = {
                "service": service,
                "product": product,
                "version": version,
                "banner": banner,
                "tunnel": tunnel,
                "reason": reason,
                "method": method,
                "confidence": confidence,
                "extra": extra,
                "state": state,
                "source": source_module,
            }

            if existing:
                has_new_detail = (
                    (service and not existing.get("service"))
                    or (product and not existing.get("product"))
                    or (version and not existing.get("version"))
                    or (banner and not existing.get("banner"))
                    or (tunnel and not existing.get("tunnel"))
                )
                if not has_new_detail:
                    return
                existing.update({k: v for k, v in new_info.items() if v})
            else:
                host_ports[key] = new_info

            self._write_entry_unlocked({
                "target": host,
                "type": TYPE_PORT,
                "port": port,
                "proto": proto,
                "state": state,
                "service": service,
                "product": product,
                "version": version,
                "banner": banner,
                "tunnel": tunnel,
                "reason": reason,
                "method": method,
                "confidence": confidence,
                "extra": extra,
                "source": source_module,
                "discovered_at": datetime.now(timezone.utc).isoformat(),
            })

    def log_ports(self, entries: list[dict], source_module: str):
        """Log multiple ports. Each dict must have: host, port, proto.
        Optional: service, product, version, banner, state, tunnel, reason,
        method, confidence, extra."""
        for entry in entries:
            self.log_port(
                host=entry["host"],
                port=entry["port"],
                proto=entry["proto"],
                source_module=source_module,
                service=entry.get("service", ""),
                product=entry.get("product", ""),
                version=entry.get("version", ""),
                banner=entry.get("banner", ""),
                state=entry.get("state", "open"),
                tunnel=entry.get("tunnel", ""),
                reason=entry.get("reason", ""),
                method=entry.get("method", ""),
                confidence=entry.get("confidence", ""),
                extra=entry.get("extra", ""),
            )

    def get_ports_for_host(self, host: str) -> dict[tuple[int, str], dict]:
        """Return {(port, proto): info_dict} for a specific host."""
        return dict(self._ports.get(host, {}))

    def get_all_open_ports(self) -> dict[str, list[tuple[int, str]]]:
        """Return {host: [(port, proto), ...]} for all hosts with open ports."""
        return {
            host: sorted(ports.keys())
            for host, ports in self._ports.items()
            if ports
        }

    def get_port_stats(self) -> dict:
        """Return summary stats for coverage reporting."""
        total_ports = sum(len(p) for p in self._ports.values())
        with_service = sum(
            1 for ports in self._ports.values()
            for info in ports.values()
            if info.get("service")
        )
        with_version = sum(
            1 for ports in self._ports.values()
            for info in ports.values()
            if info.get("version")
        )
        return {
            "hosts_with_ports": len(self._ports),
            "total_open_ports": total_ports,
            "ports_with_service_id": with_service,
            "ports_without_service_id": total_ports - with_service,
            "ports_with_version": with_version,
        }

    def export_open_ports(self, output_path: str, scope_filter: str = "strict",
                           host_only: bool = False, proto_filter: str = "tcp") -> int:
        """Write open ports in nmap-consumable format: one line per host.

        Format: ip port1,port2,port3 (tab-separated). Emits ports of one protocol
        (`proto_filter`, default "tcp") — the per-host list is proto-less, so TCP
        and UDP go to separate files. UDP is what SNMP (161) needs; TCP feeds the
        nmap re-scan / ssh/smtp consumers.
        Only includes in-scope hosts when scope_filter is strict.
        `host_only` additionally drops hosts not authorized at -t level (the
        per-host port list feeds targeted nmap re-scans, a HOST-class action).
        Returns number of hosts written.
        """
        if scope_filter == "strict":
            allowed_hosts = self._in_scope_ips
        else:
            allowed_hosts = self._all_ips

        count = 0
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w") as f:
            for host in sorted(self._ports):
                if host not in allowed_hosts:
                    continue
                if self.is_excluded(host, TYPE_IP):
                    continue
                if host_only and not self._host_authorized_ip(host):
                    continue
                ports = sorted(p for p, proto in self._ports[host] if proto == proto_filter)
                if ports:
                    f.write(f"{host}\t{','.join(str(p) for p in ports)}\n")
                    count += 1
        return count

    def export_port_list(self, output_path: str, proto: str = "tcp",
                         scope_filter: str = "strict",
                         host_only: bool = False) -> int:
        """Write a deduplicated sorted list of all open ports (one per line).

        Useful for constructing a targeted nmap -p flag from masscan results.
        `host_only` restricts the union to -t-authorized hosts (see above).
        Returns number of unique ports written.
        """
        if scope_filter == "strict":
            allowed_hosts = self._in_scope_ips
        else:
            allowed_hosts = self._all_ips

        all_ports: set[int] = set()
        for host, ports in self._ports.items():
            if host not in allowed_hosts:
                continue
            if self.is_excluded(host, TYPE_IP):
                continue
            if host_only and not self._host_authorized_ip(host):
                continue
            for (port, p), _ in ports.items():
                if p == proto:
                    all_ports.add(port)

        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w") as f:
            for port in sorted(all_ports):
                f.write(f"{port}\n")
        return len(all_ports)

    def export_live_host_targets(self, output_path: str, proto: str = "tcp",
                                 scope_filter: str = "strict",
                                 host_only: bool = False) -> int:
        """Write one IP per line for in-scope hosts with >=1 open `proto` port.

        The 'live hosts' a sweep (masscan/naabu) found responsive, so a follow-up
        nmap verify scans only those instead of the whole range. Same scope/
        host_only/exclusion filters as export_port_list. Returns host count.
        """
        allowed_hosts = self._in_scope_ips if scope_filter == "strict" else self._all_ips
        hosts = []
        for host, ports in self._ports.items():
            if host not in allowed_hosts:
                continue
            if self.is_excluded(host, TYPE_IP):
                continue
            if host_only and not self._host_authorized_ip(host):
                continue
            if any(p == proto for (_port, p) in ports.keys()):
                hosts.append(host)
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w") as f:
            for h in sorted(hosts):
                f.write(h + "\n")
        return len(hosts)

    def get_in_scope_hostnames(self) -> list[str]:
        """Return the in-scope domain/subdomain set as a sorted list."""
        return sorted(self._in_scope_domains)

    def scope_summary(self) -> dict:
        """Summarize in-scope assets by authorization channel, for the operator.

        Returns a dict with per-channel counts of in-scope IPs/hosts/URLs plus
        exclusion and lead (discovered-but-unauthorized) counts. Used by the
        start-of-run scope echo and --confirm-scope so the operator can confirm
        intent before a fleet spins up:
          {
            "host_full":  {"ips": N, "hosts": N, "urls": N},   # -t (host-scannable)
            "name_safe":  {"ips": N, "hosts": N, "urls": N},   # -d/-url (name only)
            "excluded":   N,
            "leads":      N,   # discovered, no channel (reported, not scanned)
          }
        """
        host_full = {"ips": 0, "hosts": 0, "urls": 0}
        name_safe = {"ips": 0, "hosts": 0, "urls": 0}
        leads = 0

        def _bucket(value, kind):
            nonlocal leads
            ch = self._best_channel(value)
            if ch == CHANNEL_TARGET:
                host_full[kind] += 1
            elif ch in (CHANNEL_DOMAIN, CHANNEL_URL):
                name_safe[kind] += 1
            else:
                leads += 1

        for ip in self._in_scope_ips:
            _bucket(ip, "ips")
        for host in self._in_scope_domains:
            _bucket(host, "hosts")
        for url in self._in_scope_urls:
            _bucket(url, "urls")

        excluded = (len(self._excluded_ips) + len(self._excluded_domains)
                    + len(self._excluded_domain_subs_only) + len(self._excluded_urls))

        return {"host_full": host_full, "name_safe": name_safe,
                "excluded": excluded, "leads": leads}

    def synthesize_name_urls(self, only_channels: tuple | None = None) -> int:
        """Seed http:// + https:// URLs for in-scope hostnames (name-safe).

        This is the name-addressed alternative to nmap-driven web discovery: it
        gives NAME-class web modules (httpx/nuclei/gowitness/…) a URL surface for
        hosts that will NOT be port-scanned — a -d/-url host on shared infra. The
        URLs are addressed by hostname, so on shared IPs they route to the client
        tenant via Host/SNI.

        Each URL is logged as a discovery parented at the hostname, so it inherits
        the host's scope and authorization channel exactly (a dl host's URLs are
        dl-channel; excluded hosts are skipped by log_discovery's own gating).

        `only_channels` restricts synthesis to hosts whose channel is in the set
        (e.g. (CHANNEL_DOMAIN, CHANNEL_URL) to synthesize only for name-safe
        hosts, leaving -t hosts to the richer nmap path). None = all in-scope
        hosts. Returns the number of URLs seeded.
        """
        seeded = 0
        for host in sorted(self._in_scope_domains):
            if only_channels is not None:
                ch = self._best_channel(host)
                if ch not in only_channels:
                    continue
            if self.is_excluded(host, TYPE_DOMAIN):
                continue
            for scheme in ("http", "https"):
                url = f"{scheme}://{host}"
                if self._key(url, TYPE_URL) in self._seen:
                    continue
                self.log_discovery(url, TYPE_URL, "url_synthesis_hostname",
                                   parent=host)
                seeded += 1
        return seeded

    def derived_ip_network_summary(self) -> dict:
        """Summarize the /16 spread of DERIVED (non-explicit) public IPs.

        A wide spread across many /16s is a strong signal that discovered names
        resolve to third-party / CDN / SaaS infrastructure rather than a small
        set of customer-owned hosts — useful for prompting the operator to bound
        active scanning with -t / --exclude. Returns {ip_count, network_count,
        networks: sorted[/16 str]}.
        """
        nets: set[str] = set()
        ip_count = 0
        for ip in self._all_ips:
            if ip in self._explicit_ips or "/" in ip:
                continue  # only derived bare IPs
            if _is_private_ip(ip):
                continue
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                continue
            ip_count += 1
            if addr.version == 4:
                nets.add(str(ipaddress.ip_network(f"{ip}/16", strict=False)))
            else:
                nets.add(str(ipaddress.ip_network(f"{ip}/32", strict=False)))
        return {"ip_count": ip_count, "network_count": len(nets),
                "networks": sorted(nets)}

    def _get_filtered_set(self, all_set: set, in_scope_set: set,
                          scope_filter: str, category: str) -> set:
        """Apply scope filter to return the appropriate target set."""
        if scope_filter == "strict":
            return set(in_scope_set)
        if scope_filter == "warn":
            out_of_scope = all_set - in_scope_set
            if out_of_scope:
                logger.warning(
                    "%d out-of-scope %s targets included: %s",
                    len(out_of_scope), category,
                    ", ".join(sorted(out_of_scope)[:5]) + ("..." if len(out_of_scope) > 5 else "")
                )
            return set(all_set)
        # scope_filter == "none"
        return set(all_set)

    def snapshot(self) -> LedgerSnapshot:
        """Return an immutable snapshot of current ledger state for parallel groups."""
        with self._lock:
            return LedgerSnapshot(
                ips=frozenset(self._all_ips),
                urls=frozenset(self._all_urls),
                domains=frozenset(self._all_domains),
                in_scope_ips=frozenset(self._in_scope_ips),
                in_scope_urls=frozenset(self._in_scope_urls),
                in_scope_domains=frozenset(self._in_scope_domains),
            )

    def load_from_disk(self):
        """Rebuild in-memory sets from existing JSONL file (for resume)."""
        if not os.path.exists(self.path):
            return
        # Collect (target, type, parent) for every scannable entry so we can
        # re-resolve scope to a fixpoint after the pass. The JSONL is not
        # guaranteed to be parent-before-child (parallel groups can interleave
        # writes), so a single in-order pass would drop legitimately-in-scope
        # targets whose parent appeared later in the file.
        scope_candidates = []
        with open(self.path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                target = entry.get("target", "")
                target_type = entry.get("type", "")
                scope = entry.get("scope", SCOPE_DERIVED)
                source = entry.get("source", "")
                parent = entry.get("parent")

                if not target or not target_type:
                    continue

                # MX domain entries are metadata, not scan targets
                if target_type == "mx_domain":
                    mx_hosts = entry.get("mx_hosts", [])
                    if mx_hosts:
                        self._mx_domains[target] = mx_hosts
                    continue

                # Port entries: rebuild in-memory port index (last-write-wins)
                if target_type == TYPE_PORT:
                    port_num = entry.get("port")
                    proto = entry.get("proto", "tcp")
                    if target and port_num is not None:
                        host_ports = self._ports.setdefault(target, {})
                        key = (int(port_num), proto)
                        info = {
                            "service": entry.get("service", ""),
                            "product": entry.get("product", ""),
                            "version": entry.get("version", ""),
                            "banner": entry.get("banner", ""),
                            "tunnel": entry.get("tunnel", ""),
                            "reason": entry.get("reason", ""),
                            "method": entry.get("method", ""),
                            "confidence": entry.get("confidence", ""),
                            "extra": entry.get("extra", ""),
                            "state": entry.get("state", "open"),
                            "source": source,
                        }
                        existing = host_ports.get(key)
                        if existing:
                            existing.update({k: v for k, v in info.items() if v})
                        else:
                            host_ports[key] = info
                    continue

                key = self._key(target, target_type)
                self._seen.add(key)

                # Rebuild explicit sets
                if source == "user_input" or scope == SCOPE_EXPLICIT:
                    if target_type == TYPE_IP:
                        self._explicit_ips.add(target)
                    elif target_type == TYPE_DOMAIN:
                        self._explicit_domains.add(target)
                    elif target_type == TYPE_URL:
                        self._explicit_urls.add(target)

                self._add_to_all(target, target_type)
                self._record_provenance(target, target_type, source,
                                        entry.get("discovered_at"))
                if parent:
                    self._parents_by_target.setdefault(
                        (target, target_type), set()).add(parent)
                # Restore the authorization channel recorded at discovery time.
                # Older ledgers predate the field; those are re-derived by the
                # channel fixpoint below (explicit sets get their seed channel,
                # derived targets inherit from parents).
                self._set_channel(target, target_type, entry.get("channel"))
                scope_candidates.append((target, target_type, parent))
                if self._resolve_in_scope(target, target_type, parent):
                    self._add_to_in_scope(target, target_type)

        # Restore the FULL multi-parent set from scan.db. The JSONL records only
        # one line per target (log_discovery early-returns on re-discovery), so it
        # keeps only the FIRST parent; a multi-homed IP resolved from several
        # in-scope hostnames loses its other parents on a JSONL-only reload. Left
        # unmerged, the end-of-run sync_scope_to_db() below then DELETE-inserts
        # target_parents down to that single reloaded parent — clobbering the
        # authoritative record. scan.db holds the complete set, so merge it in
        # before the fixpoint (restored parents can re-grant scope) and before
        # sync (so the union is written back, not the lossy subset).
        if self._db is not None:
            try:
                for row in self._db.iter_target_parents():
                    tkey = (row["target"], row["target_type"])
                    parents = self._parents_by_target.setdefault(tkey, set())
                    if row["parent"] not in parents:
                        parents.add(row["parent"])
                        scope_candidates.append(
                            (row["target"], row["target_type"], row["parent"]))
            except Exception as exc:  # best-effort: never abort a resume
                logger.warning("scan.db parent restore failed: %s", exc)

        # Fixpoint: keep re-resolving entries that aren't yet in-scope until a
        # full pass adds nothing new. This propagates scope down parent chains
        # regardless of the order entries were written to disk. Bounded by the
        # number of candidates (each pass adds >=1 or we stop).
        for _ in range(len(scope_candidates)):
            newly_scoped = False
            for target, target_type, parent in scope_candidates:
                if self._is_in_scope(target, target_type):
                    continue
                if self._resolve_in_scope(target, target_type, parent):
                    self._add_to_in_scope(target, target_type)
                    newly_scoped = True
            if not newly_scoped:
                break

        # Re-seed channels for explicit targets (covers ledgers written before
        # the channel field existed) — the input channel is implied by the set.
        for t in self._explicit_ips:
            self._set_channel(t, TYPE_IP, CHANNEL_TARGET)
        for d in self._explicit_domains:
            self._set_channel(d, TYPE_DOMAIN, CHANNEL_DOMAIN)
        for u in self._explicit_urls:
            self._set_channel(u, TYPE_URL, CHANNEL_URL)

        # Channel fixpoint: propagate each in-scope target's channel to its
        # children, order-independent, until nothing upgrades. Mirrors the scope
        # fixpoint above so a resumed run gates identically to the original.
        for _ in range(len(scope_candidates)):
            upgraded = False
            for target, target_type, parent in scope_candidates:
                if not self._is_in_scope(target, target_type):
                    continue
                inherited = self._channel_for_parent(parent)
                if inherited is None:
                    continue
                tkey = (target, target_type)
                before = self._channel_by_target.get(tkey)
                self._set_channel(target, target_type, inherited)
                if self._channel_by_target.get(tkey) != before:
                    upgraded = True
            if not upgraded:
                break

        total_ports = sum(len(p) for p in self._ports.values())
        logger.info("Ledger loaded from disk: %d IPs, %d URLs, %d domains, %d ports across %d hosts",
                    len(self._all_ips), len(self._all_urls), len(self._all_domains),
                    total_ports, len(self._ports))

        # Persist the fixpoint-resolved state to scan.db. On resume/continue the
        # JSONL is read (not re-appended), so the per-entry mirror never fires;
        # this one pass writes every in-memory row with its now-final in_scope.
        self.sync_scope_to_db()

    def stamp_identity(self, engagement_uuid=None, output_prefix=None):
        """Record engagement identity in scan.db meta (no-op without a DB).

        Delegates to ScanDB.stamp_identity — engagement_uuid is stable across
        --continue/--resume; returns the effective uuid (or None if no DB).
        """
        if self._db is None:
            return None
        try:
            return self._db.stamp_identity(
                engagement_uuid=engagement_uuid, output_prefix=output_prefix)
        except Exception as exc:  # best-effort: identity never aborts a run
            logger.warning("scan.db identity stamp failed: %s", exc)
            return None

    def mark_run_started(self):
        """Flag scan.db as an in-progress (not-yet-clean) run (no-op without DB).

        Call once after prior ledger state is loaded and before the scan writes
        new discoveries. A SIGKILL / power loss mid-run then leaves the flag
        'dirty', so the next resume's load_from_db() re-resolves scope instead of
        trusting write-time in_scope flags. Best-effort: never aborts a run.
        """
        if self._db is None:
            return
        try:
            self._db.mark_run_dirty()
        except Exception as exc:  # best-effort
            logger.debug("scan.db mark_run_dirty failed: %s", exc)

    def mark_clean_shutdown(self):
        """Flag scan.db as cleanly finished (no-op without DB).

        Call at the run's graceful-exit boundary AFTER sync_scope_to_db() has
        persisted fixpoint-resolved in_scope flags, so a later load_from_db()
        may trust them. Best-effort: never aborts a run.
        """
        if self._db is None:
            return
        try:
            self._db.mark_run_clean()
        except Exception as exc:  # best-effort
            logger.debug("scan.db mark_run_clean failed: %s", exc)

    def record_coverage(self, module, base_kwargs, step_index, status="fed"):
        """Record which targets/urls/domains a module was fed (scan.db coverage).

        Reads the module's actual input files (post-scope-gate, same files the
        forensic snapshot copies) and appends one coverage row per entry, tagged
        with the current run_seq for history. Records INTENT (fed), not proven
        reach. Best-effort: never aborts a run. No-op without a DB.
        """
        if self._db is None:
            return 0
        try:
            run_seq = self._db.current_run_seq()
            written = 0
            kinds = (
                ("target", base_kwargs.get("target")),
                ("url", base_kwargs.get("url_file")),
                ("domain", base_kwargs.get("domainlist")),
            )
            for ttype, src in kinds:
                if not src or not os.path.exists(str(src)):
                    continue
                with open(str(src), encoding="utf-8", errors="ignore") as fh:
                    entries = [ln.strip() for ln in fh
                               if ln.strip() and not ln.startswith("#")]
                written += self._db.record_coverage(
                    module=module, targets=entries, target_type=ttype,
                    run_seq=run_seq, step_index=step_index, status=status)
            return written
        except Exception as exc:  # best-effort: coverage never aborts a run
            logger.warning("scan.db coverage record failed for %s: %s", module, exc)
            return 0

    def reconcile_coverage(self, module, step_index, *, reached=None, all_failed=False):
        """Reconcile this step's coverage rows to their outcome (scan.db).

        all_failed=True marks the step's fed rows 'step_failed'; otherwise rows
        whose target reached (appears in output) become 'reached', the rest
        'no_response'. Best-effort; no-op without a DB. Same run_seq as the
        coverage rows (current, not a new allocation).
        """
        if self._db is None:
            return 0
        try:
            return self._db.reconcile_coverage(
                module=module, run_seq=self._db.current_run_seq(),
                step_index=step_index, reached=reached, all_failed=all_failed)
        except Exception as exc:  # best-effort: never aborts a run
            logger.warning("scan.db coverage reconcile failed for %s: %s", module, exc)
            return 0

    def load_from_db(self):
        """Rebuild in-memory ledger state from scan.db (source of truth).

        The DB-native counterpart to load_from_disk. When the prior run ended
        cleanly (was_clean_shutdown) it TRUSTS the persisted in_scope flag — a
        fast path valid because sync_scope_to_db persists fixpoint-resolved flags
        at a graceful exit, and a scope parity test guards it. If the prior run
        did NOT end cleanly (SIGKILL / power loss / a pre-marker DB), the
        persisted flags may be stale for out-of-order parent chains (a child
        mirrored before its parent was granted scope), so we re-run the same
        bounded scope fixpoint load_from_disk uses and re-persist. Multi-parent
        is restored from target_parents, so get_ip_to_hostnames / URL synthesis
        are faithful.

        Raises RunPredatesDbMigration if the DB has no ledger_authoritative
        marker (a pre-migration file whose ledger state can't be trusted).
        Exclusion sets and ip_scope_mode are NOT restored here — they are
        re-seeded from the CLI/--exclude on every invocation.
        """
        if self._db is None or not self._db.is_ledger_authoritative():
            raise RunPredatesDbMigration(
                "this run's scan.db predates the DB migration (or has no "
                "authoritative ledger state); start a fresh run")

        was_clean = self._db.was_clean_shutdown()
        loaded_targets = []  # (target, ttype) for the crash-recovery fixpoint
        for row in self._db.iter_targets():
            target, ttype = row["target"], row["target_type"]
            loaded_targets.append((target, ttype))
            self._seen.add(self._key(target, ttype))
            self._add_to_all(target, ttype)
            if row["scope"] == SCOPE_EXPLICIT:
                if ttype == TYPE_IP:
                    self._explicit_ips.add(target)
                elif ttype == TYPE_DOMAIN:
                    self._explicit_domains.add(target)
                elif ttype == TYPE_URL:
                    self._explicit_urls.add(target)
            if row["in_scope"]:  # TRUST the persisted, fixpoint-resolved flag
                self._add_to_in_scope(target, ttype)
            if row["source"]:
                self._source_by_target[(target, ttype)] = row["source"]
            if row["discovered_at"]:
                self._discovered_at_by_target[(target, ttype)] = row["discovered_at"]

        for row in self._db.iter_target_parents():
            self._parents_by_target.setdefault(
                (row["target"], row["target_type"]), set()).add(row["parent"])

        for row in self._db.iter_ports():
            host_ports = self._ports.setdefault(row["host"], {})
            host_ports[(int(row["port"]), row["proto"])] = {
                "service": row["service"] or "", "product": row["product"] or "",
                "version": row["version"] or "", "banner": row["banner"] or "",
                "tunnel": row["tunnel"] or "", "reason": row["reason"] or "",
                "method": row["method"] or "", "confidence": row["confidence"] or "",
                "extra": row["extra"] or "", "state": row["state"] or "open",
                "source": row["source"] or "",
            }

        for row in self._db.iter_mx_domains():
            self._mx_domains[row["domain"]] = json.loads(row["mx_hosts"] or "[]")

        if not was_clean:
            # The prior run didn't reach a graceful end, so a child's persisted
            # in_scope may still be False even though its parent (mirrored later,
            # or by another parallel worker) is in scope. Re-run the same bounded
            # scope fixpoint load_from_disk uses — additive, so it only promotes
            # stale-False flags, never revokes — then re-persist the resolved
            # state so the DB is trustworthy again.
            scope_candidates = []
            for target, ttype in loaded_targets:
                parents = self._parents_by_target.get((target, ttype)) or {None}
                for parent in parents:
                    scope_candidates.append((target, ttype, parent))
            for _ in range(len(scope_candidates)):
                newly_scoped = False
                for target, ttype, parent in scope_candidates:
                    if self._is_in_scope(target, ttype):
                        continue
                    if self._resolve_in_scope(target, ttype, parent):
                        self._add_to_in_scope(target, ttype)
                        newly_scoped = True
                if not newly_scoped:
                    break
            self.sync_scope_to_db()
            logger.info("Ledger scope re-resolved after unclean shutdown "
                        "(%d candidates)", len(scope_candidates))

        total_ports = sum(len(p) for p in self._ports.values())
        logger.info("Ledger loaded from scan.db: %d IPs, %d URLs, %d domains, "
                    "%d ports across %d hosts", len(self._all_ips),
                    len(self._all_urls), len(self._all_domains),
                    total_ports, len(self._ports))

    def sync_scope_to_db(self):
        """Re-assert every in-memory target/port/mx row into scan.db, faithfully.

        Idempotent (all upserts). Used after load_from_disk's scope fixpoint and
        at the end of a live run so out-of-order parent chains (child logged
        before its parent) get their final in_scope flag persisted. Writes the
        FULL parent set (target_parents), real source + discovered_at, and
        scope='excluded' when excluded — so the DB is a faithful basis for
        load_from_db(). Stamps the ledger-authoritative marker on success.
        """
        if self._db is None:
            return
        try:
            # Drop internal-only names (resolve only to private IPs) from scope
            # before persisting the authoritative in_scope flag.
            self._demote_internal_only_hosts()
            # Computed once (not per-row) for the promotion-aware channel below.
            host_to_ips = self.get_hostname_to_ips()
            for target, ttype, explicit in (
                *((t, TYPE_IP, t in self._explicit_ips) for t in self._all_ips),
                # Persist the faithful type: subdomains as TYPE_SUBDOMAIN, plain
                # domains as TYPE_DOMAIN. Forcing all of _all_domains to
                # TYPE_DOMAIN previously minted a phantom 'domain' row for every
                # subdomain, double-counting scan.db targets.
                *((t,
                   TYPE_SUBDOMAIN if t in self._subdomain_targets else TYPE_DOMAIN,
                   t in self._explicit_domains) for t in self._all_domains),
                *((t, TYPE_URL, t in self._explicit_urls) for t in self._all_urls),
            ):
                parents = self._parents_by_target.get((target, ttype)) or set()
                if self.is_excluded(target, ttype):
                    scope = SCOPE_EXCLUDED
                elif explicit:
                    scope = SCOPE_EXPLICIT
                else:
                    scope = SCOPE_DERIVED
                self._db.upsert_target(
                    target=target, target_type=ttype, scope=scope,
                    in_scope=self._is_in_scope(target, ttype),
                    channel=self._authorization_channel(target, ttype, host_to_ips),
                    source=self._source_by_target.get((target, ttype)),
                    discovered_at=self._discovered_at_by_target.get((target, ttype)),
                    parent=sorted(parents)[0] if parents else None)
                self._db.replace_target_parents(target, ttype, parents)
            for host, ports in self._ports.items():
                for (port, proto), info in ports.items():
                    self._db.upsert_port(
                        host=host, port=port, proto=proto,
                        state=info.get("state", "open"), service=info.get("service", ""),
                        product=info.get("product", ""), version=info.get("version", ""),
                        banner=info.get("banner", ""), tunnel=info.get("tunnel", ""),
                        reason=info.get("reason", ""), method=info.get("method", ""),
                        confidence=info.get("confidence", ""), extra=info.get("extra", ""),
                        source=info.get("source", ""))
            for domain, mx_hosts in self._mx_domains.items():
                self._db.upsert_mx_domain(domain, json.dumps(mx_hosts))
            self._db.mark_ledger_authoritative()
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("scan.db scope sync failed: %s", exc)

    def export_discovery_ledger(self):
        """Regenerate discovery-ledger.jsonl from scan.db (the finalize export).

        Writes JSONL in the historical _write_entry shape so existing readers
        (analyze._find_mx_domains, external tooling, the results zip) keep
        working once the engine stops appending JSONL inline. One target line
        PER PARENT (mirrors the old per-parent appends,
        preserving the audit trail); plus port and mx_domain entries.

        Overwrites the file atomically-ish (write temp, os.replace). Best-effort:
        an export failure logs and is non-fatal — scan.db remains the truth.
        """
        if self._db is None:
            return
        try:
            parents_by = {}
            for r in self._db.iter_target_parents():
                parents_by.setdefault((r["target"], r["target_type"]), []).append(r["parent"])

            tmp = self.path + ".export.tmp"
            with open(tmp, "w") as f:
                for r in self._db.iter_targets():
                    tkey = (r["target"], r["target_type"])
                    base = {
                        "target": r["target"],
                        "type": r["target_type"],
                        "source": r["source"],
                        "scope": r["scope"],
                        "discovered_at": r["discovered_at"],
                    }
                    plist = sorted(parents_by.get(tkey, [])) or [r["parent"]]
                    for parent in plist:
                        f.write(json.dumps({**base, "parent": parent}) + "\n")
                for r in self._db.iter_ports():
                    f.write(json.dumps({
                        "target": r["host"], "type": TYPE_PORT, "port": r["port"],
                        "proto": r["proto"], "state": r["state"],
                        "service": r["service"], "product": r["product"],
                        "version": r["version"], "banner": r["banner"],
                        "tunnel": r["tunnel"], "reason": r["reason"],
                        "method": r["method"], "confidence": r["confidence"],
                        "extra": r["extra"], "source": r["source"],
                        "discovered_at": r["updated_at"],
                    }) + "\n")
                for r in self._db.iter_mx_domains():
                    f.write(json.dumps({
                        "target": r["domain"], "type": "mx_domain",
                        "source": "dnsx", "scope": SCOPE_DERIVED,
                        "discovered_at": None, "parent": None,
                        "mx_hosts": json.loads(r["mx_hosts"] or "[]"),
                    }) + "\n")
            os.replace(tmp, self.path)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("discovery-ledger.jsonl export from scan.db failed: %s", exc)

    def close(self):
        """Checkpoint + close the scan.db mirror. Safe to call once at run end."""
        if self._db is not None:
            self._db.close()
            self._db = None


class _NoOpLedger:
    """Drop-in replacement when no output_dir is provided."""

    def set_ip_scope_mode(self, *args, **kwargs):
        pass

    def _authorized_ip_networks(self):
        return []

    def _ip_authorized(self, *args, **kwargs):
        return True

    def seed_user_inputs(self, *args, **kwargs):
        pass

    def seed_exclusions(self, *args, **kwargs):
        pass

    def seed_persisted_exclusions(self, *args, **kwargs):
        return 0

    def is_excluded(self, *args, **kwargs):
        return False

    def log_discovery(self, *args, **kwargs):
        pass

    def log_discoveries(self, *args, **kwargs):
        pass

    def export_targets(self, *args, **kwargs):
        return 0

    def export_target_ips(self, *args, **kwargs):
        return 0

    def export_urls(self, *args, **kwargs):
        return 0

    def export_urls_live(self, *args, **kwargs):
        return 0

    def record_httpx_result(self, *args, **kwargs):
        pass

    def set_url_prune(self, *args, **kwargs):
        pass

    def export_domains(self, *args, **kwargs):
        return 0

    def export_root_domains(self, *args, **kwargs):
        return 0

    def stamp_identity(self, *args, **kwargs):
        return None

    def mark_run_started(self, *args, **kwargs):
        pass

    def mark_clean_shutdown(self, *args, **kwargs):
        pass

    def record_coverage(self, *args, **kwargs):
        return 0

    def reconcile_coverage(self, *args, **kwargs):
        return 0

    def snapshot(self):
        return LedgerSnapshot()

    def load_from_disk(self):
        pass

    def load_from_db(self):
        pass

    def sync_scope_to_db(self):
        pass

    def export_discovery_ledger(self):
        pass

    def close(self):
        pass

    def get_ip_to_hostnames(self):
        return {}

    def get_hostname_to_ips(self):
        return {}

    def get_url_hosts(self):
        return set()

    def log_mx_domain(self, *args, **kwargs):
        pass

    def get_mx_domains(self):
        return {}

    def export_mx_domains(self, *args, **kwargs):
        return 0

    def get_in_scope_hostnames(self):
        return []

    def derived_ip_network_summary(self):
        return {"ip_count": 0, "network_count": 0, "networks": []}

    def log_port(self, *args, **kwargs):
        pass

    def log_ports(self, *args, **kwargs):
        pass

    def get_ports_for_host(self, host):
        return {}

    def get_all_open_ports(self):
        return {}

    def get_port_stats(self):
        return {"hosts_with_ports": 0, "total_open_ports": 0,
                "ports_with_service_id": 0, "ports_without_service_id": 0,
                "ports_with_version": 0}

    def export_open_ports(self, *args, **kwargs):
        return 0

    def export_port_list(self, *args, **kwargs):
        return 0

    def export_live_host_targets(self, *args, **kwargs):
        return 0


NO_OP_LEDGER = _NoOpLedger()


def _classify_target(value: str) -> str:
    """Determine if a target string is an IP, CIDR, or domain/hostname.

    Validates IPs and CIDRs via the ipaddress module so malformed entries
    like 'garbage/12' or '999.999.999.999' fall through to TYPE_DOMAIN
    instead of being seeded as bogus IP entries that scanners will reject.
    """
    import ipaddress

    if "/" in value:
        try:
            ipaddress.ip_network(value, strict=False)
            return TYPE_IP
        except ValueError:
            return TYPE_DOMAIN

    # IPv6 literal (no slash)
    if ":" in value and not value.startswith("http"):
        try:
            ipaddress.ip_address(value)
            return TYPE_IP
        except ValueError:
            return TYPE_DOMAIN

    # IPv4 literal — exactly four octets, each 0..255
    parts = value.split(".")
    if len(parts) == 4 and all(_is_numeric(p) for p in parts):
        try:
            ipaddress.ip_address(value)
            return TYPE_IP
        except ValueError:
            return TYPE_DOMAIN

    return TYPE_DOMAIN


def _is_numeric(s: str) -> bool:
    try:
        n = int(s)
        return 0 <= n <= 255
    except ValueError:
        return False
