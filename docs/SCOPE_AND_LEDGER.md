# Execution Flow & Target Discovery Ledger

> Part of the MonkeyX Core docs. See [`../CLAUDE.md`](../CLAUDE.md) for the index.

## Key execution flow

1. `monkeyx.py` validates inputs via `validate_module_inputs()`, inits Axiom fleet
2. `run_modules()` seeds the target ledger with user-provided inputs (targets, domains, URLs)
3. Before each step: `_regenerate_target_files()` exports deduplicated, scope-filtered target files from the ledger and updates kwargs (`target`, `url_file`, `domainlist`)
4. Module runs, discovering new targets
5. After each step: `_extract_discoveries()` logs new IPs/subdomains/URLs to the ledger with parent attribution. Before each step, `_snapshot_module_inputs()` copies the input files the module was **actually fed** into `data/step-snapshots/step-{N:03d}-{module}-{label}.txt` for forensics — "what did module X actually scan when it ran?" It uses the module's **post-remap kwargs** (host-scoped `.host.txt` + url-pruned live file), so the snapshot matches reality. It captures exactly the inputs the module reads: PASSIVE modules snapshot nothing; service modules snapshot their real input via `_MODULE_EXTRA_INPUTS` (snmp_sweep→UDP+TCP ports, ssh_audit_scan/smtp_security→open-ports, ax_nuclei→URLs+open-ports, shodan_enrich→target-ips, dns_security→root-domains); others snapshot target/url/domain per `REQUIRED_INPUTS`/`CONSUMES_URLS`.
6. Next step picks up the expanded target set automatically via ledger regeneration
7. If a step fails (exception or missing prerequisites), it's logged as failed and the run **continues to the next step** — individual module failures don't abort the workflow
8. Fleet cleanup runs in `finally` block

## Target discovery ledger (source of truth)

The ledger (`discovery-ledger.jsonl`) is the **single source of truth** for what gets scanned. It drives target file generation for every module step.

Each entry records:
- `target`: the discovered value (or host IP for port entries)
- `type`: `ip`, `domain`, `subdomain`, `url`, or `port`
- `source`: module name that found it, or `user_input`
- `scope`: `explicit` (user-provided) or `derived` (found through scanning)
- `parent`: what led to the discovery (e.g., the hostname that resolved to an IP)

Port entries (`type: "port"`) additionally carry: `port`, `proto`, `state`, `service`, `product`, `version`, `banner`, plus the nmap detail fields `tunnel`, `reason`, `method`, `confidence`, `extra`. These are logged from nmap XML and masscan greppable (`-oG`) output after each scan module. Last-write-wins: if masscan finds port 443 open and nmap later identifies it as `nginx 1.24.0`, the in-memory record updates with the richer service info (only non-empty fields overwrite).

Each entry also carries a `channel` (`t`/`dl`/`ul`, or null) — see "Input-channel authorization model" below.

### Scope filtering (--scope-filter, default: strict)

Controls which ledger entries are exported to module target files:
- `strict` (default): only export in-scope targets (explicit + traceable to explicit via parent chain)
- `warn`: export all targets, log warnings for out-of-scope entries
- `none`: export all targets without warnings

All discoveries are always logged to the JSONL regardless of scope filter — filtering only applies at export time.

### IP authorization (--ip-scope, default: provenance)

A second, independent axis from `--scope-filter`. Where `--scope-filter` governs
*traceability* (is a target reachable from explicit scope?), `--ip-scope` governs
*IP authorization* (is a discovered bare IP actually one we were authorized to
scan?). This separates provenance from authorization: an in-scope hostname can
resolve to a shared/CDN/third-party IP, and traceability alone would authorize
scanning that IP.

- `provenance` (default): a discovered IP is exported if it's traceable to
  explicit scope, wherever it resolves (legacy behavior — no change).
- `strict`: a discovered **bare IP** (one exported as an IP, i.e. with no
  authorized hostname mapping) is exported only if it falls within the
  **authorized IP ranges** — the IP/CIDR entries from `-t`. Named targets
  (hostnames/URLs, and IPs that map to an in-scope hostname) are authorized by
  name and are unaffected: you're scanning the vhost you were authorized for,
  not the bare shared IP.

**Limitation — `--ip-scope strict` gates BARE IPs, not names.** The IP-range
check fires only for a derived IP with *no* hostname mapping. An IP a hostname
resolved to is exported **as the hostname**, so **if a hostname (from `-t`,
`-d`, or discovery) resolves to an IP OUTSIDE your `-t` ranges, that host is
still scanned** — the scanner re-resolves the name and connects out-of-range.
Listing a hostname is an implicit grant to scan whatever it resolves to. This is
intentional for the CDN/vhost case (a named in-scope app behind Cloudflare must
stay scannable), but it means `strict` does **not** confine scanning to `-t` IP
ranges when names are in play. To hard-block a specific out-of-scope IP or host,
use `--exclude` — exclusions always win, `-t` names included.

- `strict-resolved` (opt-in): everything `strict` does, **plus** it gates NAMES
  by where they resolve — a hostname/URL is exported only if it resolves to
  IP(s) that ALL fall within the `-t` ranges. **Fail-closed**: a name with no
  resolved IP yet is dropped (so run resolution — dns_resolve/dnsx_resolve —
  before scanning). This closes the strict footgun above: a hostname resolving
  outside `-t` is no longer scanned via its name. Explicit `-d` domains are
  still kept in the *domainlist* (that feeds discovery/resolution, not active
  scanners); active-scan confinement applies to the target/URL exports. Multi-IP
  names: ALL resolved IPs must be in range, else the name is dropped. Use this
  when your `-t` IP ranges are the hard authorization boundary and you don't
  want names straying outside them. (Trade-off: a legitimate in-scope app behind
  a CDN whose edge IP is outside `-t` will also be dropped — that's the price of
  strict IP confinement; add its CDN range to `-t` or use plain `strict`.)

`strict` is a **no-op when `-t` has no IP ranges** (e.g. domain-only runs): with
no authorized-range boundary, derived IPs fall back to provenance so
domain-only workflows behave as documented. When `strict` is set but there are
no `-t` ranges, `run_modules` prints a prominent warning at start (the control
is not actually enforcing anything).

**`-t` IS the authorization boundary.** Put the customer's stated in-scope
IP/CIDR ranges in `-t`; that is the ONLY source of truth for which IPs may be
actively scanned, and `--ip-scope strict` enforces exactly it. The tool does
**not** try to infer authorization from DNS/WHOIS/ASN, and deliberately so: a
customer's own cloud VMs (Azure/AWS/GCP) share their provider's org/ASN, so an
org-match check would both scan third parties in the target's ASN AND exclude
the customer's real cloud-hosted assets — it cannot distinguish "customer's
Azure VM" from "Microsoft's Azure service." Authorization is a fact about the
engagement, not a property derivable from an IP. Accordingly:
- provide in-scope ranges via `-t` (authoritative), and
- list known third parties (CDN/SaaS/mail) via `--exclude`.

To help spot the situation, after a run `run_modules` prints a recon summary
when discovered names resolved to public IPs spread across ≥3 distinct /16
networks — a strong signal of CDN/SaaS/third-party sprawl (e.g. a name behind
Cloudflare + SendGrid + M365) rather than a small set of customer-owned hosts.

Implementation: `core/target_ledger.py:set_ip_scope_mode()` + `_ip_authorized()`
+ `derived_ip_network_summary()`, gated in `export_targets()` and the
parallel-group snapshot path in `workflows.py`.

### Input-channel authorization model (the primary scope control)

Layered on top of `--scope-filter`/`--ip-scope`, the **input channel a target
came from IS its authorization ceiling**. This is the operator-facing model;
`--scope-filter`/`--ip-scope` remain but are now internal mechanics.

| Channel | Input flag | Means | Gets |
|---------|-----------|-------|------|
| `t`  | `-t`  | fully owned/authorized | full treatment incl. port sweeps, UDP, name-blind service probes |
| `dl` | `-d` | in scope, may be shared | name-safe modules only (HTTP Host/TLS SNI); **never** a port sweep |
| `ul` | `-url` | web surface | name-safe web modules by URL |

**Why:** testing `app.example.com` by hostname (Host header / TLS SNI) only ever
reaches the client's vhost, even on a shared IP. Scanning the IP (port fanout,
UDP, raw service probes) touches co-tenants — so that is confined to `-t`.

**Channel field:** each ledger entry carries a `channel` (`t`/`dl`/`ul`, or null
for a lead). Set at seed time (`seed_user_inputs`), propagated to derived assets
via the parent chain (`log_discovery` → `_channel_for_parent`), highest wins
(`t > dl > ul`). Persisted to JSONL and restored on resume/continue.
Accessor: `ledger.get_channel(target, type)`.

**Ownership promotion:** a `dl`/`ul`-derived IP (or a name resolving to an IP)
that falls inside a `-t` CIDR is authorized for host scanning — `-t` is the
ownership boundary. See `_host_authorized_ip` / `_host_authorized_name`.

**Module classification** (`core/scope_classes.py`, single auditable registry):
- `host` — probes an address (nmap/masscan/naabu, ssh_audit_scan, snmp_sweep,
  smtp_security, shodan_enrich, dns_resolve). May only hit `-t`-authorized assets.
- `name` — web/DNS by name (httpx/nuclei/gowitness/testssl/ffuf/…, subfinder,
  dnsx_resolve, bbot passive/web/…). Safe on `-d`/`-url` shared infra.
- `passive` — no target contact (normalize/analyze/ai_analyze/summary/…).
- Fail-safe default = `host`; a module-level `SCOPE_CLASS` attr overrides.
- Orthogonal tags: `ENUM_MODULES` (suppressible by `--no-subdomain-enum`),
  `INVASIVE_MODULES` (dalfox/bbot_dast — explicit opt-in regardless of channel).

**Enforcement** (`workflows.py`): regeneration writes `-t`-only variants
(`ledger-*.host.txt`) via `export_*(host_only=True)`; `_host_scoped_kwargs`
remaps a `host`-class module's target-family kwargs to those variants right
before it runs (sequential + parallel). `name`/`passive` modules see the full
in-scope set (no over-restriction).

**Host-class targets collapse to unique IPs.** The `.host.txt` target file for
HOST-class port scanners is written by `export_host_targets()`, which emits each
authorized **IP once** (not one line per resolved hostname like the name-expanded
`ledger-targets.txt`). A shared IP that hundreds of in-scope names resolve to is
then scanned ONCE, not once per name — no self-inflicted hammering. Rules that
keep it from dropping coverage: multi-IP names contribute ALL their IPs (union);
an unresolved `-t` name falls back to the bare hostname (fail-open for owned
scope). NAME/web modules keep the per-hostname `ledger-targets.txt`, so vhost/SNI
coverage is unaffected. Because the per-member kwargs are computed once and used
for BOTH the run and the forensic step-snapshot/coverage row, a parallel member's
`step-snapshots/` file reflects exactly what it was fed (host-scoped + url-pruned),
not the pre-remap group kwargs.

**UDP ports are a separate file.** The per-host port list is proto-less, and
`ledger-open-ports.txt` is TCP-only, so `export_open_ports(proto_filter="udp")`
writes `ledger-open-ports-udp.txt` (+ `.host.txt`). `snmp_sweep` reads that UDP
file **and** globs the UDP scan's purpose-built `{prefix}*-snmp-hosts.txt`
(`ip:161` lines from `nmap_to_udphosts`) — either source gets it its 161 hosts.

**Name-safe web discovery:** for `-d`/`-url` hosts (no host-class port scan),
`ledger.synthesize_name_urls()` seeds `http://name`+`https://name` during
regeneration so web modules probe by hostname (logged with
`source: "url_synthesis_hostname"` for audit). Auto-injection in `monkeyx.py`
does NOT inject the host-class nmap web scan for a domains-only run (it would be
gated to nothing).

**ai_validate** is exempt from the whole-module remap and enforces the ceiling
per-command in `_is_safe_command`: every target must be in the full in-scope
set, AND a host-touching tool (nmap/nc/snmp/smb/ssh-audit/testssl/openssl) must
also be in the `-t` `host_scope` (from `.host` files via `_parse_host_scope`).
Name-safe tools (curl/nuclei/dig/whatweb/ffuf) reach the full name surface.

**Operator flags:** `--no-subdomain-enum` (skip enum modules, warn-and-skip if
explicitly selected), `--confirm-scope` (dry pass: seed+resolve+classify, print
the scope echo, no fleet). Start-of-run scope echo via
`workflows.format_scope_echo` / `ledger.scope_summary()`.

### Scope inheritance via parent chain

A target is "in-scope" if it traces back to an explicit target through its parent chain:
- `example.com` (explicit, user-provided)
- → `api.example.com` (in-scope: subdomain of explicit domain)
- → `10.0.0.5` (in-scope: parent `api.example.com` is in-scope)
- → `https://10.0.0.5:8080/admin` (in-scope: host is in-scope IP)

The `_in_scope_*` sets accumulate as discoveries are logged — no full chain re-walk needed.

### Third-party guard on parent-chain inheritance

Parent-chain inheritance is deliberately gated for **NAME** targets (URL host /
domain / subdomain) so a redirect or crawl to someone else's host doesn't get
actively scanned. In `_resolve_in_scope`, the parent-chain grant is skipped when
`_is_third_party_name()` is true:
- **#1 identity/SaaS provider** — the host matches `_THIRD_PARTY_SUFFIXES`
  (login.microsoftonline.com, okta.com, auth0.com, …): provider-owned, never the
  customer's asset (e.g. an M365 SSO redirect from an in-scope host).
- **#2 cross-domain (default-deny)** — a host under **none** of the operator's
  owned name anchors is a third-party redirect/crawl target. The anchors are the
  explicit `-t`/`-d` domains **plus the hosts of explicit `-url` targets** (each
  owning itself + its subdomains). A run always has explicit scope, so this
  **default-denies**: a derived NAME matching no anchor is third-party even when
  no `-d` was given (which closes an older fail-open where a redirect from a
  `-url`/`-t`-only run dragged an unlisted domain into active scope).

Such targets are still **logged** to the ledger for audit (scope `derived`,
`in_scope=False`) but are **not** exported to any scanner — authorization comes
from `-t`/`-d`/`-url`, not from a redirect. This gate applies ONLY to the
parent-chain grant: an explicitly-listed provider (user put it in `-t`/`-d`) and
a subdomain of an explicit domain are authorized by the other checks and
unaffected. **IPs are exempt** — their authorization is the `--ip-scope` axis,
not this.

### Private IP filtering (external-only scanning)

MonkeyX is designed for external penetration testing. Private/non-routable IPs are automatically excluded from target lists at export time, so fleet time isn't spent on addresses unreachable from the internet.

Filtered ranges are defined **explicitly** in `_PRIVATE_NETS` — deliberately NOT via Python's `ipaddress.is_private`, whose definition widens across Python versions (3.12.4+ also marks RFC5737 doc ranges private), which would silently change what gets filtered on an interpreter upgrade:
- `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` (RFC1918)
- `127.0.0.0/8` (loopback)
- `169.254.0.0/16` (link-local)
- `100.64.0.0/10` (RFC6598 Carrier-Grade NAT)
- `::1/128`, `fe80::/10`, `fc00::/7` (IPv6 loopback/link-local/ULA)

The filter also blocks **names**: a hostname that resolves ONLY to private IPs is dropped from the target export (`export_targets` fail-closed — the scanner re-resolves the name and would otherwise hit the internal IP) and demoted from in-scope at finalize (`_demote_internal_only_hosts`, so it doesn't over-report coverage). Explicit `-t` private IPs are unaffected (authorized by name/range before this check). A derived private IP is also never in-scope via parent-chain inheritance.

Private IPs are still logged to the discovery ledger for audit — just not written to the exported target files. When filtered, a log message indicates how many were excluded.

Controlled by `_PRIVATE_FILTER_ENABLED = True` in `core/target_ledger.py`. Applies to `export_targets()`/`export_urls()` and the parallel-group snapshot export path in `workflows.py`.

### Ledger-driven target files

Before each module step, `_regenerate_target_files()` in workflows.py exports
(all under the `data/ledger/` subdir — the paths are built via the single
`core/output_layout.py:ledger_file()` helper so the location is defined once;
the exporters `os.makedirs` the subdir on write):
- `{data_dir}/ledger/ledger-targets.txt` → `kwargs['target']` (IPs/CIDRs; a resolved IP is exported **as its hostname** so scanners record the vhost — see `export_targets`)
- `{data_dir}/ledger/ledger-target-ips.txt` → `kwargs['target_ips_file']` (authorized **bare IPs**, `ip\thost1,host2` with resolved-from provenance; for resolver-less tools like `shodan_enrich` that can't scan by name. Same scope_filter + ip_scope + exclusion + private gating as `ledger-targets.txt` — never a superset of what the scanners may hit)
- `{data_dir}/ledger/ledger-urls.txt` → `kwargs['url_file']` (URLs — the full set)
- `{data_dir}/ledger/ledger-urls-live.txt` → `kwargs['url_file_live']` (httpx-live subset; only when `--url-prune` is on — see "URL pruning" below)
- `{data_dir}/ledger/ledger-domains.txt` → `kwargs['domainlist']` (domains + subdomains)
- `{data_dir}/ledger/ledger-open-ports.txt` → `kwargs['open_ports_file']` (per-host **TCP** port list: `ip\tport1,port2,...`)
- `{data_dir}/ledger/ledger-open-ports-udp.txt` → `kwargs['udp_open_ports_file']` (per-host **UDP** ports; the port file is proto-less so TCP/UDP are split — `snmp_sweep` reads this one for 161)

The exported `.txt` list files are the only thing that moved into `data/ledger/`
— the run-root JSONL (`discovery-ledger.jsonl`, `progress.jsonl`) is unchanged.
The results zip (CLI `_create_results_archive` + API `zip_directory`) includes
`data/ledger/` explicitly, since both otherwise archive `data/` top-level only.

Parallel groups take a snapshot before spawning threads — all members read the same files.

### URL pruning (`--url-prune`, feeds heavy web scanners the httpx-live subset)

On a subdomain-heavy run, `ax_gau` (historical), `ax_katana` (crawl), and hostname/URL synthesis can balloon the ledger to thousands of URLs — most dead — which would then hammer the fleet through `ax_nuclei`/`ax_gowitness`/`ax_ffuf`/`ax_feroxbuster`. `--url-prune` (default **`live`**) feeds those heavy scanners only the httpx-confirmed-live URLs while leaving the full inventory in the ledger.

- **Export-time, data-preserving.** The ledger keeps every URL. `TargetLedger.export_urls_live()` writes `ledger-urls-live.txt` as a **subset** of the scoped `ledger-urls.txt` (never a superset — same scope_filter/exclusion/private/ip_scope gating first). Probers (`ax_httpx`) and discovery modules (katana/gau/subjs/arjun/linkfinder/amass) keep reading the **full** `ledger-urls.txt`; only `_LIVE_URL_SCANNERS` (nuclei/gowitness/ffuf/feroxbuster/dalfox/corsy/mantra/wpscan/wafw00f/testssl and the invasive `bbot_dast`) are remapped to the live file, by `_live_url_kwargs()` (a NAME-class sibling of `_host_scoped_kwargs`). `bbot_dast` is included so the loud fuzzer only ever hits live endpoints, never dead/historical URLs; `wafw00f`/`testssl` are host-level and additionally base-collapsed (below).
- **Liveness source.** `_log_discoveries_from_httpx_jsonl` calls `ledger.record_httpx_result(url, status)` for every httpx response — recording the URL as live (with status) and its `host:port` as *covered*.
- **Policy** (`ledger.set_url_prune`, set once per run from the CLI): `off` (heavy scanners read the full list), `live` (any httpx response), `interesting` (2xx/3xx/401/403 — auth-gated pages kept).
- **`--url-max-per-host`** (optional, default unlimited) caps URLs per host:port at THREE points: the live-URL export above, **ledger ingestion** of crawled URLs (`_log_urls_from_file` — stops a crawl from promoting every URL to a derived target), and **web_dirs minting** in `normalize`. First-N per host:port; the raw crawl file is left intact for audit. Opt-in — without it nothing is capped. On a wildcard scope an uncapped katana crawl can emit ~1M URLs → 1.1M ledger targets / web_dirs and millions of coverage rows, so this is the lever that bounds the scan.db blast radius. To bound the *crawl itself* (so the multi-GB raw file never forms), set katana's own options on the `ax_katana` step — `depth`, `crawl_duration`, `field_scope`.
- **Fail-open, per host:port.** A URL on a host:port httpx **never answered on** is KEPT (unknown ≠ dead). Only on a host:port httpx *did* respond for are the non-live URLs dropped. So with no httpx data the live file equals the full file, and pruning only ever removes URLs proven dead among live neighbours — it can't starve a scanner.
- **Auto-injection.** Because the prune needs httpx data, `monkeyx.py:_auto_inject_httpx_for_prune()` injects `ax_httpx` before the first heavy scanner when `--url-prune` is on and no httpx precedes it (respects `--no-auto-discovery`). So the feature is self-provisioning — you don't have to remember to add httpx.
- **Ordering caveat.** httpx liveness is only available to steps that run AFTER it. If a workflow puts `ax_httpx` in the **same parallel group** as a heavy scanner (they run concurrently, and the group's URL files are snapshotted before it spawns), the scanner fail-opens to the full list for that run — httpx must complete in a **strictly earlier** step. Put httpx ahead of the scanner group (as `standard_ai` does), or the auto-injection covers the case where httpx is absent entirely.
- **Limitation.** `_httpx_live`/`_httpx_covered` are in-memory (not persisted to JSONL), so on `--continue`/`--resume` (a fresh process) liveness is empty until httpx re-runs → the prune fail-opens to the full list for that invocation.

### Base-URL targeting for site/host-level tools (`_base_url_kwargs`)

Some tools act on a **site / host:port**, not per-path, so feeding them the full
path inventory (every deep URL from gau/katana/httpx — often thousands) is pure
duplicate work. `_base_url_kwargs` (a NAME-class remap applied right **after**
`_live_url_kwargs`, in both the sequential and parallel-group paths) collapses
their `url_file` to deduplicated `scheme://host:port` roots (via
`_extract_base_url`), written to `ledger/ledger-urls-ferox-base.txt`. Because it
runs after the url-prune remap, it collapses whatever set the module would
otherwise read (full list, or the httpx-live subset when `--url-prune` is on).
**Fail-open:** a missing/empty/unparseable input leaves `url_file` unchanged, so
the module is never starved.

`_BASE_URL_SCANNERS` currently holds:
- `ax_feroxbuster` — **recursive** dir brute-force; given a root it walks the tree
  itself, so one root per host (the full list would make it recurse *each* path
  and melt the fleet).
- `ax_ffuf` — wordlist fuzzer invoked with no `FUZZ` keyword, so it fuzzes the
  wordlist under each input URL; base roots keep it to one pass per host.
- `ax_wpscan` — fingerprints/enumerates a whole WordPress site (identical per
  path) → one scan per host.
- `ax_wafw00f` — WAF fingerprint is per host → one probe per host, not per URL.
- `ax_testssl` — TLS config is a `host:port` property → one (slow) audit per
  host:port, not per path.

`ax_wafw00f`/`ax_testssl` are also in `_LIVE_URL_SCANNERS`, so under `--url-prune`
they base-collapse the live subset (live host:port roots). Of these, only
`ax_ffuf` is in a default workflow (`deep`); the rest are opt-in (`-m <name>`).
`ax_feroxbuster` carries the recursion/runtime limits below.

**Recursion/runtime limits (`modules/ax_feroxbuster.py:_ferox_flags`).** Base-URL
targeting bounds the *number* of roots but not per-root recursion — feroxbuster
recurses by default and can run effectively forever on a wildcard/soft-404 host
(a "freeze"). The module now appends validated tuning flags: `--depth 2`,
`--time-limit 15m`, `--auto-bail` (defaults), plus optional `--scan-limit`/
`--threads`/`--rate-limit`, all tunable under `modules.ax_feroxbuster` in
monkeyx.config. Numeric knobs are int-cast and `time_limit` is format-checked, so
nothing shell-unsafe reaches the (shell) `ax` command. `tuning: false` emits none
of them (fallback for an ax build that doesn't forward tool flags — bake the
limits into the ax feroxbuster module template instead). `ax_ffuf` is
non-recursive, so it has no such limits.

### Discovery extraction (`_extract_discoveries`)

After each nmap-based module completes, `_extract_discoveries()` picks up three things:
- **Alive IPs**: derived from the XML output path — if module produces `{prefix}-tcpscan.xml`, it looks for `{prefix}-tcpscan-alive-hosts.txt` (written by `nmap_to_tcphosts`/`nmap_to_udphosts`)
- **URLs**: from the `parsed_urls` key in the module result dict (also produced by nmap service parsing)
- **Open ports with service info**: parsed from the nmap XML — each open port is logged via `ledger.log_port()` with service, product, version, and banner when available

These IPs become in-scope (their parent is the target file), which in turn makes URLs pointing to those IPs in-scope via the scope inheritance chain.

For masscan, only ports and alive IPs are extracted (no service info, no URLs). The discovered open ports land in the ledger and are exported as `kwargs['open_ports_file']` for the port-consuming modules (smtp/ssh/snmp/nuclei).

**Masscan output is greppable (`-oG`), not XML.** `ax_masscan` writes `{prefix}-masscan.txt` (ax selects the format by the output extension; `.txt` → `-oG`, `.xml` → `-oX`). Greppable is one short line per open port versus XML's element-per-port, so on a large/all-ports sweep the raw file is multiple times smaller — an all-ports sweep over a tarpit-heavy scope produces GBs of greppable text vs tens of GB of XML. `_log_ports_from_masscan_grep()` **stream-parses** it line-by-line (no DOM load) and applies a **per-host tarpit cap**: a host reporting more open ports than `scan.masscan_tarpit_port_cap` (default 500; `≤0` disables) is a tarpit/SYN-proxy — it is logged **alive** but its ports are **dropped** (ingesting them would bloat the ledger and poison the nmap `ports: open` verify step), with a warning per host. If a sweep finds hosts but yields **zero** usable ports (or drops some as tarpits), the `ax_masscan` step is escalated to `warning` so the run reports `completed_with_warnings` rather than a silent clean run.

### Parent attribution

The `parent` field tracks provenance for scope inheritance:
- **nmap/ax_naabu**: parent = target file path
- **subfinder**: parent = input domain (from subfinder JSONL `input` field) or inferred parent domain
- **dns_resolve**: parent = hostname that resolved to each IP (from resolve-report JSONL)
- **ax_ffuf**: parent = input FUZZ value or base URL
- **ax_feroxbuster**: parent = base URL being brute-forced
- **URLs from nmap**: parent = hostname extracted from URL (bare IP for standard ports, `host:port` for non-standard)

### Resume support

On resume (`--resume`) and `--continue`, `ledger.seed_persisted_exclusions()` runs **first** (re-seeding `--exclude` rules a prior run saved to `scan.db`, so exclusions are honored even when `--exclude` isn't re-passed — they must apply before the fixpoint so previously-excluded targets don't re-enter scope), then `ledger.load_from_disk()` rebuilds all in-memory sets from the existing JSONL. Because the JSONL isn't guaranteed parent-before-child, load re-resolves scope to a **fixpoint** (repeated passes until no new target is scoped) rather than a single in-order pass. A parallel channel fixpoint re-propagates authorization channels the same way, so a resumed run gates identically to the original. The next step's regeneration then produces correct target files.

Implementation: `core/target_ledger.py` — `TargetLedger` class. Thread-safe, deduplicates by target+type. If no `output_dir` is provided, `NO_OP_LEDGER` is used.

All URL provenance is now in `discovery-ledger.jsonl` — the legacy `master-urls.txt` and `discovery-log-urls.jsonl` files have been removed. To get the URL audit trail, filter the ledger by `type=url` (it has `source` and `discovered_at` fields).
