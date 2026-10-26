# MonkeyX Modules & Workflows

## Overview

MonkeyX uses a modular architecture: each scanning/analysis task is a discrete module (`modules/*.py`) that can run standalone (`-m name ...`) or be composed into a workflow (`-w name`). Modules are auto-discovered — a file exposing `run_<name>()` becomes module `<name>`.

Targets flow through a **discovery ledger** (`discovery-ledger.jsonl`), the single source of truth for what gets scanned. Before each step the engine regenerates that step's input files (targets, domains, URLs, open-ports) from the ledger, so modules automatically pick up whatever earlier steps discovered — there is no manual hand-off of files between modules.

## Input Types

At least one of `-t`, `-d`, `-url` is required (not needed for `--resume`/`--continue`).

### Target file (`-t/--target`)
- IPs (`192.168.1.1`), CIDRs (`10.0.0.0/24`), hostnames, and subdomains — mixed freely, one per line, a single value, or comma-separated.
- **`-t` is the authorization boundary** — its IP/CIDR ranges are what `--ip-scope strict` enforces.

### Domain list (`-d/--domain-list`)
- Domains **and subdomains** — e.g. both `example.com` and `api.example.com` are accepted (they're treated identically for resolution, scope, and export).
- Feeds subdomain enumeration/resolution. One caveat: `ax_puredns_bruteforce` bruteforces only **root** domains you provide (it deliberately does not recurse into discovered subdomains).

### URL list (`-url/--url-list`)
- Full URLs (`https://host:8443/path`) or bare hostnames — a bare `host` (or `host:port`) is expanded to both `http://` and `https://`.
- Merged and deduplicated with URLs discovered during scanning; all URL-consuming modules read the combined set from the ledger.

## Module input contract

Each module declares `REQUIRED_INPUTS` (a frozenset). Validation is **pipeline-aware** — a requirement is satisfied either by user input OR by a producing module earlier in the run:

| Requirement | Satisfied by user input | …or by an earlier module |
|---|---|---|
| `target` | `-t` | a target-producer (`dns_resolve`, `dnsx_resolve`) satisfies validation, but resolved IPs are name-safe (`dl`/`ul`) — host-full modules (nmap/ssh/smtp/snmp) still require `-t` |
| `domainlist` | `-d` | a domain-producer: `subfinder`, `ax_subfinder`, `ax_puredns_bruteforce` |
| `url_file` | `-url` | a target-scanning module (`ax_nmap_tcp`, `ax_naabu`, `ax_nmap_udp`, `ax_masscan`), or auto-injected `ax_nmap_tcp` |
| *(empty set)* | — | runs with whatever the ledger provides |

## Available Modules

### Discovery & resolution
| Module | Requires | Fleet | Purpose |
|---|---|---|---|
| `subfinder` | `domainlist` | local | Subdomain enumeration (local). |
| `ax_subfinder` | `domainlist` | fleet | Fleet-distributed subfinder. |
| `ax_amass` | `domainlist` | fleet | Subdomain enumeration via OWASP Amass. |
| `ax_puredns_bruteforce` | `domainlist` | fleet | DNS subdomain bruteforce (root domains only). |
| `dns_resolve` | `target` | local | Local DNS resolution with scope filtering + wildcard detection. |
| `dnsx_resolve` | *(none)* | local | Resolution via locally installed dnsx (forward + PTR). |

### Port & service scanning
| Module | Requires | Fleet | Purpose |
|---|---|---|---|
| `ax_nmap_tcp` | `target` | fleet | Unified TCP nmap scan (`PRODUCES` nmap XML; ports/scan-type configurable). `ports: open` = sweep-then-verify: scan only the ports a prior masscan/naabu sweep found open, on live hosts only (standard workflow uses this). |
| `ax_nmap_udp` | `target` | fleet | UDP port scan. |
| `ax_naabu` | `target` | fleet | Fast TCP port discovery (naabu). `ports`: `all` (default), `top-100`/`top-1000`, or explicit `-p` list. |
| `ax_masscan` | `target` | fleet | Masscan port discovery. Writes greppable (`-oG`) output, stream-parsed into the ledger with a per-host tarpit cap (`scan.masscan_tarpit_port_cap`, default 500). Feeds `ax_nmap_tcp ports: open` (sweep-then-verify). |

### Web probing, crawling & content discovery
| Module | Requires | Fleet | Purpose |
|---|---|---|---|
| `ax_httpx` | `url_file` | fleet | Live-web fingerprinting (feeds filtering/intel). |
| `ax_gowitness` | `url_file` | fleet | Web screenshots. |
| `ax_katana` | `url_file` | fleet | JS-aware crawl → URLs into the ledger. Crawl-bounding opts (katana-native, opt-in via step `args`): `depth` (1-10), `crawl_duration` (e.g. `10m`), `field_scope` (`rdn`/`fqdn`/`dn`). |
| `ax_gau` | `domainlist` | fleet | Historical URL discovery (GetAllUrls). |
| `ax_subjs` | `url_file` | fleet | JS endpoint extraction (subjs). |
| `ax_linkfinder` | `url_file` | fleet | JS endpoint extraction (LinkFinder). Absolute URLs it finds are ingested into the ledger; relative endpoints stay in the raw `-linkfinder/` output. Not in `deep` by default (ax_katana covers the JS-endpoint niche and also feeds the ledger) — run via `-m`. |
| `ax_arjun` | `url_file` | fleet | Hidden HTTP parameter discovery. |
| `ax_ffuf` | `url_file` | fleet | Directory/file fuzzing. |
| `ax_feroxbuster` | `url_file` | fleet | Recursive content brute-force. |

### Vulnerability & misconfiguration
| Module | Requires | Fleet | Purpose |
|---|---|---|---|
| `ax_nuclei` | *(none)* | fleet | Nuclei template-based vuln scanning of web URLs AND `-t`-authorized `IP:port` service endpoints (SSH/SMTP/DBs/…) in a single pass. HOST-class: the URL surface stays full (name-safe via Host/SNI) while raw `IP:port` scanning is restricted to `-t`-authorized IPs. |
| `ax_testssl` | `url_file` | fleet | TLS/SSL audit (testssl.sh). **Opt-in — not in the default workflows** (nuclei's ssl/CVE templates cover the actionable TLS findings); run with `-m ax_testssl` for a deep TLS audit. |
| `ax_wafw00f` | `url_file` | fleet | WAF fingerprinting. |
| `ax_dalfox` | `url_file` | fleet | XSS scanning (**invasive**). |
| `ax_corsy` | `url_file` | fleet | CORS misconfiguration checks. |
| `ax_mantra` | `url_file` | fleet | Secret discovery in responses/JS. |
| `ax_wpscan` | `url_file` | fleet | WordPress scanning. |
| `dns_security` | *(none)* | local | DNS posture — SPF (missing/`+all`/`?all`/multi/lookup-limit), DMARC (missing/invalid/`p=none`/no-reporting + RFC 7489 subdomain inheritance), AXFR zone transfer, dangling-NS health. |
| `ssh_audit_scan` | *(none)* | local | SSH: password-authentication-enabled (auth-methods probe, no credentials tried) + CVEs from ssh-audit's `(cve)` section (Terrapin + version-mapped). Weak-algo lines are left to nuclei's `ssh-*` templates. |
| `snmp_sweep` | *(none)* | local | SNMP READ default-community sweep (snmpwalk). 19 common defaults; override via `modules.snmp_sweep.communities`/`community_file`. |
| `smtp_security` | *(none)* | local | SMTP posture — STARTTLS-missing, AUTH-without-TLS, VRFY/EXPN, and a **non-destructive open-relay test** (MAIL FROM/RCPT TO across classic vectors, never DATA; `skip_relay` to disable). |

### bbot (recursive, local, no fleet)
| Module | Purpose |
|---|---|
| `bbot_recon` | **Opt-in only (`-m bbot_recon`) — removed from the built-in workflows.** Consolidated web + cloud + takeover in one recursive scan (`web`/`web-heavy` presets + `bucket_*`/`azure_tenant` + `baddns*`). Dropped from standard/deep because its `web web-heavy` scan can't finish inside its 4h timeout on real engagement-size scopes and returns nothing (burns fleet time for a guaranteed timeout-fail). |
| `bbot_passive` | Passive intelligence/enrichment without touching targets. |
| `bbot_cloud` | Cloud bucket + Azure tenant/realm discovery. In `standard`/`deep` (local/no-fleet, domain-driven) — the fast cloud coverage `bbot_recon` used to bundle. |
| `bbot_takeover` | DNS/subdomain takeover detection (baddns suite). In `standard`/`deep` (local/no-fleet, domain-driven) — the fast takeover coverage `bbot_recon` used to bundle. |
| `bbot_code` | Repo discovery + secret scanning. |
| `bbot_dast` | Dynamic application security testing (**invasive**). |

> **bbot intel → findings.** `normalize` now mints bbot `AZURE_TENANT`
> (Azure/M365 tenant + federated domains), `WAF` (WAF/CDN vendor), and
> `EMAIL_ADDRESS` events as **info-severity findings** (intel context, not
> vulnerabilities). `TECHNOLOGY` events roll up into the `summary` debrief's
> **Technology Stack** table.

### Enrichment, analysis & reporting (all local, no fleet)
| Module | Purpose |
|---|---|
| `shodan_enrich` | Shodan (pluggable-provider) attack-surface enrichment; keys in `~/.monkeyx/credentials.yaml`. CVE findings are Shodan-`verified` only by default (version-inferred CVEs surface as context); set `shodan_cve_findings: all\|none` to change. |
| `normalize` | Convert each tool's raw output into per-tool JSONL; mints findings into `scan.db`. **Idempotent** — overwrites its JSONL and upserts findings by `finding_id`, so it's safe to run repeatedly; the built-in workflows run it **once at the end** (mid-run passes dropped — not worth re-normalizing large data sets), though it stays repeatable if you want extra passes. **Run before `analyze`/`ai_*`.** |
| `analyze` | Programmatic analysis — service categorization, high-value targets, per-host rollup → `{prefix}-analysis.json`. |
| `ai_analyze` | AI attack-path/CVE research + prioritized recommendations. |
| `ai_validate` | **⚠️ EXPERIMENTAL, opt-in only** (never in a built-in workflow; run via `-m ai_validate`/`--rebuttal`). Agentic validation — actively probes findings to confirm/refute. Verdicts are unreliable; treat as leads, not ground truth. |
| `ai_analyze_gowitness` | AI (vision) analysis of gowitness screenshots. |
| `focus` | Single prioritized "where do I start" deliverable (confirmed-first). |
| `jsonl_to_csv` | JSONL → CSV exports. |
| `summary` | End-of-run operational debrief (coverage gaps, errors). |
| `html_report` | Merge all markdown reports into one navigable `report.html`. |
| `nessus_import` | Parse a `.nessus` XML export into normalized JSONL (`--nessus <file>`). |

AI and enrichment providers are configured in `~/.monkeyx/credentials.yaml` — see [AI_SETUP.md](AI_SETUP.md).

## Predefined Workflows

Defined in `workflows/*.yaml`; run with `-w <name>`. `--list-plugins` shows all discovered modules and workflows. Steps in `parallel:` groups run concurrently.

| Workflow | What it does |
|---|---|
| `fast` | Fast enumeration — `subfinder` → `dnsx_resolve` → `shodan_enrich` → masscan top-5000 sweep → `ax_nmap_tcp` (`ports: open` verify), then parallel UDP (top-50)/`ax_httpx`/`dns_security`, then `ax_gowitness` (own step), `normalize`, CSV. |
| `standard` (default) | Comprehensive: recon (`subfinder` ∥ `bbot_passive`) → `ax_puredns_bruteforce` → `dnsx_resolve`, masscan sweep (all ports) → parallel `ax_nmap_tcp` (`ports: open`) + `shodan_enrich`, `ax_httpx`, then parallel `ax_nuclei` (web URLs + `IP:port` service templates) + UDP/`dns_security`/`smtp_security`/`ssh_audit_scan` + `bbot_cloud`/`bbot_takeover`, then `snmp_sweep` (after UDP), `ax_gowitness` (own step), then a single final `normalize`, CSV, `analyze`. |
| `deep` | Maximum external coverage — recon (`ax_subfinder` ∥ `bbot_passive` → `ax_puredns_bruteforce` → `dnsx_resolve`); parallel `ax_nmap_tcp` (all ports) + `bbot_code` + `bbot_cloud`/`bbot_takeover` + `dns_security` + authenticated `shodan_enrich` pivots; `ax_httpx` ∥ UDP; service audits (`ssh_audit_scan`/`snmp_sweep`/`smtp_security`); `ax_katana` crawl (depth 2, 10m cap); `ax_nuclei`; `ax_gowitness`; `bbot_dast` (**invasive**); then a single final `normalize`, CSV, `analyze`, `ai_analyze` + `ai_analyze_gowitness`, `focus`. (`bbot_recon`, `ax_amass`, `ax_linkfinder` are opt-in via `-m`.) |

## Fleet Handling

`-f/--fleet` is optional. If omitted and the run includes fleet-requiring (`ax_*`) modules, a fleet name is auto-generated (e.g. `monkeyx-a7f3`), spun up, and torn down automatically. If **all** modules in the run are local-only, no fleet is created.

### Local modules (no fleet required)

`normalize`, `analyze`, `ai_analyze`, `ai_analyze_gowitness`, `ai_validate`, `focus`, `jsonl_to_csv`, `dns_resolve`, `dnsx_resolve`, `subfinder`, `nessus_import`, all `bbot_*`, `dns_security`, `html_report`, `summary`, `shodan_enrich`, `ssh_audit_scan`, `snmp_sweep`, `smtp_security`.

```bash
# No fleet needed (all local):
monkeyx -od ./output -t targets.txt -m dns_resolve normalize analyze
monkeyx --continue ./output -m ai_analyze

# Fleet auto-generated when any ax_* module is included:
monkeyx -od ./output -t targets.txt -m ax_nmap_tcp ax_nuclei normalize
```

### Early fleet kill

When all fleet-requiring modules have finished and only local modules remain, the fleet is killed immediately rather than idling — saving cloud cost. Automatic; override with `--keep-fleet`.

## Usage Examples

```bash
# Default (standard) workflow
monkeyx -t targets.txt -od ./output

# Specific workflow
monkeyx -t targets.txt -od ./output -w fast
monkeyx -d domains.txt -od ./output -w deep   # domain-only, maximum coverage

# Individual modules (ledger feeds inputs between them)
monkeyx -t targets.txt -od ./output -m ax_nmap_tcp ax_nuclei
monkeyx -d domains.txt -od ./output -m subfinder dnsx_resolve ax_nmap_tcp

# Web modules with a user-supplied URL list (merged with discovered URLs)
monkeyx -url my-urls.txt -od ./output -m ax_nuclei ax_gowitness

# Post-scan AI analysis on an existing run
monkeyx --continue ./output -m normalize analyze ai_analyze ai_validate --ai-depth standard

# Other options
monkeyx -t targets.txt -od ./output -p          # pause after fleet creation
monkeyx -t targets.txt -od ./output -n 50        # fleet size
monkeyx -t targets.txt -od ./output -st sT       # TCP connect instead of SYN
monkeyx -t targets.txt -od ./output -o client-2026   # custom output prefix
```

**Connect-scan fallback (`ax_nmap_tcp`):** a SYN scan reports a host that filters/rate-limits SYN probes (or when the fleet nmap lost raw-socket privilege) as **up with 0 open ports**. Set `modules.ax_nmap_tcp.connect_fallback: true` in `monkeyx.config` (off by default) to re-scan only those hosts with a full TCP connect (`-sT`) over the **same port selection** (`ports:`, default top-1000) and fold the recovered ports into the results — bounded by `connect_fallback_max_hosts` (default 32). See [`MODULE_CONFIG.md`](MODULE_CONFIG.md).

## Adding New Modules

Modules are auto-discovered. Drop a file in `modules/` and implement `run_<name>`:

```python
REQUIRED_INPUTS = frozenset({"target"})   # or "url_file", "domainlist", or frozenset()

def run_my_module(target, prefix, fleet, **kwargs):
    # your logic here
    return {"module": "my_module", "status": "success", "output_files": [f"{prefix}-my-module.txt"]}
```

The `run_` prefix is stripped to derive the module name (`my_module`). No registration needed — MonkeyX scans `modules/*.py` at startup. Common kwargs: `prefix`, `data_prefix`, `reports_prefix`, `fleet`, `scan_type`, `target`, `url_file`, `domainlist`. A URL-consuming module sets `CONSUMES_URLS = True`; an nmap-XML producer sets `PRODUCES = {"nmap_xml": "..."}`.

## Creating Custom Workflows

Workflows are YAML files. Add one to (later sources win on name conflict): `workflows/` (built-in), plugin dirs (`MONKEYX_PLUGINS` / `~/.monkeyx/plugins/`), or `~/.monkeyx/workflows/`.

### Basic

```yaml
name: my_workflow
description: A simple sequential workflow
steps:
  - subfinder
  - dnsx_resolve
  - ax_nmap_tcp
  - ax_nuclei
  - normalize
```

### Parallel execution

Independent modules can run concurrently in a `parallel:` block (via `ThreadPoolExecutor` — modules shell out, so the GIL doesn't block). Subsequent steps wait for the whole group.

```yaml
steps:
  - ax_nmap_tcp
  - parallel:
      - ax_nuclei
      - ax_gowitness
  - normalize
```

URLs discovered by a parallel group are merged into the ledger **after the group completes** (parallel groups snapshot their inputs at launch, so members read the same set).

### Per-step configuration

```yaml
steps:
  - name: ax_nmap_udp
    args:
      top_ports: 500
  - parallel:
      - ax_nuclei
      - name: ax_feroxbuster
        args:
          wordlist: /path/to/custom-wordlist.txt
  - normalize
```

Priority (highest wins): workflow step `args:` → `monkeyx.config` module defaults → hardcoded module defaults.

### Workflow references

```yaml
steps:
  - workflow: standard
  - ax_feroxbuster
  - normalize
```

Circular references are detected and raise an error.

### Duplicate steps & repeatable modules

Resolution **deduplicates by module name** (first occurrence wins), so composing
workflows that overlap won't run the same module twice. The exception is a small
allowlist of idempotent, intentionally-repeatable modules — currently just
`normalize` (`_REPEATABLE_STEPS` in `workflows.py`) — which is kept at **every**
occurrence. The built-in workflows now run `normalize` **once at the end** (the
mid-run progressive-mint passes were dropped — re-normalizing large data sets
repeatedly isn't worth the cost), but the exemption remains so you can still add
extra passes via `-m` or a custom workflow. To make another module repeatable,
add it to that set (only for modules that overwrite their outputs and dedup
their own writes, like `normalize`).

### Step types

| Syntax | Example | Description |
|--------|---------|-------------|
| Bare string | `- ax_nuclei` | Run a module with default args |
| Named step | `- name: ax_nmap_udp` (+ `args:`) | Run a module with per-step overrides |
| Parallel group | `- parallel: [ax_nuclei, ax_gowitness]` | Run modules concurrently |
| Workflow ref | `- workflow: fast` | Expand another workflow inline |

## Quick Reference: Module Input Requirements

`REQUIRED_INPUTS` per module — remember validation is pipeline-aware (an earlier producer satisfies a requirement).

| Requirement | Modules |
|---|---|
| `target` | `ax_nmap_tcp`, `ax_nmap_udp`, `ax_naabu`, `ax_masscan`, `dns_resolve` |
| `url_file` | `ax_gowitness`, `ax_httpx`, `ax_katana`, `ax_subjs`, `ax_linkfinder`, `ax_arjun`, `ax_ffuf`, `ax_feroxbuster`, `ax_testssl`, `ax_wafw00f`, `ax_dalfox`, `ax_corsy`, `ax_mantra`, `ax_wpscan` |
| `domainlist` | `subfinder`, `ax_subfinder`, `ax_amass`, `ax_gau`, `ax_puredns_bruteforce` |
| *(none — runs on ledger state)* | `ax_nuclei`, `dnsx_resolve`, `dns_security`, `shodan_enrich`, `ssh_audit_scan`, `snmp_sweep`, `smtp_security`, all `bbot_*`, `normalize`, `analyze`, `ai_analyze`, `ai_validate`, `ai_analyze_gowitness`, `focus`, `jsonl_to_csv`, `summary`, `html_report`, `nessus_import` |

### How URLs flow

URL provenance lives in the **discovery ledger** (`discovery-ledger.jsonl`, `type: url`), not a flat file. User `-url` URLs are seeded into the ledger; scanning/crawling modules (`ax_nmap_tcp`, `ax_katana`, `ax_gau`, `ax_subjs`, `ax_linkfinder`, `ax_arjun`) add more. Before each URL-consuming step, the engine regenerates that step's URL input from the ledger (scope-filtered, deduplicated), so every web module sees the complete, current set — including both IP-form and hostname-form URLs where DNS resolution mapped them.
