# Scanning Modules (bbot & external attack-surface)

> Part of the MonkeyX Core docs. See [`../CLAUDE.md`](../CLAUDE.md) for the index.

## bbot modules (recursive scanning via bbot CLI)

MonkeyX wraps [bbot](https://github.com/blacklanternsecurity/bbot) for capabilities where bbot's recursive event pipeline adds value over running individual tools. bbot modules run locally (no fleet needed) and output JSONL that flows through the standard normalize → analyze → ai_analyze → ai_validate pipeline.

**Architecture:** Two invocation modes in `modules/_bbot_common.py`:
- `run_bbot_modules(targets, modules, ...)` — explicit module list (for focused checks)
- `run_bbot_flags(targets, flags, ...)` — flag presets (lets bbot auto-chain its pipeline)

**Available modules:**

| Module | Invocation | Input | What it does |
|--------|-----------|-------|-------------|
| `bbot_cloud` | `-m bucket_amazon,bucket_google,...` | domainlist | Cloud bucket enum (S3, GCS, Azure Blob, DO, Firebase) + Azure tenant/realm discovery |
| `bbot_takeover` | `-m baddns,baddns_direct,baddns_zone` | domainlist | DNS takeover detection + zone transfer + NSEC walking |
| `bbot_passive` | `-f passive,safe` | domainlist + target | Passive intel: Shodan InternetDB, Wayback, viewdns reverse whois, ipneighbor, CT logs. Zero target contact. |
| `bbot_recon` | `-f web,web-heavy` | domainlist + target | Full recursive web pipeline: crawl → extract params → bypass403, git exposure, IIS shortnames, NTLM, host header injection, etc. **Opt-in only (`-m bbot_recon`)** — removed from `standard`/`deep` (its `web web-heavy` scan can't finish inside its 4h timeout on real-size scopes). |
| `bbot_code` | `-f code-enum` | domainlist | Discover repos (GitHub, GitLab, Postman, Docker) → clone → trufflehog secret scanning |
| `bbot_dast` | `lightfuzz` preset + `generic_ssrf` | url_file (httpx-live) + open_ports | DAST fuzzing: SQLi, XSS, SSRF, SSTI, CMDi, path traversal. INVASIVE — only run with explicit authorization. |

**Input scoping (each module is fed only what it can use).** The shared
`collect_bbot_targets()` can union domains + IPs + URLs + host:port, but each
caller passes only the sources that matter for its modules, so bbot isn't handed
targets it will ignore (which only inflate the count-scaled timeout) or mangle:
- `bbot_cloud` / `bbot_takeover` / `bbot_code` — **domainlist only** (bucket/azure
  and code-search key off org/domain names; baddns takeover is per-hostname).
  `bbot_code`'s `_extract_apex_domains` also hard-skips URLs/host:port/IPs — the
  naive last-two-labels collapse otherwise turns `https://api.example.com/v1` into
  the invalid domain `example.com/v1`.
- `bbot_passive` — **domainlist + target** (passive sources key off DNS_NAME /
  IP_ADDRESS; URLs/ports add nothing).
- `bbot_dast` — **url_file + open_ports only** (the loud fuzzer hits known-live
  endpoints; it's in `_LIVE_URL_SCANNERS` so under `--url-prune` its `url_file` is
  the httpx-live subset). Deliberately NOT fed domainlist/target, which would make
  bbot re-crawl and fuzz dead/derived hosts.
- `bbot_recon` — the one module that legitimately wants the broad union.

**Exclude lists:** Each flag-based module excludes bbot modules already covered by other MonkeyX modules (nuclei, naabu, cloud, takeover) to avoid redundant scanning.

**Data pipeline integration:**
1. bbot modules output `{prefix}-bbot-{type}.jsonl` (raw bbot event JSONL)
2. `workflows.py` extracts DNS_NAME/IP_ADDRESS/URL events into the discovery ledger (target expansion)
3. `normalize` parses `*-bbot-*.jsonl` → extracts FINDING, VULNERABILITY, OPEN_TCP_PORT, TECHNOLOGY, STORAGE_BUCKET, CODE_REPOSITORY, SOCIAL, EMAIL_ADDRESS, URL_HINT, AZURE_TENANT, WAF events → writes `{prefix}-bbot-normalized.jsonl`. AZURE_TENANT (Azure/M365 tenant + federated domains), WAF (WAF/CDN vendor), and EMAIL_ADDRESS are minted as **info-severity findings** (intel for the findings view / web viewer, not vulnerabilities — suppressed from the confirmed-first focus list by default); TECHNOLOGY events additionally roll up into `summary`'s **Technology Stack** inventory table (`_parse_technologies`).
4. `analyze` loads bbot normalized data into `analysis.json` (summary counts + bbot_findings array)
5. `ai_analyze` loads bbot findings/ports/tech into host-keyed structure for AI analysis
6. `ai_validate` receives bbot findings as recommendations via ai-analysis.json

**Cross-run merge:** All bbot modules are registered in `core/merge_outputs.py` with dedup by `(type, data)`.

**Registration:** All bbot modules are in `_NO_FLEET_MODULES` (run locally). Auto-discovered via standard `run_<name>()` convention.

## External attack-surface modules (2026-07 build)

A batch of modules added to widen external coverage and feed the AI pipeline.
They follow the standard contract and their findings flow through
normalize → analyze → ai_analyze → ai_validate → scan.db like any other tool.

**Fleet ax wrappers** (thin wrappers over built-in ax modules via
`modules/_ax_common.py:run_ax_module`; ax bundles even the Dockerized tools into
the fleet image, so all run via `ax scan`):

| Module | ax module | Input | Output → role |
|--------|-----------|-------|---------------|
| `ax_testssl` | testssl | url_file | TLS audit → findings (CVE/weak-cipher lines parsed by normalize) |
| `ax_wafw00f` | wafw00f | url_file | WAF/CDN fingerprint → info findings (origin-discovery + FP context) |
| `ax_katana` | katana | url_file | JS-aware crawl → URLs into ledger |
| `ax_gau` | gau | domainlist | historical URLs → ledger |
| `ax_arjun` | arjun | url_file | hidden params → URLs into ledger |
| `ax_dalfox` | dalfox | url_file | XSS (INVASIVE) → findings |
| `ax_corsy` | corsy | url_file | CORS misconfig → findings |
| `ax_subjs` | subjs | url_file | JS endpoints → ledger |
| `ax_linkfinder` | linkfinder | url_file | JS endpoints (Docker, ext:dir) |
| `ax_mantra` | mantra | url_file | secrets in responses → findings |
| `ax_wpscan` | wpscan | url_file | WordPress deep scan (ext:dir) |
| `ax_amass` | amass | domainlist | extra subdomains → ledger |

normalize parses the plain-text outputs of testssl/wafw00f/dalfox/corsy/mantra
into finding records (there is no JSON variant for these ax modules). katana/gau/
subjs/arjun URLs and amass subdomains are logged to the ledger in
`_extract_discoveries` (workflows.py), so downstream steps pick them up.

**`shodan_enrich`** (local, no-fleet; NOT passthrough under `--dry-run` — it
posts client IPs to the Shodan API, so a dry-run synthesizes it instead of
making the real call): authenticated
Shodan enrichment. Host lookups (`/shodan/host/{ip}`) are free and run by
default. Because Shodan has no resolver, the module reads the ledger's
scope-authorized **bare-IP** export (`target_ips_file` → `ledger-target-ips.txt`)
so it works on **domain-only runs** where the plain target file is
hostname-collapsed — it enriches the IPs behind in-scope names (resolved earlier
by `dnsx_resolve`), stamping each record with `resolved_from` so a reviewer can
tell an origin from a shared CDN edge. Credit-spending pivot searches are opt-in
(`searches: true`) and bounded
by `max_query_credits` (searches that exceed the cap are skipped and reported,
never silently dropped). Results cache to `{prefix}-shodan-cache.json` so
re-runs/resume don't re-bill. Reads keys via `core.credentials.get_enrichment_key`.
Emits normalize-shaped JSONL (`{prefix}-shodan.jsonl`). Shodan `vulns` are
version/CPE-inferred (they ignore distro backports and tag every CVE ever tied to
a banner version), so by default **only Shodan-`verified` CVEs become findings**;
the rest are surfaced as `host_info` context (`possible_cves`) rather than a
HIGH-severity flood. Tune with **`shodan_cve_findings`**: `verified` (default) |
`all` (every CVE → finding) | `none` (host_info only). Discovered IPs are logged
to the ledger as **derived** (authorization still comes from `-t`, never from
Shodan org/ASN data). Config knobs live under
`modules.shodan_enrich` in `monkeyx.config` / workflow step `args`. A provider
seam (`_provider_available`) lets censys/greynoise drop in later — absent keys
skip cleanly, they never fail the run. The module **defaults to
host-lookup-only**, but all three shipped workflows (`fast`, `standard`, `deep`)
enable the credit-bounded org/cert pivot searches.

**Shared tool runners (`core/tool_runners.py`)** — the single, AI-free home for
scope parsing, argv execution, and read-only tool runners:
- `load_scope()` / `Scope`: parse the target file + discovery ledger into
  in-scope IPs/networks/hosts, fail-closed membership test. **This is the one
  scope-parsing implementation** — `ai_validate._parse_scope` delegates to it
  (returns the legacy tuple shape so `_is_safe_command` is untouched), and the
  Phase-F modules call it directly. Guarded by
  `tests/test_ai_validate_toolrunner_parity.py`.
- `run_argv()`: `subprocess.run(shell=False)` with timeout + output truncation.
  `ai_validate._execute_command` is now a thin alias of it.
- Runners used by the Phase-F service-audit modules `ssh_audit_scan`,
  `snmp_sweep`, `smtp_security` (all local, no-fleet). They read the ledger
  open-ports file, enforce scope via `load_scope`, and run argv-only checks:
  - `ssh_audit()` — ssh-audit (algorithm/version/CVE audit). `ssh_audit_scan`
    now uses only its `(cve)` section (Terrapin + version CVEs); weak-algo lines
    are left to nuclei's `ssh-*` templates.
  - `ssh_auth_methods()` — queries permitted SSH auth methods with
    `PreferredAuthentications=none` (**attempts no credentials**); `ssh_audit_scan`
    raises a finding when `password`/`keyboard-interactive` is offered.
  - `snmp_walk()` — fixed READ-community snmpwalk (community list is
    config-overridable in `snmp_sweep`, still a caller-controlled allowlist).
  - `smtp_probe()` — EHLO-capability grab (STARTTLS/AUTH/VRFY/EXPN posture).
  - `smtp_relay_probe()` — **non-destructive** open-relay test: MAIL FROM/RCPT TO
    across the classic vectors, never DATA (no mail relayed). `smtp_security`
    runs it on 25/587 by default (`skip_relay` to disable).

SNMP write and VRFY user-enumeration remain only in ai_validate's opt-in
intrusive tier. **Not yet shared:** ai_validate's 12
command *builders* (`_build_command`) still live in `ai_validate.py` — moving
them into `tool_runners` is an eval-scored follow-up (a golden byte-identical
command test is the merge gate), deliberately deferred so verdict behaviour
can't shift.

**Workflows:** `deep` (maximum external coverage) chains the heavy set;
`standard` was retrofitted with the cheap high-signal win `shodan_enrich`
(`ax_wafw00f`/`ax_testssl` and the ax JS/param/XSS/CORS tools stay opt-in via
`-m`). Noisy tools (`crlfuzz`, `http2smugl`) were deliberately not built.

**`ax_testssl` is opt-in, NOT in any default workflow.** It was removed from
`standard` and `deep`: nuclei's `ssl` templates + CVE templates cover the
actionable TLS findings (weak protocol/cipher, cert issues, Heartbleed/ROBOT/…)
in structured JSONL, while testssl's unique output is mostly low-severity crypto
detail (SWEET32/RC4/BEAST/LUCKY13) that adds runtime, findings-table noise, and a
brittle plain-text parser in `normalize`. Reach for it explicitly (`-m
ax_testssl`) when an engagement needs a deep TLS audit; `ai_validate` can also
still invoke testssl via its `testssl_check` tool to validate a specific TLS
finding on demand. The module + its normalize parser are retained unchanged — the
demotion is purely a workflow-membership change.
