# Running MonkeyX (CLI & webserver)

> Part of the MonkeyX Core docs. See [`../CLAUDE.md`](../CLAUDE.md) for the index.

## Preflight — validate before you run (`--check`)

Validate inputs, credentials, and config **without** starting a scan or touching
the fleet, then exit (`0` = OK, `1` = errors; warnings never fail the check):

```bash
python3 monkeyx.py --check -t targets.txt -w standard
python3 monkeyx.py --check -t 10.0.0.0/24 -d example.com -m ai_analyze
```

It checks:
- **`-t`/`-d`/`-url` formatting** — every line is a valid IP/CIDR/hostname/URL for
  its channel, catching the gotchas that bite at runtime (a UTF-8 BOM or stray
  char that makes masscan report "invalid IP address on line #1", a hostname in a
  `-t` file, a URL in `-d`, …). Inline lists and file paths both validate.
- **`credentials.yaml`** — parses, and the AI provider resolves exactly as a real
  run would (env → `ai.default_provider` → `claude-code` auto-detect when the
  `claude` CLI is on PATH). A missing/placeholder AI key is an **error only when
  the run selects an AI module** (AI is opt-in — `--check -w standard` with no AI
  module passes even with no AI key configured); otherwise it is informational.
  Enrichment placeholder keys (shodan/censys/…) are flagged as warnings.
- **`monkeyx.config`** — parses and its top-level sections are recognized.

## Running

```bash
# Fleet name auto-generated if -f is omitted (e.g. monkeyx-a7f3)
python3 monkeyx.py -n 20 -t targets.txt -od ./output -w standard --ax-account myaccount
python3 monkeyx.py -t targets.txt -od ./output -m ax_nmap_tcp ax_nuclei
python3 monkeyx.py --list-plugins  # show all discovered modules/workflows with source

# Live web view of a run (reads scan.db read-only; works during a scan and after)
python3 monkeyx.py --webserver ./output                        # http://127.0.0.1:8765
python3 monkeyx.py --webserver ./output --webserver-port 9000
python3 monkeyx.py --webserver ./output --webserver-host 0.0.0.0  # bind other iface
# Binds 127.0.0.1 by default (localhost-only); tunnel remotely with `ssh -L`
# rather than exposing it. Serves until stopped (Ctrl+C), then exits.
#
# Implementation: monkeyx/webserver.py — FastAPI + one inline HTML page (no build
# step, no new deps). A left SIDEBAR (nav + live status + per-view count badge)
# plus a main area that swaps between VIEWS: Overview (count cards + findings-by-
# severity bar + step progress), Focus, Report, Findings, Ports, Targets, Web,
# Web Directories (ffuf/feroxbuster hits), Web Screenshots, Coverage. Endpoints:
#  - /api/status — per-run step progress X/Y scoped to the current invocation via
#    run_seq (a --continue run shows "Run 2 · step 4/11" for THIS run plus a
#    cumulative "N steps across M runs" line). Returns `runs` (per-run history,
#    newest first, each with status/done/total/failed/timings/steps[]) rebuilt
#    from progress_events; steps[] includes QUEUED-but-unstarted modules (status
#    `pending`) from the `run_planned` event, so the Overview shows the full
#    upcoming pipeline. Plus counts (findings/ports/targets/web/focus/coverage/
#    screenshots) and `by_severity`. The coverage count is the ACTIONABLE gap
#    (# of no_response rows), not the raw row total.
#  - /api/findings + /api/findings.csv — rich findings view. Defaults to
#    "interesting" (hides info-severity); the "all"/"info" chips browse the rest
#    (no_info governs it server-side). SERVER-side filter (severity + no_info + q
#    search + per-column f.<col>) + sort + pagination (page/size/sort/dir); returns
#    one page + `total` + `by_severity` (unfiltered grand totals). ids_only=1
#    returns the full filtered finding_id list for cross-page "select all". CSV:
#    ?ids= exports those, else re-runs the q/severity/no_info/f.<col> filter so the
#    export matches the on-screen view.
#  - /api/view/{name} + /api/view/{name}.csv (name ∈ focus|ports|targets|web|
#    coverage) — generic tables. Each returns rows + `total` + the COLUMN ORDER
#    (one source of truth: _VIEWS in webserver.py) so table/sort/CSV header stay in
#    sync. Same server-side q + per-column f.<col> + sort + pagination. The .csv
#    route is registered BEFORE /api/view/{name} (Starlette path params match dots
#    and would otherwise capture "ports.csv"). focus = findings ⋈ latest validation,
#    confirmed-first (mirrors modules/focus.py, via the shared
#    scan_db.focus_includes_info predicate so the live view and the generated
#    focus.md/report.html never diverge). coverage = module_coverage ordered
#    gap-first (no_response → step_failed → fed → reached).
#  - /report — serves the consolidated report.html inline (checks reports/report.html
#    then the output-dir root), embedded in the Report view's iframe. Deliberately
#    has NO modules/ import, so it also works in the bundled standalone viewer
#    (viewer/, which ships webserver.py + core/scan_db.py but NOT modules/).
#    Returns a 404 placeholder if no report.html exists yet.
# PAGINATION IS SERVER-SIDE: filter → sort → slice all run over the FULL set on the
# server, then only ONE page is serialized + sent, so a 50k-finding run never ships
# as one payload. The client re-fetches on page/sort/search/filter (debounced) and
# preserves them across the 4s live refresh; filter/sort changes reset to page 0; a
# stale page past the end clamps to the last valid page. CSV export reaches the full
# filtered set and neutralizes formula-injection. NOTE: sort is Python-side over the
# full result set (load → sort → slice), not SQL ORDER BY/LIMIT — rows still live in
# server memory momentarily; true DB-level LIMIT/OFFSET is the next tier only if a
# single table hits millions of rows.

# Explicit fleet name (optional — for reuse with --keep-fleet)
python3 monkeyx.py -f myfleet -n 20 -t targets.txt -od ./output -w standard

# Domain-only workflow (no -t — puredns/subfinder discover subdomains, dnsx_resolve
# resolves them). Resolved names/IPs are name-safe scope: web/URL modules scan them,
# but nmap/ssh/smtp/snmp do NOT (port-scanning needs host-full -t targets). Add
# `-t <ips/cidrs>` if you're authorized to port-scan the resolved IPs.
python3 monkeyx.py -n 20 -d domains.txt -od ./output -w deep

# Local-only modules (no fleet required — no fleet spun up)
python3 monkeyx.py -od ./output -t targets.txt -m dns_resolve normalize analyze
python3 monkeyx.py --continue ./output -m normalize analyze ai_analyze
python3 monkeyx.py --continue ./output -m ai_analyze

# Scope filter (default: strict — only scan in-scope targets)
python3 monkeyx.py -t targets.txt -od ./output --scope-filter warn
python3 monkeyx.py -t targets.txt -od ./output --scope-filter none

# Exclude specific hosts/CIDRs/URLs (always wins, even over -t/-d/-url)
python3 monkeyx.py -t targets.txt -d domains.txt --exclude exclusions.txt -od ./output
# exclusions.txt format (one per line):
#   legacy.example.com          ← matches it AND any subdomain
#   *.staging.example.com       ← subdomains only, NOT the bare domain
#   192.168.99.0/24             ← CIDR
#   10.0.99.42                  ← single IP
#   https://x.example.com/admin ← exact URL
#   # comments and blank lines ignored

# Web modules (gowitness/nuclei/etc.) without an explicit nmap step:
# ax_nmap_tcp is auto-injected to discover open web ports first.
python3 monkeyx.py -d domains.txt -od ./output -m ax_gowitness
# Pass --no-auto-discovery to disable auto-injection:
python3 monkeyx.py -url urls.txt -od ./output -m ax_gowitness --no-auto-discovery

# Pause/resume (Ctrl+C cancels current step and writes checkpoint)
python3 monkeyx.py --resume ./output                     # resume (fleet name from checkpoint)
python3 monkeyx.py --resume ./output -f myfleet          # resume with explicit fleet override
python3 monkeyx.py --resume ./output --keep-fleet        # keep fleet alive between pauses

# Graceful pause (finish current step before checkpointing)
python3 monkeyx.py -t targets.txt -od ./output --finish-step

# Continue — run new modules/workflows in an existing output directory
python3 monkeyx.py --continue ./output -m ax_nuclei
python3 monkeyx.py --continue ./output -w fast
python3 monkeyx.py --continue ./output -w fast -m ax_feroxbuster ax_ffuf
python3 monkeyx.py --continue ./output -m ax_nuclei -t extra-targets.txt
python3 monkeyx.py --continue ./output --dry-run -m ax_nuclei ax_gowitness
```

Required flags: `-od` (output directory). At least one of `-t`, `-d`, `-url` needed (not required for `--resume` or `--continue`).

`-f` (fleet name) is optional — auto-generated if omitted and fleet-requiring modules are in the run. Not needed at all when ALL modules are local-only (normalize, analyze, ai_analyze, dns_resolve, subfinder, the `bbot_*` modules, etc. — authoritative set is `_NO_FLEET_MODULES` in `workflows.py`).

Authentication: pass `--ax-account <name>`, set the `AXIOM_ACCOUNT` env var, or set `fleet.account` in `monkeyx.config` (flag > env > config). If none is set, `iauth()` is skipped.

## Flag reference

Verify against `monkeyx.py` argparse — this table is a summary.

### Inputs & output
| Flag | Purpose |
|------|---------|
| `-t, --target` | Targets: file, single IP/host, or comma-list of IPs/hosts/CIDRs |
| `-d, --domain-list` | Domains: file, single domain, or comma-list |
| `-url, --url-list` | Web hosts: full URLs or bare hostnames (bare → http+https) |
| `-od, --output-dir` | Output directory (required for a scan) |
| `-o, --output` | Output filename prefix (default: today `YYYY-MM-DD`) |

### Fleet
| Flag | Purpose |
|------|---------|
| `-n, --nodes` | Fleet node count (default `1`) |
| `-f, --fleet` | Fleet name (auto-generated if omitted) |
| `--ax-account` | Axiom account for auth (falls back to `AXIOM_ACCOUNT`) |
| `-p, --pause` | Pause after fleet creation, before scanning |
| `--keep-fleet` | Keep fleet alive after completion/pause |
| `--auto-scale` | Size/resize fleet to workload (respects `--max-nodes`) |
| `--max-nodes` | Autoscale cap (default `10`) |

### Pipeline selection
| Flag | Purpose |
|------|---------|
| `-m, --modules` | Run specific modules (space-separated) |
| `-w, --workflow` | Run one or more workflows (default `standard`); concatenated in order |
| `--no-auto-discovery` | Disable auto-injection of `ax_nmap_tcp`/`dns_resolve` before web modules |
| `--no-subdomain-enum` | Skip subdomain-enum modules (test a fixed `-d` list) |
| `--no-sweep` | Skip the masscan pre-sweep; nmap scans top-1000 directly |
| `-st, --scantype` | TCP scan type: `sS` (SYN, default) or `sT` (connect) |

### Scope
| Flag | Purpose |
|------|---------|
| `--exclude FILE` | Exclusion list — always wins over `-t`/`-d`/`-url` |
| `--scope-filter` | `none`\|`warn`\|`strict` (default `strict`; hidden power-user knob) |
| `--ip-scope` | `provenance`\|`strict`\|`strict-resolved` (hidden power-user knob) |
| `--url-prune` | Feed heavy web scanners live URLs only: `off`\|`live`\|`interesting` |
| `--url-max-per-host` | Cap URLs kept per host:port (default unlimited) |

### Run control
| Flag | Purpose |
|------|---------|
| `--resume DIR` | Resume a paused scan from checkpoint |
| `--continue DIR` | Run new modules/workflows in an existing output dir (needs `-m`/`-w`) |
| `--finish-step` | On pause, finish the current step before checkpointing |
| `--dry-run` | Full pipeline with synthetic data (no fleet, no real tools) |
| `--confirm-scope` | Print what WOULD be scanned per channel, then exit (no fleet) |
| `--check` | Validate inputs/credentials/config, then exit (0 ok, 1 errors) |

### AI & misc
| Flag | Purpose |
|------|---------|
| `--ai-depth` | `quick`\|`standard`\|`deep`\|`unlimited` (hosts/findings analyzed) |
| `--multi-pass` | `ai_analyze` runs pure + KB-grounded passes, then reconciles |
| `--allow-intrusive-validation` | Permit `ai_validate` state-changing Tier 2/3 checks |
| `--rebuttal` | `ai_validate` adversarial rebuttal pass |
| `--nessus FILE` | Import a `.nessus` XML export (adds `nessus_import`) |
| `--engagement-id` | Stable id stamped into `scan.db` meta (preserved across continue/resume) |
| `--sync-knowledge` | Sync + re-index the knowledge base, then exit |
| `--list-plugins` | List modules/workflows and their source, then exit |
| `-v, --verbose` | DEBUG-level console logging |
| `--webserver DIR` / `--webserver-host` / `--webserver-port` | Live web view (see above) |
