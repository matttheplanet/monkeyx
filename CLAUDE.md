# CLAUDE.md — MonkeyX Core

> **Editing note:** This file is a *lean index*, kept under a char budget (enforced by `tests/test_claude_md_size.py`). Deep-dive detail belongs in `docs/*.md`, not here — add a one-line pointer below, put the prose in the relevant doc.

## What this is

Distributed security scanning orchestrator built on Axiom (Attack Surge Ax). Runs nmap, nuclei, gowitness, feroxbuster, ffuf, subfinder across a fleet of cloud nodes. Used for external pentesting engagements.

## Architecture

```
monkeyx.py          CLI entry point — parses args, inits fleet, delegates to workflows.py
workflows.py         Module discovery, workflow resolution, execution engine (sequential + parallel)
core/
  plugin_loader.py   Discovers modules/workflows from built-ins, env var, ~/.monkeyx/, entry points, YAML
  fleet.py           Axiom fleet lifecycle: iauth(account), initialize_fleet(), kill_fleet()
  progress.py        Step-level progress tracking (JSONL + scan.db mirror)
  checkpoint.py      Pause/resume via sentinel file + checkpoint.json
  target_ledger.py   Target discovery tracking with scope/provenance (JSONL + scan.db mirror)
  scan_db.py         Per-engagement SQLite store (output_dir/scan.db) + shared finding_id
  credentials.py     Credential store loader (~/.monkeyx/credentials.yaml + env var overrides)
  ai_provider.py     AI provider abstraction (Anthropic, Anthropic via AWS Bedrock, OpenAI, Ollama)
  utils.py           bash_command() — all shell execution goes through here
  scanning.py        Nmap folder merging
  nmap_service_parse.py  Nmap XML parsing, URL extraction for downstream tools
modules/             One file per tool, auto-discovered at import time
workflows/           YAML workflow definitions (fast, standard, deep)
```

## Module contract

Every module in `modules/` exposes:
- `run_<name>(**kwargs)` — auto-discovered by `_discover_modules()` in workflows.py
- `REQUIRED_INPUTS = frozenset({"target"})` — declares what user-provided inputs are needed (empty frozenset means the module can run with whatever the pipeline provides)

Input vocabulary: `"target"` (IPs/CIDRs file), `"url_file"` (URL list), `"domainlist"` (domain list).

Validation is pipeline-aware: a module's `"target"` requirement is satisfied not only by user-provided `-t` but also by a target-producing module (`dns_resolve`, `dnsx_resolve`) appearing earlier in the pipeline. Similarly, `"domainlist"` is satisfied by domain-producing modules (`subfinder`, `ax_puredns_bruteforce`). This enables domain-only workflows like `fast` where `-d` is the only user input. **Validation only lets the run proceed — it does NOT mean resolved IPs get port-scanned.** IPs resolved from `-d`/`-url` are name-safe scope (`dl`/`ul` channel): web/URL modules scan them, but host-full modules (nmap/ssh/smtp/snmp) run ONLY on `-t` (`t`-channel) targets. So a domain-only run does no port scan unless `-t` is also given.

Common kwargs passed to all modules: `prefix`, `data_prefix`, `reports_prefix`, `fleet`, `scan_type`, `target`, `url_file`, `domainlist`.

Output is split into subdirectories under the output dir:
- `report.html` — **the human front door**, at the output-dir root. A copy of
  `reports/report.html` (self-contained HTML), surfaced so a user lands on the
  deliverable instead of a pile of machine files. Written by `html_report.py`.
- `README.txt` — root orientation guide ("open report.html; reports/ = human,
  data/ = machine, logs/ = operational"). Written by `summary.py:_write_readme`.
- `data/` — machine-readable files (JSONL, XML, CSV, raw text). Modules use `kwargs.get('data_prefix', prefix)`.
- `reports/` — human-readable files (markdown reports, CSVs, gowitness screenshots, `report.html`). Modules use `kwargs.get('reports_prefix', prefix)`.
- `logs/` — operational logs: `{prefix}-monkeyx.log`, `{prefix}-errors.log`, `{prefix}-axiom-source-ips.txt`.

Both root files (`report.html`, `README.txt`) are regenerated every run and
archived in the results zip (top-level files are always included). Tabular
exports are CSV (`jsonl_to_csv`) — there is no XLSX.

Modules fall back to `prefix` if the new kwargs are absent, so calling a module directly still works.

`url_file` is set to `data/ledger/ledger-urls.txt` (regenerated from the ledger before each step). User-provided URLs are seeded into the ledger via `user_url_file` kwarg.

## Workflow YAML format

```yaml
name: example_workflow
description: Example with parallel web scanning
steps:
  - name: ax_nmap_tcp                  # named step with custom args
    args:
      ports: all
  - parallel:                 # parallel group — runs concurrently via ThreadPoolExecutor
      - ax_nuclei
      - ax_gowitness
  - name: ax_nmap_udp            # named step with custom args
    args:
      ports: top-500
  - normalize
```

Step types:
- **Bare string**: `- ax_nuclei` — run a module sequentially
- **Named step with args**: `- name: module` + `args: {...}` — custom per-step config
- **Parallel group**: `- parallel: [...]` — run modules concurrently via ThreadPoolExecutor
- **Workflow reference**: `- workflow: fast` — expand another workflow inline (recursive, not allowed inside parallel blocks)

## Detailed documentation

The deep-dive docs below live in `docs/`. Read the relevant one when a task touches that subsystem — they are NOT auto-loaded, keeping this file a lean map.

- **[`docs/SCOPE_AND_LEDGER.md`](docs/SCOPE_AND_LEDGER.md)** — Execution flow + the target discovery ledger (source of truth): scope filtering, `--ip-scope`, input-channel authorization, private-IP filtering, discovery extraction, URL pruning, resume.
- **[`docs/SCAN_DB.md`](docs/SCAN_DB.md)** — Per-engagement `scan.db` (SQLite): tables, engagement identity, module coverage, shared `finding_id`, who writes what, findings triage state.
- **[`docs/AI_MODULES.md`](docs/AI_MODULES.md)** — `ai_analyze`, `ai_validate` (agentic validation, tools, scope safety, rebuttal), `focus`, the eval harness, and the knowledge base.
- **[`docs/MODULES_INTERNALS.md`](docs/MODULES_INTERNALS.md)** — engine-internal detail on bbot modules and the external attack-surface modules (ax wrappers, `shodan_enrich`, shared tool runners). See also the module/workflow catalog in [`docs/MODULES.md`](docs/MODULES.md).
- **[`docs/FLEET.md`](docs/FLEET.md)** — Fleet tool configs auto-pushed via `--local-config`, and early fleet kill.
- **[`docs/CREDENTIALS.md`](docs/CREDENTIALS.md)** — `~/.monkeyx/credentials.yaml` — AI provider + enrichment keys, provider options.
- **[`docs/MODULE_CONFIG.md`](docs/MODULE_CONFIG.md)** — `monkeyx.config` per-module defaults and priority order.
- **[`docs/PIPELINE.md`](docs/PIPELINE.md)** — Background modules, progress tracking, the scan debrief (`summary`).
- **[`docs/GOTCHAS.md`](docs/GOTCHAS.md)** — The full gotchas list (target/url regeneration, continue/resume, cross-run merge, pause/resume, auto-injection, etc.).
- **[`docs/CLI_USAGE.md`](docs/CLI_USAGE.md)** — Running MonkeyX: CLI examples, flags, and the `--webserver` live view.
- **[`docs/AI_SETUP.md`](docs/AI_SETUP.md)** — AI provider setup (Anthropic direct, AWS Bedrock, OpenAI, Ollama, Claude Code CLI), model options, cost estimation.
- **[`docs/AI_DATA_HANDLING.md`](docs/AI_DATA_HANDLING.md)** — Data-egress posture: what AI modules send to the provider, aliasing, screenshots, `--dry-run`.
- **[`docs/KNOWLEDGE.md`](docs/KNOWLEDGE.md)** — Optional knowledge base: `knowledge.yaml` sources, `--sync-knowledge`, retrieval-by-service injection.
- **[`docs/PLUGINS.md`](docs/PLUGINS.md)** — Plugin system: discovery sources and the external module/workflow contract.
- **[`docs/DEVELOPERS_GUIDE.md`](docs/DEVELOPERS_GUIDE.md)** — Adding modules/workflows and repo conventions.
- **[`docs/LOGGING.md`](docs/LOGGING.md)** — Log files and what each records.
- **[`docs/STRUCTURE.md`](docs/STRUCTURE.md)** — Repo and output-directory layout.

## Tests

```bash
cd tests && python -m pytest
```
