# Pipeline Internals (background modules, progress, debrief)

> Part of the MonkeyX Core docs. See [`../CLAUDE.md`](../CLAUDE.md) for the index.

## Background modules

Modules in `_BACKGROUND_MODULES` (currently empty) can be launched in a background thread and do not block the pipeline. The remaining steps continue executing immediately. At the end of the run, the engine waits for any still-running background modules to finish before exiting.

Background modules:
- Receive a snapshot of the current target files at launch time
- Run concurrently with subsequent steps
- Report success/failure to the progress tracker
- Are waited on before final completion (the run won't exit until they finish)

## Progress tracking

`run_modules()` writes `progress.jsonl` (append-only) to the output directory when `output_dir` is passed. One JSON line per event: `run_planned` (the full ordered plan for this run, so the live view can show queued-but-not-started modules), `step_started`, `step_completed`, `step_failed`, `parallel_group_started`, `parallel_group_completed`, the pause/cancel lifecycle (`scan_paused`, `scan_cancelled`, `scan_resumed`), and — under `--auto-scale` — `fleet_scaled` (`direction` up/down, `from_nodes`/`to_nodes`, `reason`, `old_fleet`/`new_fleet`), emitted by `FleetScaler` on each fleet transition so scaling is trackable alongside step progress (also in `logs/cost-summary.json` generations). Thread-safe for parallel groups.

A `step_completed` event preserves the module's own outcome in a `status` field — `success`, `skipped` (the module was fed nothing, e.g. a host-class port scan on a URL-only run — must not read as "scanned, found 0"), or `warning` (completed but flagged a concern, with a human-readable `warning` message). `step_failed` is always a failure. Every event is stamped with a per-invocation `run_seq` (allocated from `scan.db`) so the web view can separate this run from cumulative `--continue`/`--resume` history. Run-status derivation from these outcomes (`completed` / `completed_with_warnings` / `completed_with_errors`) lives in the API layer.

Implementation: `core/progress.py` — `ProgressTracker` class. If no `output_dir` is provided, a no-op tracker is used (backward compatible). Each event is also mirrored into `scan.db` (`progress_events` + `module_runs`) — see "Per-engagement SQLite store".

**Console heartbeat.** `HeartbeatPrinter` (same file) is a daemon thread started around the run (always on) that prints a one-line status to stdout every 15s — `[⏳] MM:SS elapsed · N/total steps done · running: <names>` — reading the tracker's live `status_snapshot()`. The first line is emitted only after one full interval, so sub-15s runs (and the test suite) print nothing; it's stopped on every exit path (completion, pause, exception).

## Findings into `scan.db` (`normalize`)

Findings only enter `scan.db` when `normalize` mints them. The built-in
`fast`/`standard`/`deep` workflows run `normalize` **once, at the end** (before
the `analyze`/`ai_*`/`focus` analysis block), so the API (`GET /api/runs/{id}`)
and the `--webserver` viewer populate when the run finishes. Earlier versions ran
extra mid-run passes at phase boundaries for *progressive* findings, but on large
data sets re-normalizing repeatedly cost more than the early visibility was worth,
so those were dropped. `normalize` stays **idempotent** (overwrites its
`-normalized` JSONL, upserts `scan.db` by `finding_id`) and **dedup-exempt**
(`_REPEATABLE_STEPS`), so you can still add mid-run passes via `-m` or a custom
workflow if you want progressive population. Placement + the exemption are covered
in [`MODULES.md`](MODULES.md#duplicate-steps--repeatable-modules).

## Scan debrief (`summary`)

`modules/summary.py` writes `reports/summary.md` (the "Scan Debrief") after every
run — an **Execution** block (module roster: succeeded / ran-no-output / skipped /
failed), a consolidated **Needs Attention** block (failed modules + warnings +
empty output + coverage gaps), a **Cost & Compute** block (total run time, fleet
nodes, instance type, fleet uptime, **cloud instance-hours / node-hours**, and AI
provider/model/tokens/**cost** — so a reader can calc their own cloud spend),
cumulative module-run history, scope counts (Total vs In-Scope),
findings-by-severity/tool, cloud/tech inventory, and AI config. It reads
`discovery-ledger.jsonl`, `data/*-normalized.jsonl`, `progress.jsonl` (run
duration = span of all timestamps), `*-ai-analysis.json`, `*-focus.json`,
`logs/*-axiom-source-ips.txt` (fleet node count = `ax ls`'d live instances),
`logs/cost-summary.json` (node-hours + AI cost, written by `core.cost_tracker`
just before this finalizer runs; instance type comes from
`fleet.instance_type` in monkeyx.config), **and `scan.db`** (authoritative for
In-Scope counts, via `_apply_scandb_scope_counts`). The earlier "Priorities —
Start Here" banner was removed; `focus.json` still ranks "where do I start"
(surfaced by the `focus` module / web viewer, not this debrief).
`modules/html_report.py` renders all
`reports/*.md` into the consolidated `report.html`, so anything added to the
debrief markdown appears in the HTML report automatically. `summary.py` also
writes the root `README.txt` front-door guide (`_write_readme`), and
`html_report.py` copies `report.html` up to the output-dir root — both
best-effort (a failure logs and never fails the run).

**Cloud / CDN / SaaS provider inventory:** `_parse_clouds()` maps hosts to
providers by DNS suffix (`_CLOUD_SUFFIXES` + `_match_provider`, longest-suffix
wins) from two signals: bbot storage buckets (`data/*-bbot-normalized.jsonl`,
selected on `bbot_type == "STORAGE_BUCKET"` — the provider comes from
`bbot_module` first, else the host suffix) and DNS records
(`data/*-resolve-report.jsonl` `cname`/`mx`, with `cdn`/`cdn-name` upgrading a
cname signal to "cdn"). Output is `stats['clouds']` → a "Cloud / CDN / SaaS
Providers" table (Provider | Category | Signals | Hosts | Examples). It is a
descriptive inventory, not a scope/authorization judgment (the tool can't infer
authorization from DNS). nmap-banner and nuclei-detect signals are not mined yet
— add them as extra passes in `_parse_clouds` feeding the same accumulator.
