# MonkeyX Logging System

> Part of the MonkeyX Core docs. See [`../CLAUDE.md`](../CLAUDE.md) for the index.

All scan activity, module execution, and errors are logged via Python's
`logging` module. Log files live in the run's `logs/` directory (under `-od`).

## Log files

```
logs/
├── {prefix}-monkeyx.log          # Main log — INFO + DEBUG (full execution flow)
├── {prefix}-errors.log           # Errors only — ERROR + CRITICAL (quick triage)
├── {prefix}-axiom-source-ips.txt # Fleet node source IPs used for the scan
├── ai-interactions.log           # Every AI prompt + response (post-aliasing) — shared egress audit sink
├── costs-YYYYMMDD-HHMMSS.txt     # Per-run AI token usage + estimated cost
└── cost-summary.json             # Machine-readable copy of the cost summary
```

`{prefix}` is the output prefix (`-o`, default today's date). `monkeyx.log` and
`errors.log` paths come from `core/logging_config.py`; `ai-interactions.log` is
the shared sink written by `core/ai_provider.py` (no prefix — one per run dir);
`costs-*.txt`/`cost-summary.json` are written by `core/cost_tracker.py`;
`axiom-source-ips.txt` is written during fleet init in `core/fleet.py`.

## Levels and verbosity

| Level | Use |
|-------|-----|
| DEBUG | Detailed diagnostics (troubleshooting, dev) |
| INFO | Normal operation tracking |
| WARNING | Non-critical issues |
| ERROR | Failed operations |
| CRITICAL | System-level failures |

- Default: console shows **INFO**, file captures **DEBUG**.
- `-v` / `--verbose`: console shows **DEBUG** too (file is DEBUG either way).

```bash
python3 monkeyx.py -t targets.txt -f myfleet        # INFO console
python3 monkeyx.py -t targets.txt -f myfleet -v      # DEBUG console
```

## Format

```
# console
INFO - Starting TCP scan
ERROR - Module ax_nmap_tcp failed: connection timeout

# file (timestamp - logger - level - message)
2026-02-24 11:45:01 - monkeyx.workflows - INFO - Starting module: ax_nmap_tcp
2026-02-24 11:45:05 - monkeyx.workflows - ERROR - Error running module 'ax_nmap_tcp': connection timeout
```

## What gets logged

- **Startup**: CLI arguments, workflow/module selection, configuration.
- **Fleet**: authentication, initialization, node count, termination.
- **Modules**: start/completion times, results (DEBUG), failures with stack traces.
- **Discovery/URLs**: list loading, merging, deduplication.
- **Errors**: module failures, missing files, timeouts, parse errors.

## Troubleshooting

```bash
cat logs/<prefix>-errors.log          # errors only
grep ERROR logs/<prefix>-monkeyx.log  # errors in the main log
tail -f logs/<prefix>-monkeyx.log     # follow live
```

## Rotation

Logs are **not** auto-rotated. For long engagements, compress or `logrotate`
old logs yourself (e.g. `gzip logs/old-engagement-*.log`). The standard
timestamp/level format parses cleanly in Splunk, ELK, Graylog, or CloudWatch.
