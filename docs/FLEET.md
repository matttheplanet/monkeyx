# Fleet & Tool Configs

> Part of the MonkeyX Core docs. See [`../CLAUDE.md`](../CLAUDE.md) for the index.

## Fleet tool configs (auto-pushed via `--local-config`)

When ax modules run tools that support local configuration files (API keys, provider databases, etc.), MonkeyX automatically detects and uploads those configs to all fleet nodes before scanning. This happens transparently — no flags needed.

**How it works:** `core/utils.py:ax_local_config(tool)` checks if a known config file exists locally. If found, it appends `--local-config '/path/to/config'` to the `ax scan` command, which uploads the file to every fleet node.

**Supported tools and their config paths:**

| Tool | Config path | What it provides |
|------|-------------|------------------|
| subfinder | `~/.config/subfinder/provider-config.yaml` | API keys for passive sources (SecurityTrails, Shodan, VirusTotal, Censys, etc.) |
| nuclei | `~/.config/nuclei/.nuclei-config.yaml` | Interactsh server, custom templates path, rate limits |
| httpx | `~/.config/httpx/config.yaml` | Custom resolvers, proxy settings |
| naabu | `~/.config/naabu/config.yaml` | Source IP, interface, rate settings |

**Setup:** Configure tools locally as you normally would (e.g. `subfinder -ls` to list sources, then edit the provider-config). When you run a fleet scan, those configs are pushed automatically. Without a subfinder provider-config, fleet nodes only use free/unauthenticated sources — with one, coverage increases significantly.

**Modules that use this:** `ax_subfinder`, `ax_nuclei`, `ax_httpx`, `ax_naabu`.

Implementation: `core/utils.py` — `ax_local_config()` function + `_TOOL_CONFIG_PATHS` dict.

## Early fleet kill

When all fleet-requiring modules have completed and only local modules remain (normalize, analyze, etc.), the fleet is killed immediately rather than waiting for the entire run to finish. This avoids burning cloud costs while long-running local modules execute.

Implementation: `_last_fleet_step_index()` in `workflows.py` pre-computes the last step index that needs a fleet. After each step completes, the engine checks if it has passed that index and kills the fleet via `_kill_fleet_early()`. The `finally` block skips fleet cleanup if it was already killed early. Respects `--keep-fleet`.

## Fleet sizing & autoscale (`--auto-scale` / `--max-nodes`)

By default the fleet is a fixed `-n`/`--nodes` count (default **1**). `--auto-scale`
(also settable via `monkeyx.config` `fleet.auto_scale`) makes the fleet size track
the workload, capped by `--max-nodes` (default **10**):

- **Initial sizing** — only when `--auto-scale` is set AND `-n` is left at its
  default of 1. `compute_initial_nodes()` seeds a throwaway ledger from the
  `-t`/`-d`/`-url` inputs (honoring `--exclude`), or loads the existing ledger on
  `--continue`/`--resume`, and sizes the opening fleet from the in-scope workload
  so it doesn't boot at 1 node and grow on step 2. Explicit `-n` always wins.
- **Between-step scaling** — `FleetScaler` resizes as the ledger's target count
  changes: scale UP when optimal > current×1.5, DOWN when optimal < current×0.5.
  A new fleet spins up under a fresh name while the old one is killed in a
  background thread.

Sizing is input-aware: IP-scanning steps size by in-scope IP count
(`TARGETS_PER_NODE`), URL-scanning steps (nuclei/gowitness/ffuf/...) by URL count
(`URLS_PER_NODE`); CIDRs count as capped host-equivalents, domains as 1 each
until resolved. Without `--auto-scale` a `NoOpScaler` keeps the fleet static.

Implementation: `compute_initial_nodes()`, `compute_optimal_nodes()`,
`FleetScaler`, `NoOpScaler` in `core/fleet.py`.

## Axiom auth timeout (`ax account`)

`iauth()` runs `ax account <name>`, which re-runs the cloud-provider login
(e.g. `ibmcloud login --apikey`). That login can be slow — IBM Cloud routinely
exceeds a minute. MonkeyX waits up to **300s** (was 60s, which proved too short);
on timeout the account may not have switched, so the next `ax fleet` can fail
with a confusing **`imageid ... not found`** (it ran against the wrong/previous
account's `axiom.json`). If that happens, the login was just slow — run
`ax account <name>` once by hand, or raise the wait:

```bash
export MONKEYX_AX_AUTH_TIMEOUT=600   # seconds; 0 = no timeout
```

Implementation: `AX_AUTH_TIMEOUT` / `_ax_auth_timeout()` in `core/fleet.py`.
