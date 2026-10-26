<table border="0">
<tr>
<td width="160" valign="middle">
<img src="docs/images/monkeyx-logo.png" width="140" alt="MonkeyX logo">
</td>
<td valign="middle">

# MonkeyX

**Effective external pentest automation — with and without AI. Built by pentesters, for pentesters.**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](docs/DEVELOPERS_GUIDE.md)
![Built by X-Force Red](https://img.shields.io/badge/built%20by-pentesters-red.svg)

</td>
</tr>
</table>

**[Quick Install](#quick-install) · [Documentation](#documentation) · [Usage](#usage) · [Responsible use](#responsible-use)**

---

> ⚠️ **Authorized use only.** MonkeyX is offensive security tooling — it actively
> scans, enumerates, and probes remote systems. Run it **only** against assets you
> own or have **explicit, written authorization** to test. You are solely
> responsible for ensuring your use is lawful and within an agreed scope. See
> [Responsible use](#responsible-use) and [SECURITY.md](SECURITY.md).
>
> Licensed under the **[Apache License 2.0](LICENSE)** — free to use, modify, and
> distribute (including commercially), with an explicit patent grant.

MonkeyX gets the most useful details and likely attack paths in front of a human operator as fast as possible, so you can cut through the noise and spend your time on novel risk discovery and validation. It's a working, open example of the approach we've found delivers the best quality and value: **automation + AI + the human operator**, not any one of them alone.

It started as an internal tool (MonkeyAx) for driving [Ax/Axiom](https://github.com/attacksurge/ax) fleets to get external enumeration done faster, used across real engagements for years. This year it was rebuilt from the ground up. No longer a wrapper around Ax, but a distributed recon-and-scan engine with a target-discovery ledger, a plugin system, structured + AI-driven analysis, and human-first output.

## Why it's built the way it is

If you just want to run it, skip to [Quick Install](#quick-install). If you want to know what's actually going on under the hood, this is the part that matters.

**Scope is enforced by design, not by hope.** The **discovery ledger** is the foundation of the tool and the single source of truth for what gets scanned. The input channel you use IS the authorization level: `-t` targets are fully owned (host-level scanning, all ports); `-d` domains and `-url` URLs are tested **name-safe only** — addressed by hostname (HTTP Host / TLS SNI) so that on shared infrastructure the request reaches the client's service and never a co-tenant, and **never** dragged into a port sweep. A derived asset inherits the ceiling of the channel it came from, so a subdomain found under a `-d` domain stays name-safe unless it resolves into one of your `-t` ranges (ownership promotion). MonkeyX deliberately does **not** infer authorization from ASN/WHOIS/DNS — a customer's cloud VM and their provider's own services share an ASN, so an org-match check would both scan third parties and miss the customer's real assets. Authorization is a fact about the engagement, not something guessed from an IP. Exclusions always win, private/non-routable IPs are dropped automatically, and `--confirm-scope` prints exactly what would be scanned (host-full vs name-safe) before any fleet spins up. Everything is logged with the channel it traces to, so if a question comes up later you can trace exactly what was scanned and why, back to the asset that put it in scope. This is a tool for professionals, not criminals.

**AI is a force multiplier, not a requirement.** MonkeyX runs fine with no AI at all — you get real speed just by turning your manual process into distributed workflows. When you do enable it, the AI layer cross-analyzes enumeration data *across tools* to surface likely attack paths a single scanner would never flag (`ai_analyze`), and can then actively, read-only-by-default, probe those findings to confirm or refute them and cut false positives (`ai_validate`). You set the depth and the limits — for scanning and for AI.

**The output is built for humans.** A command-line tool whose deliverable is an operator-focused view: prioritized findings and a "start here" focus list, a portable self-contained HTML report, CSV, and a live web viewer you can watch mid-scan. The goal isn't "critical/high checkboxes" — it's the cross-tool insight that tells you where to put your hands first.

**Scan wider and deeper, on your terms.** Where some automated pentest products run from a single small cloud instance, MonkeyX fans work out across an Ax fleet you size yourself. You choose how many nodes and how powerful, so you cover more ground in the window you have.

**Flexible by design.** Modules perform actions (an nmap scan, a DNS security review, an AI analysis); workflows chain them in YAML — sequential, parallel, even workflows within workflows. Adding a tool is as quick as *"Claude, make me a module that runs this new repo against web targets."* See [docs/DEVELOPERS_GUIDE.md](docs/DEVELOPERS_GUIDE.md) and [docs/PLUGINS.md](docs/PLUGINS.md).

> **Run it against yourself.** Because MonkeyX is open source, defenders get more than principles — you can see exactly what this class of tool puts on your wire (fleets of ephemeral cloud IPs hitting assets in parallel, CT-log/passive subdomain discovery, nmap/nuclei/ProjectDiscovery signatures, content brute-forcing, CDN-origin hunting) and confirm your monitoring actually fires on it. A tool that finds your gaps also shows your defenders precisely what to watch for.

## Documentation

- AI analysis setup: [docs/AI_SETUP.md](docs/AI_SETUP.md)
- Knowledge base (feed your notes/SOPs to the AI modules): [docs/KNOWLEDGE.md](docs/KNOWLEDGE.md)
- Modules & workflows: [docs/MODULES.md](docs/MODULES.md)
- Plugin system guide: [docs/PLUGINS.md](docs/PLUGINS.md)
- Public developer guide: [docs/DEVELOPERS_GUIDE.md](docs/DEVELOPERS_GUIDE.md)
- Custom plugin example: [examples/custom_plugin/README.md](examples/custom_plugin/README.md)

## Cost Disclaimer
Running cloud instances and AI features cost money, potentially a lot of money. Be mindful of the type and number of AX nodes you are running, AI model and AI limits in place. Manually ensure cloud nodes are properly deleted after each run, create billing alerts, etc.

## DDOS Disclaimer
Please be careful with this tool. It is possible to create a DOS if you hit a target too hard. This is more likely to happen if you are hitting hostnames that are duplicating efforts on a single server, or a large number of targets are behind a single small firewall.

Most Ax scan modules run 15 threads. An example of a safe approach to scanning would be to use a fleet that will concurrently target no more than 25% of the in-scope IPs. If you had 300 IPs in-scope divide that by 15 and then 4 to get the size fleet. In the case of 300 IPs, starting with a fleet size of 5 should be pretty safe.

## Quick Install

### Recommended server specs

The base server runs MonkeyX and orchestrates the scan (local modules + the Axiom fleet):

- **OS:** Ubuntu 24.04 LTS — the installer targets Debian/Ubuntu (`apt`) and this is the tested platform.
- **CPU:** 2–4 vCPU
- **RAM:** 8–16 GB
- **Disk:** 100+ GB — wordlists (SecLists), the Go/Rust toolchains, and per-engagement scan output/`scan.db` add up.

The installer handles system packages, Go/Rust tools, Axiom, wordlists, the Python venv, and the `monkeyx` CLI wrapper:

```bash
git clone https://github.com/matttheplanet/monkeyx
cd monkeyx
sudo bash install-monkeyx.sh
```

Post-install configuration:
1. `ax configure --run` — set up your cloud provider for the fleet. For the fleet
   node size, we recommend a cloud profile with **2 GB RAM** for basic usage, and
   **4 GB RAM** when running memory-intensive modules like `nuclei`.
2. `axiom-build` — build the fleet image.
3. Edit `~/.monkeyx/credentials.yaml` — Add AI and other provider keys (see [docs/AI_SETUP.md](docs/AI_SETUP.md))
4. Edit `~/.config/subfinder/provider-config.yaml` — Add API keys for Subfinder. These are used locally and with Ax. 
5. If desired edit `~/.monkeyx/monkeyx.config` to customize the MonkeyX config.

## Usage

See [docs/MODULES.md](docs/MODULES.md) for detailed module and workflow documentation.

### Standard Workflow on a list of IPs/CIDRs/Hostnames

```bash
# Fleet name is auto-generated if not provided
monkeyx -t scope.txt -od ./output

# Or specify a fleet name explicitly
monkeyx -t scope.txt -f myfleet -od ./output
```

### Post-Scan Analysis

After scanning completes, if your workflow did not include them run the `normalize` and `analyze` modules to produce a structured analysis report:

```bash
monkeyx --continue ./output -m normalize analyze
```

The `analyze` module produces `{prefix}-analysis.json` containing:
- Service categorization (web, databases, Kubernetes, Docker, admin panels, etc.)
- High-value target identification (exposed infrastructure ports, known-vulnerable banners)
- Baseline vs full scan comparison (detects possible scanner blocking)
- Nuclei finding correlation per host
- Outlier ports (ports open on very few hosts — potential dev/forgotten services). Services nmap reports as `tcpwrapped` are ignored here: `tcpwrapped` means the TCP handshake completed but no service banner came back (commonly a firewall/wrapper), so it's not a reliable service signal and would otherwise produce false-positive outliers.
- Per-host combined summary

**Note:** `normalize` must run before `analyze` — it converts raw scan output to JSONL that `analyze` consumes.

For AI-driven analysis, run `ai_analyze` (attack paths and prioritized recommendations, grounded in the scanner findings) and optionally `ai_validate` (an agent that actively probes findings to confirm/refute them). Both require an AI provider configured in `~/.monkeyx/credentials.yaml` — see [docs/AI_SETUP.md](docs/AI_SETUP.md). `--ai-depth {quick,standard,deep,unlimited}` controls how much data is analyzed. Add `--rebuttal` to have an independent second agent adversarially re-check each confirmed/refuted verdict (off by default; roughly doubles `ai_validate` cost). Add `--multi-pass` to have `ai_analyze` reason twice — once with no knowledge base, once grounded in it — and reconcile the two (off by default; roughly doubles `ai_analyze` cost). Every AI prompt and response is recorded in `logs/ai-interactions.log`.

```bash
monkeyx --continue ./output -m ai_analyze ai_validate --ai-depth standard
```

To ground the AI modules in your own reference material (SOPs, HackTricks, private notes), configure an optional **knowledge base** — relevant chunks are retrieved by discovered service/port/protocol and injected into the AI prompts. Copy `knowledge.yaml.example` to `~/.monkeyx/knowledge.yaml`, add your sources, and run `monkeyx --sync-knowledge` to build the index. See [docs/KNOWLEDGE.md](docs/KNOWLEDGE.md).

### Live Web View

A run's results can be browsed in a small local web UI — findings, focus list, ports, targets, web endpoints, and gowitness screenshots — reading the run's `scan.db` read-only. It works **during** a scan (live-updating) and after. There are two ways to run it, depending on whether MonkeyX is installed.

**1. Operator (full MonkeyX install) — `--webserver`:**

```bash
monkeyx --webserver ./output              # http://127.0.0.1:8765
monkeyx --webserver ./output --webserver-port 9000
```

Binds `127.0.0.1` (localhost only) by default; override with `--webserver-host` only if you knowingly need to expose it. For a remote box, tunnel instead: `ssh -L 8765:127.0.0.1:8765 <host>`.

**2. Standalone (from the results zip — no MonkeyX install):**

Every results zip bundles a self-contained `viewer/` so a recipient who has only the scan output can browse it. It needs Python 3.9+ and installs just `fastapi` + `uvicorn` into a local venv on first run — no scanning engine, Axiom, or tools required:

```bash
unzip <prefix>-results.zip -d engagement
cd engagement
./viewer/run.sh                 # macOS/Linux — serves the scan.db next to viewer/
viewer\run.bat                  # Windows
./viewer/run.sh --port 9000     # extra flags pass through
```

Both paths serve the identical UI; the standalone viewer is a verbatim copy of the operator's, bundled at zip time so it never drifts from the schema that produced the data.

### Command-line reference

`monkeyx -h` prints the full, authoritative flag list (it is generated from the code, so it never drifts). For grouped flag tables, usage patterns, and the live web view, see **[docs/CLI_USAGE.md](docs/CLI_USAGE.md)**; for the module/workflow catalog, **[docs/MODULES.md](docs/MODULES.md)** or `monkeyx --list-plugins`.

### Quick Examples

```bash
# Standard workflow — fleet name auto-generated (e.g. monkeyx-a7f3)
monkeyx -t targets.txt -od ./output

# Explicit fleet name
monkeyx -f myfleet -t targets.txt -od ./output

# Specify fleet size
monkeyx -n 5 -t targets.txt -od ./output

# Specific workflow (available: fast, standard, deep — see --list-plugins)
monkeyx -t targets.txt -od ./output -w fast

# Individual modules
monkeyx -t targets.txt -od ./output -m ax_nmap_tcp ax_nuclei

# Domain-only recon (subfinder + dnsx_resolve discover and resolve subdomains)
monkeyx -d domains.txt -od ./output -w fast

# Exclude specific hosts/CIDRs/URLs (exclusions always win over -t/-d/-url)
monkeyx -t targets.txt --exclude exclusions.txt -od ./output

# Local-only modules (no fleet required, no fleet spun up)
monkeyx -od ./output -t targets.txt -m dns_resolve normalize analyze
monkeyx --continue ./output -m normalize analyze ai_analyze

# Continue an existing run with new modules (reuses the target ledger)
monkeyx --continue ./output -m ax_nuclei ax_gowitness

# Dry run (synthetic data, no fleet, no real tools — for testing a pipeline)
monkeyx -t targets.txt -od ./output -w standard --dry-run

# Keep fleet alive after completion (reuse for next scan)
monkeyx -f myfleet -t targets.txt -od ./output --keep-fleet

# Pause/resume (Ctrl+C during scan writes checkpoint)
monkeyx --resume ./output                     # resume (fleet name from checkpoint)
monkeyx --resume ./output -f myfleet          # resume with explicit fleet name
monkeyx --resume ./output --keep-fleet        # keep fleet alive between pauses

# Graceful pause (finish current step before checkpointing)
monkeyx -t targets.txt -od ./output --finish-step

# List all available modules and workflows
monkeyx --list-plugins
```

### Credentials (`~/.monkeyx/credentials.yaml`)

API keys for the AI providers and enrichment services live in `~/.monkeyx/credentials.yaml`. It is **optional** — only the AI modules (`ai_analyze`, `ai_validate`, `ai_analyze_gowitness`) and enrichment modules (`shodan_enrich`, etc.) need it. The installer creates it from the template; on a clone, `cp ~/.monkeyx/credentials.yaml.example ~/.monkeyx/credentials.yaml` and edit in your keys. It is never overwritten by updates.

```yaml
# ~/.monkeyx/credentials.yaml
ai:
  default_provider: anthropic        # anthropic | openai | ollama | claude-code
  anthropic:
    api_key: sk-ant-YOUR-KEY-HERE    # OR comment out and set aws_region for Bedrock
    model: claude-opus-4-6
enrichment:
  shodan:
    api_key: YOUR-SHODAN-KEY         # censys / greynoise / virustotal also supported
```

Environment variables override file values (e.g. `MONKEYX_AI_PROVIDER`, `MONKEYX_AI_MODEL`, `MONKEYX_SHODAN_API_KEY`). For every provider/service, AWS Bedrock setup, and cost-estimation knobs, see [`credentials.yaml.example`](credentials.yaml.example) and [docs/AI_SETUP.md](docs/AI_SETUP.md).

### Module Configuration (`monkeyx.config`)

Override module defaults (wordlists, thread counts, ports) without editing code, in `~/.monkeyx/monkeyx.config`:

```yaml
modules:
  ax_ffuf:
    wordlist: /home/op/lists/seclists/Discovery/Web-Content/raft-large-files.txt
    threads: 80
  ax_nmap_udp:
    ports: top-500
```

Priority (highest wins): workflow YAML step args → `monkeyx.config` → hardcoded module defaults. Global settings under a top-level `fleet:` key set the Axiom account and `--auto-scale` sizing. Full key list and auto-scale behavior: [docs/MODULE_CONFIG.md](docs/MODULE_CONFIG.md) and [docs/FLEET.md](docs/FLEET.md).

### Nessus Import

Import an existing Nessus `.nessus` XML export with `--nessus` — it parses the file into the same normalized JSONL as the `normalize` module, so `ai_analyze` reasons over Nessus findings alongside nuclei/nmap data, and logs its hosts/ports to the target ledger:

```bash
monkeyx --continue ./output --nessus export.nessus -m normalize ai_analyze
```

### Pause, Resume & Continue

- **Pause:** Ctrl+C cancels the current step and writes `checkpoint.json` (exit code 42); the fleet is killed unless `--keep-fleet`. Add `--finish-step` to let the current step finish first.
- **Resume** (`--resume <dir>`): replays the interrupted run from its checkpoint; the fleet is reinitialized if needed.
- **Continue** (`--continue <dir> -m/-w ...`): runs *new* modules/workflows against a prior run's accumulated target ledger. New `-t/-d/-url` inputs are additive and deduplicated. A `--continue` run can itself be paused and resumed.

See [docs/CLI_USAGE.md](docs/CLI_USAGE.md) for the full lifecycle.

### Fleet

`-f/--fleet` is optional — if omitted, a fleet name is auto-generated (e.g. `monkeyx-a7f3`), spun up, and torn down automatically. Pass `-f` for a predictable name you can reuse with `--keep-fleet`, which skips cleanup so the fleet survives across runs or pause/resume cycles. Starting a run with an `-f` name that is already running reuses that fleet (detected via `ax ls`). Kill a kept fleet with `ax rm "myfleet*" -f`. Details: [docs/FLEET.md](docs/FLEET.md).

## Responsible use

MonkeyX is built for professional, authorized security testing, penetration
tests, red-team engagements, and defenders exercising their own environments.
Using it against systems you do not own or lack written permission to test is
very likely illegal (e.g. the US Computer Fraud and Abuse Act, the UK Computer
Misuse Act, and equivalents worldwide) and is not something this project
condones or supports.

Before you run a scan:

- **Have authorization in writing.** The engagement — not an IP, ASN, or WHOIS
  record — is what makes a target in scope. MonkeyX deliberately never infers
  authorization from network metadata.
- **Confirm your scope.** Use `--confirm-scope` to print exactly what would be
  scanned (host-full vs name-safe) before any fleet spins up, and `--exclude` to
  carve out anything off-limits. Exclusions always win.
- **Mind the blast radius.** Fleets hit targets in parallel and can cause a
  denial of service if sized too aggressively — see the [DDOS Disclaimer](#ddos-disclaimer).
- **Understand AI data egress.** Enabling AI modules sends scan data to your
  configured provider. See [docs/AI_DATA_HANDLING.md](docs/AI_DATA_HANDLING.md).

The authors accept no liability for misuse or for any damage caused by use of
this tool. See the "no warranty" terms in the [LICENSE](LICENSE).

## License

Copyright (C) 2026 IBM Corporation.

MonkeyX is licensed under the **Apache License, Version 2.0**. You may use,
modify, and distribute it — including in commercial and closed-source products —
subject to the terms of that license, which also includes an express grant of
patent rights from contributors.

This program is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
OF ANY KIND, either express or implied. See the [Apache License 2.0](LICENSE) for
the full terms.
