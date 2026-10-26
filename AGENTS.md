# AGENTS.md — MonkeyX Core (quickstart)

Distributed external-pentest scanning orchestrator: runs nmap, nuclei, gowitness,
subfinder, bbot, and more across an Axiom (Attack Surge Ax) fleet, driven by a
target-discovery ledger and composable YAML workflows.

> **This is a quickstart, not an architecture reference.** For the full
> architecture — engine internals, the discovery ledger, scope model, scan.db,
> the AI modules, and every gotcha — **see [CLAUDE.md](CLAUDE.md)**, which is the
> authoritative doc.

## Repo layout (high level)

```
monkeyx.py     CLI entry point (arg parsing, fleet init, dispatch)
workflows.py   Module discovery, workflow resolution, execution engine
core/          Engine internals (fleet, ledger, scan.db, progress, config, AI, …)
modules/       One file per tool, auto-discovered (any run_<name>() becomes a module)
workflows/     YAML workflow definitions (fast, standard, deep)
docs/          MODULES.md, AI_SETUP.md, STRUCTURE.md, LOGGING.md, and more
```

See [docs/STRUCTURE.md](docs/STRUCTURE.md) for the annotated `core/` file list.

## Running

```bash
# Standard workflow (default); fleet name auto-generated if -f is omitted
python3 monkeyx.py -t targets.txt -od ./output

# Pick a workflow
python3 monkeyx.py -t targets.txt -od ./output -w fast
python3 monkeyx.py -d domains.txt -od ./output -w deep

# Individual modules
python3 monkeyx.py -t targets.txt -od ./output -m ax_nmap_tcp ax_nuclei

python3 monkeyx.py --list-plugins   # list all modules/workflows + source
```

- `-od` (output directory) is **required**.
- Provide **at least one** of `-t` (targets), `-d` (domains), `-url` (URLs) —
  not required for `--resume` or `--continue`.
- `-f` (fleet name) is **optional**: auto-generated when fleet-requiring modules
  run, and skipped entirely when all modules are local-only.

**Workflows:** `fast` (quick enumeration), `standard` (default; comprehensive),
`deep` (maximum coverage + AI analysis).

**Tabular exports are CSV** (`jsonl_to_csv`). URL provenance lives in
`discovery-ledger.jsonl` (`type: url`).

## Axiom auth (optional)

Account resolution order (highest wins): `--ax-account` flag → `AXIOM_ACCOUNT`
env var → `monkeyx.config` `fleet.account`. If none is set, auth is skipped.

## Tests

```bash
cd tests && python -m pytest
```
