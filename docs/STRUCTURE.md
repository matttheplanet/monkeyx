# MonkeyX Project Structure

## Directory Organization

```
monkeyx/
├── core/                       # Core functionality (engine internals)
│   ├── plugin_loader.py        # Module/workflow discovery from plugins
│   ├── target_ledger.py        # Discovery ledger — targets/ports with scope + provenance
│   ├── scope_classes.py        # Module scope classification (host/name/passive) registry
│   ├── scan_db.py              # Per-engagement SQLite store (scan.db)
│   ├── fleet.py                # Axiom fleet lifecycle (iauth/init/kill)
│   ├── checkpoint.py           # Pause/resume: sentinel file + checkpoint JSON
│   ├── preflight.py            # --check preflight validation (inputs/creds/config)
│   ├── progress.py             # Step-level progress tracking (JSONL + scan.db)
│   ├── credentials.py          # ~/.monkeyx/credentials.yaml loader
│   ├── ai_provider.py          # AI provider abstraction (Anthropic/Bedrock/OpenAI/Ollama)
│   ├── anonymize.py            # IP/domain aliasing for AI egress (H1…/D1…)
│   ├── knowledge.py            # Knowledge base (FTS5) for AI prompt injection
│   ├── tool_runners.py         # Shared scope parsing + argv/read-only tool runners
│   ├── attack_policy.py        # Command denylist for ai_validate (the "bad attacks" library)
│   ├── output_layout.py        # Canonical output paths — ledger_file() (data/ledger/)
│   ├── merge_outputs.py        # Cross-run output versioning/merge (--continue)
│   ├── nmap_service_parse.py   # Nmap XML parsing, URL extraction
│   ├── config.py               # monkeyx.config loader + defaults
│   ├── dns_helpers.py          # DNS utilities
│   ├── dry_run.py              # Synthetic-data --dry-run support
│   ├── eval_harness.py         # Offline scoring for AI-module changes
│   ├── cost_tracker.py         # AI token/cost accounting
│   ├── scanning.py             # Nmap folder merging + coverage reconciliation
│   ├── severity_rerate.py      # Finding severity re-rating
│   ├── logging_config.py       # Logging setup
│   └── utils.py                # bash_command() + shared helpers
│
├── modules/                    # Scanning/analysis modules (auto-discovered; ~50)
│   ├── ax_nmap_tcp.py          # e.g. fleet TCP scan  ┐
│   ├── ax_nuclei.py            #      vuln scanning    │ full catalog: docs/MODULES.md
│   ├── normalize.py            #      output → JSONL   │
│   ├── ai_analyze.py           #      AI analysis      ┘
│   └── ...                     # one file per module, each exposing run_<name>()
│
├── workflows/                  # YAML workflow definitions
│   └── fast.yaml   standard.yaml   deep.yaml
│
├── viewer/                     # Standalone report viewer bundled into results zips
│   ├── bundle.py               # bundle_viewer() — writes viewer/ into a results zip
│   ├── view_report.py  run.sh  run.bat  requirements-viewer.txt
│
├── tests/                      # pytest suite (~140 files)
├── docs/                       # AI_SETUP.md, MODULES.md, PLUGINS.md, DEVELOPERS_GUIDE.md, this file
├── examples/
│   ├── custom_plugin/          # Runnable private-module + plugin example
│   └── workflows/              # Example workflow YAMLs (composable, full, …)
├── docker/                     # Docker install/run
├── utils/                      # Misc helper scripts
│
├── monkeyx.py                  # CLI entry point — arg parsing, fleet init, dispatch
├── workflows.py                # Module discovery, workflow resolution, execution engine
├── webserver.py                # --webserver live view (reads scan.db read-only)
├── install-monkeyx.sh          # Native installer (system pkgs, Go/Rust tools, axiom, venv)
├── monkeyx.config              # Per-module config defaults (see MODULE_CONFIG.md)
├── requirements.txt
└── *.md / *.example            # README, CLAUDE.md, AGENTS.md; credentials/knowledge/attack-policy examples
```

The `modules/` tree is abbreviated — there are ~50. Run `monkeyx --list-plugins`
or see [MODULES.md](MODULES.md) for the full, current catalog.

## Output directory layout (`-od`)

Everything a run produces lands under the `-od` directory:

```
<output-dir>/
├── report.html                 # human front door (copy of reports/report.html)
├── README.txt                  # orientation guide
├── scan.db                     # per-engagement SQLite store (+ -wal/-shm sidecars while live)
├── progress.jsonl              # step-level progress events
├── discovery-ledger.jsonl      # target/scope/provenance ledger (source of truth)
├── {prefix}-results.zip        # rebuilt every run (best-effort)
├── checkpoint.json             # written on pause (--resume reads it)
├── data/                       # machine-readable output (JSONL, nmap XML, CSV, raw text)
│   ├── ledger/                 # exported ledger-*.txt list files (targets/urls/domains/ports)
│   ├── runs/                   # cross-run versioned outputs (*.run1.*, --continue merge)
│   └── step-snapshots/         # per-step input snapshots (forensics)
├── reports/                    # human-readable reports (markdown, CSVs, gowitness screenshots, report.html)
└── logs/                       # operational logs (see LOGGING.md)
```

The output **prefix** (`-o`, default today's date) prefixes most filenames
inside `data/`, `reports/`, and `logs/`.

## Key Concepts

### Modules vs Workflows

**Modules** (`modules/`) — atomic scanning/analysis tools, one task each, runnable
independently (`-m name`). Auto-discovered at startup: any file exposing a
`run_<name>()` function is registered as module `<name>`.

**Workflows** (`workflows/*.yaml`) — ordered compositions of modules with support
for parallel groups, per-step args, and workflow references. Run with `-w name`.
Discovered by `workflows.py` + `core/plugin_loader.py`.

### How It Works

1. **User runs a command:**
   ```bash
   monkeyx -t targets.txt -od ./output -w standard
   ```
2. **`monkeyx.py`** parses args, validates inputs (`validate_module_inputs`),
   initializes logging and (if any `ax_*` module is present) the Axiom fleet,
   then calls into `workflows.py`.
3. **`workflows.py` (`run_modules`)** resolves the workflow to its step list,
   seeds the discovery ledger with user inputs, and for each step: regenerates
   that step's input files from the ledger → runs the module → logs newly
   discovered targets/URLs back to the ledger. Step failures are logged and the
   run continues.
4. **Each module** does its task, writing machine output under `data_prefix` and
   reports under `reports_prefix`, and returns a results dict.

The **discovery ledger** (`discovery-ledger.jsonl`) is the source of truth for
what gets scanned; the engine also dual-writes a per-engagement `scan.db`
(source of truth for report renderers and the live web view).

## Module Structure

Every module follows this shape (see [MODULES.md](MODULES.md) and
[PLUGINS.md](PLUGINS.md) for the full contract):

```python
"""Module description."""
from core.utils import bash_command
import logging

logger = logging.getLogger('monkeyx.modules.my_module')

REQUIRED_INPUTS = frozenset({"target"})   # "target"|"url_file"|"domainlist"|frozenset()

def run_my_module(target, prefix, fleet, **kwargs):
    data_prefix = kwargs.get('data_prefix', prefix)
    try:
        # ... logic ...
        return {"module": "my_module", "status": "success",
                "output_files": [f"{data_prefix}-my-output.jsonl"]}
    except Exception as e:
        return {"module": "my_module", "status": "failed",
                "output_files": [], "error": str(e)}
```

## Workflow Structure

```yaml
# workflows/standard.yaml (abridged)
name: standard
description: Comprehensive testing with vuln scanning, screenshots, WAF, normalized output
steps:
  - subfinder
  - dnsx_resolve
  - parallel:
      - ax_nmap_tcp
      - shodan_enrich
  - parallel:
      - ax_nuclei
      - ax_gowitness
  - normalize
  - analyze
```

Workflows support parallel groups (`parallel:`), per-step args (`name:` +
`args:`), and workflow references (`workflow: name`). See
[MODULES.md](MODULES.md#creating-custom-workflows) for full syntax.

## Adding New Modules

Auto-discovered — create `modules/my_new_module.py` with a `run_<name>`
function and an optional `REQUIRED_INPUTS`:

```python
REQUIRED_INPUTS = frozenset({"target"})

def run_my_new_module(target, prefix, fleet, **kwargs):
    data_prefix = kwargs.get('data_prefix', prefix)
    return {"module": "my_new_module", "status": "success",
            "output_files": [f"{data_prefix}-my-output.jsonl"]}
```

No imports or registration needed. For a **private** module shipped outside this
repo, register it through a plugin instead — see [PLUGINS.md](PLUGINS.md).

## Adding New Workflows

Create a YAML file in `workflows/` (or `~/.monkeyx/workflows/` for a user
override):

```yaml
# workflows/my_workflow.yaml
name: my_workflow
description: My custom workflow
steps:
  - ax_nmap_tcp
  - my_new_module
  - normalize
```

## Import Patterns

```python
# modules — the run_<name> functions
from modules import run_ax_nmap_tcp, run_ax_nuclei

# workflow engine + registries
from workflows import AVAILABLE_MODULES, WORKFLOWS, MODULE_REQUIREMENTS, run_modules

# core
from core.utils import bash_command
from core.fleet import initialize_fleet
from core.logging_config import setup_logging
```

## Testing

```bash
cd tests && python -m pytest
```

## File Naming Conventions

- **Modules**: `module_name.py` (snake_case), exposing `run_module_name()`
- **Classes**: `ClassName` (PascalCase)
- **Constants**: `CONSTANT_NAME` (UPPER_CASE)
