# MonkeyX Plugins

MonkeyX supports external plugins so teams can add private/custom **modules** and
**workflows** without modifying this repository. A plugin is a directory with a
`monkeyx_plugin.py` that declares what it provides; MonkeyX discovers and
registers it at startup, and plugin modules/workflows then work exactly like
built-in ones (`-m my_module`, `-w my_workflow`).

A complete, runnable example lives in [`examples/custom_plugin/`](../examples/custom_plugin/).

## Discovery Order

Discovery runs at startup in `core/plugin_loader.py`. **Later sources win on
name conflicts.**

**Modules** load in this order:

1. Built-in `modules/` (auto-discovered `run_<name>` functions)
2. `MONKEYX_PLUGINS` dirs (OS path-separator list, `:` on macOS/Linux)
3. `~/.monkeyx/plugins/<plugin_name>/` (each subdirectory)
4. Installed Python entry points (group `monkeyx.plugins`)

**Workflows** load in two phases — the Python `WORKFLOWS` dicts first (from the
same plugin sources, in the order above), then the YAML workflow files:

5. Built-in `workflows/*.yaml`
6. `*.yaml`/`workflows/*.yaml` inside any `MONKEYX_PLUGINS` or `~/.monkeyx/plugins` dir
7. `~/.monkeyx/workflows/*.yaml` (user overrides — win over everything)

Because the YAML phase runs after the Python phase, a built-in or user YAML
workflow overrides a plugin's Python `WORKFLOWS` entry of the same name.
`~/.monkeyx/plugins/` and `~/.monkeyx/workflows/` are created automatically if
absent.

## Writing a Private Module

A module is a Python function named `run_<name>` plus an optional
`REQUIRED_INPUTS` declaration. This is the **same contract** built-in modules
use — the only difference for a private module is *how it's registered* (via the
plugin's `MODULES` dict, below) instead of being auto-discovered from
`modules/`.

```python
# custom_module.py
REQUIRED_INPUTS = frozenset({"target"})   # "target" | "url_file" | "domainlist" | frozenset()

def run_custom(**kwargs):
    """One-line purpose (shown nowhere critical, but keep it accurate)."""
    target = kwargs.get("target")
    data_prefix = kwargs.get("data_prefix", kwargs.get("prefix"))
    out = f"{data_prefix}-custom.jsonl"
    # ... your logic; shell out via core.utils.bash_command if you need tools ...
    return {
        "module": "custom",
        "status": "success",          # "success" | "failed" | "warning" (anything else is treated as success)
        "output_files": [out],
    }
```

(The shipped example in `examples/custom_plugin/` is the minimal form of this —
`run_custom(**kwargs)` with no `REQUIRED_INPUTS`, registered as `custom_echo`.)

**The contract:**

- **Name.** The plugin `MODULES` dict maps the CLI name to this function (the
  `run_` prefix is a built-in convention; for plugins the dict key is what
  matters — see registration below).
- **`REQUIRED_INPUTS`** (module-level frozenset) declares what the module needs.
  Validation is **pipeline-aware**: a requirement is satisfied by user input OR
  by a producing module earlier in the run.

  | Value | Satisfied by |
  |---|---|
  | `frozenset({"target"})` | `-t`, or an earlier `dns_resolve`/`dnsx_resolve` (satisfies validation only — resolved IPs are name-safe; host-full port scanning still needs `-t`) |
  | `frozenset({"url_file"})` | `-url`, or an earlier target-scanning module (`ax_nmap_tcp`, `ax_naabu`, `ax_nmap_udp`) |
  | `frozenset({"domainlist"})` | `-d`, or an earlier `subfinder`/`ax_subfinder`/`ax_puredns_bruteforce` |
  | `frozenset()` | nothing — runs on whatever the ledger holds |

  Omit it and it defaults to `frozenset()`.
- **kwargs.** Every module receives `prefix`, `data_prefix`, `reports_prefix`,
  `fleet`, `scan_type`, plus the ledger-regenerated inputs `target`, `url_file`,
  `domainlist` (and `open_ports_file`, `target_ips_file`, etc.). Read inputs from
  kwargs — do **not** read raw CLI args. Accepting `**kwargs` keeps you
  forward-compatible. Write machine output under `data_prefix`, human reports
  under `reports_prefix`.
- **Return** a dict with at least `status`; include `output_files` so downstream
  steps and the results archive can find what you wrote. A raised exception is
  caught by the engine, logged as a failed step, and the run continues.
- **Fleet vs local.** If your module shells out to `ax scan ...`, it needs a
  fleet (auto-created when present). If it runs purely locally, it needs no
  fleet — see `_NO_FLEET_MODULES` in `workflows.py` for the built-in local set;
  a plugin module is treated as fleet-requiring unless you keep its work local.

To surface discovered targets/URLs to later steps, log them to the ledger the
same way built-ins do (see `core/target_ledger.py`); for most modules, writing
normalize-shaped JSONL that `normalize` picks up is enough.

## Plugin Declaration (`monkeyx_plugin.py`)

Each plugin directory contains `monkeyx_plugin.py` exporting either or both:

- `MODULES`: `dict[str, callable]` (or `{"function": callable}`) — maps a module
  name to its `run_*` function.
- `WORKFLOWS`: `dict[str, list[str]]` — maps a workflow name to an ordered list
  of module names.

```python
# monkeyx_plugin.py
from custom_module import run_custom

MODULES = {
    "custom": run_custom,
    # equivalently: "custom": {"function": run_custom}
}

WORKFLOWS = {
    "custom_quick": ["ax_nmap_tcp", "custom", "normalize"],
}
```

`REQUIRED_INPUTS` is read off the function object, so keep it on the module (as
shown above), not in the plugin declaration.

## Custom Workflows

Two ways, depending on the syntax you need:

**1. `WORKFLOWS` dict (simple, sequential only).** Values must be `list[str]` of
module names — no parallel groups or per-step args.

**2. YAML file (full syntax).** Drop a `.yaml`/`.yml` in `~/.monkeyx/workflows/`
(or a plugin dir). This supports the richer step types:

```yaml
name: my_recon
description: Custom recon workflow
steps:
  - ax_nmap_tcp
  - parallel:
      - ax_nuclei
      - ax_gowitness
  - normalize
```

Step types: bare string (`- ax_nuclei`), named step with args
(`- name: ax_nmap_udp` + `args: {top_ports: 500}`), parallel group
(`- parallel: [...]`), and workflow reference (`- workflow: fast`, expands
recursively; not allowed inside a parallel block). See
[MODULES.md](MODULES.md#creating-custom-workflows) for full syntax.

## CLI Visibility

```bash
monkeyx --list-plugins
```

Prints every registered module and workflow with its source (`built-in` vs a
plugin path or `entry-point:<name>`) — the quickest way to confirm your plugin
loaded.

## Installing a Plugin (no packaging required)

Point `MONKEYX_PLUGINS` at the directory:

```bash
export MONKEYX_PLUGINS=/absolute/path/to/my-plugin
monkeyx --list-plugins
```

Or symlink it under your user plugins dir:

```bash
mkdir -p ~/.monkeyx/plugins
ln -s /absolute/path/to/my-plugin ~/.monkeyx/plugins/my-plugin
```

## Package Entry Point Option

For a pip/Poetry-installed package, register the plugin module as an entry point:

```toml
[tool.poetry.plugins."monkeyx.plugins"]
my-plugin = "my_package.monkeyx_plugin"
```

The entry point target is the module exposing `MODULES` / `WORKFLOWS`.
