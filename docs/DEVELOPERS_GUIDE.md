# MonkeyX Public — Developer Guide

This guide is specific to the **public** repo (`monkeyx-public`) and intentionally avoids company-specific instructions.

---

## 1) Clone and set up local dev environment

```bash
git clone <your-public-monkeyx-repo-url>
cd monkeyx-public

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

If you hit missing parser dependencies, install them in the same venv (for example):

```bash
pip install beautifulsoup4
```

---

## 2) Understand plugin discovery behavior

Beyond the built-in `modules/` and `workflows/*.yaml` shipped in the repo, MonkeyX
discovers external plugins from:

1. `MONKEYX_PLUGINS` env var (OS path-separator list of plugin dirs)
2. `~/.monkeyx/plugins/*` (one subdirectory per plugin)
3. Python package entry points in group `monkeyx.plugins`
4. YAML workflow files in `~/.monkeyx/workflows/*.yaml` (user overrides)

Later sources win on name conflicts. List what is currently loaded (each item is
tagged `built-in`, a plugin path, or `entry-point:<name>`):

```bash
python3 monkeyx.py --list-plugins
```

See [`PLUGINS.md`](PLUGINS.md) for the full discovery order and the module/workflow contract.

---

## 3) Test a custom plugin during development

```bash
export MONKEYX_PLUGINS=/absolute/path/to/plugin_dir
python3 monkeyx.py --list-plugins
```

Or use the included example:

```bash
export MONKEYX_PLUGINS=/absolute/path/to/monkeyx-public/examples/custom_plugin
python3 monkeyx.py --list-plugins
```

---

## 4) Standard contribution flow

```bash
git checkout -b feature/<short-name>
# make changes
git add .
git commit -m "Describe your change"
git push -u origin feature/<short-name>
```

Open a PR into `main`.

---

## 5) If a private repo uses this as a submodule

A repo that vendors this project as a submodule is pinned to a commit and does **not** auto-track latest `main`.

It must bump the submodule pointer explicitly:

```bash
cd /path/to/your-repo
git submodule update --remote monkeyx
git add monkeyx
git commit -m "Bump monkeyx submodule"
git push
```

---

## 6) Public release hygiene checklist

Before merge/release:

- no secrets/tokens
- no private infrastructure references
- no internal-only docs or endpoints
- docs updated (`PLUGINS.md`, examples, CLI usage)
