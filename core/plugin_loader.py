"""Plugin discovery/registration for MonkeyX.

Plugins can contribute modules and workflows without modifying the OSS repo.

Discovery sources (in load order):
1) MONKEYX_PLUGINS env var (os.pathsep-separated directories)
2) ~/.monkeyx/plugins/<plugin_name>/ directories
3) Installed package entry points in group: monkeyx.plugins
4) ~/.monkeyx/workflows/*.yaml (user workflow definitions)
5) MONKEYX_PLUGINS dirs / workflows/*.yaml (plugin workflow files)

Plugin contract (preferred):
  monkeyx_plugin.py exposing:
    MODULES = {"name": callable | {"function": callable, ...}}
    WORKFLOWS = {"workflow_name": ["module_a", "module_b"]}

YAML workflow files:
  name: my_workflow
  description: optional description
  steps:
    - module_name            # run a module
    - workflow: other_name   # expand another workflow inline
"""

from __future__ import annotations

import importlib.util
import logging
import os
import sys
from pathlib import Path
from typing import Callable

try:
    import yaml
except ImportError:
    yaml = None

logger = logging.getLogger("monkeyx.plugin_loader")


# name -> source label
PLUGIN_REGISTRY = {
    "modules": {},
    "workflows": {},
}


def get_plugin_registry() -> dict:
    """Return a shallow copy of plugin source registry."""
    return {
        "modules": dict(PLUGIN_REGISTRY["modules"]),
        "workflows": dict(PLUGIN_REGISTRY["workflows"]),
    }


def _load_python_module(filepath: Path):
    spec = importlib.util.spec_from_file_location(filepath.stem, str(filepath))
    if not spec or not spec.loader:
        raise ImportError(f"Unable to create import spec for {filepath}")
    mod = importlib.util.module_from_spec(spec)

    # Ensure sibling imports from plugin directory work. Use append (not
    # insert(0)) so a file in an untrusted plugin dir (e.g. os.py, subprocess.py)
    # cannot shadow stdlib / first-party modules via import hijacking.
    plugin_root = str(filepath.parent)
    if plugin_root not in sys.path:
        sys.path.append(plugin_root)

    spec.loader.exec_module(mod)
    return mod


def _normalize_modules(raw_modules: dict, source: str) -> dict[str, Callable]:
    normalized: dict[str, Callable] = {}
    for name, value in raw_modules.items():
        fn = None
        if callable(value):
            fn = value
        elif isinstance(value, dict):
            fn = value.get("function")

        if not callable(fn):
            logger.warning(
                "Skipping plugin module '%s' from %s (missing callable function)",
                name,
                source,
            )
            continue

        normalized[name] = fn
        PLUGIN_REGISTRY["modules"][name] = source

    return normalized


def _normalize_workflows(raw_workflows: dict, source: str) -> dict[str, list[str]]:
    normalized: dict[str, list[str]] = {}
    for name, steps in raw_workflows.items():
        if not isinstance(steps, list) or not all(isinstance(s, str) for s in steps):
            logger.warning(
                "Skipping plugin workflow '%s' from %s (must be list[str])",
                name,
                source,
            )
            continue
        normalized[name] = steps
        PLUGIN_REGISTRY["workflows"][name] = source
    return normalized


def _load_plugin_dir(plugin_dir: Path) -> tuple[dict[str, Callable], dict[str, list[str]]]:
    modules: dict[str, Callable] = {}
    workflows: dict[str, list[str]] = {}

    plugin_file = plugin_dir / "monkeyx_plugin.py"
    if not plugin_file.is_file():
        return modules, workflows

    source = str(plugin_dir)
    try:
        plugin_mod = _load_python_module(plugin_file)
        raw_modules = getattr(plugin_mod, "MODULES", {}) or {}
        raw_workflows = getattr(plugin_mod, "WORKFLOWS", {}) or {}

        if isinstance(raw_modules, dict):
            modules.update(_normalize_modules(raw_modules, source))
        if isinstance(raw_workflows, dict):
            workflows.update(_normalize_workflows(raw_workflows, source))

        if modules or workflows:
            logger.info(
                "Loaded plugin %s (%d modules, %d workflows)",
                source,
                len(modules),
                len(workflows),
            )
    except Exception as exc:
        logger.error("Failed loading plugin directory %s: %s", source, exc)

    return modules, workflows


def _load_entrypoint_plugins() -> tuple[dict[str, Callable], dict[str, list[str]]]:
    modules: dict[str, Callable] = {}
    workflows: dict[str, list[str]] = {}

    try:
        from importlib.metadata import entry_points

        eps = entry_points()
        if hasattr(eps, "select"):
            candidates = eps.select(group="monkeyx.plugins")
        else:
            candidates = eps.get("monkeyx.plugins", [])

        for ep in candidates:
            source = f"entry-point:{ep.name}"
            try:
                mod = ep.load()
                raw_modules = getattr(mod, "MODULES", {}) or {}
                raw_workflows = getattr(mod, "WORKFLOWS", {}) or {}

                if isinstance(raw_modules, dict):
                    modules.update(_normalize_modules(raw_modules, source))
                if isinstance(raw_workflows, dict):
                    workflows.update(_normalize_workflows(raw_workflows, source))
            except Exception as exc:
                logger.error("Failed loading plugin entry-point %s: %s", ep.name, exc)
    except Exception as exc:
        logger.debug("No entry-point plugins loaded: %s", exc)

    return modules, workflows


def _validate_step(step, workflow_name: str, filepath):
    if isinstance(step, str):
        return step

    if not isinstance(step, dict):
        logger.warning("Workflow '%s': skipping invalid step %r in %s", workflow_name, step, filepath)
        return None

    if "workflow" in step and isinstance(step["workflow"], str):
        return step

    if "name" in step and isinstance(step["name"], str):
        if "args" in step and not isinstance(step["args"], dict):
            logger.warning("Workflow '%s': step '%s' has non-dict args, ignoring args in %s", workflow_name, step["name"], filepath)
            return {"name": step["name"]}
        return step

    if "parallel" in step and isinstance(step["parallel"], list):
        validated_inner = []
        for inner in step["parallel"]:
            v = _validate_step(inner, workflow_name, filepath)
            if v is not None:
                validated_inner.append(v)
        if validated_inner:
            return {"parallel": validated_inner}
        logger.warning("Workflow '%s': parallel block has no valid steps in %s", workflow_name, filepath)
        return None

    logger.warning("Workflow '%s': skipping invalid step %r in %s", workflow_name, step, filepath)
    return None


def _load_workflow_yaml(filepath: Path, source: str) -> dict[str, list]:
    """Load a single YAML workflow file.

    Returns {name: steps_list} where steps may contain bare strings (module
    names) or dicts like {"workflow": "other_name"}.  Resolution of workflow
    references happens later so that all workflows are available first.
    """
    if yaml is None:
        logger.warning("pyyaml not installed — skipping YAML workflow %s", filepath)
        return {}

    try:
        with filepath.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except Exception as exc:
        logger.error("Failed to parse YAML workflow %s: %s", filepath, exc)
        return {}

    if not isinstance(data, dict):
        logger.warning("Invalid workflow file (expected mapping): %s", filepath)
        return {}

    name = data.get("name")
    steps = data.get("steps")

    if not name or not isinstance(name, str):
        logger.warning("Workflow file missing 'name': %s", filepath)
        return {}
    if not steps or not isinstance(steps, list):
        logger.warning("Workflow '%s' has no steps: %s", name, filepath)
        return {}

    # Validate step entries
    validated: list = []
    for step in steps:
        v = _validate_step(step, name, filepath)
        if v is not None:
            validated.append(v)

    if not validated:
        return {}

    PLUGIN_REGISTRY["workflows"][name] = source
    logger.info("Loaded YAML workflow '%s' from %s (%d steps)", name, source, len(validated))
    return {name: validated}


def _discover_yaml_workflows(dirs: list[Path]) -> dict[str, list]:
    """Scan directories for YAML workflow files.

    Looks for *.yaml and *.yml in each dir and in each dir's workflows/ subdir.
    """
    workflows: dict[str, list] = {}

    for d in dirs:
        search_dirs = [d]
        wf_subdir = d / "workflows"
        if wf_subdir.is_dir():
            search_dirs.append(wf_subdir)

        for search_dir in search_dirs:
            if not search_dir.is_dir():
                continue
            for ext in ("*.yaml", "*.yml"):
                for filepath in sorted(search_dir.glob(ext)):
                    wfs = _load_workflow_yaml(filepath, str(filepath))
                    workflows.update(wfs)

    return workflows


def discover_plugins() -> tuple[dict[str, Callable], dict[str, list]]:
    """Discover plugin modules/workflows and return merged dicts.

    Later sources override earlier sources when names collide.

    Workflow values may contain raw step lists with workflow references
    (dicts like {"workflow": "name"}).  Call resolve_workflow_steps() from
    workflows.py to flatten these before execution.
    """
    discovered_modules: dict[str, Callable] = {}
    discovered_workflows: dict[str, list] = {}

    # Reset only discovered sources per run
    PLUGIN_REGISTRY["modules"].clear()
    PLUGIN_REGISTRY["workflows"].clear()

    plugin_dirs: list[Path] = []

    env_val = os.environ.get("MONKEYX_PLUGINS", "")
    if env_val:
        for raw in env_val.split(os.pathsep):
            raw = raw.strip()
            if not raw:
                continue
            p = Path(raw).expanduser().resolve()
            if p not in plugin_dirs:
                plugin_dirs.append(p)

    user_plugin_root = Path.home() / ".monkeyx" / "plugins"
    user_plugin_root.mkdir(parents=True, exist_ok=True)
    for child in sorted(user_plugin_root.iterdir()):
        if child.is_dir() and child not in plugin_dirs:
            plugin_dirs.append(child)

    # Python plugins (modules + workflows as flat lists)
    for pdir in plugin_dirs:
        mods, wfs = _load_plugin_dir(pdir)
        discovered_modules.update(mods)
        discovered_workflows.update(wfs)

    ep_mods, ep_wfs = _load_entrypoint_plugins()
    discovered_modules.update(ep_mods)
    discovered_workflows.update(ep_wfs)

    # YAML workflow files: repo built-ins first, then plugins, then user overrides
    repo_workflows_dir = Path(__file__).resolve().parent.parent / "workflows"
    yaml_search_dirs = [repo_workflows_dir] + list(plugin_dirs)
    user_workflows_dir = Path.home() / ".monkeyx" / "workflows"
    user_workflows_dir.mkdir(parents=True, exist_ok=True)
    yaml_search_dirs.append(user_workflows_dir)

    yaml_wfs = _discover_yaml_workflows(yaml_search_dirs)
    discovered_workflows.update(yaml_wfs)

    return discovered_modules, discovered_workflows
