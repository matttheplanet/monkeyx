"""Configuration constants and config file loader for MonkeyX."""

import logging
import os
from pathlib import Path

logger = logging.getLogger('monkeyx.core.config')

# Axiom install path — override via AXIOM_PATH env var (e.g. in Docker).
# Default resolves against the home of whoever runs MonkeyX (root on clouds
# like DigitalOcean, ubuntu on AWS/GCP), matching core/fleet.py and the
# installer — a hardcoded /home/ubuntu broke the nmap merge when run as root.
AXIOM_PATH = os.environ.get('AXIOM_PATH') or os.path.expanduser('~/.axiom')

# Default configuration values
DEFAULT_NODES = '20'
DEFAULT_SCAN_TYPE = 'sS'

# Config file locations — user config takes priority over repo default
_USER_CONFIG_PATH = Path.home() / ".monkeyx" / "monkeyx.config"
_REPO_CONFIG_PATH = Path(__file__).parent.parent / "monkeyx.config"
_module_defaults_cache = None


def _load_yaml_file(path: Path) -> dict:
    """Load and parse a YAML config file. Returns empty dict on failure."""
    if not path.exists():
        return {}
    try:
        import yaml
    except ImportError:
        logger.warning("pyyaml not installed — cannot load %s", path)
        return {}
    try:
        with path.open() as f:
            return yaml.safe_load(f) or {}
    except Exception as e:
        logger.warning("Failed to parse %s: %s", path, e)
        return {}


def load_module_defaults() -> dict:
    """Load per-module default overrides from config files.

    Checks ~/.monkeyx/monkeyx.config first, then falls back to the repo
    monkeyx.config. User config values override repo defaults per-module
    (shallow merge at the module level).

    Returns a dict like:
        {"ax_ffuf": {"wordlist": "/path/to/list"}, "ax_feroxbuster": {...}}

    Returns empty dict if no config files exist or have no 'modules' key.
    """
    global _module_defaults_cache
    if _module_defaults_cache is not None:
        return _module_defaults_cache

    repo_modules = _load_yaml_file(_REPO_CONFIG_PATH).get("modules") or {}
    user_modules = _load_yaml_file(_USER_CONFIG_PATH).get("modules") or {}

    # Merge: start with repo defaults, overlay user config per-module
    merged = dict(repo_modules)
    for module_name, user_overrides in user_modules.items():
        if module_name in merged and isinstance(merged[module_name], dict) and isinstance(user_overrides, dict):
            merged[module_name] = {**merged[module_name], **user_overrides}
        else:
            merged[module_name] = user_overrides

    _module_defaults_cache = merged

    if user_modules:
        logger.info("Loaded user config from %s (%d modules)", _USER_CONFIG_PATH, len(user_modules))
    if repo_modules:
        logger.info("Loaded repo config from %s (%d modules)", _REPO_CONFIG_PATH, len(repo_modules))
    if merged:
        logger.info("Effective module config: %d modules configured", len(merged))

    return _module_defaults_cache


def get_module_defaults(module_name: str) -> dict:
    """Get config overrides for a specific module.

    Returns empty dict if no overrides configured for this module.
    """
    # `or {}` guards a comment-only YAML section (e.g. `ax_gowitness:` with only
    # commented lines) which parses to None — otherwise callers doing `**defaults`
    # or `.get(...)` on the result would crash.
    return load_module_defaults().get(module_name) or {}


_fleet_config_cache = None


def load_fleet_config() -> dict:
    """Load fleet/global settings from config files.

    Reads the 'fleet' key from config. User config overrides repo config.

    Returns a dict like:
        {"auto_scale": True, "max_nodes": 10, "targets_per_node": 60,
         "urls_per_node": 150}
    `targets_per_node` sizes IP-scanning steps, `urls_per_node` the URL-driven
    ones (nuclei/gowitness/ffuf/...); both are optional and fall back to the
    constants in core.fleet when unset.
    """
    global _fleet_config_cache
    if _fleet_config_cache is not None:
        return _fleet_config_cache

    repo_fleet = _load_yaml_file(_REPO_CONFIG_PATH).get("fleet") or {}
    user_fleet = _load_yaml_file(_USER_CONFIG_PATH).get("fleet") or {}

    merged = {**repo_fleet, **user_fleet}
    _fleet_config_cache = merged

    if merged:
        logger.info("Fleet config: %s", merged)

    return _fleet_config_cache


def load_scan_config() -> dict:
    """Load the 'scan' section from config files (user overrides repo).

    Currently holds `sweep` (bool, default true) — the global on/off for the
    sweep-then-verify nmap pattern (masscan sweep -> nmap on open ports). A
    `--no-sweep` CLI flag overrides this.
    """
    repo = _load_yaml_file(_REPO_CONFIG_PATH).get("scan") or {}
    user = _load_yaml_file(_USER_CONFIG_PATH).get("scan") or {}
    return {**repo, **user}


def get_axiom_account() -> str | None:
    """Axiom account name from monkeyx.config (``fleet.account``), or None.

    The lowest-priority source for the account: the CLI ``--ax-account`` flag
    and the ``AXIOM_ACCOUNT`` env var both win over this (resolved in
    ``core.fleet.iauth``). Lets an operator set the account once per host/repo
    instead of exporting an env var or passing the flag every run.
    """
    account = load_fleet_config().get("account")
    return str(account) if account else None
