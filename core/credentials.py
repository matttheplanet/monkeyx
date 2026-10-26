"""Credential store for MonkeyX — loads API keys from ~/.monkeyx/credentials.yaml."""

import os
import logging
import shutil
from pathlib import Path

import yaml

logger = logging.getLogger('monkeyx.core.credentials')

_MONKEYX_DIR = Path.home() / ".monkeyx"
_CRED_PATH = _MONKEYX_DIR / "credentials.yaml"
_EXAMPLE_FILENAME = "credentials.yaml.example"
_cache = None


def _ensure_example_exists():
    """Copy credentials.yaml.example to ~/.monkeyx/ if it doesn't exist there."""
    dest = _MONKEYX_DIR / _EXAMPLE_FILENAME
    if dest.exists():
        return
    _MONKEYX_DIR.mkdir(parents=True, exist_ok=True)
    src = Path(__file__).parent.parent / _EXAMPLE_FILENAME
    if src.exists():
        shutil.copy2(src, dest)
        logger.info("Created %s from repo template", dest)


def load_credentials() -> dict:
    """Load and cache credentials from ~/.monkeyx/credentials.yaml."""
    global _cache
    if _cache is not None:
        return _cache
    _ensure_example_exists()
    if not _CRED_PATH.exists():
        logger.debug("No credentials file at %s", _CRED_PATH)
        _cache = {}
        return _cache
    with _CRED_PATH.open() as f:
        _cache = yaml.safe_load(f) or {}
    logger.info("Loaded credentials from %s", _CRED_PATH)
    return _cache


def reload_credentials() -> dict:
    """Force reload credentials from disk (clears cache)."""
    global _cache
    _cache = None
    return load_credentials()


def get_ai_provider(provider_name: str | None = None) -> dict:
    """Return config dict for the requested AI provider.

    Resolution order for provider name:
      1. Explicit provider_name argument
      2. MONKEYX_AI_PROVIDER env var
      3. ai.default_provider in credentials.yaml

    The returned dict always contains 'name' and 'api_key' (if available).
    """
    creds = load_credentials()
    ai_config = creds.get("ai", {})

    name = (
        provider_name
        or os.environ.get("MONKEYX_AI_PROVIDER")
        or ai_config.get("default_provider")
    )
    if not name:
        if shutil.which("claude"):
            name = "claude-code"
            logger.info("No AI provider configured — auto-selecting claude-code (CLI found on PATH)")
        else:
            raise ValueError(
                "No AI provider configured.\n"
                "  1. Copy the example:  cp ~/.monkeyx/credentials.yaml.example ~/.monkeyx/credentials.yaml\n"
                "  2. Edit ~/.monkeyx/credentials.yaml and set your provider/keys\n"
                "  Or set MONKEYX_AI_PROVIDER env var (e.g. MONKEYX_AI_PROVIDER=claude-code)"
            )

    provider = dict(ai_config.get(name, {}))
    provider["name"] = name

    env_key = os.environ.get("MONKEYX_AI_API_KEY")
    if env_key:
        provider["api_key"] = env_key

    env_model = os.environ.get("MONKEYX_AI_MODEL")
    if env_model:
        provider["model"] = env_model

    return provider


def get_enrichment_key(service: str) -> str | None:
    """Return API key for an enrichment service (shodan, censys, greynoise, etc.).

    Checks MONKEYX_{SERVICE}_API_KEY env var first, then credentials.yaml.
    """
    env_key = os.environ.get(f"MONKEYX_{service.upper()}_API_KEY")
    if env_key:
        return env_key
    creds = load_credentials()
    # `or {}` at each level: a commented-out provider block parses as a None
    # value (e.g. `shodan:` with only comments under it), and None.get() would
    # crash. Treating it as absent is exactly right — no key configured.
    enrichment = creds.get("enrichment") or {}
    svc_config = enrichment.get(service) or {}
    return svc_config.get("api_key")


def get_enrichment_config(service: str) -> dict:
    """Return full config dict for an enrichment service (may include api_id, api_secret, etc.)."""
    creds = load_credentials()
    # `or {}`: a commented-out provider block is a None value; dict(None) crashes.
    enrichment = creds.get("enrichment") or {}
    config = dict(enrichment.get(service) or {})

    env_key = os.environ.get(f"MONKEYX_{service.upper()}_API_KEY")
    if env_key:
        config["api_key"] = env_key

    return config
