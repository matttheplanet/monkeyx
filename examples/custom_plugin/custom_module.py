"""Example user-defined MonkeyX module."""


def run_custom(**kwargs):
    """Simple example module for plugin validation."""
    target = kwargs.get("target")
    prefix = kwargs.get("prefix")
    print(f"[*] custom_echo plugin module running (target={target}, prefix={prefix})")
    return {
        "module": "custom_echo",
        "status": "ok",
        "target": target,
        "prefix": prefix,
    }
