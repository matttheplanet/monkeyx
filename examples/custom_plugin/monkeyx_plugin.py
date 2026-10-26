"""Example plugin declaration for user-defined MonkeyX extensions."""

from custom_module import run_custom


MODULES = {
    "custom_echo": run_custom,
}


WORKFLOWS = {
    "custom_demo": ["ax_nmap_tcp", "custom_echo"],
}
