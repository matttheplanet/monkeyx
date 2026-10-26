"""Fleet-distributed hidden HTTP parameter discovery via arjun.

arjun probes each URL for parameters the app accepts but doesn't advertise —
the raw material for IDOR, injection, and access-control findings. Discovered
parameterized URLs feed ax_dalfox (XSS) and manual/AI follow-up.

Inputs:  url_file
Outputs: {prefix}-arjun.txt
"""

import os

from modules._ax_common import run_ax_module

REQUIRED_INPUTS = frozenset({"url_file"})
CONSUMES_URLS = True


def run_ax_arjun(prefix, fleet, url_file="./parsed-weburls.txt", **kwargs):
    prefix = kwargs.get("data_prefix", prefix)
    result = run_ax_module(
        module_name="ax_arjun", ax_module="arjun", input_file=url_file,
        prefix=prefix, fleet=fleet, output_suffix="-arjun.txt", input_kind="URL",
    )
    if result.get("status") == "success":
        out = f"{prefix}-arjun.txt"
        if os.path.exists(out):
            result["discovered_urls_file"] = out
    return result
