"""Fleet-distributed JavaScript endpoint extraction via subjs.

subjs pulls JS file URLs referenced by each page. Combined with ax_katana, this
surfaces client-side API endpoints and paths that feed arjun / nuclei / manual
review. Extracted URLs are logged to the ledger.

Inputs:  url_file
Outputs: {prefix}-subjs.txt
"""

import os

from modules._ax_common import run_ax_module

REQUIRED_INPUTS = frozenset({"url_file"})
CONSUMES_URLS = True


def run_ax_subjs(prefix, fleet, url_file="./parsed-weburls.txt", **kwargs):
    prefix = kwargs.get("data_prefix", prefix)
    result = run_ax_module(
        module_name="ax_subjs", ax_module="subjs", input_file=url_file,
        prefix=prefix, fleet=fleet, output_suffix="-subjs.txt", input_kind="URL",
    )
    if result.get("status") == "success":
        out = f"{prefix}-subjs.txt"
        if os.path.exists(out):
            result["discovered_urls_file"] = out
    return result
