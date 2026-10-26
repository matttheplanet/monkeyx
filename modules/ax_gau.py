"""Fleet-distributed historical URL discovery via gau (GetAllUrls).

gau pulls URLs a domain has ever exposed from the Wayback Machine, Common Crawl,
and other archives — surfacing forgotten endpoints, removed-but-still-live pages,
and parameterized URLs that active crawling won't find. These URLs are logged
into the discovery ledger for downstream testing (nuclei, ffuf, arjun, dalfox).

gau reads a domain/host list on stdin (``cat input | gau``), so it consumes the
ledger domain list. Output is one URL per line.

Inputs:  domainlist
Outputs: {prefix}-gau.txt
"""

import os

from modules._ax_common import run_ax_module

REQUIRED_INPUTS = frozenset({"domainlist"})


def run_ax_gau(prefix, fleet, domainlist=None, **kwargs):
    prefix = kwargs.get("data_prefix", prefix)
    result = run_ax_module(
        module_name="ax_gau",
        ax_module="gau",
        input_file=domainlist,
        prefix=prefix,
        fleet=fleet,
        output_suffix="-gau.txt",
        input_kind="domainlist",
    )
    if result.get("status") == "success":
        out = f"{prefix}-gau.txt"
        if os.path.exists(out):
            result["discovered_urls_file"] = out
    return result
