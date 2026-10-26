"""Fleet-distributed WordPress scanning via wpscan.

Run when httpx/nuclei fingerprints WordPress. wpscan enumerates plugins/themes/
users and known vulnerabilities more deeply than generic templates. The ax
wpscan module is one-shot (``--url _target_``) and writes a per-target file into
an output directory (ext: dir), so downstream parsing reads the folder.

Inputs:  url_file
Outputs: {prefix}-wpscan/ (per-target wpscan reports)
"""

from modules._ax_common import run_ax_module

REQUIRED_INPUTS = frozenset({"url_file"})
CONSUMES_URLS = True


def run_ax_wpscan(prefix, fleet, url_file="./parsed-weburls.txt", **kwargs):
    prefix = kwargs.get("data_prefix", prefix)
    # ext:dir module — ax collects per-target outputs into this directory.
    return run_ax_module(
        module_name="ax_wpscan", ax_module="wpscan", input_file=url_file,
        prefix=prefix, fleet=fleet, output_suffix="-wpscan", input_kind="URL",
    )
