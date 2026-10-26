"""Fleet-distributed CORS misconfiguration scanning via Corsy.

Corsy checks each URL for permissive/broken CORS policies (reflected origin,
null origin, wildcard with credentials, etc.) — common data-exfiltration paths.

Inputs:  url_file
Outputs: {prefix}-corsy.txt   (normalize extracts flagged endpoints as findings)
"""

from modules._ax_common import run_ax_module

REQUIRED_INPUTS = frozenset({"url_file"})
CONSUMES_URLS = True


def run_ax_corsy(prefix, fleet, url_file="./parsed-weburls.txt", **kwargs):
    prefix = kwargs.get("data_prefix", prefix)
    return run_ax_module(
        module_name="ax_corsy", ax_module="corsy", input_file=url_file,
        prefix=prefix, fleet=fleet, output_suffix="-corsy.txt", input_kind="URL",
    )
