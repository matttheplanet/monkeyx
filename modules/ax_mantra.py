"""Fleet-distributed secret discovery in HTTP responses/JS via mantra.

mantra fetches each URL and greps responses + linked JS for leaked API keys,
tokens, and secrets. Hits are high-value findings; normalize turns each into a
medium-severity finding record (host from the URL) that flows to scan.db and
ai_analyze/ai_validate.

Inputs:  url_file
Outputs: {prefix}-mantra.txt
"""

from modules._ax_common import run_ax_module

REQUIRED_INPUTS = frozenset({"url_file"})
CONSUMES_URLS = True


def run_ax_mantra(prefix, fleet, url_file="./parsed-weburls.txt", **kwargs):
    prefix = kwargs.get("data_prefix", prefix)
    return run_ax_module(
        module_name="ax_mantra", ax_module="mantra", input_file=url_file,
        prefix=prefix, fleet=fleet, output_suffix="-mantra.txt", input_kind="URL",
    )
