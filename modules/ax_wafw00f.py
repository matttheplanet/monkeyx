"""Fleet-distributed WAF fingerprinting via wafw00f.

Identifies which discovered web endpoints sit behind a WAF/CDN and which one.
This feeds two downstream needs:
  1. ai_analyze / ai_validate context — a nuclei "vuln" on a WAF-fronted host is
     often the WAF's canned response, not a real origin vuln. Knowing the host is
     WAF-fronted lets validation lean toward refuting weakly-supported findings.
  2. Origin-discovery correlation — WAF-fronted hosts are exactly the ones
     shodan_enrich's favicon/cert pivots try to find a direct origin IP for.

Consumes the ledger URL file. Output is wafw00f's plain-text report; normalize
extracts "behind <WAF>" lines as info-severity findings and tags the web
endpoint's cdn flag in scan.db.

Inputs:  url_file
Outputs: {prefix}-wafw00f.txt
"""

from modules._ax_common import run_ax_module

REQUIRED_INPUTS = frozenset({"url_file"})
CONSUMES_URLS = True


def run_ax_wafw00f(prefix, fleet, url_file="./parsed-weburls.txt", **kwargs):
    prefix = kwargs.get("data_prefix", prefix)
    return run_ax_module(
        module_name="ax_wafw00f",
        ax_module="wafw00f",
        input_file=url_file,
        prefix=prefix,
        fleet=fleet,
        output_suffix="-wafw00f.txt",
        input_kind="URL",
    )
