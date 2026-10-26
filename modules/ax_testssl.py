"""Fleet-distributed testssl.sh TLS/SSL audit.

Runs testssl.sh across the fleet against discovered web URLs to audit TLS
configuration: protocol support (SSLv2/3, TLS1.0/1.1), weak ciphers, known
vulnerabilities (Heartbleed, ROBOT, CCS, BEAST, etc.), and certificate issues.

Consumes the ledger URL file (like ax_nuclei/ax_gowitness) so it audits every
HTTPS endpoint discovered by the pipeline. Output is testssl's plain-text report
(one host section per target); ``normalize`` parses the vulnerability lines into
findings that flow through analyze / ai_analyze / ai_validate.

Inputs:  url_file
Outputs: {prefix}-testssl.txt
"""

from modules._ax_common import run_ax_module

REQUIRED_INPUTS = frozenset({"url_file"})
CONSUMES_URLS = True


def run_ax_testssl(prefix, fleet, url_file="./parsed-weburls.txt", **kwargs):
    prefix = kwargs.get("data_prefix", prefix)
    return run_ax_module(
        module_name="ax_testssl",
        ax_module="testssl",
        input_file=url_file,
        prefix=prefix,
        fleet=fleet,
        output_suffix="-testssl.txt",
        input_kind="URL",
    )
