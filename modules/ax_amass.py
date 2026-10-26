"""Fleet-distributed subdomain enumeration via OWASP Amass.

Complements subfinder — Amass draws on a different set of data sources, so
running both widens subdomain coverage. Discovered subdomains are logged to the
ledger (as subfinder's are) and resolved by the downstream dnsx step.

Inputs:  domainlist
Outputs: {prefix}-amass.txt   (one host per line)
"""

import os

from modules._ax_common import run_ax_module

REQUIRED_INPUTS = frozenset({"domainlist"})


def run_ax_amass(prefix, fleet, domainlist=None, **kwargs):
    prefix = kwargs.get("data_prefix", prefix)
    result = run_ax_module(
        module_name="ax_amass", ax_module="amass", input_file=domainlist,
        prefix=prefix, fleet=fleet, output_suffix="-amass.txt",
        input_kind="domainlist",
        # amass reads the domain list as a file (-df); a split empty chunk makes
        # it error with "reading the first 512 bytes ... EOF". Send the whole
        # list to every node — splitting gives no benefit for enumeration anyway.
        dont_split=True,
    )
    if result.get("status") == "success":
        out = f"{prefix}-amass.txt"
        if os.path.exists(out):
            result["discovered_hosts_file"] = out
    return result
