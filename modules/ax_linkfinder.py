"""Fleet-distributed JS endpoint extraction via LinkFinder.

Deeper than subjs: LinkFinder parses JS files and regexes out endpoints/paths,
including relative API routes. The ax module is Dockerized, but ax builds the
Docker tools into the fleet image so it runs like any other ax module. One-shot
(``-i _target_``), ext: dir — writes per-target output into a directory.

Inputs:  url_file
Outputs: {prefix}-linkfinder/ (per-target endpoint lists)
"""

from modules._ax_common import run_ax_module

REQUIRED_INPUTS = frozenset({"url_file"})
CONSUMES_URLS = True


def run_ax_linkfinder(prefix, fleet, url_file="./parsed-weburls.txt", **kwargs):
    prefix = kwargs.get("data_prefix", prefix)
    return run_ax_module(
        module_name="ax_linkfinder", ax_module="linkfinder", input_file=url_file,
        prefix=prefix, fleet=fleet, output_suffix="-linkfinder", input_kind="URL",
    )
