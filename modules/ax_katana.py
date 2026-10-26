"""Fleet-distributed JS-aware web crawling via katana.

Katana crawls each discovered web endpoint (following JS-rendered links, form
actions, and script srcs) and emits every URL it finds. These URLs are logged
back into the discovery ledger so downstream modules (nuclei, ffuf, dalfox,
arjun) test endpoints that passive discovery and simple dir-brute would miss.

The built-in ax ``katana`` module is one-shot (``-u _target_``) — ax fans the
URL list across the fleet and runs katana once per target, then concatenates the
per-target URL output. We point ``normalize``/discovery at that combined output.

On a wildcard/large scope an unbounded crawl can emit ~1M URLs (multi-GB output
that then explodes the ledger/web_dirs/coverage/scan.db). The crawl is bounded
with katana's OWN options — ``depth``, ``crawl_duration``, ``field_scope`` — set
via workflow ``args:`` or ``-m`` kwargs. Defaults are None (katana's built-in
behavior), so this is opt-in and changes nothing unless configured.

Inputs:  url_file
Outputs: {prefix}-katana.txt   (one discovered URL per line)
"""

import os
import re

from modules._ax_common import run_ax_module

REQUIRED_INPUTS = frozenset({"url_file"})
CONSUMES_URLS = True

_FIELD_SCOPES = frozenset({"rdn", "fqdn", "dn"})


def _katana_extra_args(kwargs) -> str | None:
    """Build a validated katana flag string from crawl-bounding kwargs, or None.

    depth -> -depth N (1-10); crawl_duration -> -crawl-duration <N[ms|s|m|h]>;
    field_scope -> -field-scope <rdn|fqdn|dn>. Each is validated (digits /
    allowlist) so nothing configured can break out of the single-quoted
    ``--extra-args`` on the ax command line.
    """
    flags: list[str] = []
    depth = kwargs.get("depth")
    if depth is not None:
        d = str(depth)
        if not re.fullmatch(r"([1-9]|10)", d):
            raise ValueError(f"ax_katana: invalid depth {depth!r} (expected 1-10)")
        flags += ["-depth", d]
    dur = kwargs.get("crawl_duration")
    if dur is not None:
        s = str(dur)
        if not re.fullmatch(r"\d{1,5}(ms|s|m|h)?", s):
            raise ValueError(f"ax_katana: invalid crawl_duration {dur!r} (e.g. 300s, 10m)")
        flags += ["-crawl-duration", s]
    fs = kwargs.get("field_scope")
    if fs is not None:
        if str(fs) not in _FIELD_SCOPES:
            raise ValueError(f"ax_katana: invalid field_scope {fs!r} (expected one of {sorted(_FIELD_SCOPES)})")
        flags += ["-field-scope", str(fs)]
    return " ".join(flags) if flags else None


def run_ax_katana(prefix, fleet, url_file="./parsed-weburls.txt", **kwargs):
    prefix = kwargs.get("data_prefix", prefix)
    extra_args = _katana_extra_args(kwargs)
    if extra_args:
        print(f"[*] katana crawl bounded: {extra_args}")
    result = run_ax_module(
        module_name="ax_katana",
        ax_module="katana",
        input_file=url_file,
        prefix=prefix,
        fleet=fleet,
        output_suffix="-katana.txt",
        input_kind="URL",
        extra_args=extra_args,
    )
    # Expose the URL output so _extract_discoveries seeds the ledger with the
    # crawled URLs (see workflows.py handling for ax_katana/ax_gau).
    if result.get("status") == "success":
        out = f"{prefix}-katana.txt"
        if os.path.exists(out):
            result["discovered_urls_file"] = out
    return result
