"""Fleet-distributed XSS scanning via dalfox.

dalfox tests each URL (ideally after ax_arjun has surfaced parameters) for
reflected/stored/DOM XSS with parameter analysis and verification, going deeper
than nuclei's generic XSS templates.

INVASIVE — sends payloads. Run only against targets you are explicitly
authorized to test (same policy as bbot_dast). Kept out of the default
`standard` workflow; included only in `deep`.

Bounded by default: dalfox is otherwise unbounded and can run for hours — for
every URL it fires "basic-another-vuln" (BAV: SQLi/SSTI/open-redirect/CRLF)
probes and mines ~2500 dictionary parameter names, most of which yield nothing
(a real run spent 4.5h on 743 URLs for 2 findings). Since ax_arjun already
surfaces the real parameters upstream, we skip BAV + dictionary-mining and cap
concurrency + per-request timeout by default, plus a wall-clock backstop. All
knobs are overridable under `monkeyx.config` `modules.ax_dalfox`; set
`tuning: false` to run raw dalfox.

Inputs:  url_file
Outputs: {prefix}-dalfox.txt   (normalize extracts [POC]/[VULN] lines as findings)
"""

from modules._ax_common import run_ax_module, _resolve_timeout

REQUIRED_INPUTS = frozenset({"url_file"})
CONSUMES_URLS = True

DEFAULT_TIMEOUT = 3600      # wall-clock backstop (secs) — dalfox has none of its own
DEFAULT_WORKER = 30         # concurrent workers per node (dalfox default is 100)
DEFAULT_REQ_TIMEOUT = 5     # per-request timeout (secs); dalfox default is 10


def _int(value, default: int) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError):
        return default
    return n if n > 0 else default


def _as_bool(value, default: bool = True) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() not in ("0", "false", "no", "off", "")
    return default


def _dalfox_flags(kwargs) -> str:
    """Build the bounded dalfox flag string (passed via ax --extra-args).

    Values are fixed strings + int()-cast numbers, so nothing scan-derived or
    otherwise untrusted reaches the shell. `tuning: false` returns "" (raw dalfox).
    """
    if not _as_bool(kwargs.get("tuning", True)):
        return ""
    flags = []
    if _as_bool(kwargs.get("skip_bav", True)):
        flags.append("--skip-bav")            # drop SQLi/SSTI/redirect/CRLF side-probes
    if _as_bool(kwargs.get("skip_mining", True)):
        flags.append("--skip-mining-dict")    # drop the ~2500-name dictionary; keep DOM mining
    flags.append(f"--worker {_int(kwargs.get('worker'), DEFAULT_WORKER)}")
    flags.append(f"--timeout {_int(kwargs.get('req_timeout'), DEFAULT_REQ_TIMEOUT)}")
    return " ".join(flags)


def run_ax_dalfox(prefix, fleet, url_file="./parsed-weburls.txt", **kwargs):
    prefix = kwargs.get("data_prefix", prefix)
    timeout = _resolve_timeout("ax_dalfox", kwargs.get("timeout")) or DEFAULT_TIMEOUT
    return run_ax_module(
        module_name="ax_dalfox", ax_module="dalfox", input_file=url_file,
        prefix=prefix, fleet=fleet, output_suffix="-dalfox.txt", input_kind="URL",
        extra_args=(_dalfox_flags(kwargs) or None), timeout=timeout,
    )
