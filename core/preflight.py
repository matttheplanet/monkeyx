"""Preflight validation for `monkeyx --check`.

Validates — WITHOUT running a scan or touching the fleet — that the things a run
depends on are well-formed:

  * input files (-t / -d / -url): every line is a valid IP/CIDR/hostname/URL for
    its channel, with the gotchas that actually bite called out (a hostname in a
    `-t` file masscan can't resolve, a UTF-8 BOM / stray char that makes masscan
    report "invalid IP address on line #1", a URL in a -d file, etc.);
  * credentials.yaml: parses, and the configured AI provider has a USABLE key
    (not a `YOUR-...` placeholder) — the exact gap that otherwise surfaces as a
    silent 401 mid-run;
  * free disk on the output volume: errors under ~5 GB, warns under ~20 GB
    (tunable via `scan.min_free_disk_gb`) — a full disk ENOSPC-cascades mid-run
    (normalize can't write scan.db, analyze/zip fail, parallel-group siblings
    are lost), so it's caught upfront instead;
  * monkeyx.config: parses and its top-level sections are recognized;
  * axiom (controller side): the install resolved from AXIOM_PATH exists and its
    `nMap_Merger.py` helper is present + executable — a user/path mismatch (axiom
    under /root/.axiom while AXIOM_PATH points at /home/ubuntu) otherwise 127s the
    nmap merge mid-run and the nmap XML comes back empty;
  * claude-code (when selected): advisory that the CLI must be logged in for the
    user running MonkeyX (headless `claude -p`), else AI modules abort.

Returns an exit code (0 = ok, 1 = errors). Warnings never fail the check.
"""
from __future__ import annotations

import ipaddress
import os
import re
from pathlib import Path
from urllib.parse import urlparse

# A hostname label: 1-63 chars, alnum/hyphen, no leading/trailing hyphen; the
# whole name <= 253 chars. Deliberately strict so garbage ("1.2.3.999", a URL,
# a path) doesn't pass as a "hostname".
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$")

# A value that looks like an unfilled template placeholder rather than a real key.
_PLACEHOLDER_RE = re.compile(r"YOUR[-_ ]|KEY[-_ ]?HERE|CHANGE[-_ ]?ME|\.\.\.|<[^>]+>", re.I)

_KNOWN_CONFIG_SECTIONS = {"modules", "fleet", "ai", "scan", "scanning",
                          "enrichment", "knowledge", "ai_validate"}


class Report:
    """Collected findings. `ok` is False iff there is at least one error."""

    def __init__(self) -> None:
        self.errors: list[str] = []
        self.warnings: list[str] = []
        self.notes: list[str] = []

    def error(self, msg: str) -> None:
        self.errors.append(msg)

    def warn(self, msg: str) -> None:
        self.warnings.append(msg)

    def note(self, msg: str) -> None:
        self.notes.append(msg)

    @property
    def ok(self) -> bool:
        return not self.errors


def _is_placeholder(value) -> bool:
    return bool(value) and bool(_PLACEHOLDER_RE.search(str(value)))


def _nonprintable(s: str) -> str | None:
    """Return a description of the first non-printable/non-ASCII char, or None.

    This is what catches the masscan 'invalid IP address on line #1' class of
    failure: a UTF-8 BOM (\\ufeff), a smart-quote, or a stray control byte that
    a human can't see but masscan refuses to parse."""
    for idx, ch in enumerate(s):
        o = ord(ch)
        if o == 0xFEFF:
            return f"UTF-8 BOM at position {idx}"
        if o < 0x20 or o > 0x7E:
            return f"non-ASCII/control char {ch!r} (U+{o:04X}) at position {idx}"
    return None


def _iter_entries(path: str):
    """Yield (lineno, raw, stripped) for non-blank, non-comment lines."""
    with open(path, encoding="utf-8", errors="replace") as fh:
        for i, raw in enumerate(fh, 1):
            raw = raw.rstrip("\n").rstrip("\r")
            s = raw.strip()
            if not s or s.startswith("#"):
                continue
            yield i, raw, s


def _check_file_exists(path: str, kind: str, report: Report) -> bool:
    if not path:
        return False
    if not os.path.exists(path):
        report.error(f"{kind}: file not found: {path}")
        return False
    if os.path.getsize(path) == 0:
        report.warn(f"{kind}: file is empty: {path}")
        return False
    return True


def check_targets(path: str, report: Report) -> None:
    """`-t`: IPs, CIDRs, or hostnames. Host-class scanners (masscan/naabu/nmap)
    scan IPs; a hostname is resolved first (nmap) but masscan can't use it."""
    if not _check_file_exists(path, "targets(-t)", report):
        return
    count = 0
    for i, raw, s in _iter_entries(path):
        count += 1
        if raw != raw.strip():
            report.warn(f"targets:{i}: leading/trailing whitespace around '{s}'")
        bad = _nonprintable(s)
        if bad:
            report.error(f"targets:{i}: {bad} — this is what makes masscan report "
                         f"'invalid IP address on line #1'. Line: {s!r}")
            continue
        if "/" in s and "://" not in s:
            try:
                ipaddress.ip_network(s, strict=False)
            except ValueError:
                report.error(f"targets:{i}: invalid CIDR {s!r}")
            continue
        try:
            ipaddress.ip_address(s)
            continue
        except ValueError:
            pass
        if re.fullmatch(r"[0-9.]+", s):
            report.error(f"targets:{i}: malformed IP address {s!r} (looks like an IP "
                         f"but isn't valid) — masscan would reject this")
        elif "://" in s or "/" in s:
            report.error(f"targets:{i}: looks like a URL/path, not an IP/CIDR/host: {s!r}")
        elif _HOSTNAME_RE.match(s):
            report.note(f"targets:{i}: hostname {s!r} — resolved before host scans; "
                        f"masscan/naabu scan the resolved IP, not the name")
        else:
            report.error(f"targets:{i}: not a valid IP, CIDR, or hostname: {s!r}")
    report.note(f"targets(-t): {count} entr{'y' if count == 1 else 'ies'}")


def check_domains(path: str, report: Report) -> None:
    """`-d`: bare domains/subdomains only (no scheme, no IP, no path)."""
    if not _check_file_exists(path, "domains(-d)", report):
        return
    count = 0
    for i, raw, s in _iter_entries(path):
        count += 1
        bad = _nonprintable(s)
        if bad:
            report.error(f"domains:{i}: {bad}: {s!r}")
            continue
        if "://" in s or "/" in s:
            report.error(f"domains:{i}: a domain must have no scheme/path — got {s!r}")
            continue
        try:
            ipaddress.ip_address(s)
            report.error(f"domains:{i}: {s!r} is an IP — put IPs in -t, not -d")
            continue
        except ValueError:
            pass
        if re.fullmatch(r"[0-9.]+", s):
            report.error(f"domains:{i}: {s!r} looks like a (malformed) IP, not a domain")
        elif not _HOSTNAME_RE.match(s):
            report.error(f"domains:{i}: not a valid domain: {s!r}")
    report.note(f"domains(-d): {count} entr{'y' if count == 1 else 'ies'}")


def check_urls(path: str, report: Report) -> None:
    """`-url`: full http(s) URLs with a host."""
    if not _check_file_exists(path, "urls(-url)", report):
        return
    count = 0
    for i, raw, s in _iter_entries(path):
        count += 1
        bad = _nonprintable(s)
        if bad:
            report.error(f"urls:{i}: {bad}: {s!r}")
            continue
        try:
            p = urlparse(s)
        except ValueError:
            report.error(f"urls:{i}: unparseable URL: {s!r}")
            continue
        if p.scheme not in ("http", "https"):
            report.error(f"urls:{i}: URL must start with http:// or https:// — got {s!r}")
        elif not p.hostname:
            report.error(f"urls:{i}: URL has no host: {s!r}")
    report.note(f"urls(-url): {count} entr{'y' if count == 1 else 'ies'}")


def check_credentials(report: Report, ai_required: bool = False) -> None:
    """credentials.yaml parses; the configured AI provider has a usable (non-
    placeholder) key; enrichment placeholders are flagged (they masquerade as
    configured keys and then 401 silently).

    `ai_required` is True only when the run actually selected an AI module. AI is
    opt-in, so a missing/placeholder AI key fails the check (ERROR) only then;
    otherwise it is informational (a note). Preflight mirrors the engine's own
    provider resolution (`get_ai_provider`) — including the claude-code
    auto-detect — so it never false-fails a setup that a real run would accept."""
    try:
        from core.credentials import (load_credentials, get_enrichment_key,
                                       get_ai_provider)
    except Exception as e:  # noqa: BLE001
        report.warn(f"credentials: could not import loader ({e}) — skipping")
        return
    try:
        creds = load_credentials()
    except Exception as e:  # noqa: BLE001
        report.error(f"credentials: failed to load/parse credentials.yaml: {e}")
        return
    if not creds:
        report.warn("credentials: no credentials.yaml found or it is empty "
                    "(AI + enrichment modules will have no keys)")
        return

    # Resolve the AI provider exactly as the engine would at runtime (env ->
    # ai.default_provider -> claude-code auto-detect when the CLI is on PATH).
    ai_fail = report.error if ai_required else report.note
    try:
        provider_cfg = get_ai_provider()
    except Exception as e:  # noqa: BLE001  (ValueError: nothing configured, no claude CLI)
        ai_fail(f"credentials: no AI provider configured ({e}). "
                f"AI modules would fail at runtime." if ai_required else
                f"credentials: no AI provider configured — fine, no AI modules selected.")
        provider_cfg = None
    if provider_cfg is not None:
        provider = provider_cfg.get("name")
        report.note(f"credentials: AI provider = {provider}"
                    f"{'' if ai_required else ' (no AI modules selected)'}")
        if provider == "claude-code":
            report.note("credentials: provider 'claude-code' needs no API key")
            # The CLI must be authenticated for NON-interactive (`claude -p`) use
            # by the SAME user that runs MonkeyX. On a cloud that logs you in as
            # root (e.g. DigitalOcean), auth set up as another user won't apply —
            # the run then aborts with 'Not logged in · Please run /login'.
            (report.warn if ai_required else report.note)(
                "credentials: claude-code — ensure the `claude` CLI is logged in "
                "for the user running MonkeyX (run `claude setup-token`, or "
                "`claude` once interactively). ai_analyze_gowitness additionally "
                "needs the Anthropic vision API (set an anthropic api_key/aws_region) "
                "— claude-code cannot analyze screenshots.")
        elif provider == "ollama":
            report.note(f"credentials: provider '{provider}' needs no API key")
        else:
            key = provider_cfg.get("api_key")
            if not key:
                ai_fail(f"credentials: AI provider '{provider}' has NO api_key "
                        f"(set ai.{provider}.api_key or MONKEYX_AI_API_KEY, or switch "
                        f"default_provider). AI modules would fail at runtime.")
            elif _is_placeholder(key):
                ai_fail(f"credentials: AI provider '{provider}' api_key is a PLACEHOLDER "
                        f"({key!r}) — a fake key is treated as real and 401s mid-run. "
                        f"Set a real key or comment it out.")
            else:
                report.note(f"credentials: AI provider '{provider}' has a key")

    for svc in ("shodan", "censys", "greynoise", "virustotal"):
        try:
            key = get_enrichment_key(svc)
        except Exception:  # noqa: BLE001
            key = None
        if key is None:
            continue  # absent = fine (optional; module skips cleanly)
        if _is_placeholder(key):
            report.warn(f"credentials: enrichment '{svc}' key is a PLACEHOLDER "
                        f"({key!r}) — comment it out, else the module reads it as "
                        f"configured and every lookup 401s (looks like 'no results').")
        else:
            report.note(f"credentials: enrichment '{svc}' has a key")


def check_config(report: Report) -> None:
    """monkeyx.config (user + repo) parses and its sections are recognized."""
    try:
        import yaml
    except ImportError:
        report.warn("config: pyyaml not installed — cannot validate monkeyx.config")
        return
    paths = [Path.home() / ".monkeyx" / "monkeyx.config",
             Path(__file__).parent.parent / "monkeyx.config"]
    seen = False
    for path in paths:
        if not path.exists():
            continue
        seen = True
        try:
            with path.open() as fh:
                data = yaml.safe_load(fh)
        except Exception as e:  # noqa: BLE001
            report.error(f"config: {path} failed to parse as YAML: {e}")
            continue
        if data is None:
            report.note(f"config: {path} is empty (defaults apply)")
            continue
        if not isinstance(data, dict):
            report.error(f"config: {path} top level must be a mapping, got {type(data).__name__}")
            continue
        unknown = [k for k in data if k not in _KNOWN_CONFIG_SECTIONS]
        if unknown:
            report.warn(f"config: {path} has unrecognized top-level section(s): "
                        f"{', '.join(sorted(unknown))} (ignored)")
        report.note(f"config: {path} OK")
    if not seen:
        report.note("config: no monkeyx.config found (built-in defaults apply)")


def check_axiom(report: Report) -> None:
    """The Axiom install (controller side) is where MonkeyX expects it, and the
    `nMap_Merger.py` helper it shells out to after every nmap step is present and
    runnable. A path/user mismatch here (e.g. axiom under /root/.axiom but
    AXIOM_PATH pointing at /home/ubuntu) makes the merge exit 127 mid-run and the
    nmap XML comes back empty. Warn-level: a local-only run (no fleet) needs none
    of this, so preflight can't know if it's required — it flags, never fails."""
    try:
        from core.config import AXIOM_PATH
    except Exception as e:  # noqa: BLE001
        report.warn(f"axiom: could not resolve AXIOM_PATH ({e})")
        return
    axiom_dir = Path(AXIOM_PATH)
    if not axiom_dir.is_dir():
        report.warn(
            f"axiom: {axiom_dir} not found — fleet scans (ax) will fail. Install "
            f"axiom for the user running MonkeyX, or set AXIOM_PATH to its location "
            f"(install + run as the SAME user; root is fine). Local-only runs are "
            f"unaffected.")
        return
    merger = axiom_dir / "interact" / "nMap_Merger.py"
    if not merger.exists():
        report.warn(
            f"axiom: {merger} missing — the nmap merge after each scan will exit "
            f"127 and the merged nmap XML will be empty. Reinstall axiom / check "
            f"the install under {axiom_dir}.")
    elif not os.access(merger, os.X_OK):
        report.warn(
            f"axiom: {merger} is not executable — the nmap merge will fail. "
            f"Fix with: chmod +x '{axiom_dir}/interact/'*")
    else:
        report.note(f"axiom: {axiom_dir} OK (nMap_Merger.py present + executable)")


# Free-disk thresholds for the output volume. A scan writes raw tool output
# (nuclei JSONL alone can be 100s of MB), the scan.db, and the results zip to the
# output dir; running out mid-run ENOSPC-cascades every downstream step (normalize
# can't write scan.db, jsonl_to_csv/analyze/zip all fail) and silently costs any
# parallel-group siblings still running. Checked here so it's an upfront warning,
# not a mid-run crash. Tunable via monkeyx.config `scan.min_free_disk_gb`.
_DISK_ERROR_GB = 5      # below this, a run almost certainly fails — hard error
_DISK_WARN_GB = 20      # below this, a large/deep run is at real risk — warn


def check_disk_space(output_dir: str | None, report: Report) -> None:
    """Warn/err on low free disk for the volume the output dir lives on.

    Uses the output dir's parent (it may not exist yet); falls back to cwd. A
    genuinely huge scope can still blow past 20 GB — this catches the common
    "box is nearly full" case, not every possible run size.
    """
    try:
        err_gb, warn_gb = _DISK_ERROR_GB, _DISK_WARN_GB
        try:  # optional override: scan.min_free_disk_gb raises the WARN floor
            from core.config import load_scan_config
            v = load_scan_config().get("min_free_disk_gb")
            if v is not None:
                warn_gb = float(v)
        except Exception:  # noqa: BLE001
            pass

        probe = output_dir or os.getcwd()
        # Walk up to the first existing ancestor — the dir itself may be unmade.
        probe = os.path.abspath(probe)
        while probe and not os.path.exists(probe):
            parent = os.path.dirname(probe)
            if parent == probe:
                break
            probe = parent
        st = os.statvfs(probe)
        free_gb = (st.f_bavail * st.f_frsize) / (1024 ** 3)
    except Exception as e:  # noqa: BLE001
        report.warn(f"disk: could not determine free space ({e}) — skipping")
        return

    where = os.path.abspath(output_dir) if output_dir else "the output volume"
    if free_gb < err_gb:
        report.error(
            f"disk: only {free_gb:.1f} GB free on {where} — a scan will almost "
            f"certainly fail mid-run with 'No space left on device' (ENOSPC "
            f"cascades: normalize can't write scan.db, analyze/zip fail, and any "
            f"parallel-group siblings still running are lost). Free space or add disk.")
    elif free_gb < warn_gb:
        report.warn(
            f"disk: {free_gb:.1f} GB free on {where} — a deep/large scan can "
            f"exceed this (nuclei JSONL alone runs to 100s of MB; 150 GB+ is "
            f"recommended). Monitor free space or prune old runs.")
    else:
        report.note(f"disk: {free_gb:.1f} GB free on {where}")


def run_preflight(target=None, domainlist=None, urllist=None,
                  check_creds=True, check_cfg=True, output_dir=None,
                  ai_required=False) -> int:
    """Run all applicable checks, print a report, return an exit code (0/1).

    `ai_required` reflects whether the run selected an AI module; it gates
    whether a missing/placeholder AI key fails the check (see check_credentials).
    """
    report = Report()
    if target:
        check_targets(target, report)
    if domainlist:
        check_domains(domainlist, report)
    if urllist:
        check_urls(urllist, report)
    if not (target or domainlist or urllist):
        report.note("inputs: no -t/-d/-url provided — skipped input checks")
    check_disk_space(output_dir, report)
    if check_creds:
        check_credentials(report, ai_required=ai_required)
    if check_cfg:
        check_config(report)
    check_axiom(report)

    print("\n=== MonkeyX preflight (--check) ===")
    for n in report.notes:
        print(f"[*] {n}")
    for w in report.warnings:
        print(f"[!] WARN  {w}")
    for e in report.errors:
        print(f"[-] ERROR {e}")
    print(f"\n{'[-] FAILED' if not report.ok else '[+] OK'}: "
          f"{len(report.errors)} error(s), {len(report.warnings)} warning(s)\n")
    return 0 if report.ok else 1
