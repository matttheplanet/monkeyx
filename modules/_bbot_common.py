"""Shared bbot CLI invocation logic. Not a module (underscore prefix)."""

import json
import glob
import logging
import os
import tempfile

from core.utils import bash_command

logger = logging.getLogger('monkeyx.modules._bbot_common')

# A real floor, not None: `timeout = timeout or DEFAULT_TIMEOUT` would otherwise
# leave a caller that passes no timeout running bbot UNBOUNDED. Callers that want
# a longer bound pass an explicit `timeout=`.
DEFAULT_TIMEOUT = 1800


def load_targets(filepath):
    """Load targets from a file (one per line, skip comments/blanks)."""
    with open(filepath, encoding="utf-8") as f:
        return [l.strip() for l in f if l.strip() and not l.startswith('#')]


def collect_bbot_targets(domainlist=None, target=None, url_file=None, **kwargs):
    """Build a combined, deduplicated target list from all available monkeyx inputs.

    bbot accepts these target types natively via its -t flag:
      DNS_NAME, IP_ADDRESS, IP_RANGE, OPEN_TCP_PORT, URL,
      EMAIL_ADDRESS, ASN, USERNAME, ORG_STUB, FILESYSTEM, MOBILE_APP

    MonkeyX feeds from:
      - domainlist: domains/subdomains (DNS_NAME)
      - target: IPs, CIDRs (IP_ADDRESS, IP_RANGE)
      - url_file: URLs (URL)
      - open_ports_file: host<tab>port1,port2,... (OPEN_TCP_PORT)

    Returns a list of target strings suitable for bbot -t, or empty list if
    nothing is available.
    """
    seen = set()
    targets = []

    def _add(value):
        if value and value not in seen:
            seen.add(value)
            targets.append(value)

    # Domains/subdomains -> DNS_NAME
    if domainlist and os.path.exists(domainlist):
        for line in load_targets(domainlist):
            _add(line)

    # IPs/CIDRs -> IP_ADDRESS / IP_RANGE
    if target and os.path.exists(target):
        for line in load_targets(target):
            _add(line)

    # URLs -> URL
    if url_file and os.path.exists(url_file):
        for line in load_targets(url_file):
            _add(line)

    # Open ports -> OPEN_TCP_PORT (host:port format)
    open_ports_file = kwargs.get('open_ports_file')
    if open_ports_file and os.path.exists(open_ports_file):
        for line in load_targets(open_ports_file):
            parts = line.split('\t')
            if len(parts) == 2:
                host = parts[0].strip()
                for port in parts[1].strip().split(','):
                    port = port.strip()
                    if host and port:
                        _add(f"{host}:{port}")

    return targets


def _build_target_arg(targets, output_file):
    """Build bbot target argument by ALWAYS writing targets to a file.

    Returns (target_arg_string, temp_file_path). Caller must clean up the file.

    Security: targets include SCAN-DERIVED values (redirect Location headers,
    crawled URLs, PTR hostnames) that never pass shell-charset validation. They
    must NOT be interpolated into the `bash -c` command string — a hostile
    target could embed `'$(...)'` and break out of quoting to run code on the
    scanning host (which holds cloud/AI/SSH credentials). Writing them to a file
    and passing `-t <file>` keeps every target off the shell command line
    entirely. bbot reads `-t <file>` natively.
    """
    output_dir = os.path.dirname(output_file) or "."
    fd, target_file = tempfile.mkstemp(
        prefix="bbot-targets-", suffix=".txt", dir=output_dir
    )
    with os.fdopen(fd, 'w', encoding="utf-8") as f:
        for t in targets:
            f.write(t + '\n')
    logger.info("Wrote %d targets to file: %s", len(targets), target_file)
    return f"'{target_file}'", target_file


def run_bbot_modules(targets, modules, scan_name, output_file, timeout=None):
    """Invoke bbot CLI with specific modules and collect JSON output.

    Args:
        targets: List of target strings (domains, IPs, etc.)
        modules: List of bbot module names to enable
        scan_name: Unique scan name (bbot uses for output directory)
        output_file: Where to write the collected JSONL
        timeout: Max seconds before killing bbot (default: 1800)

    Returns:
        dict with 'events' count, 'findings' count, 'output_file' path

    Raises:
        Exception on bbot failure or missing output
    """
    timeout = timeout or DEFAULT_TIMEOUT
    module_str = ' '.join(modules)
    target_arg, target_file = _build_target_arg(targets, output_file)
    output_dir = _bbot_output_dir(output_file)

    cmd = (f"bbot -t {target_arg} -m {module_str} "
           f"--name {scan_name} -o '{output_dir}' "
           f"-om json -y --silent --ignore-failed-deps")

    try:
        bash_command(cmd, timeout=timeout)
    finally:
        if target_file and os.path.exists(target_file):
            os.unlink(target_file)

    logger.info(f"bbot finished, looking for output in: {output_dir}/{scan_name}")
    return _collect_output(output_dir, scan_name, output_file)


def run_bbot_flags(targets, flags, scan_name, output_file, timeout=None,
                   exclude_modules=None, extra_modules=None, require_flags=False,
                   config=None):
    """Invoke bbot CLI with presets or required flags and collect JSON output.

    Args:
        targets: List of target strings (domains, IPs, etc.)
        flags: List of bbot preset names (e.g. ['web', 'web-heavy']) or
               module flags (e.g. ['passive', 'safe']) if require_flags=True
        scan_name: Unique scan name
        output_file: Where to write the collected JSONL
        timeout: Max seconds before killing bbot (default: 1800)
        exclude_modules: Optional list of module names to skip
        extra_modules: Optional list of additional modules to include
        require_flags: If True, use -rf (require flags) instead of -p (presets)
        config: Optional list of bbot `-c` KEY=VALUE settings (e.g.
                ["web.spider_distance=2"]). Callers MUST pass only validated,
                shell-safe values — these are interpolated into the command.

    Returns:
        dict with 'events' count, 'findings' count, 'output_file' path
    """
    timeout = timeout or DEFAULT_TIMEOUT
    flag_str = ' '.join(flags)
    target_arg, target_file = _build_target_arg(targets, output_file)
    output_dir = _bbot_output_dir(output_file)

    flag_arg = "-rf" if require_flags else "-p"
    cmd = (f"bbot -t {target_arg} {flag_arg} {flag_str} "
           f"--name {scan_name} -o '{output_dir}' "
           f"-om json -y --silent --ignore-failed-deps")

    if exclude_modules:
        cmd += f" -em {' '.join(exclude_modules)}"
    if extra_modules:
        cmd += f" -m {' '.join(extra_modules)}"
    if config:
        cmd += f" -c {' '.join(config)}"

    try:
        bash_command(cmd, timeout=timeout)
    finally:
        if target_file and os.path.exists(target_file):
            os.unlink(target_file)

    logger.info(f"bbot finished, looking for output in: {output_dir}/{scan_name}")
    return _collect_output(output_dir, scan_name, output_file)


def _bbot_output_dir(output_file):
    """Derive bbot output directory from the monkeyx output file path."""
    return os.path.join(os.path.dirname(output_file) or ".", ".bbot")


def _collect_output(output_dir, scan_name, output_file):
    """Parse bbot output.json into our JSONL format.

    If bbot produced no output (empty scan, no events), writes an empty file
    and returns zero counts rather than raising.
    """
    try:
        bbot_output = _find_bbot_output(output_dir, scan_name)
    except FileNotFoundError:
        logger.warning(f"bbot scan '{scan_name}' produced no output file — likely zero events")
        open(output_file, 'w', encoding="utf-8").close()
        return {'events': 0, 'findings': 0, 'output_file': output_file}

    events = 0
    findings = 0
    with open(bbot_output, encoding="utf-8", errors="replace") as infile, open(output_file, 'w', encoding="utf-8") as outfile:
        for line in infile:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
                outfile.write(json.dumps(event) + '\n')
                events += 1
                if event.get('type') in ('FINDING', 'VULNERABILITY'):
                    findings += 1
            except json.JSONDecodeError:
                continue

    return {'events': events, 'findings': findings, 'output_file': output_file}


def _find_bbot_output(output_dir, scan_name):
    """Locate bbot's output.json for a given scan.

    Checks the explicit output dir first (where -o puts it), then falls
    back to ~/.bbot/scans/ for compatibility.
    """
    # With -o, bbot writes to: output_dir/scan_name/output.json
    explicit = os.path.join(output_dir, scan_name, "output.json")
    if os.path.exists(explicit):
        return explicit

    # Glob in case bbot appended a suffix to avoid name collision
    explicit_glob = glob.glob(os.path.join(output_dir, f"{scan_name}*", "output.json"))
    if explicit_glob:
        return explicit_glob[0]

    # Fallback: default bbot home
    home_path = os.path.expanduser(f"~/.bbot/scans/{scan_name}/output.json")
    if os.path.exists(home_path):
        return home_path

    home_glob = glob.glob(os.path.expanduser(f"~/.bbot/scans/{scan_name}*/output.json"))
    if home_glob:
        return home_glob[0]

    raise FileNotFoundError(
        f"No bbot output found for scan '{scan_name}' "
        f"(checked {output_dir} and ~/.bbot/scans/)"
    )
