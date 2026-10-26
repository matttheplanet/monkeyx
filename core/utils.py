"""Utility functions for MonkeyX."""

import argparse
import subprocess
import glob
import shutil
from pathlib import Path
import datetime
import random
import logging

logger = logging.getLogger('monkeyx.utils')


def shell_safe_str(value):
    """Argparse validator: reject inputs that would break single-quote escaping.

    User-controlled strings are interpolated into shell commands wrapped in
    POSIX single quotes. Inside single quotes the only character with special
    meaning is `'` itself, so rejecting `'` (and NUL) is enough to make
    interpolation safe.
    """
    if value is None:
        return value
    if "'" in value:
        raise argparse.ArgumentTypeError(
            f"value may not contain a single-quote character: {value!r}"
        )
    if '\x00' in value:
        raise argparse.ArgumentTypeError("value may not contain a NUL byte")
    return value


def validate_port_spec(ports):
    """Validate a nmap/masscan port specification before shell interpolation.

    Accepts the sentinels 'all'/'web', 'top-<N>', or a comma-separated list of
    ports/ranges (e.g. '22,80,443', '1-1024,8080'). Values come from module
    kwargs, monkeyx.config, and workflow YAML args — none of which are otherwise
    sanitized — so anything else is rejected to prevent command injection.
    """
    import re
    ports = str(ports)
    if ports in ('all', 'web'):
        return ports
    if re.fullmatch(r'top-\d{1,5}', ports):
        return ports
    if re.fullmatch(r'\d{1,5}(?:-\d{1,5})?(?:,\d{1,5}(?:-\d{1,5})?)*', ports):
        return ports
    raise ValueError(f"invalid port specification: {ports!r}")


def validate_rate(rate):
    """Validate a packets-per-second rate (digits only) before shell interpolation."""
    import re
    rate = str(rate)
    if re.fullmatch(r'\d{1,9}', rate):
        return rate
    raise ValueError(f"invalid rate: {rate!r}")


def bash_command(cmd, capture_output=False, check=True, timeout=None):
    """Run a bash command using subprocess.

    Args:
        cmd: The bash command to execute
        capture_output: If True, return stdout/stderr
        check: If True, raise exception on non-zero exit
        timeout: Max seconds to wait before killing the process (None = no limit)

    Returns:
        CompletedProcess object if capture_output=True, None otherwise

    Raises:
        subprocess.CalledProcessError: If command fails and check=True
        subprocess.TimeoutExpired: If command exceeds timeout
    """
    import os
    import signal

    logger.debug(f"Executing command: {cmd}")
    print(f'[*] Running: {cmd}')

    if timeout is not None:
        # Use Popen with process group so we can kill the entire tree
        # (ax scan spawns SSH children that subprocess.run timeout can't reach)
        proc = subprocess.Popen(
            ['/bin/bash', '-c', cmd],
            stdin=subprocess.DEVNULL,   # non-interactive: a prompt (e.g. the
            # ibmcloud "Do you want to update? [y/N]" check, or any ax/tool
            # confirmation) must get EOF and take its default, NOT block the scan.
            stdout=subprocess.PIPE if capture_output else None,
            stderr=subprocess.PIPE if capture_output else None,
            text=True,
            preexec_fn=os.setsid,
        )
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            # Kill the entire process group
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            proc.wait()
            logger.error(f"Command timed out after {timeout}s: {cmd}")
            raise
        except KeyboardInterrupt:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            proc.wait(timeout=5)
            raise
        if check and proc.returncode != 0:
            raise subprocess.CalledProcessError(
                proc.returncode, cmd, output=stdout, stderr=stderr
            )
        if capture_output:
            return subprocess.CompletedProcess(cmd, proc.returncode, stdout, stderr)
        return None

    try:
        result = subprocess.run(
            ['/bin/bash', '-c', cmd],
            stdin=subprocess.DEVNULL,   # non-interactive — see note above; a CLI
            # prompt must EOF and take its default rather than hang the scan.
            capture_output=capture_output,
            text=True,
            check=check,
        )
        if capture_output:
            return result
        return None
    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed with exit code {e.returncode}: {cmd}")
        if e.stderr:
            logger.error(f"Error output: {e.stderr}")
        raise
    except FileNotFoundError as e:
        logger.error(f"Command not found: {e}")
        raise


def validate_file(arg):
    """Validate that a target file exists.
    
    Args:
        arg: File path to validate
        
    Returns:
        Path object if file exists
        
    Raises:
        FileNotFoundError: If file does not exist
    """
    if (file := Path(arg)).is_file():
        return file
    else:
        raise FileNotFoundError("TARGET FILE NOT FOUND, MAKE SURE YOU PICKED THE CORRECT FILE AND PATH: " + arg)


def mergetext(in_file, out_file, ext):
    """Merge multiple text files into one output file.
    
    Args:
        in_file: Input directory containing files to merge
        out_file: Output file path
        ext: File extension to filter by
    """
    print(in_file)
    print(out_file)
    print(ext)
    with open(out_file, 'wb') as outfile:
        for filename in glob.glob('./%s/*.%s' % (in_file, ext)):
            if filename == out_file:
                # don't want to copy the output into the output
                continue
            with open(filename, 'rb') as readfile:
                shutil.copyfileobj(readfile, outfile)


def get_current_date():
    """Return the current date with random 5-digit ID: YYYY-MM-DD-XXXXX.

    Used for default prefix when no output name is specified.
    The random ID prevents conflicts when running multiple scans per day.

    Returns:
        Formatted date string with random identifier
    """
    date_str = datetime.datetime.now().strftime('%Y-%m-%d')
    random_id = random.randint(10000, 99999)
    return f"{date_str}-{random_id}"


import os
import re as _re


def version_output_path(path: str) -> str:
    """If `path` already exists, archive it into a `previous-runs/` subfolder and
    return `path` unchanged.

    The caller always writes the newest output to the canonical `path`. Superseded
    versions are moved to `previous-runs/{stem}.run1.{ext}`, `.run2.{ext}`, ... so
    the working directory only ever shows the current file (no confusing
    plain/run1/run2 siblings), while downstream globs and the results zip keep
    consuming the stable canonical name. The `.runN` suffix is kept so the zip's
    prior-run-snapshot filter still recognizes and skips these archives.
    """
    if not os.path.exists(path):
        return path

    directory = os.path.dirname(path) or "."
    basename = os.path.basename(path)
    stem, ext = os.path.splitext(basename)

    archive_dir = os.path.join(directory, "previous-runs")
    os.makedirs(archive_dir, exist_ok=True)

    # Count existing archives in both the new subfolder and (for dirs written by
    # an older layout) the same directory, so run numbering keeps incrementing.
    existing_runs = (glob.glob(os.path.join(archive_dir, f"{stem}.run*{ext}"))
                     + glob.glob(os.path.join(directory, f"{stem}.run*{ext}")))
    run_numbers = []
    for f in existing_runs:
        m = _re.search(r'\.run(\d+)', os.path.basename(f))
        if m:
            run_numbers.append(int(m.group(1)))

    next_run = max(run_numbers, default=0) + 1
    versioned = os.path.join(archive_dir, f"{stem}.run{next_run}{ext}")
    shutil.move(path, versioned)
    logger.info("Versioned existing output: %s -> %s", path, versioned)
    return path


_TOOL_CONFIG_PATHS = {
    "subfinder": "~/.config/subfinder/provider-config.yaml",
    "nuclei": "~/.config/nuclei/.nuclei-config.yaml",
    "httpx": "~/.config/httpx/config.yaml",
    "naabu": "~/.config/naabu/config.yaml",
}


def ax_local_config(tool: str) -> str:
    """Return '--local-config <path>' fragment if a config file exists for the tool.

    Checks known config paths for projectdiscovery tools. Returns empty string
    if no config exists, so it can be safely interpolated into command strings.
    """
    config_path = _TOOL_CONFIG_PATHS.get(tool)
    if not config_path:
        return ""
    expanded = os.path.expanduser(config_path)
    if os.path.isfile(expanded):
        logger.info("ax_local_config: found %s config at %s", tool, expanded)
        return f" --local-config '{expanded}'"
    return ""
