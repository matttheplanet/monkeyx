"""Naabu TCP port scan module.

Runs naabu via Axiom to discover open TCP ports across targets. Defaults to the
full TCP range; port selection is configurable (see ``ports`` kwarg).
Produces three output files:
  {prefix}-naabu.txt      — raw naabu output (host:port per line)
  {prefix}-live-hosts.txt — unique IPs with at least one open port
  {prefix}-naabu-ports.txt — unique ports in nmap -p format (e.g. 22,80,443)
"""

import os

from core.utils import ax_local_config, bash_command, validate_port_spec

REQUIRED_INPUTS = frozenset({"target"})

DEFAULT_PORTS = "all"

# naabu's own `-top-ports`/`-tp` flag accepts only these presets (nmap's baked-in
# top-ports lists), NOT an arbitrary N. For other counts use an explicit `-p`
# list, or ax_masscan whose `--top-ports` does take any N.
_NAABU_TOP_PORTS = {"100", "1000"}


def _port_flag(ports):
    """Map a validated port spec to naabu's native port flag.

    naabu uses `-p` for explicit ports/ranges (and `-p 0-65535` for the full
    range) and `-top-ports <100|1000>` for the baked-in presets. Unlike
    masscan/nmap it has no arbitrary `top-N`, so those are rejected here rather
    than passed through to fail on the fleet.
    """
    if ports == "all":
        return "-p 0-65535", "all ports"
    if ports == "web":
        raise ValueError(
            "ax_naabu: 'web' port profile is not supported — pass an explicit "
            "'-p' list (e.g. '80,443,8080,8443') or use ax_nmap_tcp"
        )
    if ports.startswith("top-"):
        n = ports.split("-", 1)[1]
        if n not in _NAABU_TOP_PORTS:
            raise ValueError(
                f"ax_naabu: naabu's top-ports supports only "
                f"{sorted(_NAABU_TOP_PORTS)} (got 'top-{n}') — use an explicit "
                f"'-p' port list or ax_masscan for arbitrary top-N"
            )
        return f"-top-ports {n}", f"top {n} ports"
    return f"-p {ports}", f"{len(ports.split(','))} ports"


def _post_process(output_path, prefix):
    """Extract unique hosts and ports from naabu host:port text output."""
    hosts = set()
    ports = set()

    with open(output_path, "r", encoding="utf-8", errors="ignore") as fh:
        for raw_line in fh:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" not in line:
                continue
            host, _, port_str = line.rpartition(":")
            host = host.strip()
            port_str = port_str.strip()
            if host:
                hosts.add(host)
            try:
                ports.add(int(port_str))
            except ValueError:
                continue

    live_hosts_path = f"{prefix}-live-hosts.txt"
    with open(live_hosts_path, "w", encoding="utf-8") as fh:
        for ip in sorted(hosts):
            fh.write(ip + "\n")

    ports_path = f"{prefix}-naabu-ports.txt"
    port_str = ",".join(str(p) for p in sorted(ports))
    with open(ports_path, "w", encoding="utf-8") as fh:
        fh.write(port_str + "\n")

    print(f"[+] naabu: {len(hosts)} live hosts, {len(ports)} unique ports")
    return live_hosts_path, ports_path, len(hosts), len(ports)


def run_ax_naabu(target, prefix, fleet, **kwargs):
    """Run naabu TCP port scan to discover open ports.

    Args:
        target: Target file containing hosts/IPs/CIDRs
        prefix: Output file prefix
        fleet: Name of the Axiom fleet
        **kwargs:
            data_prefix: Override for output prefix
            ports: Port selection (default: all)
                   "all"         -> -p 0-65535 (full TCP range)
                   "top-100" /
                   "top-1000"    -> -top-ports N (naabu's only presets)
                   "22,80,443"   -> -p 22,80,443
                   NOTE: naabu's -top-ports supports ONLY the 100/1000 presets
                   (nmap's baked-in lists), not an arbitrary top-N. For e.g.
                   "top 1024" use an explicit range like "1-1024", or ax_masscan
                   whose --top-ports does compute any N.

    Returns:
        dict: Results including live hosts file and port list
    """
    prefix = kwargs.get('data_prefix', prefix)
    port_flag, port_desc = _port_flag(validate_port_spec(kwargs.get('ports', DEFAULT_PORTS)))
    print(f"[*] Running naabu TCP port scan module ({port_desc})")

    output_path = f"{prefix}-naabu.txt"

    naabu_cmd = (
        f"ax scan '{target}' --fleet '{fleet}' --expand-cidr "
        f"-m naabu -o '{output_path}' {port_flag}"
        f"{ax_local_config('naabu')}"
    )

    try:
        bash_command(naabu_cmd)

        if not os.path.exists(output_path):
            print("[!] naabu: no output file produced")
            return {
                "module": "ax_naabu",
                "status": "failed",
                "output_files": [],
                "error": "No output file produced",
            }

        live_hosts_path, ports_path, host_count, port_count = _post_process(
            output_path, prefix
        )

        return {
            "module": "ax_naabu",
            "status": "success",
            "output_files": [output_path, live_hosts_path, ports_path],
            "live_hosts": live_hosts_path,
            "live_host_count": host_count,
            "ports_file": ports_path,
            "port_count": port_count,
        }
    except Exception as e:
        print(f"[!] naabu scan failed: {e}")
        return {
            "module": "ax_naabu",
            "status": "failed",
            "output_files": [],
            "error": str(e),
        }
