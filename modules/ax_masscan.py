"""Masscan port discovery module (fleet-distributed via ax).

Fast SYN scan for open port discovery. Use for initial port finding
before targeted nmap service detection.

Outputs:
    {prefix}-masscan.txt    masscan greppable (-oG) output

Output format note: ax's masscan module offers two variants selected by the
output file extension — ``.txt`` runs ``masscan -oG`` (greppable) and ``.xml``
runs ``masscan -oX``. We use greppable: it is one short line per open port
versus XML's bulky element-per-port, so on a large/all-ports sweep the raw file
is multiple times smaller (XML on a tarpit-heavy scope can balloon to tens of
GB). The ledger ingest in ``workflows._log_ports_from_masscan_grep`` stream-parses
this format.
"""

from core.utils import bash_command, validate_port_spec, validate_rate

REQUIRED_INPUTS = frozenset({"target"})

DEFAULT_PORTS = "top-10000"
DEFAULT_RATE = "10000"


def run_ax_masscan(target, prefix, fleet, **kwargs):
    """Run masscan via axiom fleet.

    Args:
        target:    Target file containing hosts/IPs/CIDRs
        prefix:    Output file prefix
        fleet:     Axiom fleet name
        **kwargs:
            data_prefix: Override for output prefix
            ports:       Port selection (default: top-10000)
                         "all"       -> -p 0-65535
                         "top-N"     -> --top-ports N
                         "22,80,443" -> -p 22,80,443
            rate:        Packets per second (default: 10000)
    """
    prefix = kwargs.get('data_prefix', prefix)
    ports = validate_port_spec(kwargs.get('ports', DEFAULT_PORTS))
    rate = validate_rate(kwargs.get('rate', DEFAULT_RATE))

    if ports == 'all':
        port_flag = '-p 0-65535'
        port_desc = 'all ports'
    elif ports.startswith('top-'):
        n = ports.split('-', 1)[1]
        port_flag = f'--top-ports {n}'
        port_desc = f'top {n} ports'
    else:
        port_flag = f'-p {ports}'
        port_desc = f'{len(ports.split(","))} ports'

    print(f'[*] Running masscan ({port_desc}, rate={rate})')

    # --expand-cidr: ax must expand a CIDR into individual hosts so it can split
    # the work ACROSS the fleet. Without it, ax treats the CIDR as one input line
    # and pins the whole range to a single node (no distribution) — every other
    # ax scanner (nmap/naabu/nuclei/gowitness) passes this for the same reason.
    # -o <file>.txt selects ax's greppable (-oG) masscan variant (see module
    # docstring). ax picks the format by the output extension — .xml would force
    # the far bulkier -oX variant.
    cmd = (
        f"ax scan '{target}' --fleet '{fleet}' --expand-cidr"
        f" -m masscan -o '{prefix}-masscan.txt'"
        f" {port_flag} --rate {rate}"
    )

    try:
        bash_command(cmd)
    except Exception as e:
        print(f'[!] Masscan failed: {e}')
        return {
            'module': 'ax_masscan',
            'status': 'failed',
            'output_files': [],
            'error': str(e),
        }

    print('[+] Masscan complete')
    return {
        'module': 'ax_masscan',
        'status': 'success',
        'output_files': [f"{prefix}-masscan.txt"],
    }
