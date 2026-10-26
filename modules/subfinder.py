"""Subfinder enumeration module."""

from core.utils import bash_command

REQUIRED_INPUTS = frozenset({"domainlist"})


def run_subfinder(domainlist, prefix, **kwargs):
    """Run subfinder for subdomain enumeration.
    
    Args:
        domainlist: File containing domains to enumerate
        prefix: Output file prefix
        **kwargs: Additional arguments (fleet, etc.)
    
    Returns:
        dict: Results of the subfinder scan
    """
    prefix = kwargs.get('data_prefix', prefix)
    print(f'[*] Running subfinder module')
    
    subfinder_cmd = f"subfinder -dL '{domainlist}' -oJ -o '{prefix}-subfinder-output.jsonl'"
    
    try:
        bash_command(subfinder_cmd)
        return {
            'module': 'subfinder',
            'status': 'success',
            'output_files': [f"{prefix}-subfinder-output.jsonl"]
        }
    except Exception as e:
        print(f'[!] Subfinder scan failed: {e}')
        return {
            'module': 'subfinder',
            'status': 'failed',
            'output_files': [],
            'error': str(e)
        }