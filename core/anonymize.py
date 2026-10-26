"""Client-identifier anonymization for AI egress.

Scan data sent to an external AI provider is aliased first: client-identifying
IPs and domains are replaced with opaque tokens (``H1``, ``H2``, … for hosts;
``D1``, ``D2``, … for domains) before the payload leaves the host, and the
provider's response is de-aliased back to the real values before anything is
written to disk. So the report a user reads is fully de-anonymized, but the
third party only ever saw ``H1``/``D1``.

This is the single, auditable home for that logic — used by ``ai_analyze`` and
``ai_analyze_gowitness``.

IMPORTANT LIMITATION — text only. These helpers alias TEXT. They CANNOT
anonymize a binary payload, most importantly the screenshot JPEGs
``ai_analyze_gowitness`` sends to the vision API: a screenshot inherently renders
hostnames, logos, and on-page content, none of which can be aliased without
destroying the image the model must look at. Aliasing the text metadata that
accompanies an image (URL, title, technologies) reduces the identifying data in
the text channel, but the image itself still egresses with identifying content.
See ``docs/AI_DATA_HANDLING.md`` for the full data-handling posture.
"""

import re

_IP_RE = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')

# The model sometimes wraps a host label in a command-template placeholder —
# e.g. `redis-cli -h <H1_IP>` — treating the alias as a token to substitute
# rather than the literal address to use. After de-aliasing, `H1` becomes the
# real IP and the placeholder reads `<198.18.7.111_IP>`: non-runnable, with a
# leftover `<>` wrapper and a redundant `_IP`/`_hostname` suffix. This unwraps
# that specific artifact back to the bare value the command needs. Scoped to the
# `_IP`/`_hostname` suffix forms so legitimate angle-bracket text (e.g. an HTML
# `<title>` in gowitness page data) is never touched.
_PLACEHOLDER_WRAPPER_RE = re.compile(r'<([^<>]+?)_(?:IP|hostname)>', re.IGNORECASE)


def _strip_placeholder_wrappers(text: str) -> str:
    """Unwrap `<value_IP>` / `<value_hostname>` command-template artifacts."""
    return _PLACEHOLDER_WRAPPER_RE.sub(r'\1', text)


def extract_domains_from_text(text: str, domains: set) -> None:
    """Extract domain-like strings from text (URLs, hostnames in findings)."""
    # Match URLs and extract hostname
    for match in re.finditer(r'https?://([a-zA-Z0-9._-]+)', text):
        host = match.group(1).lower()
        if not _IP_RE.match(host):
            domains.add(host)
    # Match bare hostnames (word.word.tld patterns)
    for match in re.finditer(r'\b([a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)+\.[a-zA-Z]{2,})\b', text):
        domains.add(match.group(1).lower())


def anonymize_text(text: str, token_to_alias: dict) -> str:
    """Replace all IPs and domains in text with their aliases.

    Longest tokens first so a subdomain is aliased before its parent domain and
    an IP before a shorter substring of it.
    """
    for token, alias in sorted(token_to_alias.items(), key=lambda x: len(x[0]), reverse=True):
        text = text.replace(token, alias)
    return text


def deanonymize_obj(obj, alias_to_token: dict):
    """Recursively replace aliases back to IPs/domains in a parsed JSON structure.

    Longest aliases first so ``H10`` is restored before ``H1``.
    """
    if isinstance(obj, str):
        for alias, token in sorted(alias_to_token.items(), key=lambda x: len(x[0]), reverse=True):
            obj = obj.replace(alias, token)
        # Clean up `<H1_IP>`-style placeholders the model emits in commands: after
        # the substitution above they read `<198.18.7.111_IP>` (broken). Done
        # here — the single de-alias chokepoint — so every caller/site benefits.
        return _strip_placeholder_wrappers(obj)
    elif isinstance(obj, list):
        return [deanonymize_obj(item, alias_to_token) for item in obj]
    elif isinstance(obj, dict):
        return {k: deanonymize_obj(v, alias_to_token) for k, v in obj.items()}
    return obj


def build_alias_map(ips, domains) -> tuple[dict, dict]:
    """Build bidirectional token<->alias maps from explicit IP + domain iterables.

    IPs get ``H1, H2, …`` (in the caller's iteration order); domains get
    ``D1, D2, …`` sorted longest-first. Anything in ``domains`` that looks like a
    bare IP or isn't a plausible domain is dropped. Returns
    ``(token_to_alias, alias_to_token)``.

    Note: map insertion order only decides which host is H1 vs H2 (cosmetic) —
    replacement safety comes from the longest-first sorts in ``anonymize_text`` /
    ``deanonymize_obj``, not from this ordering.
    """
    token_to_alias: dict = {}
    alias_to_token: dict = {}

    seen_ips = []
    for ip in ips:
        if ip and ip not in token_to_alias:
            token_to_alias[ip] = None  # placeholder to dedup; alias assigned below
            seen_ips.append(ip)
    token_to_alias.clear()
    for i, ip in enumerate(seen_ips, 1):
        alias = f"H{i}"
        token_to_alias[ip] = alias
        alias_to_token[alias] = ip

    clean_domains = {
        d.lower() for d in domains
        if d and not _IP_RE.match(d) and '.' in d and len(d) > 3
    }
    for i, domain in enumerate(sorted(clean_domains, key=len, reverse=True), 1):
        alias = f"D{i}"
        token_to_alias[domain] = alias
        alias_to_token[alias] = domain

    return token_to_alias, alias_to_token
