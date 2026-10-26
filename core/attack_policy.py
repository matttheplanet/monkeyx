"""Attack policy — the in-process "bad attacks" denylist.

A curated, categorized set of substrings that indicate a destructive,
state-changing, exfiltration, persistence, credential-spray, reverse-shell, or
privilege action the AI validation agent (and any future AI-driven active-testing
component) must never run. This hardens and replaces ai_validate's original flat
``BLOCKED_PATTERNS``.

This is the in-process **policy layer** — *what may be attempted*. A separate
network-layer containment (an egress-firewalled runner) could complement it later
(*where traffic may actually go*) if a headless attacker is ever pursued, sharing
the same engagement scope; it is not implemented today. This module is AI-free and
dependency-light so ai_validate, core.tool_runners, and future components can all
share one policy.

**Matching is per-token, case-insensitive substring** — the same cheap,
ReDoS-free approach as the original (no regex). Per-token (not joined) is correct
for the threat model: because ``ai_validate._build_command`` fixes the binaries
(curl/nmap/nuclei/…), a dangerous payload can only reach the shell smuggled inside
a single free-text VALUE token (a curl --data body, an nmap flags string, an ffuf
path), which is exactly one argv element. Per-token matching catches that without
the cross-token false positives a joined match would cause (e.g. ``useradd`` vs.
the ``dd `` disk-write pattern).

**Operator-extensible** via ``~/.monkeyx/attack-policy.yaml`` (optional):

    deny:
      - {pattern: "some-forbidden-string", reason: "why", category: "custom"}
    allow:                 # drop a built-in pattern (e.g. an authorized red-team op)
      - "chmod 777"

``allow`` removes a built-in pattern for an engagement that has explicit
authorization for it; ``deny`` adds site-specific forbidden strings.
"""

import logging
import os
from pathlib import Path

logger = logging.getLogger("monkeyx.core.attack_policy")

# (pattern, category, reason) — pattern is matched lowercased against each argv
# token. The first block wins. Keep patterns SPECIFIC enough that they only match
# a genuinely dangerous form, never a legitimate tool flag/value.
_DEFAULT_DENY: list[tuple[str, str, str]] = [
    # --- destructive filesystem / disk ---
    ("rm ", "destructive_fs", "file deletion"),
    ("rm\t", "destructive_fs", "file deletion"),
    ("rmdir", "destructive_fs", "directory deletion"),
    ("; rm", "destructive_fs", "chained file deletion"),
    ("&& rm", "destructive_fs", "chained file deletion"),
    ("| rm", "destructive_fs", "piped file deletion"),
    ("dd ", "destructive_fs", "raw disk write"),
    ("mkfs", "destructive_fs", "filesystem format"),
    ("shred ", "destructive_fs", "secure file wipe"),
    ("truncate -", "destructive_fs", "file truncation"),
    ("> /dev", "destructive_fs", "device overwrite"),
    (":(){ :|:& };:", "destructive_fs", "fork bomb"),
    # NOTE: no bare "fork" pattern — matching is per-token case-insensitive
    # substring, so "fork" would false-positive on benign tokens (--fork-mode,
    # a github fork URL, nuclei template ids). The specific fork-bomb sequence
    # above already covers the actual attack.
    # --- system control ---
    ("reboot", "system_control", "host reboot"),
    ("shutdown", "system_control", "host shutdown"),
    ("halt", "system_control", "host halt"),
    ("poweroff", "system_control", "host power off"),
    ("init 0", "system_control", "runlevel halt"),
    ("init 6", "system_control", "runlevel reboot"),
    # --- shell spawn / pipe-to-shell ---
    ("curl|sh", "shell_spawn", "pipe download to shell"),
    ("curl|bash", "shell_spawn", "pipe download to shell"),
    ("wget -o-|sh", "shell_spawn", "pipe download to shell"),
    ("|sh", "shell_spawn", "pipe to shell"),
    ("| sh", "shell_spawn", "pipe to shell"),
    ("|bash", "shell_spawn", "pipe to shell"),
    ("| bash", "shell_spawn", "pipe to shell"),
    ("bash -i", "shell_spawn", "interactive shell"),
    ("sh -i", "shell_spawn", "interactive shell"),
    # --- reverse shell primitives ---
    ("/dev/tcp/", "reverse_shell", "bash /dev/tcp reverse shell"),
    (">& /dev/tcp", "reverse_shell", "reverse shell redirect"),
    ("nc -e", "reverse_shell", "netcat exec reverse shell"),
    ("ncat -e", "reverse_shell", "ncat exec reverse shell"),
    ("mkfifo", "reverse_shell", "named-pipe reverse shell"),
    ("import socket", "reverse_shell", "python socket reverse shell"),
    # --- exploit shells / OS command ---
    ("--os-shell", "exploit_shell", "sqlmap OS shell"),
    ("--os-pwn", "exploit_shell", "sqlmap OS pwn"),
    ("--os-cmd", "exploit_shell", "sqlmap OS command"),
    ("meterpreter", "exploit_shell", "meterpreter payload"),
    # --- credential spraying / brute force (forbidden even in intrusive tier) ---
    ("hydra ", "cred_spray", "credential brute force"),
    ("hydra\t", "cred_spray", "credential brute force"),
    ("medusa ", "cred_spray", "credential brute force"),
    ("patator", "cred_spray", "credential brute force"),
    ("ncrack", "cred_spray", "credential brute force"),
    ("crackmapexec", "cred_spray", "credential spraying"),
    # --- persistence ---
    ("crontab", "persistence", "cron persistence"),
    ("authorized_keys", "persistence", "ssh key persistence"),
    ("useradd", "persistence", "account creation"),
    ("adduser", "persistence", "account creation"),
    ("systemctl enable", "persistence", "service persistence"),
    # --- privilege / permissions ---
    ("chmod 777", "priv_perms", "world-writable perms"),
    ("chmod +s", "priv_perms", "setuid bit"),
    ("chmod u+s", "priv_perms", "setuid bit"),
    # --- secret / sensitive-file access (exfil) ---
    ("/etc/shadow", "exfil", "password hash file"),
    ("id_rsa", "exfil", "private ssh key"),
    (".aws/credentials", "exfil", "cloud credentials"),
    ("@/", "exfil", "read absolute-path file as request body"),
    ("@~", "exfil", "read home-dir file as request body"),
]

_USER_CONFIG_PATH = Path.home() / ".monkeyx" / "attack-policy.yaml"
_policy_cache: list[tuple[str, str, str]] | None = None


def _load_user_overrides() -> tuple[list[tuple[str, str, str]], set[str]]:
    """Return (extra_deny, allow_set) from ~/.monkeyx/attack-policy.yaml.

    Best-effort: a missing/malformed file yields no overrides (the built-in
    denylist still applies). Never raises."""
    if not _USER_CONFIG_PATH.exists():
        return [], set()
    try:
        import yaml
    except ImportError:
        logger.warning("pyyaml not installed — ignoring %s", _USER_CONFIG_PATH)
        return [], set()
    try:
        with _USER_CONFIG_PATH.open() as fh:
            data = yaml.safe_load(fh) or {}
    except Exception as e:
        logger.warning("Failed to parse %s: %s — using built-in policy only",
                       _USER_CONFIG_PATH, e)
        return [], set()

    extra: list[tuple[str, str, str]] = []
    for item in (data.get("deny") or []):
        if isinstance(item, dict) and item.get("pattern"):
            extra.append((str(item["pattern"]).lower(),
                          str(item.get("category", "custom")),
                          str(item.get("reason", "operator-defined"))))
        elif isinstance(item, str) and item:
            extra.append((item.lower(), "custom", "operator-defined"))
    allow = {str(p).lower() for p in (data.get("allow") or [])}
    return extra, allow


def load_policy(force: bool = False) -> list[tuple[str, str, str]]:
    """The effective denylist: built-ins minus operator ``allow`` plus ``deny``.

    Cached after first load; pass ``force=True`` to re-read (used by tests)."""
    global _policy_cache
    if _policy_cache is not None and not force:
        return _policy_cache
    extra, allow = _load_user_overrides()
    effective = [entry for entry in _DEFAULT_DENY if entry[0] not in allow]
    effective.extend(extra)
    _policy_cache = effective
    if extra or allow:
        logger.info("Attack policy: %d built-in rules, +%d operator deny, -%d allowed",
                    len(_DEFAULT_DENY), len(extra), len(allow))
    return _policy_cache


def check_command(argv: list) -> tuple[bool, str]:
    """Return (allowed, reason) for an argv command against the attack policy.

    ``allowed`` is False if ANY token contains a denied pattern; ``reason`` names
    the pattern + category so the block is auditable (kept in the ``blocked
    pattern:`` style ai_validate reported before). Empty reason when allowed.
    """
    policy = load_policy()
    for tok in (argv or []):
        tok_lower = str(tok).lower()
        for pattern, category, reason in policy:
            if pattern in tok_lower:
                return False, f"blocked pattern: {pattern.strip()} [{category}: {reason}]"
    return True, ""
