"""Shared, non-AI-coupled security tool runners.

Extracts the scope-safe, read-only tool-execution pattern that has lived only
inside ``modules/ai_validate.py`` so that *both* standalone scan modules
(``ssh_audit_scan``, ``snmp_sweep``, ``smtp_security``) and — in a future,
eval-scored change — ai_validate's agent can call the same audited runners
instead of duplicating command construction and safety checks.

Design rules (mirrors ai_validate's contract):
  * argv lists + ``shell=False`` always. No value is ever interpolated into a
    shell string, so scan-derived hostnames/banners cannot inject commands.
  * Read-only. These runners never take output-file flags or state-changing
    actions; each tool is invoked with a fixed, safe flag set.
  * Per-command timeout; output truncated. Failures return a string, never raise.
  * Scope: callers pass an in-scope set built from the target file + ledger via
    ``load_scope``; ``target_in_scope`` fails closed on anything unrecognised.

Nothing here talks to an LLM.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import shutil
import subprocess

from core.output_layout import ledger_file

logger = logging.getLogger("monkeyx.core.tool_runners")

DEFAULT_TIMEOUT = 45
_MAX_OUTPUT = 8000


# --------------------------------------------------------------------------- #
# Scope (shared with the model in ai_validate._parse_scope)
# --------------------------------------------------------------------------- #

class Scope:
    """In-scope IPs, CIDR networks, and hostnames for an engagement."""

    def __init__(self, ips: set[str], networks: list, hosts: set[str]):
        self.ips = ips
        self.networks = networks
        self.hosts = hosts

    def contains(self, target: str) -> bool:
        """Fail-closed membership test for a bare IP or hostname."""
        if not target:
            return False
        t = target.strip().lower().rstrip(".")
        # strip a :port if present
        host = t.rsplit(":", 1)[0] if t.count(":") == 1 and t.rsplit(":", 1)[1].isdigit() else t
        try:
            ip = ipaddress.ip_address(host)
            if host in self.ips:
                return True
            for net in self.networks:
                try:
                    if ip.version == net.version and ip in net:
                        return True
                except (ValueError, TypeError):
                    continue
            return False
        except ValueError:
            # hostname
            if host in self.hosts:
                return True
            # allow subdomains of an in-scope host
            return any(host.endswith("." + h) for h in self.hosts)


def load_scope(target_file: str | None, data_prefix: str | None = None) -> Scope:
    """Build a Scope from the ENGINE-EXPORTED, policy-clean target files.

    Authorization for active probing (ai_validate agent + the standalone
    service-audit modules) must be exactly what the fleet was allowed to scan —
    no broader. So scope is derived only from the exported ledger files
    (``data/ledger/ledger-targets.txt`` / ``ledger-domains.txt`` /
    ``ledger-urls.txt`` — resolved via ``core.output_layout.ledger_file``),
    which the export layer (``TargetLedger.export_*``) has already
    scope-filtered, ip-scope-gated, private-IP-filtered, and exclusion-carved.

    It deliberately does NOT read raw ``discovery-ledger.jsonl``: that file logs
    EVERY discovery (including internal/RFC1918 IPs, CDN/third-party IPs a name
    resolved to, and out-of-scope derived hosts) with only a ``scope`` audit
    label, so unioning it in would re-widen the boundary past the export policy
    and let the agent probe hosts the fleet was specifically withheld from
    (fail-open). The exported files are the single source of authorization truth.
    """
    ips: set[str] = set()
    networks: list = []
    hosts: set[str] = set()
    seen_target_file = False

    def _consume(path: str):
        if not path or not os.path.exists(path):
            return
        try:
            with open(path, encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    _add_scope_line(line, ips, networks, hosts)
        except OSError:
            pass

    # The passed-in target file is the exported ledger-targets.txt (IPs/CIDRs +
    # any explicit hostnames).
    if target_file:
        _consume(target_file)
        seen_target_file = True

    # Pull the sibling exported domain/url files so hostnames the fleet was
    # allowed to hit (and only those) are in scope too.
    if data_prefix:
        data_dir = os.path.dirname(data_prefix)
        _consume(ledger_file(data_dir, "ledger-domains.txt"))
        _consume(ledger_file(data_dir, "ledger-urls.txt"))
        # Back-compat: if no explicit target file was supplied, fall back to the
        # exported ledger-targets.txt in the data dir.
        if not seen_target_file:
            _consume(ledger_file(data_dir, "ledger-targets.txt"))

    return Scope(ips, networks, hosts)


def _add_scope_line(line: str, ips: set, networks: list, hosts: set) -> None:
    """Classify one exported-file line into ips / networks / hosts.

    URLs are reduced to their hostname (ledger-urls.txt holds full URLs).
    """
    from urllib.parse import urlparse
    if "://" in line:
        host = urlparse(line).hostname
        if host:
            hosts.add(host.lower().rstrip("."))
        return
    try:
        if "/" in line:
            networks.append(ipaddress.ip_network(line, strict=False))
        else:
            ipaddress.ip_address(line)
            ips.add(line)
    except ValueError:
        hosts.add(line.lower().rstrip("."))


# --------------------------------------------------------------------------- #
# Execution (argv only, shell=False, read-only)
# --------------------------------------------------------------------------- #

def run_argv(argv: list[str], timeout: int = DEFAULT_TIMEOUT,
             stdin: str | None = None) -> str:
    """Execute argv with shell=False, capture combined output, never raise."""
    try:
        result = subprocess.run(  # noqa: S603 - argv list, shell=False, no interpolation
            argv, shell=False, capture_output=True, text=True,
            timeout=timeout, input=stdin,
        )
        output = result.stdout or ""
        if result.stderr:
            output += f"\n[stderr]: {result.stderr[-1000:]}"
        return (output or "(no output)")[:_MAX_OUTPUT]
    except FileNotFoundError:
        return f"ERROR: tool not found: {argv[0]}"
    except subprocess.TimeoutExpired:
        return f"TIMEOUT: exceeded {timeout}s"
    except Exception as e:  # noqa: BLE001
        return f"ERROR: {e}"


def tool_available(binary: str) -> bool:
    return shutil.which(binary) is not None


# --------------------------------------------------------------------------- #
# Read-only tool runners (fixed safe flags; target validated by the caller)
# --------------------------------------------------------------------------- #

def ssh_audit(target: str, port: int = 22, timeout: int = DEFAULT_TIMEOUT) -> str:
    """Audit an SSH endpoint's algorithms/version. Read-only."""
    return run_argv(["ssh-audit", "-p", str(int(port)), target], timeout=timeout)


def ssh_auth_methods(target: str, port: int = 22,
                     timeout: int = DEFAULT_TIMEOUT) -> list[str]:
    """Return the SSH server's permitted auth methods WITHOUT trying any.

    Uses PreferredAuthentications=none so the server replies with its allowed
    list ('… Permission denied (publickey,password,keyboard-interactive).').
    Attempts NO credentials — read-only. Returns lowercased method names, or []
    (none-auth allowed, host unreachable, or the reply couldn't be parsed).
    """
    import re

    t = str(target)
    if t.startswith("-"):          # never let a target parse as an ssh option
        return []
    out = run_argv([
        "ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=8",
        "-o", "NumberOfPasswordPrompts=0", "-o", "PreferredAuthentications=none",
        "-o", "PubkeyAuthentication=no", "-p", str(int(port)),
        f"monkeyxprobe@{t}",
    ], timeout=timeout)
    m = re.search(r"[Pp]ermission denied \(([^)]*)\)", out)
    if not m:
        return []
    return [x.strip().lower() for x in m.group(1).split(",") if x.strip()]


def snmp_walk(target: str, community: str = "public", version: str = "2c",
              oid: str = "1.3.6.1.2.1.1", timeout: int = DEFAULT_TIMEOUT) -> str:
    """Read-only SNMP GET/walk of the system OID with a READ community string.

    community/version are chosen from a fixed caller allowlist (see snmp_sweep),
    never free text, and this only ever reads (snmpwalk, not snmpset).
    """
    return run_argv(
        ["snmpwalk", f"-v{version}", "-c", community, "-t", "2", "-r", "1",
         target, oid],
        timeout=timeout,
    )


def smtp_probe(target: str, port: int = 25, timeout: int = 15) -> str:
    """Grab an SMTP banner + EHLO capabilities with openssl/nc-free stdlib.

    Read-only: connects, reads the banner, sends EHLO, records the capability
    list (which reveals STARTTLS support, VRFY/EXPN exposure, AUTH mechanisms),
    then QUITs. Does not attempt relay or user enumeration — that stays in
    ai_validate's intrusive tier.
    """
    import socket

    lines: list[str] = []
    try:
        with socket.create_connection((target, int(port)), timeout=timeout) as sock:
            sock.settimeout(timeout)
            # Read FULL multiline replies (via _smtp_read): the EHLO capability
            # list (STARTTLS / AUTH / VRFY / EXPN) spans several "250-" lines and
            # a single recv() often returns only the first ("250-<host>"), which
            # made STARTTLS look absent (false-positive starttls_missing) and hid
            # AUTH/VRFY/EXPN. _smtp_read loops until the terminating "250 " line.
            banner = _smtp_read(sock)
            lines.append(f"banner: {banner}")
            ehlo = _smtp_cmd(sock, "EHLO monkeyx-probe.local")
            lines.append("ehlo:")
            for l in ehlo.splitlines():
                lines.append(f"  {l.strip()}")
            try:
                sock.sendall(b"QUIT\r\n")
            except OSError:
                pass
    except (OSError, socket.timeout) as e:
        return f"ERROR: {e}"
    return "\n".join(lines)[:_MAX_OUTPUT]


def _smtp_read(sock) -> str:
    """Read a full (possibly multiline) SMTP reply. A reply ends at a line whose
    4th char is a space ('250 ok'); continuation lines use '250-...'."""
    import socket as _s
    data = b""
    while len(data) < 8192:
        try:
            chunk = sock.recv(1024)
        except (OSError, _s.timeout):
            break
        if not chunk:
            break
        data += chunk
        last = data.decode("utf-8", "replace").splitlines()[-1] if data else ""
        if len(last) >= 4 and last[3] == " ":
            break
    return data.decode("utf-8", "replace").strip()


def _smtp_cmd(sock, cmd: str) -> str:
    sock.sendall(cmd.encode("utf-8", "replace") + b"\r\n")
    return _smtp_read(sock)


def _smtp_server_name(banner: str) -> str | None:
    """Extract the server's own hostname from the 220 banner (the domain it
    treats as local) — '220 mail.example.com ESMTP …' -> 'mail.example.com'."""
    parts = banner.replace("220-", "220 ").split()
    if len(parts) >= 2 and "." in parts[1]:
        return parts[1].strip().lower().rstrip(".")
    return None


def smtp_relay_probe(target: str, port: int = 25, timeout: int = 15) -> dict:
    """NON-DESTRUCTIVE open-relay test.

    For a matrix of MAIL FROM / RCPT TO addressing tricks (the classic open-relay
    vectors), checks whether the server accepts an EXTERNAL recipient WITHOUT
    authentication. Stops at RCPT — it never issues DATA, so no message is ever
    relayed/delivered; a 250 on RCPT to an off-server address is the open-relay
    signal. Meaningful only on plaintext SMTP (25/587); 465 is implicit-TLS and
    is skipped by the caller.

    Returns {'local', 'starttls_required', 'results': [(vector, accepted, reply)]}
    or {'error': ...}. Read-transaction only (RSET between tests, then QUIT).
    """
    import socket

    ext = "relaytest@example.com"          # RFC 2606 reserved — never hosted here
    ext2 = "relaytest@example.net"
    try:
        with socket.create_connection((target, int(port)), timeout=timeout) as s:
            s.settimeout(timeout)
            banner = _smtp_read(s)
            local = _smtp_server_name(banner) or str(target)
            _smtp_cmd(s, "EHLO monkeyx-probe.local")
            # (vector name, MAIL FROM, RCPT TO)
            tests = [
                ("external-to-external", ext, ext2),
                ("null-sender", "", ext),
                (f"from-local-domain", f"probe@{local}", ext),
                ("source-route", ext, f"@{local}:{ext}"),
                ("percent-hack", ext, f"relaytest%example.com@{local}"),
                ("bang-path", ext, f"example.com!relaytest@{local}"),
                ("quoted-external", ext, '"relaytest@example.com"'),
            ]
            results, starttls_required = [], False
            for name, mail_from, rcpt_to in tests:
                _smtp_cmd(s, "RSET")
                mresp = _smtp_cmd(s, f"MAIL FROM:<{mail_from}>")
                code = mresp[:3]
                if code == "530":            # server demands STARTTLS/AUTH first
                    starttls_required = True
                    results.append((name, False, mresp[:120]))
                    continue
                if not code.startswith(("2", "3")):
                    results.append((name, False, mresp[:120]))
                    continue
                rresp = _smtp_cmd(s, f"RCPT TO:<{rcpt_to}>")
                accepted = rresp[:3] in ("250", "251")
                results.append((name, accepted, rresp[:120]))
            try:
                _smtp_cmd(s, "QUIT")
            except OSError:
                pass
    except (OSError, socket.timeout) as e:
        return {"error": str(e)}
    return {"local": local, "starttls_required": starttls_required,
            "results": results}
