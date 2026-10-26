"""Tests for ai_validate scope/target extraction (authorization boundary).

Scanner output is untrusted and feeds the model, so a prompt-injected command
must not slip the scope check. The target parser previously hand-rolled URL
stripping and missed userinfo (https://x@127.0.0.1/ parsed to no host and was
never checked). It now uses urlparse and fails closed on unparseable hosts.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def _load():
    # ai_validate imports cleanly under the test deps (requirements.txt installs
    # anthropic[bedrock]); a plain import is more robust than stubbing core, which
    # broke once ai_validate began importing core.scan_db + modules.normalize.
    from modules import ai_validate
    return ai_validate


aiv = _load()


class TestTargetExtraction:
    def test_userinfo_url_resolves_to_real_host(self):
        # The whole point: userinfo must not hide the host.
        assert aiv._extract_targets_from_argv(["curl", "https://x@127.0.0.1/admin"]) == ["127.0.0.1"]

    def test_plain_url_host(self):
        assert aiv._extract_targets_from_argv(["curl", "https://127.0.0.1/admin"]) == ["127.0.0.1"]

    def test_url_with_port_and_path(self):
        assert aiv._extract_targets_from_argv(["curl", "https://api.example.com:8443/x"]) == ["api.example.com"]

    def test_bare_userinfo_token_fails_closed(self):
        out = aiv._extract_targets_from_argv(["nc", "user@10.0.0.1", "25"])
        assert out and out[0].startswith("\x00")  # sentinel -> never in scope

    def test_flags_and_binary_skipped(self):
        assert aiv._extract_targets_from_argv(["nmap", "-sV", "--open", "198.18.10.9"]) == ["198.18.10.9"]


class TestScopeEnforcement:
    def test_userinfo_bypass_blocked(self):
        ok, reason = aiv._is_safe_command(
            ["curl", "https://x@127.0.0.1/admin"], {"93.184.216.34"}, [], set())
        assert ok is False
        assert "127.0.0.1" in reason

    def test_in_scope_ip_allowed(self):
        ok, _ = aiv._is_safe_command(["nmap", "93.184.216.34"], {"93.184.216.34"}, [], set())
        assert ok is True

    def test_in_scope_host_allowed(self):
        ok, _ = aiv._is_safe_command(
            ["curl", "https://api.example.com/x"], set(), [], {"api.example.com"})
        assert ok is True

    def test_out_of_scope_host_blocked(self):
        ok, _ = aiv._is_safe_command(
            ["curl", "https://evil.example.net/x"], set(), [], {"api.example.com"})
        assert ok is False

    def test_bare_single_label_host_blocked(self):
        # `nmap internalhost` extracts no recognizable target; a network command
        # with no verifiable target must fail closed, not slip the scope check.
        ok, reason = aiv._is_safe_command(
            ["nmap", "-sV", "internalhost"], {"198.18.10.9"}, [], set())
        assert ok is False
        assert "no verifiable" in reason

    def test_option_only_command_blocked(self):
        # An option-smuggled input list with no target token must block, not pass.
        ok, reason = aiv._is_safe_command(
            ["nmap", "-iL", "/etc/passwd"], {"198.18.10.9"}, [], set())
        assert ok is False

    def test_smb_unc_host_scope_checked(self):
        # smbclient -L //host — the UNC host must be extracted and scope-checked.
        ok, _ = aiv._is_safe_command(
            ["smbclient", "-N", "-L", "//198.18.10.9"], {"198.18.10.9"}, [], set())
        assert ok is True
        ok, _ = aiv._is_safe_command(
            ["smbclient", "-N", "-L", "//10.0.0.1"], {"198.18.10.9"}, [], set())
        assert ok is False


class TestToolCapabilityHardening:
    def _wordlist_used(self, requested):
        argv, _ = aiv._build_command("ffuf_fuzz", {"url": "https://t/", "wordlist": requested})
        return argv[argv.index("-w") + 1]

    def test_ffuf_rejects_arbitrary_file(self):
        # Model must not exfiltrate local files via the wordlist path.
        assert self._wordlist_used("/etc/passwd") == aiv._DEFAULT_WORDLIST
        assert self._wordlist_used("/home/op/.ssh/id_rsa") == aiv._DEFAULT_WORDLIST

    def test_ffuf_rejects_traversal_out_of_root(self):
        assert self._wordlist_used("/usr/share/seclists/../../etc/passwd") == aiv._DEFAULT_WORDLIST

    def test_ffuf_allows_paths_under_allowed_roots(self):
        assert self._wordlist_used("/home/op/lists/x.txt") == "/home/op/lists/x.txt"
        good = "/usr/share/seclists/Discovery/Web-Content/common.txt"
        assert self._wordlist_used(good) == good

    def test_ffuf_none_uses_default(self):
        assert self._wordlist_used(None) == aiv._DEFAULT_WORDLIST

    def test_curl_never_follows_redirects(self):
        # Only the initial URL is scope-checked; -L would follow a 3xx anywhere.
        argv, _ = aiv._build_command("curl_request", {"url": "https://t/", "follow_redirects": True})
        assert "-L" not in argv

    def _blocked(self, argv):
        # A rejected option yields the sentinel argv, which _is_safe_command
        # fails closed on.
        ok, _ = aiv._is_safe_command(argv, {"198.18.10.9"}, [], set())
        return argv[0] == aiv._BLOCKED_OPTION_SENTINEL and ok is False

    def test_nmap_output_flag_blocked(self):
        # -oN <path> would write nmap output to an arbitrary file (RCE via a
        # shell profile / file clobber). Must be rejected.
        argv, _ = aiv._build_command(
            "nmap_scan", {"target": "198.18.10.9", "flags": "-oN /home/op/.bashrc"})
        assert self._blocked(argv)

    def test_nmap_intrusive_scripts_gated(self):
        payload = {"target": "198.18.10.9", "scripts": "exploit,dos"}
        argv_off, _ = aiv._build_command("nmap_scan", payload, allow_intrusive=False)
        assert self._blocked(argv_off)
        # Opted in: destructive categories are allowed through.
        argv_on, _ = aiv._build_command("nmap_scan", payload, allow_intrusive=True)
        assert argv_on[0] == "nmap" and "exploit,dos" in argv_on

    def test_nmap_intrusive_scripts_via_flags_blocked(self):
        # The intrusive-NSE gate lives on the dedicated `scripts` field. Smuggling
        # `--script exploit` through the free-text `flags` string must NOT run
        # destructive scripts with the operator gate bypassed — even when the
        # operator did NOT opt in.
        argv, _ = aiv._build_command(
            "nmap_scan",
            {"target": "198.18.10.9", "flags": "--script exploit,dos"},
            allow_intrusive=False)
        assert self._blocked(argv)
        # Still blocked even WITH the flag: the gate is only reachable via the
        # `scripts` field, so `flags`-smuggled scripts are always rejected.
        argv_on, _ = aiv._build_command(
            "nmap_scan",
            {"target": "198.18.10.9", "flags": "--script exploit"},
            allow_intrusive=True)
        assert argv_on[0] == aiv._BLOCKED_OPTION_SENTINEL

    def test_nmap_target_source_flags_blocked(self):
        # -iL <file> reads targets (any file) from disk; -iR <n> scans random
        # internet hosts. Both add targets the scope check never sees, so they
        # escape scope even alongside an in-scope target. Must be rejected.
        for smuggle in ("-iL /home/op/targets.txt", "-iR 1000", "-iL/etc/passwd"):
            argv, _ = aiv._build_command(
                "nmap_scan", {"target": "198.18.10.9", "flags": smuggle})
            assert self._blocked(argv), smuggle

    def test_nmap_benign_scripts_and_flags_pass(self):
        argv, _ = aiv._build_command(
            "nmap_scan",
            {"target": "198.18.10.9", "flags": "-sV -sC", "scripts": "http-title,ssl-cert"})
        assert argv[0] == "nmap"
        assert "http-title,ssl-cert" in argv and "-sV" in argv

    def test_testssl_logfile_blocked(self):
        argv, _ = aiv._build_command(
            "testssl_check", {"target": "198.18.10.9:443", "checks": "--logfile /tmp/x"})
        assert self._blocked(argv)

    def test_openssl_output_flag_blocked(self):
        argv, _ = aiv._build_command(
            "openssl_connect", {"target": "198.18.10.9:443", "flags": "-out /tmp/evil"})
        assert self._blocked(argv)


class TestProtocolHintSafetyTiers:
    """Intrusive (state-changing) protocol checks — SMTP open-relay, SNMP write,
    FTP upload — must be OFF by default and only appear with allow_intrusive.
    Guards against the 'non-destructive' prompt being contradicted by the hints."""

    SMTP = {"target": "mail.example.com:25", "action": "smtp open on port 25", "commands": []}
    SNMP = {"target": "h", "action": "snmp port 161 exposed", "commands": []}
    FTP = {"target": "h", "action": "ftp port 21 anonymous", "commands": []}

    def test_smtp_open_relay_gated(self):
        safe = aiv._get_protocol_hints(self.SMTP, allow_intrusive=False)
        intr = aiv._get_protocol_hints(self.SMTP, allow_intrusive=True)
        assert "EHLO" in safe                    # read-only step present by default
        assert "MAIL FROM" not in safe and "open relay test" not in safe.lower()
        assert "MAIL FROM" in intr               # only when opted in

    def test_snmp_write_gated(self):
        safe = aiv._get_protocol_hints(self.SNMP, allow_intrusive=False)
        intr = aiv._get_protocol_hints(self.SNMP, allow_intrusive=True)
        # default reads with public/community, never instructs a SET/write
        assert "SET" not in safe and "Test WRITE" not in safe
        assert "WRITE" in intr

    def test_ftp_upload_gated(self):
        safe = aiv._get_protocol_hints(self.FTP, allow_intrusive=False)
        intr = aiv._get_protocol_hints(self.FTP, allow_intrusive=True)
        assert "STOR" not in safe
        assert "STOR" in intr

    def test_no_hint_for_unrelated_finding(self):
        assert aiv._get_protocol_hints({"target": "x", "action": "http title", "commands": []}) == ""


class TestCategoryPlaybooks:
    """_classify_finding (was dead code) now drives per-category validation
    playbooks that steer the agent away from confirming on weak signals."""

    def test_classification(self):
        assert aiv._classify_finding({"action": "TLS 1.0 offered", "target": "h:443", "commands": ["testssl h"]}) == "crypto"
        assert aiv._classify_finding({"action": "SMB signing", "target": "h:445", "commands": []}) == "network"
        assert aiv._classify_finding({"action": "snmp default community", "target": "h:161", "commands": []}) == "network"
        assert aiv._classify_finding({"action": "exposed admin panel", "target": "https://h/admin", "commands": ["curl"]}) == "web"
        assert aiv._classify_finding({"action": "mystery", "target": "h", "commands": []}) == "web"  # default

    def test_playbook_matches_category(self):
        crypto = aiv._category_playbook({"action": "tls", "target": "h:443", "commands": []})
        network = aiv._category_playbook({"action": "smb signing", "target": "h:445", "commands": []})
        web = aiv._category_playbook({"action": "panel", "target": "https://h/", "commands": ["curl"]})
        assert "testssl" in crypto.lower() or "openssl" in crypto.lower()
        assert "signing" in network.lower() or "null session" in network.lower()
        assert "curl_request" in web
        # non-empty for every category
        assert crypto and network and web


class TestFlagsTargetSmuggling:
    """L3: a scan TARGET smuggled via free-text nmap/openssl `flags`/`checks`
    bypasses the per-target scope check. _safe_option_tokens rejects a STANDALONE
    bare positional (not following a flag); option VALUES after a flag stay
    allowed (any IP/host among them is still scope-checked downstream)."""

    def test_standalone_bare_target_rejected(self):
        # The real gap: a bare single-label host as a positional.
        _, reason = aiv._safe_option_tokens("internalhost".split())
        assert reason is not None

    def test_standalone_ip_rejected(self):
        _, reason = aiv._safe_option_tokens("10.0.0.5".split())
        assert reason is not None

    def test_second_positional_rejected(self):
        # A value after a flag is fine, but a further bare positional is not.
        _, reason = aiv._safe_option_tokens("-p 80 evilhost".split())
        assert reason is not None

    def test_legit_option_values_allowed(self):
        # Values that follow a flag are fine — including IP/host-valued flags
        # (those are still extracted + scope-checked downstream, not here).
        for flags in ("-starttls smtp", "-p 80", "-sV --version-intensity 5",
                      "-sV -T4", "--dns-servers 8.8.8.8", "--exclude host.example.com"):
            _, reason = aiv._safe_option_tokens(flags.split())
            assert reason is None, f"legit flags wrongly blocked: {flags!r} ({reason})"


class TestCurlHeaderInjection:
    """L4: CR/LF/NUL in model-controlled curl method/headers would inject extra
    request lines against the in-scope service — rejected (fail closed)."""

    def test_crlf_in_header_value_blocked(self):
        argv, _ = aiv._build_command(
            "curl_request",
            {"url": "https://h/", "headers": {"X-Foo": "bar\r\nX-Injected: 1"}},
            allow_intrusive=False)
        assert argv[0] == aiv._BLOCKED_OPTION_SENTINEL

    def test_crlf_in_method_blocked(self):
        argv, _ = aiv._build_command(
            "curl_request", {"url": "https://h/", "method": "GET\r\nHost: evil"},
            allow_intrusive=False)
        assert argv[0] == aiv._BLOCKED_OPTION_SENTINEL

    def test_clean_curl_allowed(self):
        argv, _ = aiv._build_command(
            "curl_request",
            {"url": "https://h/", "method": "GET", "headers": {"User-Agent": "mx"}},
            allow_intrusive=False)
        assert argv[0] == "curl" and argv[-1] == "https://h/"
