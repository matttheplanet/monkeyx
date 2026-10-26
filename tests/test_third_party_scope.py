"""A redirect/crawl target to a third-party host must not inherit ACTIVE-scan
scope from its in-scope parent (e.g. an M365 SSO redirect). It's logged for
audit but never exported to the scanners. Authorization comes from -t/-d.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.target_ledger import TargetLedger, TYPE_URL, TYPE_IP, TYPE_SUBDOMAIN


def _dl_ledger(tmp_path, domain="example.com"):
    (tmp_path / "d.txt").write_text(domain + "\n")
    led = TargetLedger(str(tmp_path))
    led.seed_user_inputs(None, str(tmp_path / "d.txt"), None)
    # an in-scope URL on the customer domain, to act as the redirect parent
    led.log_discovery("https://www.example.com/", TYPE_URL, "ax_httpx")
    return led


def test_ms_login_redirect_not_in_scope(tmp_path):
    led = _dl_ledger(tmp_path)
    ms = "https://login.microsoftonline.com/common/oauth2/authorize"
    led.log_discovery(ms, TYPE_URL, "ax_httpx", parent="https://www.example.com/")
    assert ms not in led._in_scope_urls                      # provider host -> not scanned
    assert "https://www.example.com/" in led._in_scope_urls  # the real asset stays in-scope


def test_same_org_subdomain_still_in_scope(tmp_path):
    led = _dl_ledger(tmp_path)
    url = "https://api.example.com/login"
    led.log_discovery(url, TYPE_URL, "ax_katana", parent="https://www.example.com/")
    assert url in led._in_scope_urls                         # under an explicit domain -> ours


def test_cross_domain_redirect_not_in_scope(tmp_path):
    led = _dl_ledger(tmp_path)
    other = "https://thirdparty.io/x"
    led.log_discovery(other, TYPE_URL, "ax_katana", parent="https://www.example.com/")
    assert other not in led._in_scope_urls                   # #2 cross-domain (not a provider)


def test_provider_blocked_even_without_explicit_domains(tmp_path):
    # IP-only run: no explicit domains, so the cross-domain guard can't fire, but
    # the identity-provider suffix (#1) still blocks the redirect target.
    (tmp_path / "t.txt").write_text("198.18.10.10\n")
    led = TargetLedger(str(tmp_path))
    led.seed_user_inputs(str(tmp_path / "t.txt"), None, None)
    led.log_discovery("https://198.18.10.10/", TYPE_URL, "ax_httpx")   # host is an in-scope IP
    ms = "https://login.microsoftonline.com/x"
    led.log_discovery(ms, TYPE_URL, "ax_httpx", parent="https://198.18.10.10/")
    assert ms not in led._in_scope_urls


def test_url_only_cross_domain_redirect_not_in_scope(tmp_path):
    # -url only (NO -d). Previously the cross-domain guard fail-OPENED with no
    # explicit domains, so a redirect to an unlisted domain inherited scope. The
    # explicit -url host is now an owned anchor, so the redirect is third-party.
    (tmp_path / "u.txt").write_text("https://app.example.com/\n")
    led = TargetLedger(str(tmp_path))
    led.seed_user_inputs(None, None, str(tmp_path / "u.txt"))
    other = "https://login.evil-partner.com/sso"
    led.log_discovery(other, TYPE_URL, "ax_httpx", parent="https://app.example.com/")
    assert other not in led._in_scope_urls
    assert "https://app.example.com/" in led._in_scope_urls   # the real -url asset stays in-scope


def test_url_only_same_url_host_subdomain_in_scope(tmp_path):
    # A subdomain of an explicit -url host is owned (owns self + subdomains).
    (tmp_path / "u.txt").write_text("https://app.example.com/\n")
    led = TargetLedger(str(tmp_path))
    led.seed_user_inputs(None, None, str(tmp_path / "u.txt"))
    url = "https://admin.app.example.com/"
    led.log_discovery(url, TYPE_URL, "ax_katana", parent="https://app.example.com/")
    assert url in led._in_scope_urls


def test_facebook_dns_record_not_in_scope_no_dash_d(tmp_path):
    # Prod regression: a *.facebook.com host reached via an in-scope domain's DNS
    # record was marked in-scope and got a dns_security DMARC finding. facebook is
    # NOT in the SSO suffix list, so with no -d the old code fail-opened. Here the
    # run has a -url anchor; the facebook subdomain must be third-party.
    (tmp_path / "u.txt").write_text("https://mail.example.com/\n")
    led = TargetLedger(str(tmp_path))
    led.seed_user_inputs(None, None, str(tmp_path / "u.txt"))
    fb = "1h8jnoa.dns.facebook.com"
    led.log_discovery(fb, TYPE_SUBDOMAIN, "bbot_passive", parent="https://mail.example.com/")
    assert fb not in led._in_scope_domains


def test_ip_only_cross_domain_name_not_in_scope(tmp_path):
    # -t IP only (no -d/-url). A redirect from the in-scope IP's synthesized URL
    # to an unlisted NAME must not inherit scope (the real fail-open the H1 fix
    # closes). The IP-host URL itself stays in-scope via the explicit-IP fallback.
    (tmp_path / "t.txt").write_text("198.18.10.10\n")
    led = TargetLedger(str(tmp_path))
    led.seed_user_inputs(str(tmp_path / "t.txt"), None, None)
    led.log_discovery("https://198.18.10.10/", TYPE_URL, "ax_httpx")
    other = "https://partner.example.net/"
    led.log_discovery(other, TYPE_URL, "ax_katana", parent="https://198.18.10.10/")
    assert "https://198.18.10.10/" in led._in_scope_urls   # explicit-IP host -> in scope
    assert other not in led._in_scope_urls                # cross-domain name -> third-party


def test_explicitly_listed_provider_is_still_scanned(tmp_path):
    # If the operator deliberately lists the provider domain, it IS in scope —
    # the guard only blocks redirect/crawl inheritance, not explicit authorization.
    (tmp_path / "d.txt").write_text("login.microsoftonline.com\n")
    led = TargetLedger(str(tmp_path))
    led.seed_user_inputs(None, str(tmp_path / "d.txt"), None)
    url = "https://login.microsoftonline.com/x"
    led.log_discovery(url, TYPE_URL, "ax_httpx")
    assert url in led._in_scope_urls
