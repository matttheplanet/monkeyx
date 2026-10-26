"""Tests for the live web view (monkeyx --webserver).

Exercise the read-only endpoints against a hand-built scan.db via FastAPI's
TestClient (no real port bound). The server only reads scan.db, so these also
guard that it never writes.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core import scan_db

# The server needs fastapi/uvicorn (shipped in requirements.txt); skip cleanly
# if a bare env lacks them rather than erroring the whole suite.
fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

import webserver  # noqa: E402


def _seed_db(output_dir):
    db = scan_db.open_db(output_dir)
    db.upsert_finding(finding_id="f1", host="h.tld", port=443, proto="tcp",
                      claim="CVE-2019-9874", tool="nuclei", severity="critical",
                      title="Sitecore RCE", cve_id="CVE-2019-9874")
    db.upsert_finding(finding_id="f2", host="h.tld", port=80, proto="tcp",
                      claim="tech-detect", tool="nuclei", severity="info",
                      title="nginx detected")
    db.set_verdict("f1", "confirmed")
    db.upsert_port(host="h.tld", port=443, proto="tcp", service="https")
    db.upsert_target(target="h.tld", target_type="domain", scope="explicit",
                     in_scope=True)
    db.upsert_web_dir(url="https://h.tld/admin", tool="ffuf", host="h.tld",
                      port=443, status_code=200, size=512, words=40)
    db.upsert_web_dir(url="https://h.tld/nope", tool="ffuf", host="h.tld",
                      port=443, status_code=404, size=12, words=2)
    db.upsert_web_dir(url="https://h.tld/secret", tool="feroxbuster", host="h.tld",
                      port=443, status_code=403, size=99, words=8)
    db.mark_ledger_authoritative()
    db.close()


def _client(output_dir):
    # Build the app the same way serve() does, without binding a socket.
    # serve() constructs the app inline, so re-run its endpoint wiring via a
    # tiny shim: call serve's internals by importing the module functions.
    # Simplest: monkeypatch uvicorn.run to capture the app.
    captured = {}

    import uvicorn
    orig = uvicorn.run
    uvicorn.run = lambda app, **kw: captured.setdefault("app", app)
    try:
        webserver.serve(output_dir, host="127.0.0.1", port=0)
    finally:
        uvicorn.run = orig
    return TestClient(captured["app"])


class TestWebserver:
    def test_index_page_renders(self, tmp_path):
        _seed_db(str(tmp_path))
        c = _client(str(tmp_path))
        r = c.get("/")
        assert r.status_code == 200
        assert "MonkeyX" in r.text
        assert os.path.basename(str(tmp_path)) in r.text  # run name injected

    def test_status_counts(self, tmp_path):
        _seed_db(str(tmp_path))
        c = _client(str(tmp_path))
        st = c.get("/api/status").json()
        assert st["available"] is True
        assert st["counts"]["findings"] == 2
        assert st["counts"]["ports"] == 1
        assert st["counts"]["targets"] == 1
        assert st["counts"]["webdirs"] == 3

    def test_web_dirs_view_rows_facets_and_filter(self, tmp_path):
        _seed_db(str(tmp_path))
        c = _client(str(tmp_path))
        d = c.get("/api/view/webdirs").json()
        assert d["total"] == 3
        assert d["columns"] == ["host", "url", "status_code", "size", "words", "tool"]
        # low-cardinality columns are offered as checkbox facets
        assert set(d["facets"].get("tool", [])) == {"ffuf", "feroxbuster"}
        assert set(d["facets"].get("status_code", [])) == {"200", "404", "403"}
        # fe.<col> exact filtering
        assert c.get("/api/view/webdirs?fe.tool=ffuf").json()["total"] == 2
        assert c.get("/api/view/webdirs?fe.status_code=200").json()["total"] == 1
        # CSV export honors the filter
        lines = [l for l in c.get("/api/view/webdirs.csv?fe.tool=feroxbuster").text.splitlines() if l]
        assert len(lines) == 2  # header + 1 row

    def test_step_progress(self, tmp_path):
        # Generate realistic progress events via the tracker: 3-step run, two
        # done and one mid-flight.
        from core.progress import ProgressTracker
        _seed_db(str(tmp_path))
        t = ProgressTracker(str(tmp_path), total_steps=3)
        s1 = t.step_started("ax_nmap_tcp"); t.step_completed("ax_nmap_tcp", s1, {})
        s2 = t.step_started("ax_nuclei"); t.step_completed("ax_nuclei", s2, {})
        t.step_started("ax_gowitness")  # left running (no completed)
        t.close()

        st = _client(str(tmp_path)).get("/api/status").json()
        p = st["progress"]
        assert p["total"] == 3
        assert p["done"] == 2
        assert p["current"]["module"] == "ax_gowitness"
        assert p["current"]["status"] == "running"
        assert p["current"]["idx"] == 3
        # full step list with per-step status
        by_module = {s["module"]: s["status"] for s in p["steps"]}
        assert by_module == {"ax_nmap_tcp": "completed",
                             "ax_nuclei": "completed",
                             "ax_gowitness": "running"}

    def test_step_progress_failed_counts_as_done(self, tmp_path):
        from core.progress import ProgressTracker
        _seed_db(str(tmp_path))
        t = ProgressTracker(str(tmp_path), total_steps=2)
        s1 = t.step_started("a"); t.step_completed("a", s1, {})
        s2 = t.step_started("b"); t.step_failed("b", s2, "boom")
        t.close()
        p = _client(str(tmp_path)).get("/api/status").json()["progress"]
        assert p["done"] == 2  # completed + failed both count as done
        assert {s["module"]: s["status"] for s in p["steps"]} == {
            "a": "completed", "b": "failed"}

    def test_findings_sorted_and_shaped(self, tmp_path):
        _seed_db(str(tmp_path))
        c = _client(str(tmp_path))
        fd = c.get("/api/findings").json()
        assert fd["total"] == 2
        # critical sorts before info
        assert fd["findings"][0]["severity"] == "critical"
        assert fd["findings"][0]["verdict"] == "confirmed"
        assert fd["by_severity"] == {"critical": 1, "info": 1}

    def test_findings_severity_filter(self, tmp_path):
        _seed_db(str(tmp_path))
        c = _client(str(tmp_path))
        fd = c.get("/api/findings?severity=critical").json()
        assert fd["total"] == 1
        assert fd["findings"][0]["finding_id"] == "f1"

    def test_findings_column_filter(self, tmp_path):
        # f.<col> substring-filters findings server-side (ci), combining with
        # the severity/no_info/q filters.
        _seed_db(str(tmp_path))
        c = _client(str(tmp_path))
        fd = c.get("/api/findings?f.title=nginx").json()
        assert fd["total"] == 1 and fd["findings"][0]["finding_id"] == "f2"
        # a column the findings view doesn't expose is ignored (never widens).
        fd2 = c.get("/api/findings?f.bogus=x").json()
        assert fd2["total"] == 2

    def test_findings_offers_facets(self, tmp_path):
        # The findings endpoint offers checkbox-facet options for the low-
        # cardinality columns (severity/port/tool/verdict) — the UI renders these
        # as checkboxes instead of text boxes.
        _seed_db(str(tmp_path))
        fd = _client(str(tmp_path)).get("/api/findings").json()
        facets = fd.get("facets") or {}
        assert set(facets.get("severity", [])) == {"critical", "info"}
        assert set(facets.get("tool", [])) == {"nuclei"}
        # port is faceted too (f1=443, f2=80), tokens are the string values.
        assert set(facets.get("port", [])) == {"443", "80"}

    def test_findings_facet_filter(self, tmp_path):
        # fe.<col> is the checkbox-facet channel: exact-match, multi-select (OR).
        _seed_db(str(tmp_path))
        c = _client(str(tmp_path))
        fd = c.get("/api/findings?fe.severity=critical").json()
        assert fd["total"] == 1 and fd["findings"][0]["finding_id"] == "f1"
        # multi-select ORs within a column.
        fd2 = c.get("/api/findings?fe.severity=critical&fe.severity=info").json()
        assert fd2["total"] == 2
        # facet on port.
        fd3 = c.get("/api/findings?fe.port=80").json()
        assert fd3["total"] == 1 and fd3["findings"][0]["finding_id"] == "f2"

    def test_findings_csv_column_filter(self, tmp_path):
        # CSV export honors f.<col>, matching the on-screen findings table.
        _seed_db(str(tmp_path))
        r = _client(str(tmp_path)).get("/api/findings.csv?f.title=Sitecore")
        lines = [l for l in r.text.splitlines() if l]
        assert len(lines) == 2 and "f1" in lines[1]  # header + f1 only

    def test_serve_no_db_prints_and_returns(self, tmp_path, capsys):
        # No scan.db in an otherwise-valid dir -> serve() bails before binding.
        webserver.serve(str(tmp_path))
        out = capsys.readouterr().out
        assert "No scan.db" in out

    def test_serve_bad_dir(self, tmp_path, capsys):
        webserver.serve(str(tmp_path / "does-not-exist"))
        assert "Not a directory" in capsys.readouterr().out

    def test_readonly_connection_cannot_write(self, tmp_path):
        _seed_db(str(tmp_path))
        conn = webserver._connect_ro(str(tmp_path))
        assert conn is not None
        with pytest.raises(Exception):
            conn.execute("UPDATE findings SET severity='low'")
        conn.close()


class TestFindingsCsv:
    def test_csv_all_filtered(self, tmp_path):
        _seed_db(str(tmp_path))
        c = _client(str(tmp_path))
        r = c.get("/api/findings.csv")
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("text/csv")
        assert "attachment" in r.headers["content-disposition"]
        lines = [l for l in r.text.splitlines() if l]
        assert lines[0].startswith("finding_id,host,port,proto,tool,claim,severity")
        assert len(lines) == 3            # header + 2 findings
        assert any("Sitecore RCE" in l for l in lines)

    def test_csv_severity_filter(self, tmp_path):
        _seed_db(str(tmp_path))
        c = _client(str(tmp_path))
        lines = [l for l in c.get("/api/findings.csv?severity=critical").text.splitlines() if l]
        assert len(lines) == 2            # header + 1 critical
        assert "f1" in lines[1]

    def test_csv_selected_ids(self, tmp_path):
        _seed_db(str(tmp_path))
        c = _client(str(tmp_path))
        lines = [l for l in c.get("/api/findings.csv?ids=f2").text.splitlines() if l]
        assert len(lines) == 2            # header + only f2
        assert "nginx detected" in lines[1]

    def test_csv_neutralizes_formula_injection(self, tmp_path):
        db = scan_db.open_db(str(tmp_path))
        db.upsert_finding(finding_id="fx", host="h.tld", port=1, proto="tcp",
                          claim="c", tool="nuclei", severity="low",
                          title="=cmd|'/c calc'!A1")   # spreadsheet injection attempt
        db.mark_ledger_authoritative(); db.close()
        c = _client(str(tmp_path))
        text = c.get("/api/findings.csv").text
        # the dangerous leading '=' must be prefixed with a quote
        assert "'=cmd" in text
        assert ",=cmd" not in text        # never a bare formula cell

    def test_findings_json_includes_claim(self, tmp_path):
        _seed_db(str(tmp_path))
        c = _client(str(tmp_path))
        fd = c.get("/api/findings").json()
        assert all("claim" in f for f in fd["findings"])


class TestNoInfoAndCap:
    def test_csv_no_info_excludes_info(self, tmp_path):
        _seed_db(str(tmp_path))   # f1 critical, f2 info
        c = _client(str(tmp_path))
        lines = [l for l in c.get("/api/findings.csv?no_info=1").text.splitlines() if l]
        assert len(lines) == 2            # header + only the critical one
        assert "f1" in lines[1]
        assert "nginx detected" not in "".join(lines)

    def test_csv_no_info_excludes_null_severity(self, tmp_path):
        db = scan_db.open_db(str(tmp_path))
        db.upsert_finding(finding_id="fn", host="h", port=1, proto="tcp",
                          claim="c", tool="nuclei")   # severity None -> treated as info
        db.upsert_finding(finding_id="fh", host="h", port=2, proto="tcp",
                          claim="c", tool="nuclei", severity="high")
        db.mark_ledger_authoritative(); db.close()
        c = _client(str(tmp_path))
        lines = [l for l in c.get("/api/findings.csv?no_info=1").text.splitlines() if l]
        assert len(lines) == 2 and "fh" in lines[1]   # only the high one

    def test_no_info_with_severity_still_works(self, tmp_path):
        # no_info + explicit severity=critical is just the criticals.
        _seed_db(str(tmp_path))
        c = _client(str(tmp_path))
        lines = [l for l in c.get("/api/findings.csv?severity=critical&no_info=1").text.splitlines() if l]
        assert len(lines) == 2 and "f1" in lines[1]


class TestRunSeqProgress:
    """Progress is scoped to the CURRENT invocation; cumulative summarized."""

    def test_continue_shows_current_run_not_cumulative(self, tmp_path):
        from core.progress import ProgressTracker
        _seed_db(str(tmp_path))
        # Run 1: a 2-step invocation, both completed.
        t1 = ProgressTracker(str(tmp_path), total_steps=2)
        for m in ("ax_nmap_tcp", "ax_nuclei"):
            s = t1.step_started(m); t1.step_completed(m, s, {})
        t1.close()
        # Run 2 (like --continue): a 3-step invocation, one running.
        t2 = ProgressTracker(str(tmp_path), total_steps=3)
        s = t2.step_started("ax_ffuf"); t2.step_completed("ax_ffuf", s, {})
        t2.step_started("ax_gowitness")   # running
        t2.close()

        p = _client(str(tmp_path)).get("/api/status").json()["progress"]
        # current run = run 2: total 3, its own steps only
        assert p["run_seq"] == 2
        assert p["runs_count"] == 2
        assert p["total"] == 3
        assert p["current"]["module"] == "ax_gowitness"
        assert p["current"]["status"] == "running"
        assert {s["module"] for s in p["steps"]} == {"ax_ffuf", "ax_gowitness"}
        # cumulative spans both runs (2 completed in run1 + 1 completed in run2 = 3)
        assert p["cumulative"]["runs"] == 2
        assert p["cumulative"]["done"] == 3

    def test_single_run_has_run_seq_1(self, tmp_path):
        from core.progress import ProgressTracker
        _seed_db(str(tmp_path))
        t = ProgressTracker(str(tmp_path), total_steps=1)
        s = t.step_started("only"); t.step_completed("only", s, {})
        t.close()
        p = _client(str(tmp_path)).get("/api/status").json()["progress"]
        assert p["run_seq"] == 1 and p["runs_count"] == 1

    def test_runs_history_covers_every_run(self, tmp_path):
        """`runs` gives per-run status/steps for ALL invocations, newest first —
        so a tester keeps visibility into earlier --continue runs, not just the
        last one."""
        from core.progress import ProgressTracker
        _seed_db(str(tmp_path))
        # Run 1: 2 steps, both completed.
        t1 = ProgressTracker(str(tmp_path), total_steps=2)
        for m in ("ax_nmap_tcp", "ax_nuclei"):
            s = t1.step_started(m); t1.step_completed(m, s, {})
        t1.close()
        # Run 2 (--continue): 3 steps, one failed, last still running.
        t2 = ProgressTracker(str(tmp_path), total_steps=3)
        s = t2.step_started("ax_ffuf"); t2.step_completed("ax_ffuf", s, {})
        s = t2.step_started("ax_nuclei"); t2.step_failed("ax_nuclei", s, "boom")
        t2.step_started("ax_gowitness")  # running
        t2.close()

        p = _client(str(tmp_path)).get("/api/status").json()["progress"]
        runs = p["runs"]
        assert [r["run_seq"] for r in runs] == [2, 1]  # newest first
        assert runs[0]["run_seq"] == p["run_seq"]      # runs[0] is the current run
        run2, run1 = runs
        assert run2["status"] == "running"
        assert run2["done"] == 2 and run2["total"] == 3 and run2["failed"] == 1
        assert {s["module"]: s["status"] for s in run2["steps"]} == {
            "ax_ffuf": "completed", "ax_nuclei": "failed", "ax_gowitness": "running"}
        assert run1["status"] == "completed"
        assert run1["done"] == 2 and run1["total"] == 2 and run1["failed"] == 0


def _seed_views_db(output_dir):
    """Richer seed: a validated finding, ports, targets, and a web endpoint."""
    db = scan_db.open_db(output_dir)
    db.upsert_finding(finding_id="f1", host="h.tld", port=443, proto="tcp",
                      claim="CVE-2019-9874", tool="nuclei", severity="critical",
                      title="Sitecore RCE", cve_id="CVE-2019-9874")
    db.upsert_finding(finding_id="f2", host="h.tld", port=80, proto="tcp",
                      claim="tech-detect", tool="nuclei", severity="info",
                      title="nginx detected")
    db.upsert_finding(finding_id="f3", host="h2.tld", port=22, proto="tcp",
                      claim="ssh-weak", tool="nmap", severity="medium",
                      title="Weak SSH ciphers")
    db.set_verdict("f1", "confirmed")
    db.record_validation(finding_id="f1", host="h.tld", port=443, proto="tcp",
                         verdict="confirmed", evidence="matched",
                         poc_command="curl -sk https://h.tld/")
    db.upsert_port(host="h.tld", port=443, proto="tcp", service="https",
                   product="nginx", version="1.24.0")
    db.upsert_port(host="h2.tld", port=22, proto="tcp", service="ssh")
    db.upsert_target(target="h.tld", target_type="domain", scope="explicit",
                     in_scope=True, source="user_input", channel="dl")
    db.upsert_target(target="10.0.0.5", target_type="ip", scope="derived",
                     in_scope=True, source="dns_resolve", parent="h.tld",
                     channel="dl")
    db.upsert_web_endpoint(host="h.tld", url="https://h.tld/", port=443,
                           scheme="https", status_code=200, title="Home",
                           webserver="nginx", tech='["nginx"]')
    db.mark_ledger_authoritative()
    db.close()


class TestGenericViews:
    def test_status_includes_web_count(self, tmp_path):
        _seed_views_db(str(tmp_path))
        st = _client(str(tmp_path)).get("/api/status").json()
        assert st["counts"]["web"] == 1

    def test_focus_view_ranked_confirmed_first(self, tmp_path):
        _seed_views_db(str(tmp_path))
        d = _client(str(tmp_path)).get("/api/view/focus").json()
        assert d["available"] is True
        assert d["columns"][0] == "rank"
        rows = d["rows"]
        # info-severity finding (f2) is dropped; f1/f3 remain.
        assert {r["host"] for r in rows} == {"h.tld", "h2.tld"}
        # confirmed critical ranks first, carries its poc command.
        assert rows[0]["rank"] == 1
        assert rows[0]["verdict"] == "confirmed"
        assert rows[0]["poc_command"] == "curl -sk https://h.tld/"
        # the unverified medium is below it and labeled unverified.
        assert rows[1]["verdict"] == "unverified"

    def test_focus_view_surfaces_flagged_info(self, tmp_path):
        # Info findings are noise EXCEPT when flagged: a confirmed info finding
        # appears in focus; a plain unverified info finding stays hidden.
        db = scan_db.open_db(str(tmp_path))
        db.upsert_finding(finding_id="i1", host="h.tld", port=80, proto="tcp",
                          claim="git-exposed", tool="nuclei", severity="info",
                          title="exposed .git")
        db.upsert_finding(finding_id="i2", host="h.tld", port=8080, proto="tcp",
                          claim="tech", tool="nuclei", severity="info",
                          title="nginx detected")
        db.record_validation(finding_id="i1", host="h.tld", port=80, proto="tcp",
                             verdict="confirmed", evidence="readable",
                             poc_command="curl -s http://h.tld/.git/config")
        db.set_verdict("i1", "confirmed")
        db.mark_ledger_authoritative()
        db.close()
        rows = _client(str(tmp_path)).get("/api/view/focus").json()["rows"]
        titles = {r["title"] for r in rows}
        assert "exposed .git" in titles          # flagged info surfaces
        assert "nginx detected" not in titles    # unverified info suppressed

    def test_ports_view(self, tmp_path):
        _seed_views_db(str(tmp_path))
        d = _client(str(tmp_path)).get("/api/view/ports").json()
        assert d["total"] == 2
        assert "service" in d["columns"] and "version" in d["columns"]
        first = d["rows"][0]
        assert first["host"] == "h.tld" and first["service"] == "https"

    def test_targets_view(self, tmp_path):
        _seed_views_db(str(tmp_path))
        d = _client(str(tmp_path)).get("/api/view/targets").json()
        assert d["total"] == 2
        by_target = {r["target"]: r for r in d["rows"]}
        assert by_target["10.0.0.5"]["scope"] == "derived"
        assert by_target["10.0.0.5"]["parent"] == "h.tld"
        # channel -> access column: both seeded dl -> name-safe (not port-scannable)
        assert "scope_class" in d["columns"]
        assert by_target["10.0.0.5"]["scope_class"] == "name-safe"
        assert by_target["h.tld"]["scope_class"] == "name-safe"
        # the raw channel column is not leaked to the client
        assert "channel" not in by_target["10.0.0.5"]

    def test_targets_view_channel_access_mapping(self, tmp_path):
        # host-full (-t), name-safe (-d/-url), and lead (no channel) each map to
        # the right access label the viewer badge renders.
        db = scan_db.open_db(str(tmp_path))
        db.upsert_target(target="1.2.3.4", target_type="ip", scope="explicit",
                         in_scope=True, channel="t")
        db.upsert_target(target="app.tld", target_type="domain", scope="explicit",
                         in_scope=True, channel="dl")
        db.upsert_target(target="u.tld", target_type="domain", scope="explicit",
                         in_scope=True, channel="ul")
        db.upsert_target(target="lead.tld", target_type="domain", scope="derived",
                         in_scope=False)  # no channel -> lead
        db.mark_ledger_authoritative()
        db.close()
        d = _client(str(tmp_path)).get("/api/view/targets").json()
        access = {r["target"]: r["scope_class"] for r in d["rows"]}
        assert access["1.2.3.4"] == "host-full"
        assert access["app.tld"] == "name-safe"
        assert access["u.tld"] == "name-safe"
        assert access["lead.tld"] == "lead"

    def test_web_view(self, tmp_path):
        _seed_views_db(str(tmp_path))
        d = _client(str(tmp_path)).get("/api/view/web").json()
        assert d["total"] == 1
        assert d["rows"][0]["url"] == "https://h.tld/"
        assert d["rows"][0]["status_code"] == 200

    def test_view_search_filter(self, tmp_path):
        _seed_views_db(str(tmp_path))
        d = _client(str(tmp_path)).get("/api/view/ports?q=ssh").json()
        assert d["total"] == 1 and d["rows"][0]["host"] == "h2.tld"

    def test_view_column_filter(self, tmp_path):
        # f.<col> narrows to rows whose column contains the substring (ci).
        _seed_views_db(str(tmp_path))
        d = _client(str(tmp_path)).get("/api/view/ports?f.service=SSH").json()
        assert d["total"] == 1 and d["rows"][0]["service"] == "ssh"

    def test_view_column_filters_are_anded(self, tmp_path):
        # Two column filters must BOTH match (narrowing, not widening).
        _seed_views_db(str(tmp_path))
        c = _client(str(tmp_path))
        both = c.get("/api/view/ports?f.host=h.tld&f.service=https").json()
        assert both["total"] == 1 and both["rows"][0]["service"] == "https"
        # host matches two rows but service=https only one -> AND yields one.
        none = c.get("/api/view/ports?f.host=h2.tld&f.service=https").json()
        assert none["total"] == 0

    def test_view_column_filter_combines_with_search(self, tmp_path):
        # global q AND per-column filter both apply.
        _seed_views_db(str(tmp_path))
        d = _client(str(tmp_path)).get(
            "/api/view/ports?q=h.tld&f.service=ssh").json()
        assert d["total"] == 0   # q keeps both hosts, but no ssh on h.tld

    def test_view_column_filter_unknown_col_ignored(self, tmp_path):
        # A filter on a column the view doesn't expose is ignored (can't widen).
        _seed_views_db(str(tmp_path))
        d = _client(str(tmp_path)).get("/api/view/ports?f.bogus=xyz").json()
        assert d["total"] == 2

    # ---- checkbox facets (low-cardinality columns) ----
    def test_view_returns_facets_for_enum_cols(self, tmp_path):
        # The server offers option lists for categorical columns; high-card
        # columns (target/parent/…) are absent so the client keeps a text box.
        _seed_views_db(str(tmp_path))
        f = _client(str(tmp_path)).get("/api/view/targets").json()["facets"]
        assert f["scope"] == ["derived", "explicit"]
        assert f["target_type"] == ["domain", "ip"]
        # 0/1 rendered yes/no. The name-safe derived IP (10.0.0.5, channel 'dl')
        # is displayed in_scope=no per _TARGETS_IN_SCOPE (a non-'t' IP is never
        # port-swept as a bare IP); the explicit domain h.tld stays yes.
        assert f["in_scope"] == ["no", "yes"]
        assert "target" not in f and "parent" not in f  # unique -> text box

    def test_facet_severity_sorted_by_rank(self, tmp_path):
        # severity options come back in severity order, not alphabetical.
        # (focus drops the unflagged info finding, so only critical/medium remain.)
        _seed_views_db(str(tmp_path))
        f = _client(str(tmp_path)).get("/api/view/focus").json()["facets"]
        assert f["severity"] == ["critical", "medium"]

    def test_enum_facet_exact_match(self, tmp_path):
        _seed_views_db(str(tmp_path))
        d = _client(str(tmp_path)).get("/api/view/targets?fe.scope=explicit").json()
        assert d["total"] == 1 and d["rows"][0]["target"] == "h.tld"

    def test_enum_facet_multi_value_is_or(self, tmp_path):
        # Two values on ONE column widen (OR) within that column.
        _seed_views_db(str(tmp_path))
        d = _client(str(tmp_path)).get(
            "/api/view/targets?fe.scope=explicit&fe.scope=derived").json()
        assert d["total"] == 2

    def test_enum_facets_across_columns_are_anded(self, tmp_path):
        # explicit is the domain; ip is derived -> the AND yields nothing.
        _seed_views_db(str(tmp_path))
        d = _client(str(tmp_path)).get(
            "/api/view/targets?fe.scope=explicit&fe.target_type=ip").json()
        assert d["total"] == 0

    def test_bool_facet_yes_no(self, tmp_path):
        _seed_views_db(str(tmp_path))
        c = _client(str(tmp_path))
        # h.tld (explicit domain) is in_scope=yes; 10.0.0.5 (name-safe 'dl' IP)
        # displays in_scope=no per _TARGETS_IN_SCOPE.
        assert c.get("/api/view/targets?fe.in_scope=yes").json()["total"] == 1
        assert c.get("/api/view/targets?fe.in_scope=no").json()["total"] == 1

    def test_none_token_matches_null_values(self, tmp_path):
        # Neither seeded port carries a validation verdict -> the '(none)'
        # option is offered and selects the un-validated rows.
        _seed_views_db(str(tmp_path))
        f = _client(str(tmp_path)).get("/api/view/ports").json()["facets"]
        assert f["verdict"] == ["(none)"]
        d = _client(str(tmp_path)).get("/api/view/ports?fe.verdict=(none)").json()
        assert d["total"] == 2

    def test_csv_honors_enum_facet(self, tmp_path):
        _seed_views_db(str(tmp_path))
        body = _client(str(tmp_path)).get(
            "/api/view/targets.csv?fe.scope=explicit").text
        assert "h.tld" in body and "10.0.0.5" not in body

    def test_unknown_view_404(self, tmp_path):
        _seed_views_db(str(tmp_path))
        r = _client(str(tmp_path)).get("/api/view/nope")
        assert r.status_code == 404


class TestFacetHelpers:
    def test_filter_token_bool_none_and_plain(self):
        assert webserver._filter_token("in_scope", 1) == "yes"
        assert webserver._filter_token("in_scope", 0) == "no"
        assert webserver._filter_token("cdn", None) == "no"
        assert webserver._filter_token("verdict", None) == "(none)"
        assert webserver._filter_token("verdict", "") == "(none)"
        assert webserver._filter_token("severity", "high") == "high"

    def test_facets_drops_high_cardinality(self):
        # More than _ENUM_MAX_OPTIONS distinct values -> dropped (no checkbox facet).
        rows = [{"tool": f"t{i}"} for i in range(webserver._ENUM_MAX_OPTIONS + 10)]
        assert "tool" not in webserver._facets(rows, ("tool",))

    def test_facets_keeps_small_enum(self):
        rows = [{"tool": "nuclei"}, {"tool": "nmap"}, {"tool": "nuclei"}]
        assert webserver._facets(rows, ("tool",))["tool"] == ["nmap", "nuclei"]

    def test_facets_ignore_non_enum_column(self):
        rows = [{"title": "a"}, {"title": "b"}]
        assert webserver._facets(rows, ("title",)) == {}


class TestSecurityHeaders:
    def test_headers_present_on_index(self, tmp_path):
        _seed_db(str(tmp_path))
        r = _client(str(tmp_path)).get("/")
        assert r.headers["x-content-type-options"] == "nosniff"
        assert r.headers["x-frame-options"] == "SAMEORIGIN"
        assert "default-src 'self'" in r.headers["content-security-policy"]

    def test_headers_present_on_500(self, tmp_path):
        # A handler that raises must still come back through the middleware with
        # the security headers set (not a header-less 500).
        _seed_db(str(tmp_path))
        c = _client(str(tmp_path))

        @c.app.get("/_boom")
        def _boom():
            raise RuntimeError("boom")

        r = TestClient(c.app, raise_server_exceptions=False).get("/_boom")
        assert r.status_code == 500
        assert r.headers["x-content-type-options"] == "nosniff"
        assert r.headers["x-frame-options"] == "SAMEORIGIN"


class TestTableCountAllowlist:
    def test_rejects_table_not_in_allowlist(self):
        import sqlite3
        conn = sqlite3.connect(":memory:")
        with pytest.raises(ValueError):
            webserver._table_count(conn, "web_dirs; DROP TABLE findings")

    def test_allowlisted_missing_table_returns_zero(self):
        import sqlite3
        conn = sqlite3.connect(":memory:")
        # In the allowlist but not present in this empty DB -> 0, not an error.
        assert webserver._table_count(conn, "web_dirs") == 0


class TestRunNameSanitization:
    def test_run_name_html_escaped_in_index(self, tmp_path):
        d = tmp_path / "<img src=x onerror=alert(1)>"
        d.mkdir()
        _seed_db(str(d))
        r = _client(str(d)).get("/")
        assert r.status_code == 200
        assert "<img src=x onerror=alert(1)>" not in r.text
        assert "&lt;img" in r.text

    def test_csv_filename_sanitized(self, tmp_path):
        d = tmp_path / 'bad"name<x>'
        d.mkdir()
        _seed_views_db(str(d))
        cd = _client(str(d)).get("/api/view/ports.csv").headers["content-disposition"]
        # Payload chars gone; only the two wrapping quotes of filename="..." remain.
        assert "<" not in cd and ">" not in cd
        assert cd.count('"') == 2


class TestPageSizeClamp:
    def test_size_zero_does_not_return_all_rows(self, tmp_path):
        # ?size=0 must NOT dump the whole table on a JSON endpoint (unauth DoS).
        _seed_views_db(str(tmp_path))
        r = _client(str(tmp_path)).get("/api/view/ports?size=0").json()
        assert r["total"] == 2          # two ports seeded
        assert len(r["rows"]) == 1      # clamped to a single-row page, not all
        assert r["size"] == 1

    def test_negative_size_clamped(self, tmp_path):
        _seed_views_db(str(tmp_path))
        r = _client(str(tmp_path)).get("/api/view/ports?size=-5").json()
        assert r["size"] == 1 and len(r["rows"]) <= 1


class TestGenericViewCsv:
    def test_ports_csv_header_and_rows(self, tmp_path):
        _seed_views_db(str(tmp_path))
        r = _client(str(tmp_path)).get("/api/view/ports.csv")
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("text/csv")
        lines = [l for l in r.text.splitlines() if l]
        assert lines[0].startswith("host,port,proto,state,service")
        assert len(lines) == 3            # header + 2 ports

    def test_focus_csv_matches_columns(self, tmp_path):
        _seed_views_db(str(tmp_path))
        r = _client(str(tmp_path)).get("/api/view/focus.csv")
        lines = [l for l in r.text.splitlines() if l]
        assert lines[0].startswith("rank,host,port,severity,verdict,title")
        # f2 (info) excluded -> header + 2 rows
        assert len(lines) == 3

    def test_view_csv_search_filter(self, tmp_path):
        _seed_views_db(str(tmp_path))
        r = _client(str(tmp_path)).get("/api/view/targets.csv?q=10.0.0.5")
        lines = [l for l in r.text.splitlines() if l]
        assert len(lines) == 2 and "10.0.0.5" in lines[1]

    def test_view_csv_column_filter_matches_view(self, tmp_path):
        # CSV export honors f.<col> so it mirrors the on-screen table.
        _seed_views_db(str(tmp_path))
        r = _client(str(tmp_path)).get("/api/view/ports.csv?f.service=ssh")
        lines = [l for l in r.text.splitlines() if l]
        assert len(lines) == 2 and "ssh" in lines[1]  # header + one ssh port

    def test_view_csv_neutralizes_formula_injection(self, tmp_path):
        db = scan_db.open_db(str(tmp_path))
        db.upsert_port(host="h.tld", port=1, proto="tcp", service="s",
                       banner="=cmd|'/c calc'!A1")
        db.mark_ledger_authoritative(); db.close()
        text = _client(str(tmp_path)).get("/api/view/ports.csv").text
        assert "'=cmd" in text and ",=cmd" not in text

    def test_unknown_view_csv_404(self, tmp_path):
        _seed_views_db(str(tmp_path))
        r = _client(str(tmp_path)).get("/api/view/nope.csv")
        assert r.status_code == 404


class TestScreenshots:
    def _seed(self, output_dir):
        db = scan_db.open_db(output_dir)
        # An httpx endpoint with a linked screenshot + an AI visual finding.
        db.upsert_web_endpoint(host="h.tld", url="https://h.tld/admin",
                               port=443, scheme="https", title="Admin",
                               screenshot="reports/shots/admin.jpeg")
        db.upsert_finding(finding_id="g1", host="h.tld", port=443, proto="tcp",
                          claim="gowitness:admin_interface", tool="gowitness",
                          type="finding", severity="high",
                          title="Jenkins admin panel",
                          detail="Login form visible", matched_at="https://h.tld/admin")
        # A capture with no AI finding (should still appear, after analyzed ones).
        db.upsert_web_endpoint(host="h.tld", url="https://h.tld/",
                               port=443, scheme="https", title="Home",
                               screenshot="reports/shots/home.jpeg")
        db.mark_ledger_authoritative()
        db.close()
        shots = os.path.join(output_dir, "reports", "shots")
        os.makedirs(shots, exist_ok=True)
        with open(os.path.join(shots, "admin.jpeg"), "wb") as fh:
            fh.write(b"\xff\xd8\xff\xe0jpeg-bytes")

    def test_screenshots_ranked_analyzed_first(self, tmp_path):
        self._seed(str(tmp_path))
        r = _client(str(tmp_path)).get("/api/screenshots")
        assert r.status_code == 200
        rows = r.json()["rows"]
        assert len(rows) == 2
        assert rows[0]["analyzed"] == 1        # AI finding ranks first
        assert rows[0]["category"] == "admin_interface"
        assert rows[0]["severity"] == "high"
        assert rows[1]["analyzed"] == 0        # bare capture after

    def test_all_findings_grouped_before_non_findings(self, tmp_path):
        """Regression: two critical findings must both precede every non-finding
        capture, even when one finding sits in a large visual cluster of
        non-finding siblings. The old cluster-first sort rendered
        [critical, its non-finding siblings, critical] — findings split apart."""
        db = scan_db.open_db(str(tmp_path))
        # Finding A: critical, in a phash cluster with 3 non-finding siblings.
        db.upsert_web_endpoint(host="a.tld", url="https://a.tld/x", port=443,
                               scheme="https", title="A",
                               screenshot="reports/shots/a.jpeg", phash_group=7)
        for i in range(3):
            db.upsert_web_endpoint(host="a.tld", url=f"https://a.tld/sib{i}",
                                   port=443, scheme="https", title=f"sib{i}",
                                   screenshot=f"reports/shots/sib{i}.jpeg",
                                   phash_group=7)
        db.upsert_finding(finding_id="A", host="a.tld", port=443, proto="tcp",
                          claim="gowitness:panel", tool="gowitness",
                          type="finding", severity="critical", title="crit A",
                          matched_at="https://a.tld/x")
        # Finding B: critical, its own singleton cluster.
        db.upsert_web_endpoint(host="b.tld", url="https://b.tld/y", port=443,
                               scheme="https", title="B",
                               screenshot="reports/shots/b.jpeg", phash_group=9)
        db.upsert_finding(finding_id="B", host="b.tld", port=443, proto="tcp",
                          claim="gowitness:panel", tool="gowitness",
                          type="finding", severity="critical", title="crit B",
                          matched_at="https://b.tld/y")
        db.mark_ledger_authoritative(); db.close()

        rows = _client(str(tmp_path)).get("/api/screenshots").json()["rows"]
        analyzed_flags = [r["analyzed"] for r in rows]
        # Every finding (analyzed=1) comes before every non-finding (analyzed=0):
        # no 1 appears after a 0.
        first_non_finding = analyzed_flags.index(0)
        assert all(f == 1 for f in analyzed_flags[:first_non_finding])
        assert all(f == 0 for f in analyzed_flags[first_non_finding:])
        # Both criticals lead; the cluster's siblings are pushed to the remainder.
        assert {rows[0]["title"], rows[1]["title"]} == {"crit A", "crit B"}

    def test_screenshots_search(self, tmp_path):
        self._seed(str(tmp_path))
        rows = _client(str(tmp_path)).get(
            "/api/screenshots?q=jenkins").json()["rows"]
        assert len(rows) == 1 and rows[0]["analyzed"] == 1

    def test_screenshot_file_served(self, tmp_path):
        self._seed(str(tmp_path))
        r = _client(str(tmp_path)).get(
            "/screenshot?path=reports/shots/admin.jpeg")
        assert r.status_code == 200
        assert r.content.startswith(b"\xff\xd8\xff")

    def test_screenshot_path_traversal_blocked(self, tmp_path):
        self._seed(str(tmp_path))
        c = _client(str(tmp_path))
        assert c.get("/screenshot?path=../../etc/passwd").status_code == 400
        assert c.get("/screenshot?path=/etc/passwd").status_code == 400
        # a non-image extension is rejected even inside the tree
        assert c.get("/screenshot?path=scan.db").status_code == 400

    def test_web_view_exposes_screenshot_column(self, tmp_path):
        self._seed(str(tmp_path))
        d = _client(str(tmp_path)).get("/api/view/web").json()
        assert "screenshot" in d["columns"]


def _seed_coverage(output_dir, n=1200):
    db = scan_db.open_db(output_dir)
    db.next_run_seq()
    db.record_coverage(module="ax_nuclei",
                       targets=[f"h{i}.tld" for i in range(n)],
                       target_type="url", run_seq=1, step_index=1)
    # a couple reconciled so status filtering/ordering is exercised
    db.reconcile_coverage(module="ax_nuclei", run_seq=1, step_index=1,
                          reached=["h0.tld"])
    db.mark_ledger_authoritative()
    db.close()


class TestPagination:
    """The server must return a BOUNDED slice, never the whole table — the
    crash-safety guarantee for large coverage/ports sets."""

    def test_view_returns_only_one_page(self, tmp_path):
        _seed_coverage(str(tmp_path), n=1200)
        d = _client(str(tmp_path)).get("/api/view/coverage?page=0&size=100").json()
        assert d["total"] == 1200          # full count reported
        assert len(d["rows"]) == 100       # but only a page shipped
        assert d["page"] == 0 and d["size"] == 100

    def test_second_page_is_disjoint(self, tmp_path):
        _seed_coverage(str(tmp_path), n=1200)
        c = _client(str(tmp_path))
        p0 = c.get("/api/view/coverage?page=0&size=50&sort=target").json()["rows"]
        p1 = c.get("/api/view/coverage?page=1&size=50&sort=target").json()["rows"]
        t0 = {r["target"] for r in p0}
        t1 = {r["target"] for r in p1}
        assert len(t0) == 50 and len(t1) == 50
        assert t0.isdisjoint(t1)           # no overlap across pages

    def test_server_side_sort_spans_full_set(self, tmp_path):
        # Sort must be applied before slicing, so page 0 holds the global min.
        _seed_coverage(str(tmp_path), n=1200)
        d = _client(str(tmp_path)).get(
            "/api/view/coverage?page=0&size=10&sort=target&dir=asc").json()
        targets = [r["target"] for r in d["rows"]]
        assert targets == sorted(targets)  # lexicographic within the page
        # h0.tld sorts first lexicographically and must be on page 0
        assert "h0.tld" in targets

    def test_search_filters_server_side(self, tmp_path):
        _seed_coverage(str(tmp_path), n=1200)
        d = _client(str(tmp_path)).get(
            "/api/view/coverage?q=h1.tld&size=500").json()
        assert d["total"] >= 1
        assert all("h1.tld" in r["target"] for r in d["rows"])

    def test_csv_export_is_full_not_paged(self, tmp_path):
        # CSV path uses size<=0 (all rows) so an export is complete.
        _seed_coverage(str(tmp_path), n=1200)
        r = _client(str(tmp_path)).get("/api/view/coverage.csv")
        assert r.status_code == 200
        # header + 1200 rows
        lines = [ln for ln in r.text.splitlines() if ln.strip()]
        assert len(lines) == 1201

    def test_coverage_status_count(self, tmp_path):
        _seed_coverage(str(tmp_path), n=10)
        st = _client(str(tmp_path)).get("/api/status").json()
        # 1 reached, 9 no_response -> badge counts the gap (no_response)
        assert st["counts"]["coverage"] == 9

    def test_out_of_range_page_returns_empty_with_true_total(self, tmp_path):
        # Contract the client's page-clamp relies on: a too-high page yields an
        # empty slice BUT the real total, so the client can snap back to the
        # last valid page instead of stranding on a blank, pager-less view.
        _seed_coverage(str(tmp_path), n=120)
        d = _client(str(tmp_path)).get(
            "/api/view/coverage?page=99&size=50").json()
        assert d["rows"] == [] and d["total"] == 120

    def test_last_partial_page(self, tmp_path):
        # 120 rows / size 50 -> page 2 holds the final 20.
        _seed_coverage(str(tmp_path), n=120)
        d = _client(str(tmp_path)).get(
            "/api/view/coverage?page=2&size=50").json()
        assert len(d["rows"]) == 20 and d["total"] == 120

    def test_pagination_respects_column_filter(self, tmp_path):
        # Per-column filter narrows the set BEFORE paging, and total reflects the
        # filtered count so the pager sizes correctly.
        _seed_coverage(str(tmp_path), n=120)
        c = _client(str(tmp_path))
        full = c.get("/api/view/coverage?size=500").json()["total"]
        d = c.get("/api/view/coverage?f.target=h1&page=0&size=50").json()
        assert 0 < d["total"] < full
        assert all("h1" in r["target"] for r in d["rows"])


def _seed_findings(output_dir, n=1000):
    db = scan_db.open_db(output_dir)
    for i in range(n):
        sev = "info" if i % 2 else "high"
        db.upsert_finding(finding_id=f"f{i}", host=f"h{i}.tld", port=443,
                          proto="tcp", claim=f"c{i}", tool="nuclei",
                          severity=sev, title=f"finding {i}")
    db.mark_ledger_authoritative()
    db.close()


class TestFindingsPagination:
    def test_findings_returns_one_page_with_total(self, tmp_path):
        _seed_findings(str(tmp_path), n=1000)
        # no_info=0 so the 'info' half is included -> 1000 total
        d = _client(str(tmp_path)).get(
            "/api/findings?page=0&size=100&no_info=0").json()
        assert d["total"] == 1000
        assert len(d["findings"]) == 100

    def test_no_info_filter_is_server_side(self, tmp_path):
        _seed_findings(str(tmp_path), n=1000)
        d = _client(str(tmp_path)).get(
            "/api/findings?no_info=1&size=2000").json()
        assert d["total"] == 500                     # info half excluded
        assert all(r["severity"] != "info" for r in d["findings"])

    def test_by_severity_is_unfiltered_grand_total(self, tmp_path):
        _seed_findings(str(tmp_path), n=1000)
        d = _client(str(tmp_path)).get("/api/findings?no_info=1").json()
        # chips show grand totals regardless of the no_info view filter
        assert d["by_severity"].get("high") == 500
        assert d["by_severity"].get("info") == 500

    def test_ids_only_returns_full_filtered_id_list(self, tmp_path):
        _seed_findings(str(tmp_path), n=1000)
        d = _client(str(tmp_path)).get(
            "/api/findings?no_info=1&ids_only=1").json()
        assert "findings" not in d
        assert len(d["ids"]) == 500                  # spans all pages, ids only

    def test_search_filters_findings_server_side(self, tmp_path):
        _seed_findings(str(tmp_path), n=1000)
        d = _client(str(tmp_path)).get(
            "/api/findings?q=finding+1&size=2000&no_info=0").json()
        assert d["total"] >= 1
        assert all("finding 1" in (r["title"] or "") for r in d["findings"])

    def test_csv_honors_search(self, tmp_path):
        _seed_findings(str(tmp_path), n=1000)
        r = _client(str(tmp_path)).get("/api/findings.csv?q=finding+1&no_info=0")
        assert r.status_code == 200
        lines = [ln for ln in r.text.splitlines() if ln.strip()]
        # header + only the matching subset (far fewer than 1000)
        assert 1 < len(lines) < 1000

    def test_findings_out_of_range_page_true_total(self, tmp_path):
        # Same client-clamp contract as the generic views: empty page, real total.
        _seed_findings(str(tmp_path), n=1000)
        d = _client(str(tmp_path)).get(
            "/api/findings?page=999&size=100&no_info=0").json()
        assert d["findings"] == [] and d["total"] == 1000

    def test_findings_pagination_respects_column_filter(self, tmp_path):
        # f.<col> narrows before paging; total is the filtered count.
        _seed_findings(str(tmp_path), n=1000)
        d = _client(str(tmp_path)).get(
            "/api/findings?f.title=finding+1&size=100&no_info=0").json()
        assert 0 < d["total"] < 1000
        assert all("finding 1" in (r["title"] or "") for r in d["findings"])


class TestScreenshotPathSafety:
    """The /screenshot endpoint serves files by output-dir-relative path — it
    must not become an arbitrary-file-read primitive via traversal or symlink."""

    def _png(self, path):
        # A tiny valid-enough file; the endpoint only checks extension + location.
        with open(path, "wb") as f:
            f.write(b"\x89PNG\r\n\x1a\n")

    def test_serves_image_under_output_dir(self, tmp_path):
        _seed_db(str(tmp_path))
        shots = tmp_path / "reports" / "shots"
        shots.mkdir(parents=True)
        self._png(str(shots / "a.png"))
        c = _client(str(tmp_path))
        r = c.get("/screenshot", params={"path": "reports/shots/a.png"})
        assert r.status_code == 200

    def test_rejects_parent_traversal(self, tmp_path):
        _seed_db(str(tmp_path))
        c = _client(str(tmp_path))
        assert c.get("/screenshot", params={"path": "../secret.png"}).status_code == 400

    def test_rejects_absolute_path(self, tmp_path):
        _seed_db(str(tmp_path))
        c = _client(str(tmp_path))
        assert c.get("/screenshot", params={"path": "/etc/hosts"}).status_code == 400

    def test_rejects_non_image_extension(self, tmp_path):
        _seed_db(str(tmp_path))
        c = _client(str(tmp_path))
        assert c.get("/screenshot", params={"path": "run.log"}).status_code == 400

    def test_rejects_symlink_escaping_output_dir(self, tmp_path):
        # A symlink INSIDE output_dir pointing at a file OUTSIDE it must not be
        # followed — os.path.abspath would have; os.path.realpath closes it.
        _seed_db(str(tmp_path))
        outside = tmp_path.parent / "outside_secret.png"
        self._png(str(outside))
        link = tmp_path / "evil.png"
        try:
            os.symlink(str(outside), str(link))
        except (OSError, NotImplementedError):
            pytest.skip("symlinks unavailable on this platform")
        c = _client(str(tmp_path))
        r = c.get("/screenshot", params={"path": "evil.png"})
        assert r.status_code == 403, "symlink escaping output_dir must be refused"


class TestClientXssGuards:
    """The single-page client interpolates scan-derived strings into HTML. These
    lock in the sanitizers so a refactor can't silently drop them (the JS itself
    isn't executed here, so we assert on the served template)."""

    def test_slug_and_safeurl_helpers_present(self, tmp_path):
        _seed_db(str(tmp_path))
        html = _client(str(tmp_path)).get("/").text
        assert "function slug(" in html
        assert "function safeUrl(" in html

    def test_severity_verdict_status_classes_are_slugged(self, tmp_path):
        _seed_db(str(tmp_path))
        html = _client(str(tmp_path)).get("/").text
        # class-attribute interpolation of scan-derived tokens must go through slug()
        assert 'class="badge ${slug(' in html
        assert 'class="v-${slug(' in html
        assert 'class="cov cov-${slug(' in html
        assert 'class="badge ${slug(r.severity)}' in html   # screenshots gallery

    def test_scan_urls_go_through_safeurl(self, tmp_path):
        _seed_db(str(tmp_path))
        html = _client(str(tmp_path)).get("/").text
        assert "href=\"${esc(safeUrl(r.url))}\"" in html     # gallery anchor
        assert "lbLink.href = safeUrl(" in html              # lightbox link
        # the old unsanitized forms must be gone
        assert "href=\"${encodeURI(r.url" not in html
        assert "lbLink.href = url;" not in html
