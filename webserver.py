"""Live web view for a MonkeyX run.

    monkeyx --webserver ./engagement

Serves a small, self-contained web UI that reads a run's ``scan.db`` and shows
live-updating status + findings while a scan runs, and afterwards. It only ever
READS the DB (read-only connection), so it is safe to run alongside the engine
writing the same file (WAL serves the last committed snapshot).

Deliberately minimal — reuses FastAPI + uvicorn (already in requirements.txt),
one inline HTML page (no build step, no extra deps), binds 127.0.0.1 by default.
"""

# NOTE: do NOT add `from __future__ import annotations` here — FastAPI resolves
# these route annotations at runtime and postponed (stringized) annotations
# break it. For 3.9 compatibility (the bundled viewer runs on macOS's default
# 3.9) use typing.Optional/Union below rather than PEP 604 `X | None`.
import csv
import html
import io
import json
import logging
import os
import re
from typing import Optional
import sqlite3
from collections import Counter, defaultdict
from datetime import datetime

from core import scan_db

logger = logging.getLogger("monkeyx.webserver")

# Severity ordering for display + counts.
_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Hard cap on a JSON page size so an unauthenticated peer can't request the
# whole table (e.g. ?size=0/-1) as a single response. The CSV export path is
# the only "return everything" path and does not read this.
_MAX_PAGE_SIZE = 1000

# Columns exported to CSV (also the order in the file).
_CSV_COLUMNS = ("finding_id", "host", "port", "proto", "tool", "claim",
                "severity", "title", "matched_at", "cve_id", "verdict",
                "triage_status", "false_positive")

# Neutralize spreadsheet formula injection (same convention as jsonl_to_csv).
_CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _csv_safe(value):
    if isinstance(value, str) and value and value[0] in _CSV_FORMULA_PREFIXES:
        return "'" + value
    return value


def _connect_ro(output_dir: str) -> Optional[sqlite3.Connection]:
    """Open the run's scan.db read-only, or None if absent.

    Read-only + query_only means this can never contend with or corrupt the
    engine's writer; WAL lets us read the latest committed snapshot live.
    """
    db_path = scan_db.db_path_for(output_dir)
    if not os.path.exists(db_path):
        return None
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only=ON")
    return conn


def _sev_rank(sev):
    return _SEV_ORDER.get((sev or "info").lower(), 5)


def _query_findings(conn, severity=None, verdict=None, no_info=False) -> list[dict]:
    """Fetch findings (optionally filtered), severity-ranked then host/port.

    Shared by the JSON and CSV endpoints so both return the exact same rows.
    ``no_info`` excludes info-severity (the default "interesting" view) —
    done server-side so a huge export doesn't need every id in the URL.
    """
    where, params = [], []
    if severity:
        where.append("severity = ?"); params.append(severity)
    if verdict:
        where.append("verdict = ?"); params.append(verdict)
    if no_info:
        # NULL severity is treated as 'info' (matches the client), so exclude it too.
        where.append("severity IS NOT NULL AND severity != 'info'")
    clause = (" WHERE " + " AND ".join(where)) if where else ""
    rows = [dict(r) for r in conn.execute(
        "SELECT finding_id, host, port, proto, tool, claim, severity, "
        "original_severity, severity_source, rerate_reason, title, "
        "matched_at, cve_id, verdict, triage_status, false_positive "
        f"FROM findings{clause}", params)]
    # Collapse the weburls IP↔hostname dual-emit for presentation: keep the
    # hostname row with its resolved `ip` alongside, drop the redundant bare-IP
    # row. Raw rows stay in scan.db; this is display-only.
    host_to_ip, _ = scan_db.host_ip_maps_from_parents(conn)
    rows = scan_db.dedup_ip_hostname_findings(rows, host_to_ip)
    rows.sort(key=lambda r: (_sev_rank(r.get("severity")),
                             r.get("host") or "", r.get("port") or 0))
    return rows


def _query_focus(conn, q=None) -> list[dict]:
    """Findings joined to their latest validation, confirmed-first ranked.

    The DB-backed spine of the focus list (analysis-only attack chains without a
    finding row live in focus.json/report.html — the webserver only reads
    scan.db). Ranking mirrors modules/focus.py: false-positive last, then
    verdict (confirmed<unclear<unverified<refuted), then severity, then
    has-proof. ``q`` is an optional substring over host/title/cve/tool.
    """
    verdict_rank = {"confirmed": 0, "unclear": 1, "unverified": 2,
                    "error": 2, None: 2, "refuted": 3}
    rows = [dict(r) for r in conn.execute(
        "SELECT f.finding_id, f.host, f.port, f.proto, f.tool, f.severity, "
        "f.title, f.cve_id, f.false_positive, "
        "COALESCE(f.verdict, v.verdict) AS verdict, "
        "v.poc_command, v.evidence "
        "FROM findings f LEFT JOIN validations v "
        "ON v.id = (SELECT id FROM validations WHERE finding_id = f.finding_id "
        "ORDER BY id DESC LIMIT 1)")]
    # Only genuine NON-INFO findings — UNLESS an info finding was flagged by
    # validation (confirmed/unclear verdict or proof), in which case it is signal
    # and surfaces. Info-severity detections (tech-detect, DNS fingerprints, ...)
    # are context and stay out of focus. Mirrors modules/focus.py via in_focus.
    rows = [r for r in rows if scan_db.in_focus(
        {"type": None, "severity": r.get("severity")},
        r.get("verdict"), r.get("poc_command"))]
    rows.sort(key=lambda r: (
        1 if r.get("false_positive") else 0,
        verdict_rank.get((r.get("verdict") or None), 2),
        _sev_rank(r.get("severity")),
        0 if r.get("poc_command") else 1))
    for i, r in enumerate(rows, 1):
        r["rank"] = i
        r["verdict"] = r.get("verdict") or "unverified"
    return _substr_filter(rows, q, ("host", "title", "cve_id", "tool"))


# Authorization channel -> human "access ceiling". host-full (-t) means the
# target can be port-scanned; name-safe (-d/-url) means hostname-only, never
# swept. The targets spec mirrors this map as a SQL CASE (_TARGETS_SCOPE_CLASS).

# --- Generic single-table views: served entirely from SQL --------------------
# web_dirs / module_coverage / targets can each hold millions of rows on a large
# scope. Filtering/sorting/counting them in Python meant materializing the WHOLE
# table per request (OOM-slow). Each view below is a declarative spec driving one
# builder that pushes the q filter, per-column filters, sort, COUNT and
# LIMIT/OFFSET into SQLite, so a request only ever materializes one page.
#
# `cols` maps an output column to its SQL expression (a plain column, or a CASE
# for a computed one — scope_class/in_scope); `search` is the columns the
# free-text `q` matches; `order` is the default ORDER BY (identifiers come only
# from these specs, never from the request, so they can't be injected).

_TARGETS_SCOPE_CLASS = (
    "CASE channel WHEN 't' THEN 'host-full' WHEN 'dl' THEN 'name-safe' "
    "WHEN 'ul' THEN 'name-safe' ELSE 'lead' END")
# An IP discovered by resolving a -d/-url NAME is name-safe scope (scanned by
# name, never port-swept as a bare IP), so show in_scope=0 for a non-'t' IP;
# names keep their raw in_scope. Mirrors the old Python override.
_TARGETS_IN_SCOPE = (
    "CASE WHEN target_type='ip' AND channel!='t' THEN 0 ELSE in_scope END")
# Surface coverage gaps first: no_response, then step_failed, fed, reached;
# newest run_seq first within a status.
_COVERAGE_ORDER = (
    "CASE status WHEN 'no_response' THEN 0 WHEN 'step_failed' THEN 1 "
    "WHEN 'fed' THEN 2 WHEN 'reached' THEN 3 ELSE 4 END, run_seq DESC, module, target")

_VIEW_SPECS = {
    "ports": {
        "table": "ports",
        "cols": {"host": "host", "port": "port", "proto": "proto",
                 "state": "state", "service": "service", "product": "product",
                 "version": "version", "banner": "banner", "verdict": "verdict"},
        "search": ("host", "service", "product", "version", "banner"),
        "order": "host, port",
    },
    "webdirs": {
        "table": "web_dirs",
        "cols": {"host": "host", "url": "url", "status_code": "status_code",
                 "size": "size", "words": "words", "tool": "tool"},
        "search": ("host", "url", "tool"),
        "order": "host, url",
    },
    "targets": {
        "table": "targets",
        "cols": {"target": "target", "target_type": "target_type", "scope": "scope",
                 "in_scope": _TARGETS_IN_SCOPE, "scope_class": _TARGETS_SCOPE_CLASS,
                 "source": "source", "parent": "parent",
                 "discovered_at": "discovered_at"},
        "search": ("target", "target_type", "source", "parent"),
        "order": "target_type, target",
    },
    "web": {
        "table": "web_endpoints",
        "cols": {"host": "host", "url": "url", "port": "port", "scheme": "scheme",
                 "status_code": "status_code", "title": "title",
                 "webserver": "webserver", "tech": "tech", "cdn": "cdn",
                 "screenshot": "screenshot"},
        "search": ("host", "url", "title", "webserver", "tech"),
        "order": "host, url",
    },
    "coverage": {
        "table": "module_coverage",
        "cols": {"module": "module", "target": "target", "target_type": "target_type",
                 "status": "status", "run_seq": "run_seq", "step_index": "step_index",
                 "ts": "ts"},
        "search": ("module", "target", "target_type", "status"),
        "order": _COVERAGE_ORDER,
    },
}

# Above this many rows (post-q), skip the GROUP BY facet queries — on a
# multi-million-row table each facet column is a full scan, and the client just
# falls back to text boxes. Paging/counting stay fast regardless.
_FACET_MAX_ROWS = 200_000


def _view_select_list(spec):
    return ", ".join(f"{expr} AS {col}" for col, expr in spec["cols"].items())


def _token_predicate(expr, col, token):
    """(sql, params) matching _filter_token semantics for one enum token: bool
    cols -> yes/no (no includes NULL); '(none)' -> NULL/empty; else equality."""
    if col in _BOOL_FILTER_COLS:
        return (f"{expr}=1", []) if token == "yes" else (f"({expr}=0 OR {expr} IS NULL)", [])
    if token == "(none)":
        return (f"({expr} IS NULL OR {expr}='')", [])
    return (f"{expr}=?", [token])


def _build_view_where(spec, q, column_filters):
    """(where_sql, params) for the q substring + per-column filters. Columns are
    taken only from the spec (allowlist), so a name can never be injected."""
    clauses, params = [], []
    if q:
        ors = [f"{spec['cols'][c]} LIKE ?" for c in spec["search"]]
        if ors:
            clauses.append("(" + " OR ".join(ors) + ")")
            params.extend([f"%{q}%"] * len(ors))
    for col, filt in (column_filters or {}).items():
        if col not in spec["cols"]:
            continue
        expr = spec["cols"][col]
        if isinstance(filt, list):          # enum tokens, OR'd within the column
            ors, oparams = [], []
            for tok in filt:
                p, pp = _token_predicate(expr, col, tok)
                ors.append(p)
                oparams.extend(pp)
            if ors:
                clauses.append("(" + " OR ".join(ors) + ")")
                params.extend(oparams)
        elif filt:                          # substring needle
            clauses.append(f"{expr} LIKE ?")
            params.append(f"%{filt}%")
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    return where, params


def _query_view(conn, name, q=None, column_filters=None, sort=None,
                direction="asc", limit=None, offset=0):
    """Serve a generic table view from SQL -> (rows, total). Filter/sort/count
    run in the DB; only `limit` rows are materialized (limit=None -> all, for the
    CSV export). Unknown sort col falls back to the spec default order. A missing
    table (older scan.db) yields ([], 0) rather than an error."""
    spec = _VIEW_SPECS[name]
    where, params = _build_view_where(spec, q, column_filters)
    try:
        total = conn.execute(
            f"SELECT COUNT(*) FROM {spec['table']}{where}", params).fetchone()[0]
    except sqlite3.Error:
        return [], 0
    if sort and sort in spec["cols"]:
        order = f"{spec['cols'][sort]} {'DESC' if str(direction).lower() == 'desc' else 'ASC'}"
    else:
        order = spec["order"]
    sql = (f"SELECT {_view_select_list(spec)} FROM {spec['table']}"
           f"{where} ORDER BY {order}")
    qparams = list(params)
    if limit is not None and limit > 0:
        sql += " LIMIT ? OFFSET ?"
        qparams += [limit, max(0, offset)]
    try:
        rows = [dict(r) for r in conn.execute(sql, qparams)]
    except sqlite3.Error:
        return [], total
    return rows, total


def _view_facets_sql(conn, name, q, total):
    """Facet option lists via GROUP BY (q-filtered but NOT column-filtered, so the
    options stay stable while the user toggles boxes). Mirrors _facets' tokens,
    cap and ordering; skipped above _FACET_MAX_ROWS so a huge table never pays N
    full scans."""
    spec = _VIEW_SPECS[name]
    if total > _FACET_MAX_ROWS:
        return {}
    where, params = _build_view_where(spec, q, None)
    out = {}
    for col, expr in spec["cols"].items():
        if col not in _ENUM_FILTER_COLS:
            continue
        vals, overflow = set(), False
        try:
            for (raw,) in conn.execute(
                    f"SELECT {expr} AS v FROM {spec['table']}{where} GROUP BY v", params):
                vals.add(_filter_token(col, raw))
                if len(vals) > _ENUM_MAX_OPTIONS:
                    overflow = True
                    break
        except sqlite3.Error:
            continue
        if not vals or overflow:
            continue
        if col == "severity":
            out[col] = sorted(vals, key=_sev_rank)
        elif col in _NUMERIC_SORT_COLS:
            out[col] = sorted(vals, key=lambda v: (v == "(none)",
                                                   int(v) if v.isdigit() else 1 << 62, v))
        else:
            out[col] = sorted(vals)
    return out


# Thin list-returning wrappers over _query_view, preserving the (conn, q) ->
# [rows] contract the API result endpoints call by name. The webserver's own
# /api/view path calls _query_view directly for true SQL pagination.
def _query_ports(conn, q=None) -> list[dict]:
    return _query_view(conn, "ports", q)[0]


def _query_web_dirs(conn, q=None) -> list[dict]:
    return _query_view(conn, "webdirs", q)[0]


def _query_targets(conn, q=None) -> list[dict]:
    return _query_view(conn, "targets", q)[0]


def _query_web(conn, q=None) -> list[dict]:
    return _query_view(conn, "web", q)[0]


def _query_coverage(conn, q=None) -> list[dict]:
    return _query_view(conn, "coverage", q)[0]


# The table name is interpolated into SQL (SQLite can't bind an identifier), so
# it must never come from user input. All call sites pass a literal; this
# allowlist enforces that invariant so a future call site can't turn it into an
# injection vector.
_COUNTABLE_TABLES = frozenset({
    "findings", "validations", "targets", "target_parents", "ports",
    "web_endpoints", "web_dirs", "mx_domains", "progress_events",
    "module_runs", "module_coverage", "meta",
})


def _table_count(conn, table: str) -> int:
    """COUNT(*) for a table, or 0 if it doesn't exist (older scan.db opened
    read-only can't have the DDL applied, so a new table may be absent)."""
    if table not in _COUNTABLE_TABLES:
        raise ValueError(f"_table_count: table not in allowlist: {table!r}")
    try:
        return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
    except Exception:
        return 0


def _coverage_gap_count(conn) -> int:
    """Count of 'no_response' coverage rows (fed but absent from output).

    This is the actionable "maybe missed" gap surfaced as the nav badge. Returns
    0 if the table doesn't exist yet (pre-v6 scan.db)."""
    try:
        return conn.execute(
            "SELECT COUNT(*) FROM module_coverage WHERE status='no_response'"
        ).fetchone()[0]
    except Exception:
        return 0


def _query_screenshots(conn, q=None) -> list[dict]:
    """Screenshots grouped by visual similarity, most valuable group first.

    Joins gowitness visual findings (tool='gowitness', minted by
    ai_analyze_gowitness) to the endpoint's screenshot path via matched_at=url.
    Falls back to ALL captured screenshots (endpoints with a screenshot but no
    AI finding), so the gallery is useful even without ai_analyze_gowitness.

    Ordering is value-first, then similar: screenshots are grouped by gowitness's
    perceptual-hash group (``phash_group``) so visually-identical pages sit
    together; groups are ordered by their best AI severity (analyzed groups
    lead), then by group size (largest visual clusters first). When
    ai_analyze_gowitness has NOT run, every group has no severity so this
    degrades to pure similarity grouping — gowitness's built-in behaviour.
    ``q`` filters host/title/category/url."""
    analyzed = [dict(r) for r in conn.execute(
        "SELECT f.host, f.port, f.severity, f.title, f.claim, f.detail, "
        "f.matched_at AS url, w.screenshot, w.phash_group "
        "FROM findings f LEFT JOIN web_endpoints w ON w.url = f.matched_at "
        "WHERE f.tool = 'gowitness'")]
    for r in analyzed:
        r["category"] = (r.pop("claim", "") or "").replace("gowitness:", "")
        r["analyzed"] = 1
    seen = {r["url"] for r in analyzed if r.get("url")}
    extra = [dict(r) for r in conn.execute(
        "SELECT host, port, title, url, screenshot, phash_group "
        "FROM web_endpoints WHERE screenshot IS NOT NULL AND screenshot != ''")]
    for r in extra:
        if r.get("url") in seen:
            continue
        r.update(severity=None, category="", detail="", analyzed=0)
        analyzed.append(r)

    # Group by perceptual-hash similarity; rows without a group id are their own
    # singleton group (keyed by url) so they are never merged with unrelated pages.
    def _gkey(r):
        pg = r.get("phash_group")
        return ("p", pg) if pg is not None else ("u", r.get("url"))

    members = defaultdict(list)
    for r in analyzed:
        members[_gkey(r)].append(r)
    group_size = {}
    for k, ms in members.items():
        group_size[k] = len(ms)
        for m in ms:
            m["sim_count"] = len(ms)  # >1 means part of a visual-similarity cluster

    # Two-tier order (row-level, NOT cluster-first):
    #   Tier 0 — every analyzed (finding-bearing) screenshot, ALL together and
    #            ranked by its OWN severity (critical first); visually-identical
    #            findings sit adjacent via their phash group.
    #   Tier 1 — the rest, perception-grouped by phash (largest cluster first).
    # A cluster-first key (the previous behaviour) kept each phash cluster
    # contiguous, so a finding's non-finding visual siblings — and any larger
    # cluster — rendered BETWEEN two critical findings. Splitting the tier at the
    # row level keeps all findings up front and pushes non-finding siblings into
    # the perception-sorted remainder.
    def _row_key(r):
        k = _gkey(r)
        if r.get("analyzed"):
            return (0, _sev_rank(r.get("severity")), str(k),
                    r.get("host") or "", r.get("url") or "")
        return (1, -group_size[k], str(k),
                r.get("host") or "", r.get("url") or "")

    analyzed.sort(key=_row_key)
    return _substr_filter(analyzed, q, ("host", "title", "category", "url"))


def _substr_filter(rows, q, fields):
    if not q:
        return rows
    ql = q.lower()
    return [r for r in rows if any(
        ql in str(r.get(f) or "").lower() for f in fields)]


# Categorical columns that render as a checkbox facet (exact-match, multi-select)
# instead of a free-text substring box. These have a small, bounded set of
# values (severity, verdict, scope, …); high-cardinality columns (title, host,
# target, url, cve_id, …) are deliberately absent and keep the text box.
_ENUM_FILTER_COLS = frozenset(
    {"severity", "verdict", "proto", "state", "scope", "in_scope",
     "scope_class", "target_type", "status", "scheme", "cdn",
     "false_positive", "tool", "source",
     # These render as checkbox facets where the value set is small: port + service
     # /product/version (Ports), status_code/webserver (Web), module/run_seq/
     # step_index (Coverage). The _ENUM_MAX_OPTIONS cap falls a high-cardinality
     # column back to a text box, so host/banner/url/title stay text (not listed).
     "port", "service", "product", "version",
     "status_code", "webserver",
     "module", "run_seq", "step_index"})

# Columns stored as 0/1 in the DB but shown as yes/no — their filter token is
# the yes/no label, so the checkbox matches what the table renders.
_BOOL_FILTER_COLS = frozenset({"in_scope", "cdn", "false_positive"})

# Safety cap: an enum column with more distinct values than this in the current
# data falls back to a text box (never a checkbox list a mile long).
_ENUM_MAX_OPTIONS = 50


def _filter_token(col, val):
    """The canonical string a value filters/facets as — matches what the table
    shows, so a checkbox labelled 'yes'/'confirmed'/'(none)' selects the right
    rows. Bool columns → yes/no; empty/NULL → '(none)'; else str(val)."""
    if col in _BOOL_FILTER_COLS:
        return "yes" if val else "no"
    s = "" if val is None else str(val)
    return s if s != "" else "(none)"


def _column_filters(request, allowed):
    """Per-column filters, two channels merged into one ``{col: spec}`` dict:

    - ``f.<col>=text``  → substring needle (str spec). Single value, last wins.
    - ``fe.<col>=token`` → exact enum token (list spec). Repeatable; multiple
      values on one column are OR'd. This is the checkbox-facet channel.

    Only columns in ``allowed`` are honored (a stray/unknown param can never
    widen the query). Blank ``f.`` values are dropped; blank ``fe.`` values are
    ignored (the '(none)' option sends the literal token '(none)'). If both
    channels name the same column, the enum selection wins."""
    out = {}
    for k, v in request.query_params.multi_items():
        if k.startswith("fe.") and v != "":
            col = k[3:]
            if col in allowed:
                cur = out.get(col)
                if not isinstance(cur, list):
                    cur = out[col] = []
                cur.append(v)
        elif k.startswith("f.") and v:
            col = k[2:]
            if col in allowed and not isinstance(out.get(col), list):
                out[col] = v
    return out


def _apply_column_filters(rows, filters):
    """AND-combine per-column filters (narrowing, like stacking spreadsheet
    filters). A list spec is an enum selection: the row's canonical token must
    be one of the selected values (OR within the column). A str spec is a
    case-insensitive substring needle."""
    if not filters:
        return rows

    def _ok(r):
        for c, spec in filters.items():
            if isinstance(spec, list):
                if _filter_token(c, r.get(c)) not in spec:
                    return False
            elif spec.lower() not in str(r.get(c) or "").lower():
                return False
        return True

    return [r for r in rows if _ok(r)]


def _facets(rows, columns):
    """Distinct values for each enum column present in ``columns`` — the option
    list the client renders as checkboxes. Computed over the (q-filtered but not
    column-filtered) rows so the options stay stable while the user checks and
    unchecks boxes. A column with more than ``_ENUM_MAX_OPTIONS`` distinct values
    is dropped (client falls back to a text box)."""
    out = {}
    for c in columns:
        if c not in _ENUM_FILTER_COLS:
            continue
        vals = set()
        overflow = False
        for r in rows:
            vals.add(_filter_token(c, r.get(c)))
            if len(vals) > _ENUM_MAX_OPTIONS:
                overflow = True
                break
        if vals and not overflow:
            if c == "severity":
                out[c] = sorted(vals, key=_sev_rank)
            elif c in _NUMERIC_SORT_COLS:
                # Numeric columns (port, status_code, run_seq, step_index, …) sort
                # by value, not lexicographically ("2" before "10"); "(none)" last.
                out[c] = sorted(vals, key=lambda v: (v == "(none)",
                                                     int(v) if v.isdigit() else 1 << 62, v))
            else:
                out[c] = sorted(vals)
    return out


# Findings expose a richer endpoint than the generic views; these are the
# columns a per-column filter may target (matches the on-screen table plus the
# searchable body fields), guarding _column_filters against arbitrary keys.
_FINDINGS_FILTER_COLS = frozenset(
    {"host", "port", "proto", "tool", "severity", "title", "verdict",
     "cve_id", "claim", "matched_at"})


_NUMERIC_SORT_COLS = frozenset(
    {"rank", "port", "status_code", "run_seq", "step_index", "size", "words"})


def _sort_rows(rows, col, direction):
    """Sort rows by a column, mirroring the old client-side sort semantics.

    severity -> severity rank; numeric cols -> numeric (None last); else
    case-insensitive string. Unknown/absent column -> rows unchanged (keeps the
    query fn's default order). direction: 'desc' reverses.
    """
    if not col or not rows:
        return rows
    if col not in rows[0]:
        return rows
    rev = str(direction).lower() == "desc"
    if col == "severity":
        return sorted(rows, key=lambda r: _sev_rank(r.get("severity")), reverse=rev)
    if col in _NUMERIC_SORT_COLS:
        return sorted(rows, key=lambda r: (r.get(col) is None,
                                           r.get(col) if r.get(col) is not None else 0),
                      reverse=rev)
    return sorted(rows, key=lambda r: str(r.get(col) if r.get(col) is not None else "").lower(),
                  reverse=rev)


def _paginate(rows, page, size):
    """Return (page_slice, total). size<=0 means 'all' (CSV/export path)."""
    total = len(rows)
    if not size or size <= 0:
        return rows, total
    start = max(0, page) * size
    return rows[start:start + size], total


# View registry for the in-Python views (currently just `focus`, a join + custom
# rank that isn't a single-table projection). The generic single-table views are
# served from SQL via _VIEW_SPECS above; both carry a column list that is BOTH
# the CSV header/order AND what the client renders — one source of truth so the
# table, sort, and export never drift. Findings keep their own richer endpoint.
_VIEWS = {
    "focus":   (_query_focus,   ("rank", "host", "port", "severity", "verdict",
                                 "title", "cve_id", "poc_command", "tool")),
}


def _duration_s(started, finished):
    """Wall-clock seconds between two ISO timestamps, or None if unparseable."""
    if not started or not finished:
        return None
    try:
        d = (datetime.fromisoformat(finished)
             - datetime.fromisoformat(started)).total_seconds()
    except (ValueError, TypeError):
        return None
    return d if d >= 0 else None


def _step_progress(conn) -> dict:
    """Build a per-step progress view with PER-RUN history.

    progress_events accumulates across --continue/--resume, so the live bar
    ("step 4/11 running") shows only the latest run (max run_seq). But a project
    can have many runs, and a tester needs visibility into the earlier ones too —
    so we also return a `runs` list (newest first), each a full per-run summary
    (status/done/total/failed/timing + its step list). Returns:
      {run_seq, runs_count, total, done, current, steps,
       runs: [{run_seq, status, total, done, failed, started_at, finished_at,
               duration_s, steps}], cumulative: {done, runs}}
    where the top-level total/done/current/steps describe the CURRENT run (for
    the live bar, back-compat), and `runs` carries the history. Older events with
    no run_seq (pre-v3 DBs) are treated as run 1.
    """
    rows = list(conn.execute(
        "SELECT event, step, idx, total_steps, run_seq, started_at, finished_at, raw "
        "FROM progress_events ORDER BY id"))

    def _seq(r):
        return r["run_seq"] if r["run_seq"] is not None else 1

    run_seqs = sorted({_seq(r) for r in rows})
    runs_count = len(run_seqs)
    current_seq = run_seqs[-1] if run_seqs else 0

    # Cumulative: distinct completed/failed steps across all runs (by run+idx).
    cum_done = len({(_seq(r), r["idx"]) for r in rows
                    if r["event"] in ("step_completed", "step_failed")
                    and r["idx"] is not None})

    def _build_run(seq):
        steps, order, total = {}, [], 0
        started_at, finished_at = None, None
        plan_names = None  # ordered module names from the run_planned event, if any
        for r in rows:
            if _seq(r) != seq:
                continue
            if r["total_steps"]:
                total = max(total, r["total_steps"])
            if r["event"] == "run_planned":
                if plan_names is None and r["raw"]:
                    try:
                        payload = json.loads(r["raw"])
                        plan_names = [p.get("name") for p in payload.get("steps", [])
                                      if isinstance(p, dict) and p.get("name")]
                    except (ValueError, TypeError):
                        plan_names = None
                continue
            if r["started_at"] and (started_at is None or r["started_at"] < started_at):
                started_at = r["started_at"]
            if r["finished_at"] and (finished_at is None or r["finished_at"] > finished_at):
                finished_at = r["finished_at"]
            idx, step, event = r["idx"], r["step"], r["event"]
            if step is None or idx is None:
                continue  # parallel_group_* / scan_* events have no single step
            if idx not in steps:
                steps[idx] = {"idx": idx, "module": step, "status": "pending"}
                order.append(idx)
            if event == "step_started":
                steps[idx]["status"] = "running"
            elif event == "step_completed":
                steps[idx]["status"] = "completed"
            elif event == "step_failed":
                steps[idx]["status"] = "failed"
            steps[idx]["module"] = step
        ordered = [steps[i] for i in sorted(order)]
        # Append planned modules that haven't started yet (queued), in plan order.
        # Match by name against what's already run so duplicates are consumed once.
        if plan_names:
            started = Counter(s["module"] for s in ordered)
            for name in plan_names:
                if started.get(name):
                    started[name] -= 1
                else:
                    ordered.append({"idx": None, "module": name, "status": "pending"})
        done = sum(1 for s in ordered if s["status"] in ("completed", "failed"))
        failed = sum(1 for s in ordered if s["status"] == "failed")
        running = any(s["status"] == "running" for s in ordered)
        eff_total = total or len([s for s in ordered if s["status"] != "pending"]) or len(ordered)
        if running:
            status = "running"
        elif eff_total and done >= eff_total:
            status = "completed_with_errors" if failed else "completed"
        elif done:
            status = "incomplete"  # paused/cancelled before finishing
        else:
            status = "pending"
        return {"run_seq": seq, "total": eff_total, "done": done,
                "failed": failed, "status": status,
                "started_at": started_at, "finished_at": finished_at,
                "duration_s": _duration_s(started_at, finished_at),
                "steps": ordered}

    runs = [_build_run(s) for s in run_seqs]
    cur = next((r for r in runs if r["run_seq"] == current_seq), None)
    ordered = cur["steps"] if cur else []
    current = next((s for s in ordered if s["status"] == "running"), None)
    if current is None:
        # Fall back to the last step that actually ran — never a queued/pending one.
        ran = [s for s in ordered if s["status"] != "pending"]
        current = ran[-1] if ran else (ordered[-1] if ordered else None)
    return {"run_seq": current_seq, "runs_count": runs_count,
            "total": cur["total"] if cur else 0, "done": cur["done"] if cur else 0,
            "current": current, "steps": ordered,
            "runs": list(reversed(runs)),  # newest first; runs[0] == current
            "cumulative": {"done": cum_done, "runs": runs_count}}


def serve(output_dir: str, host: str = "127.0.0.1", port: int = 8765) -> None:
    """Boot the live web view for ``output_dir`` and block until Ctrl+C."""
    output_dir = os.path.abspath(output_dir)
    if not os.path.isdir(output_dir):
        print(f"[!] Not a directory: {output_dir}")
        return
    if not os.path.exists(scan_db.db_path_for(output_dir)):
        print(f"[!] No scan.db found in {output_dir} — run a scan there first "
              f"(the DB is created at the output-dir root).")
        return

    try:
        import uvicorn
        from fastapi import FastAPI, Request, Response
        from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
    except ImportError as exc:  # pragma: no cover - deps ship in requirements.txt
        print(f"[!] Web server needs fastapi + uvicorn (in requirements.txt): {exc}")
        return

    app = FastAPI(title="MonkeyX Live View")
    run_name = os.path.basename(output_dir.rstrip("/")) or output_dir
    # run_name is a filesystem path component (operator-controlled). Escape it
    # before it lands in HTML, and reduce it to an ASCII filename-safe token
    # before it lands in a Content-Disposition header — never interpolate raw.
    run_name_html = html.escape(run_name)
    run_name_file = re.sub(r"[^A-Za-z0-9._-]", "_", run_name) or "monkeyx"

    @app.middleware("http")
    async def _security_headers(request, call_next):
        # Defense-in-depth: the server defaults to 127.0.0.1 but --webserver-host
        # can bind 0.0.0.0. The page is one inline HTML app (inline script/style)
        # that also frames report.html, so CSP must allow 'unsafe-inline' and
        # same-origin framing; images include data:/blob: (screenshots).
        # Catch handler exceptions so the headers are set even on a 500 (an
        # unhandled error escaping call_next would otherwise return a
        # header-less response); log it so nothing is silently swallowed.
        try:
            resp = await call_next(request)
        except Exception:
            logger.exception("Unhandled error serving %s", request.url.path)
            resp = JSONResponse({"detail": "Internal server error"}, status_code=500)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
        resp.headers.setdefault("Content-Security-Policy",
            "default-src 'self'; script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; "
            "frame-src 'self'")
        return resp

    @app.get("/", response_class=HTMLResponse)
    def index():
        return _PAGE.replace("__RUN_NAME__", run_name_html)

    @app.get("/api/status")
    def status():
        conn = _connect_ro(output_dir)
        if conn is None:
            return JSONResponse({"available": False})
        try:
            counts = {"targets": conn.execute(
                          "SELECT COUNT(*) FROM targets").fetchone()[0],
                      "ports": conn.execute(
                          "SELECT COUNT(*) FROM ports").fetchone()[0],
                      "findings": conn.execute(
                          "SELECT COUNT(*) FROM findings").fetchone()[0],
                      "web": conn.execute(
                          "SELECT COUNT(*) FROM web_endpoints").fetchone()[0],
                      "webdirs": _table_count(conn, "web_dirs"),
                      "screenshots": conn.execute(
                          "SELECT COUNT(*) FROM web_endpoints WHERE "
                          "screenshot IS NOT NULL AND screenshot != ''"
                          ).fetchone()[0],
                      # Focus filters to genuine findings (drops info-level
                      # script_output), so its count differs from the raw
                      # findings total — compute it the same way the view does.
                      "focus": len(_query_focus(conn)),
                      # Coverage badge = the actionable gap: targets fed but not
                      # seen in output (maybe-missed). 0 if table absent (pre-v6).
                      "coverage": _coverage_gap_count(conn)}
            by_severity = {}
            for r in conn.execute(
                    "SELECT severity, COUNT(*) c FROM findings GROUP BY severity"):
                by_severity[r["severity"] or "info"] = r["c"]
            progress = _step_progress(conn)
            return {"available": True, "run": run_name,
                    "progress": progress, "counts": counts,
                    "by_severity": by_severity}
        finally:
            if conn:
                conn.close()

    @app.get("/api/findings")
    def findings(request: Request, severity: Optional[str] = None,
                 verdict: Optional[str] = None,
                 no_info: int = 0, q: Optional[str] = None, page: int = 0,
                 size: int = 500, sort: str = "severity", dir: str = "asc",
                 ids_only: int = 0):
        """Findings, filtered + sorted + paginated SERVER-side (findings can be
        50k+ rows). Returns one page + `total` (filtered count) + `by_severity`
        (UNfiltered, so the chips always show grand totals).

        ids_only=1 returns just the finding_ids for the full filtered set (no row
        bodies) — the client uses it for cross-page "select all" without shipping
        every row. size<=0 -> all (unused by the client, handy for debugging)."""
        conn = _connect_ro(output_dir)
        if conn is None:
            return JSONResponse({"available": False, "findings": []})
        try:
            rows = _query_findings(conn, severity, verdict, no_info=bool(no_info))
            if q:
                rows = _substr_filter(rows, q,
                                      ("host", "title", "cve_id", "tool", "claim"))
            # Checkbox-facet options for the low-cardinality filter columns —
            # computed over the q-filtered but NOT column-filtered rows so the
            # option list stays stable as the user checks/unchecks boxes (same
            # contract as the generic views).
            facets = _facets(rows, ("severity", "port", "tool", "verdict"))
            rows = _apply_column_filters(
                rows, _column_filters(request, _FINDINGS_FILTER_COLS))
            if sort:
                rows = _sort_rows(rows, sort, dir)
            if ids_only:
                return {"available": True, "total": len(rows),
                        "ids": [r["finding_id"] for r in rows]}
            by_sev = {}
            for r in conn.execute(
                    "SELECT severity, COUNT(*) c FROM findings GROUP BY severity"):
                by_sev[r["severity"] or "info"] = r["c"]
            size = max(1, min(size, _MAX_PAGE_SIZE))  # JSON is paged; cap the payload
            page_rows, total = _paginate(rows, page, size)
            return {"available": True, "total": total, "by_severity": by_sev,
                    "facets": facets,
                    "page": max(0, page), "size": size, "findings": page_rows}
        finally:
            if conn:
                conn.close()

    @app.get("/api/findings.csv")
    def findings_csv(request: Request, severity: Optional[str] = None,
                     verdict: Optional[str] = None,
                     no_info: int = 0, ids: Optional[str] = None, q: Optional[str] = None):
        """Stream findings as CSV. If ``ids`` (comma-separated finding_ids) is
        given, export exactly those; otherwise export the current filter set
        (severity + no_info + ``q`` search + ``f.<col>`` per-column filters
        applied server-side, matching the on-screen view). Cells are neutralized
        against spreadsheet formula injection."""
        conn = _connect_ro(output_dir)
        try:
            rows = _query_findings(conn, severity, verdict, no_info=bool(no_info)) if conn else []
        finally:
            if conn:
                conn.close()
        if ids:
            wanted = {i for i in ids.split(",") if i}
            rows = [r for r in rows if r["finding_id"] in wanted]
        else:
            if q:
                rows = _substr_filter(rows, q,
                                      ("host", "title", "cve_id", "tool", "claim"))
            rows = _apply_column_filters(
                rows, _column_filters(request, _FINDINGS_FILTER_COLS))

        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(_CSV_COLUMNS)
        for r in rows:
            w.writerow([_csv_safe(r.get(c)) for c in _CSV_COLUMNS])
        return Response(
            content=buf.getvalue(), media_type="text/csv",
            headers={"Content-Disposition":
                     f'attachment; filename="{run_name_file}-findings.csv"'})

    # NOTE: register the .csv route BEFORE the generic one — Starlette matches in
    # definition order, and `/api/view/{name}` would otherwise greedily capture
    # `name="ports.csv"` (path params match dots), shadowing the CSV handler.
    @app.get("/api/view/{name}.csv")
    def view_csv(request: Request, name: str, q: Optional[str] = None):
        """Stream a data view as CSV (same columns/order as /api/view/{name}),
        formula-injection-neutralized. ``q`` applies the same substring filter,
        and ``f.<col>`` params apply the same per-column filters as the on-screen
        table, so the export matches exactly what the user is looking at."""
        if name in _VIEW_SPECS:
            columns = list(_VIEW_SPECS[name]["cols"].keys())
            conn = _connect_ro(output_dir)
            try:
                if conn is None:
                    rows = []
                else:
                    cf = _column_filters(request, set(columns))
                    rows, _ = _query_view(conn, name, q, cf, limit=None)  # export: all rows
            finally:
                if conn:
                    conn.close()
        elif name in _VIEWS:
            query_fn, columns = _VIEWS[name]
            columns = list(columns)
            conn = _connect_ro(output_dir)
            try:
                rows = query_fn(conn, q) if conn else []
            finally:
                if conn:
                    conn.close()
            rows = _apply_column_filters(rows, _column_filters(request, columns))
        else:
            return Response(content="unknown view\n", media_type="text/csv",
                            status_code=404)
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(columns)
        for r in rows:
            w.writerow([_csv_safe(r.get(c)) for c in columns])
        return Response(
            content=buf.getvalue(), media_type="text/csv",
            headers={"Content-Disposition":
                     f'attachment; filename="{run_name_file}-{name}.csv"'})

    @app.get("/api/view/{name}")
    def view(request: Request, name: str, q: Optional[str] = None, page: int = 0,
             size: int = 500, sort: Optional[str] = None, dir: str = "asc"):
        """Generic data view (focus/ports/targets/web/coverage).

        Filter (q + per-column) + sort + pagination run in SQL for the generic
        table views, so a request only ever materializes one page — coverage /
        web_dirs can be millions of rows and shipping or even loading them all
        would spike server memory. Returns the page plus `total` (full filtered
        count) so the client can render a pager. focus (a join + custom rank)
        stays on the in-Python path; it's bounded (non-info findings)."""
        size = max(1, min(size, _MAX_PAGE_SIZE))  # JSON is paged; cap the payload
        page = max(0, page)
        if name in _VIEW_SPECS:
            columns = list(_VIEW_SPECS[name]["cols"].keys())
            conn = _connect_ro(output_dir)
            if conn is None:
                return JSONResponse({"available": False, "rows": [], "columns": columns,
                                     "total": 0, "page": 0, "size": size, "facets": {}})
            try:
                cf = _column_filters(request, set(columns))
                rows, total = _query_view(conn, name, q, cf, sort, dir,
                                          limit=size, offset=page * size)
                facets = _view_facets_sql(conn, name, q, total)
                return {"available": True, "view": name, "columns": columns,
                        "total": total, "page": page, "size": size,
                        "facets": facets, "rows": rows}
            finally:
                conn.close()
        if name not in _VIEWS:
            return JSONResponse({"available": False, "error": "unknown view"},
                                status_code=404)
        query_fn, columns = _VIEWS[name]
        conn = _connect_ro(output_dir)
        if conn is None:
            return JSONResponse({"available": False, "rows": [], "columns": columns,
                                 "total": 0, "page": 0, "size": size})
        try:
            rows = query_fn(conn, q)
            facets = _facets(rows, columns)
            rows = _apply_column_filters(rows, _column_filters(request, columns))
            if sort:
                rows = _sort_rows(rows, sort, dir)
            page_rows, total = _paginate(rows, page, size)
            return {"available": True, "view": name, "columns": list(columns),
                    "total": total, "page": page, "size": size,
                    "facets": facets, "rows": page_rows}
        finally:
            if conn:
                conn.close()

    @app.get("/api/screenshots")
    def screenshots(q: Optional[str] = None):
        """Gallery of gowitness screenshots, AI-analyzed (severity-ranked) first,
        then any remaining captures. Each row carries a `screenshot` path the
        client renders via /screenshot?path=..."""
        conn = _connect_ro(output_dir)
        if conn is None:
            return JSONResponse({"available": False, "rows": []})
        try:
            rows = _query_screenshots(conn, q)
            return {"available": True, "total": len(rows), "rows": rows}
        finally:
            if conn:
                conn.close()

    @app.get("/screenshot")
    def screenshot(path: str):
        """Serve a screenshot image by its output-dir-relative path.

        Path-traversal safe: the requested path is resolved and confirmed to sit
        UNDER output_dir before serving, and only image extensions are allowed."""
        # Reject traversal on normalized path *components* (catches "a/../.." that
        # a bare substring check on the pre-normalized string could miss); the
        # realpath+commonpath containment below is the authoritative backstop.
        if (not path or path.startswith(("/", "\\"))
                or ".." in os.path.normpath(path).split(os.sep)):
            return Response(status_code=400)
        if os.path.splitext(path)[1].lower() not in (".jpg", ".jpeg", ".png",
                                                     ".webp", ".gif"):
            return Response(status_code=400)
        # realpath (not abspath) so a symlink *inside* output_dir that points
        # outside it can't be used to exfiltrate arbitrary files — abspath only
        # normalizes '..'/'.' lexically and would follow such a symlink.
        abs_path = os.path.realpath(os.path.join(output_dir, path))
        root = os.path.realpath(output_dir)
        if os.path.commonpath([abs_path, root]) != root:
            return Response(status_code=403)
        if not os.path.isfile(abs_path):
            return Response(status_code=404)
        return FileResponse(abs_path)

    # ---- Report --------------------------------------------------------------
    @app.get("/report")
    def report():
        """Serve the consolidated report.html inline — the whole Report view.
        Resolved server-side so it needs NO modules/ import; this is what makes
        the Report view work in the bundled standalone viewer."""
        for cand in (os.path.join(output_dir, "reports", "report.html"),
                     os.path.join(output_dir, "report.html")):
            if os.path.isfile(cand):
                return FileResponse(cand, media_type="text/html")
        return HTMLResponse(
            "<body style='font-family:-apple-system,sans-serif;color:#7a8da0;"
            "background:#0a0e14;padding:40px;line-height:1.6'>No <code>report.html"
            "</code> for this run yet — it's written once <code>normalize</code> / "
            "<code>analyze</code> have run.</body>", status_code=404)

    print(f"\n[+] MonkeyX live view for '{run_name}'")
    print(f"    http://{host}:{port}")
    if host == "127.0.0.1":
        print("    (localhost only — tunnel with: ssh -L "
              f"{port}:127.0.0.1:{port} <host>)")
    print("    Ctrl+C to stop.\n")
    if host not in ("127.0.0.1", "::1", "localhost"):
        logger.warning(
            "webserver bound to %s (not loopback): this server has NO "
            "authentication and exposes all scan data + the report to the "
            "network. Prefer 127.0.0.1 + an SSH tunnel.", host)
    uvicorn.run(app, host=host, port=port, log_level="warning")


# One self-contained page: inline CSS + JS, polls the JSON endpoints. No build
# step, no external assets. Styled to match the report.html palette. Layout is a
# fixed sidebar (nav + live status) + a main area that swaps between views:
# Overview (dashboard), Focus, Findings (rich), and generic tables for Ports,
# Targets, Web driven by the columns each /api/view endpoint returns.
_PAGE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>MonkeyX — __RUN_NAME__</title>
<style>
:root{--bg:#0a0e14;--surface:#12171f;--border:#2a3545;--text:#e6edf3;
--muted:#7a8da0;--accent:#ff6b35;--critical:#ff4757;--high:#ff7b3a;
--medium:#ffa82e;--low:#7a8da0;--info:#4dabf7;--sidebar:#0d1220;}
*{box-sizing:border-box;margin:0;padding:0;}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif;
background:var(--bg);color:var(--text);line-height:1.5;}
.layout{display:flex;min-height:100vh;}
/* sidebar */
.sidebar{width:220px;flex:0 0 220px;background:var(--sidebar);
border-right:1px solid var(--border);padding:20px 0;position:sticky;top:0;
height:100vh;overflow-y:auto;}
.sidebar h1{font-size:17px;color:var(--accent);padding:0 20px;margin-bottom:2px;}
.sidebar .run{font-size:11px;color:var(--muted);padding:0 20px;
word-break:break-all;margin-bottom:14px;}
.sidebar .live{padding:0 20px;font-size:11px;color:var(--muted);margin-bottom:18px;}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:#3fb950;
margin-right:6px;animation:pulse 1.5s infinite;}
.dot.off{background:var(--critical);animation:none;}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}
nav a{display:flex;justify-content:space-between;align-items:center;gap:8px;
padding:9px 20px;color:var(--muted);cursor:pointer;font-size:14px;
border-left:3px solid transparent;text-decoration:none;}
nav a:hover{color:var(--text);background:var(--surface);}
nav a.active{color:var(--accent);border-left-color:var(--accent);background:var(--surface);}
nav a .badge-n{font-size:11px;background:var(--surface);border:1px solid var(--border);
border-radius:10px;padding:0 7px;color:var(--muted);min-width:22px;text-align:center;
white-space:nowrap;flex:none;}
nav a.active .badge-n{border-color:var(--accent);color:var(--accent);}
/* main */
.main{flex:1;padding:26px 30px;min-width:0;}
.view-title{font-size:18px;margin-bottom:2px;}
.view-sub{color:var(--muted);font-size:12px;margin-bottom:18px;}
.hidden{display:none;}
.cards{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:22px;}
.card{background:var(--surface);border:1px solid var(--border);border-radius:8px;
padding:12px 18px;min-width:120px;}
.card .n{font-size:24px;font-weight:700;}
.card .l{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:1px;}
.card.click{cursor:pointer;}.card.click:hover{border-color:var(--accent);}
/* severity breakdown (excludes info) */
.sevchart{background:var(--surface);border:1px solid var(--border);border-radius:8px;
padding:14px 16px;margin-bottom:22px;}
.sevchart .hd{font-size:11px;color:var(--muted);text-transform:uppercase;
letter-spacing:1px;margin-bottom:10px;}
.sevbar{display:flex;height:16px;border-radius:4px;overflow:hidden;gap:2px;background:var(--bg);}
.sevbar .seg{height:100%;}
.sevbar .seg.critical{background:var(--critical);}.sevbar .seg.high{background:var(--high);}
.sevbar .seg.medium{background:var(--medium);}.sevbar .seg.low{background:var(--low);}
.sevlegend{display:flex;flex-wrap:wrap;gap:14px;margin-top:12px;font-size:12px;}
.sevlegend .it{display:flex;align-items:center;gap:6px;color:var(--muted);}
.sevlegend .sw{width:10px;height:10px;border-radius:2px;flex:none;}
.sevlegend .sw.critical{background:var(--critical);}.sevlegend .sw.high{background:var(--high);}
.sevlegend .sw.medium{background:var(--medium);}.sevlegend .sw.low{background:var(--low);}
.sevlegend b{color:var(--text);}
.sevchart .empty{color:var(--muted);font-size:12px;}
.status{background:var(--surface);border:1px solid var(--border);border-radius:8px;
padding:12px 16px;margin-bottom:22px;font-size:13px;color:var(--muted);}
.status b{color:var(--text);}
.bar{height:6px;background:var(--border);border-radius:3px;overflow:hidden;margin-bottom:8px;}
.bar .fill{height:100%;background:var(--accent);transition:width .4s;}
.barlabel{font-size:13px;color:var(--text);}
.cum{font-size:11px;color:var(--muted);margin-top:3px;}
.run{color:var(--accent);}
.steps{display:flex;flex-wrap:wrap;gap:6px;}
.step{font-size:11px;padding:3px 8px;border-radius:5px;border:1px solid var(--border);
background:var(--surface);color:var(--muted);}
.step.s-done{color:#3fb950;border-color:#243b2a;}
.step.s-fail{color:var(--critical);border-color:#3b2427;}
.step.s-run{color:var(--accent);border-color:var(--accent);}
.step.s-pend{opacity:.6;}
/* previous-run history (Overview accordion) */
.runs{margin-top:14px;display:flex;flex-direction:column;gap:6px;}
.runs-hd{font-size:11px;text-transform:uppercase;letter-spacing:1px;color:var(--muted);
margin-top:4px;}
.runbox{border:1px solid var(--border);border-radius:6px;background:var(--surface);}
.run-hd{padding:8px 12px;font-size:12px;color:var(--muted);cursor:pointer;user-select:none;}
.run-hd:hover{color:var(--text);}
.run-hd .caret{color:var(--muted);margin-right:4px;}
.run-st{font-weight:600;}
.run-st.st-completed{color:#3fb950;}
.run-st.st-completed_with_errors{color:var(--medium);}
.run-st.st-running{color:var(--accent);}
.run-st.st-incomplete,.run-st.st-pending{color:var(--muted);}
.run-steps{padding:0 12px 12px;}
.filters{margin-bottom:12px;}
.filters button{background:var(--surface);color:var(--muted);border:1px solid var(--border);
border-radius:6px;padding:5px 12px;margin-right:6px;cursor:pointer;font-size:12px;}
.filters button.active{color:var(--accent);border-color:var(--accent);}
table{width:100%;border-collapse:collapse;font-size:13px;}
th,td{padding:7px 10px;border-bottom:1px solid var(--border);text-align:left;
vertical-align:top;}
th{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.5px;}
tr:hover td{background:var(--surface);}
.badge{display:inline-block;padding:1px 7px;border-radius:4px;font-size:10px;
font-weight:700;text-transform:uppercase;}
.critical{background:var(--critical);color:#fff;}.high{background:var(--high);color:#fff;}
.medium{background:var(--medium);color:#000;}.low{background:var(--low);color:#000;}
.info{background:#243040;color:var(--info);}
.v-confirmed{color:#3fb950;font-weight:600;}.v-refuted{color:var(--muted);}
.v-unclear{color:var(--medium);}.v-unverified{color:var(--muted);}
.cov{display:inline-block;padding:1px 7px;border-radius:4px;font-size:10px;
font-weight:700;text-transform:uppercase;}
.cov-reached{background:#243040;color:#3fb950;}
.cov-no_response{background:var(--medium);color:#000;}
.cov-step_failed{background:var(--high);color:#fff;}
.cov-fed{background:var(--surface);color:var(--muted);}
.cov-host-full{background:#3a2a12;color:#e0a458;}
.cov-name-safe{background:#243040;color:#58a6ff;}
.cov-lead{background:var(--surface);color:var(--muted);}
.yes{color:#3fb950;}.no{color:var(--muted);}
.mono{font-family:"SF Mono",Consolas,monospace;font-size:12px;}
.empty{color:var(--muted);padding:30px;text-align:center;}
.toolbar{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:10px;}
.search{background:var(--surface);color:var(--text);border:1px solid var(--border);
border-radius:6px;padding:6px 10px;font-size:13px;min-width:280px;}
.search:focus{outline:none;border-color:var(--accent);}
.count{color:var(--muted);font-size:12px;}
.pager{display:flex;align-items:center;gap:10px;margin-top:12px;font-size:12px;
color:var(--muted);}
.pager button{background:var(--surface);color:var(--text);border:1px solid var(--border);
border-radius:6px;padding:4px 12px;cursor:pointer;font-size:12px;}
.pager button:hover:not(:disabled){border-color:var(--accent);color:var(--accent);}
.pager button:disabled{opacity:.4;cursor:default;}
.pager .pinfo{min-width:120px;text-align:center;}
.btn{background:var(--surface);color:var(--text);border:1px solid var(--border);
border-radius:6px;padding:6px 12px;cursor:pointer;font-size:12px;}
.btn:hover{border-color:var(--accent);color:var(--accent);}
th.sortable{cursor:pointer;user-select:none;white-space:nowrap;}
th.sortable:hover{color:var(--text);}
th .arrow{color:var(--accent);}
/* per-column filter row: sits under the sortable headers */
tr.filterrow th{padding:4px 6px 8px;border-bottom:1px solid var(--border);}
tr.filterrow:hover th{background:transparent;}
input.colf{width:100%;box-sizing:border-box;background:var(--bg);color:var(--text);
border:1px solid var(--border);border-radius:4px;padding:3px 6px;font-size:11px;
text-transform:none;letter-spacing:normal;font-weight:400;}
input.colf:focus{outline:none;border-color:var(--accent);}
input.colf::placeholder{color:var(--muted);opacity:.7;}
/* checkbox facet: a compact dropdown for low-cardinality columns */
details.facet{position:relative;font-weight:400;text-transform:none;letter-spacing:normal;}
details.facet>summary{list-style:none;cursor:pointer;background:var(--bg);
color:var(--text);border:1px solid var(--border);border-radius:4px;
padding:3px 18px 3px 6px;font-size:11px;white-space:nowrap;overflow:hidden;
text-overflow:ellipsis;position:relative;}
details.facet>summary::-webkit-details-marker{display:none;}
details.facet>summary::after{content:"▾";position:absolute;right:5px;color:var(--muted);}
details.facet[open]>summary{border-color:var(--accent);}
details.facet>summary.on{border-color:var(--accent);color:var(--accent);}
.facetbox{position:absolute;z-index:20;top:calc(100% + 2px);left:0;min-width:100%;
max-height:240px;overflow:auto;background:var(--panel,#161b22);
border:1px solid var(--border);border-radius:6px;padding:4px;
box-shadow:0 6px 20px rgba(0,0,0,.4);}
.facetbox label{display:flex;align-items:center;gap:6px;padding:3px 6px;
font-size:11px;white-space:nowrap;cursor:pointer;border-radius:4px;color:var(--text);}
.facetbox label:hover{background:var(--bg);}
.facetbox input{margin:0;cursor:pointer;}
.facetbox .facetclear{display:block;width:100%;text-align:left;background:none;
border:none;border-top:1px solid var(--border);margin-top:3px;padding:4px 6px;
color:var(--muted);font-size:11px;cursor:pointer;}
.facetbox .facetclear:hover{color:var(--accent);}
td.chk,th.chk{width:26px;text-align:center;}
tr.frow{cursor:pointer;}
tr.detail td{background:#0d1017;color:var(--muted);font-size:12px;
padding:10px 14px 14px 40px;}
tr.detail .kv{margin:2px 0;}
tr.detail .k{color:var(--muted);display:inline-block;min-width:90px;vertical-align:top;}
tr.detail .v{color:var(--text);}
.wrap{max-width:520px;white-space:normal;word-break:break-word;}
.copybtn{margin-left:6px;background:var(--bg);border:1px solid var(--border);color:var(--muted);
border-radius:4px;font-size:11px;line-height:1;padding:2px 5px;cursor:pointer;vertical-align:middle;}
.copybtn:hover{color:var(--accent);border-color:var(--accent);}
.copybtn.ok{color:#3fb950;border-color:#3fb950;}
/* report */
.report-frame{width:100%;height:calc(100vh - 190px);min-height:520px;border:0;
border-radius:8px;display:block;background:#fff;}
/* screenshots */
.gallery{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));
gap:14px;}
.shot{background:var(--surface);border:1px solid var(--border);border-radius:8px;
overflow:hidden;display:flex;flex-direction:column;}
.shot.analyzed{border-color:var(--accent);}
.shot .thumb{width:100%;aspect-ratio:16/10;object-fit:cover;object-position:top;
background:#0d1017;cursor:pointer;display:block;}
.shot .meta{padding:9px 11px;font-size:12px;}
.shot .meta .t{color:var(--text);font-weight:600;margin-bottom:3px;
white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
.shot .meta .u{color:var(--muted);font-size:11px;word-break:break-all;
display:block;margin-bottom:5px;}
.shot .meta .u:hover{color:var(--accent);}
.shot .meta .d{color:var(--muted);font-size:11px;margin-top:5px;
max-height:64px;overflow:auto;}
.thumb-cell{width:120px;}
.thumb-cell img{width:110px;height:64px;object-fit:cover;object-position:top;
border:1px solid var(--border);border-radius:4px;cursor:zoom-in;background:#0d1017;}
.shot .thumb{cursor:zoom-in;}
/* lightbox */
.lightbox{position:fixed;inset:0;background:rgba(5,8,12,.92);z-index:1000;
display:none;flex-direction:column;align-items:center;justify-content:center;
padding:32px;}
.lightbox.open{display:flex;}
.lightbox img{max-width:95vw;max-height:85vh;object-fit:contain;
border:1px solid var(--border);border-radius:6px;background:#0d1017;}
.lightbox .lb-bar{position:absolute;top:0;left:0;right:0;display:flex;
align-items:center;gap:12px;padding:14px 18px;font-size:13px;color:var(--muted);}
.lightbox .lb-bar a{color:var(--accent);text-decoration:none;word-break:break-all;}
.lightbox .lb-close{position:absolute;top:12px;right:18px;font-size:26px;
line-height:1;color:var(--muted);cursor:pointer;background:none;border:none;}
.lightbox .lb-close:hover{color:var(--text);}
</style></head>
<body>
<div class="layout">
  <aside class="sidebar">
    <h1>MonkeyX</h1>
    <div class="run">__RUN_NAME__</div>
    <div class="live"><span class="dot" id="dot"></span><span id="livelabel">live</span>
      · updates 4s</div>
    <nav id="nav">
      <a data-view="overview" class="active">Overview</a>
      <a data-view="focus">Focus <span class="badge-n" id="n-focus">·</span></a>
      <a data-view="reports">Report</a>
      <a data-view="findings">Findings <span class="badge-n" id="n-findings">·</span></a>
      <a data-view="ports">Ports <span class="badge-n" id="n-ports">·</span></a>
      <a data-view="targets">Targets <span class="badge-n" id="n-targets">·</span></a>
      <a data-view="web">Web Endpoints <span class="badge-n" id="n-web">·</span></a>
      <a data-view="webdirs">Web Directories <span class="badge-n" id="n-webdirs">·</span></a>
      <a data-view="screenshots">Web Screenshots <span class="badge-n" id="n-screenshots">·</span></a>
      <a data-view="coverage">Coverage <span class="badge-n" id="n-coverage">·</span></a>
    </nav>
  </aside>
  <main class="main">
    <!-- Overview -->
    <section id="v-overview">
      <div class="view-title">Overview</div>
      <div class="view-sub">Live run status · reading scan.db</div>
      <div class="cards" id="cards"></div>
      <div class="sevchart" id="sevchart" hidden>
        <div class="hd">Findings by severity <span style="text-transform:none">(excludes info)</span></div>
        <div class="sevbar" id="sevbar"></div>
        <div class="sevlegend" id="sevlegend"></div>
      </div>
      <div class="status" id="status">loading…</div>
      <div class="steps" id="steps"></div>
      <div class="runs" id="runs"></div>
    </section>
    <!-- Focus -->
    <section id="v-focus" class="hidden">
      <div class="view-title">Focus — Start Here</div>
      <div class="view-sub">Confirmed findings first, then unverified by severity.
        Analysis-only attack chains live in report.html.</div>
      <div class="toolbar">
        <input class="search" data-for="focus" type="text" placeholder="🔍 search host / title / CVE / tool …" autocomplete="off">
        <span class="count" id="count-focus"></span>
        <button class="btn" data-export="focus">Export CSV</button>
      </div>
      <table id="t-focus"><thead></thead><tbody><tr><td class="empty">loading…</td></tr></tbody></table>
      <div class="pager" id="pager-focus"></div>
    </section>
    <!-- Report -->
    <section id="v-reports" class="hidden">
      <div class="view-title">Report</div>
      <div class="view-sub">The consolidated HTML report.
        <a href="/report" target="_blank" style="color:var(--info)">open in new tab ↗</a></div>
      <iframe class="report-frame" id="report-frame" src="about:blank"></iframe>
    </section>
    <!-- Findings (rich) -->
    <section id="v-findings" class="hidden">
      <div class="view-title">Findings</div>
      <div class="view-sub">All scanner findings. sev / port / tool / verdict filter as checkboxes; host / finding are text-searchable. Click a row for detail; check rows to export a selection.</div>
      <div class="toolbar">
        <input class="search" id="search" type="text" placeholder="🔍 search host / title / CVE / tool / claim …" autocomplete="off">
        <span class="count" id="count"></span>
        <button class="btn" id="export">Export CSV</button>
      </div>
      <table><thead><!-- rebuilt by renderTable: sort row + checkbox-facet/text filter row --></thead>
      <tbody id="rows"><tr><td colspan="7" class="empty">loading…</td></tr></tbody></table>
      <div class="pager" id="pager-findings"></div>
    </section>
    <!-- Generic views -->
    <section id="v-ports" class="hidden">
      <div class="view-title">Ports</div>
      <div class="view-sub">Open ports with service/version detail.</div>
      <div class="toolbar">
        <input class="search" data-for="ports" type="text" placeholder="🔍 search host / service / product / banner …" autocomplete="off">
        <span class="count" id="count-ports"></span>
        <button class="btn" data-export="ports">Export CSV</button>
      </div>
      <table id="t-ports"><thead></thead><tbody><tr><td class="empty">loading…</td></tr></tbody></table>
      <div class="pager" id="pager-ports"></div>
    </section>
    <section id="v-targets" class="hidden">
      <div class="view-title">Targets</div>
      <div class="view-sub">Discovery ledger — scope, access ceiling (host-full vs name-safe), and provenance for every target.</div>
      <div class="toolbar">
        <input class="search" data-for="targets" type="text" placeholder="🔍 search target / type / source / parent …" autocomplete="off">
        <span class="count" id="count-targets"></span>
        <button class="btn" data-export="targets">Export CSV</button>
      </div>
      <table id="t-targets"><thead></thead><tbody><tr><td class="empty">loading…</td></tr></tbody></table>
      <div class="pager" id="pager-targets"></div>
    </section>
    <section id="v-web" class="hidden">
      <div class="view-title">Web Endpoints</div>
      <div class="view-sub">HTTP endpoints with tech fingerprint + status.</div>
      <div class="toolbar">
        <input class="search" data-for="web" type="text" placeholder="🔍 search host / url / title / tech …" autocomplete="off">
        <span class="count" id="count-web"></span>
        <button class="btn" data-export="web">Export CSV</button>
      </div>
      <table id="t-web"><thead></thead><tbody><tr><td class="empty">loading…</td></tr></tbody></table>
      <div class="pager" id="pager-web"></div>
    </section>
    <section id="v-webdirs" class="hidden">
      <div class="view-title">Web Directories</div>
      <div class="view-sub">Content-discovery hits (ffuf / feroxbuster). Defaults to
        interesting HTTP statuses — clear the status filter to see everything.</div>
      <div class="toolbar">
        <input class="search" data-for="webdirs" type="text" placeholder="🔍 search host / url / tool …" autocomplete="off">
        <span class="count" id="count-webdirs"></span>
        <button class="btn" data-export="webdirs">Export CSV</button>
      </div>
      <table id="t-webdirs"><thead></thead><tbody><tr><td class="empty">loading…</td></tr></tbody></table>
      <div class="pager" id="pager-webdirs"></div>
    </section>
    <section id="v-coverage" class="hidden">
      <div class="view-title">Coverage</div>
      <div class="view-sub">What each module was fed and the outcome.
        <b>reached</b> = seen in output · <b>no_response</b> = fed but absent (maybe
        missed — down, blocked, or skipped; verify) · <b>step_failed</b> = module
        errored · <b>fed</b> = submitted (not yet reconciled, or no reader for that
        tool). Not proof of a scan — it surfaces the gap to eyeball.</div>
      <div class="toolbar">
        <input class="search" data-for="coverage" type="text" placeholder="🔍 search module / target / status …" autocomplete="off">
        <span class="count" id="count-coverage"></span>
        <button class="btn" data-export="coverage">Export CSV</button>
      </div>
      <table id="t-coverage"><thead></thead><tbody><tr><td class="empty">loading…</td></tr></tbody></table>
      <div class="pager" id="pager-coverage"></div>
    </section>
    <!-- Screenshots gallery -->
    <section id="v-screenshots" class="hidden">
      <div class="view-title">Web Screenshots</div>
      <div class="view-sub">Gowitness captures — AI-analyzed (highest attack-surface
        value first), then remaining captures. Click a thumbnail to open the URL.</div>
      <div class="toolbar">
        <span class="count" id="count-screenshots"></span>
      </div>
      <div class="gallery" id="gallery"><div class="empty">loading…</div></div>
      <div class="pager" id="pager-screenshots"></div>
    </section>
  </main>
</div>
<div class="lightbox" id="lightbox">
  <div class="lb-bar"><a id="lb-link" href="#" target="_blank"></a></div>
  <button class="lb-close" id="lb-close" title="close (Esc)">&times;</button>
  <img id="lb-img" src="" alt="">
</div>
<script>
const SEV_RANK = {critical:0,high:1,medium:2,low:3,info:4};
// Rows drawn per page, by view. Search/sort still span the FULL set; only the
// slice rendered to the DOM is paginated. CSV export always reaches everything.
const PAGE_SIZE = {focus:500, ports:500, targets:500, web:40, webdirs:500, findings:500, coverage:500};
function pageSize(name){ return PAGE_SIZE[name] || 500; }
let currentView = "overview";

function esc(s){return (s==null?"":String(s)).replace(/[&<>"]/g,
  c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));}
// A CSS-class token built from scan data (severity/verdict/status) must never
// break out of the class attribute — keep only [a-z0-9_-]. esc() guards text
// content; this guards the attribute-name interpolation.
function slug(s){return String(s==null?"":s).toLowerCase().replace(/[^a-z0-9_-]/g,"");}
// A href/link built from a scanned URL must not carry a javascript:/data: scheme
// (a malicious host can set its title/URL to anything). Allow only http(s):// or
// a root-relative path; everything else collapses to a dead "#".
function safeUrl(u){u=String(u==null?"":u).trim();var l=u.toLowerCase();
  return (l.startsWith("http://")||l.startsWith("https://")||u.startsWith("/"))?u:"#";}

/* ---------------- navigation ---------------- */
function showView(name){
  currentView = name;
  document.querySelectorAll('.main > section').forEach(s=>s.classList.add('hidden'));
  document.getElementById('v-'+name).classList.remove('hidden');
  document.querySelectorAll('#nav a').forEach(a=>
    a.classList.toggle('active', a.dataset.view===name));
  if(name==="findings") fetchFindings();
  else if(name==="screenshots") fetchScreenshots();
  else if(name==="reports") showReport();
  else if(GENERIC[name]) fetchGeneric(name);
}
// Lazy-load report.html into the iframe the first time the Report view is opened.
function showReport(){
  const f=document.getElementById('report-frame');
  if(f && !f.dataset.loaded){ f.src='/report'; f.dataset.loaded='1'; }
}
document.getElementById('nav').addEventListener('click',e=>{
  const a=e.target.closest('a[data-view]'); if(!a) return;
  showView(a.dataset.view);
});

/* ---------------- generic table views (focus/ports/targets/web) ------------ */
// Each holds its fetched rows, columns (from the server), search + sort state.
// rows = the CURRENT page (server-sliced); total = full filtered count.
// filters = text substring per col; efilters = {col:[tokens]} checkbox facets;
// facets = {col:[options]} the server offers for this view; openFacet = which
// facet dropdown is open (preserved across the 4s re-render).
const _gbase = ()=>({rows:[], columns:[], total:0, search:"", filters:{},
  efilters:{}, facets:{}, openFacet:null, sortCol:null, sortDir:1, page:0});
const GENERIC = {
  focus: _gbase(), ports: _gbase(), targets: _gbase(),
  web: _gbase(), webdirs: _gbase(), coverage: _gbase(),
};
// Render a pager into the container after table `t-<name>`; wires prev/next to
// setPage(name, delta). total = filtered row count, page = current 0-based page.
function renderPager(id, page, total, size, onGo){
  const el = document.getElementById(id);
  if(!el) return;
  const pages = Math.max(1, Math.ceil(total/size));
  if(total <= size){ el.innerHTML=''; return; }
  const from = total ? page*size+1 : 0;
  const to = Math.min(total, (page+1)*size);
  el.innerHTML =
    `<button data-go="-1" ${page<=0?'disabled':''}>‹ Prev</button>`+
    `<span class="pinfo">${from}–${to} of ${total}</span>`+
    `<button data-go="1" ${page>=pages-1?'disabled':''}>Next ›</button>`+
    `<span>page ${page+1} / ${pages}</span>`;
  el.querySelectorAll('button[data-go]').forEach(b=>
    b.onclick=()=>onGo(page + (+b.dataset.go)));
}
const COL_LABEL = {cve_id:"cve",poc_command:"proof",status_code:"status",
  target_type:"type",in_scope:"in scope",scope_class:"access",
  discovered_at:"discovered",false_positive:"fp"};
const WRAP_COLS = new Set(["title","poc_command","banner","url","tech"]);
// Sortable-but-not-filterable columns (no filter widget in the filter row).
const NO_FILTER_COLS = new Set(["rank"]);
// Identifier/text columns that get a click-to-copy (⧉) button in the generic
// views (same affordance the Findings view has on host). host/target/url/title.
const COPY_COLS = new Set(["host","target","url","title"]);

// Server-side paged fetch: the server filters (q), sorts, and slices, returning
// one page + the full filtered `total`. Prevents shipping 100k+ rows at once.
// Web Directories defaults to interesting HTTP statuses (dir-brute output is
// noisy). Seeded ONCE, only if it actually narrows (some interesting AND some
// noise present) and the user hasn't touched the status filter; clearing the
// facet reveals everything. Status facet tokens are strings.
let webdirsSeeded = false;
const WEBDIRS_INTERESTING = new Set(
  ["200","201","204","301","302","307","308","401","403","405","500"]);
async function fetchGeneric(name){
  const g = GENERIC[name];
  try{
    const size = pageSize(name);
    const p = new URLSearchParams({page:g.page, size:size, dir:(g.sortDir>0?'asc':'desc')});
    if(g.search) p.set('q', g.search);
    if(g.sortCol) p.set('sort', g.sortCol);
    for(const c in g.filters){ if(g.filters[c]) p.set('f.'+c, g.filters[c]); }
    for(const c in g.efilters){ (g.efilters[c]||[]).forEach(v=>p.append('fe.'+c, v)); }
    const d = await (await fetch('/api/view/'+name+'?'+p)).json();
    g.rows = d.rows||[]; g.columns = d.columns||[]; g.total = d.total||0;
    g.facets = d.facets||{};
    if(!g.sortCol && g.columns.length) g.sortCol = g.columns[0];
    if(name==='webdirs' && !webdirsSeeded){
      webdirsSeeded = true;
      const opts = g.facets.status_code || [];
      const pick = opts.filter(o=>WEBDIRS_INTERESTING.has(String(o)));
      if(pick.length && pick.length !== opts.length && !(g.efilters.status_code||[]).length){
        g.efilters.status_code = pick;
        return fetchGeneric(name);   // one refetch with the interesting default applied
      }
    }
    renderGeneric(name);
  }catch(e){ /* leave last render; live dot handles disconnect */ }
}
function fmtCell(col,val){
  if(col==="screenshot"){
    if(!val) return '—';
    const src = `/screenshot?path=${encodeURIComponent(val)}`;
    return `<img class="thumb lb-open" loading="lazy" src="${src}" data-full="${src}">`;
  }
  if(col==="severity"){ const s=(val||'info').toLowerCase();
    return `<span class="badge ${slug(s)}">${esc(s)}</span>`; }
  if(col==="verdict"){ const v=(val||'').toLowerCase();
    return val?`<span class="v-${slug(v)}">${esc(val)}</span>`:''; }
  if(col==="status"){ const s=(val||'').toLowerCase();
    return val?`<span class="cov cov-${slug(s)}">${esc(val)}</span>`:''; }
  if(col==="in_scope"||col==="cdn"||col==="false_positive")
    return val?'<span class="yes">yes</span>':'<span class="no">no</span>';
  if(col==="scope_class"){ const v=val||'lead';
    return `<span class="cov cov-${slug(v)}" title="host-full = -t, port-scannable; name-safe = -d/-url, by hostname only; lead = not authorized for active scanning">${esc(v)}</span>`; }
  if(col==="poc_command"||col==="banner")
    return val?`<span class="mono">${esc(val)}</span>`:'—';
  if(col==="host"||col==="target"||col==="url"||col==="cve_id")
    return val==null?'':`<span class="mono">${esc(val)}</span>`
      +(COPY_COLS.has(col)?copyBtn(val):'');
  return val==null?'':esc(val)+(COPY_COLS.has(col)?copyBtn(val):'');
}
function setPage(name, page){
  const g = GENERIC[name]; if(!g) return;
  g.page = Math.max(0, page); fetchGeneric(name);   // server returns the new page
}
function renderGeneric(name){
  const g = GENERIC[name];
  const shown = g.rows;                 // already the server-sliced page
  const size = pageSize(name);
  const total = g.total;
  const anyFilter = Object.keys(g.filters).some(c=>g.filters[c])
    || Object.keys(g.efilters).some(c=>(g.efilters[c]||[]).length);
  const cnt = document.getElementById('count-'+name);
  if(cnt) cnt.textContent = `${total} rows${(g.search||anyFilter)?' (filtered)':''}`;
  const table = document.getElementById('t-'+name);
  const thead = table.querySelector('thead');
  const tbody = table.querySelector('tbody');
  const ncol = g.columns.length || 1;
  // The thead is rebuilt every render (arrows change; the 4s live refresh
  // re-renders too), so remember which per-column filter box was focused and
  // where the caret sat, then restore it after — otherwise typing loses focus.
  const act = document.activeElement;
  const focusCol = (act && act.classList && act.classList.contains('colf')
    && table.contains(act)) ? act.dataset.col : null;
  const caret = focusCol ? [act.selectionStart, act.selectionEnd] : null;
  const sortRow = '<tr>'+g.columns.map(c=>{
    const label=COL_LABEL[c]||c;
    const arrow = c===g.sortCol ? ` <span class="arrow">${g.sortDir>0?'▲':'▼'}</span>`:'';
    return `<th class="sortable" data-col="${esc(c)}">${esc(label)}${arrow}</th>`;
  }).join('')+'</tr>';
  // Filter row (not .sortable, so the header sort-click handler ignores it). A
  // low-cardinality column the server offered a facet for gets a checkbox
  // dropdown (exact multi-select); everything else keeps a substring box. Both
  // read their state from g.efilters/g.filters so selections persist across the
  // live re-render.
  const filterRow = '<tr class="filterrow">'+g.columns.map(c=>{
    // Some columns are sortable but not filterable (e.g. focus "rank" — a
    // computed position, not a value you'd filter on): render an empty cell so
    // the sort header stays but no filter widget shows.
    if(NO_FILTER_COLS.has(c)) return '<th></th>';
    const opts = g.facets[c];
    if(opts && opts.length){
      const sel = g.efilters[c]||[];
      const label = COL_LABEL[c]||c;
      const summary = sel.length ? `${label} (${sel.length})` : label;
      const box = opts.map(o=>
        `<label><input type="checkbox" class="fchk" data-col="${esc(c)}" `
        +`value="${esc(o)}" ${sel.includes(o)?'checked':''}> ${esc(o)}</label>`).join('')
        + (sel.length?`<button class="facetclear" data-col="${esc(c)}">clear</button>`:'');
      return `<th><details class="facet" data-col="${esc(c)}"${g.openFacet===c?' open':''}>`
        +`<summary class="${sel.length?'on':''}">${esc(summary)}</summary>`
        +`<div class="facetbox">${box}</div></details></th>`;
    }
    return `<th><input class="colf" data-col="${esc(c)}" value="${esc(g.filters[c]||'')}" `
      +`placeholder="filter…" autocomplete="off"></th>`;
  }).join('')+'</tr>';
  thead.innerHTML = sortRow + filterRow;
  if(focusCol){
    const inp = thead.querySelector('.colf[data-col="'+CSS.escape(focusCol)+'"]');
    if(inp){ inp.focus(); if(caret) try{ inp.setSelectionRange(caret[0],caret[1]); }catch(_){} }
  }
  if(!shown.length){
    // Empty slice but total>0 means the page fell out of range (the filtered or
    // live-refreshed set shrank under a high page number): clamp to the last
    // valid page and re-fetch instead of stranding on a blank, pager-less page.
    const lastPage = total>0 ? Math.ceil(total/size)-1 : 0;
    if(total>0 && g.page>lastPage){ g.page=lastPage; fetchGeneric(name); return; }
    tbody.innerHTML=`<tr><td colspan="${ncol}" class="empty">no matching rows</td></tr>`;
    renderPager('pager-'+name, 0, 0, size, p=>setPage(name,p));
    return;
  }
  tbody.innerHTML = shown.map(r=>'<tr>'+g.columns.map(c=>{
    const cls = c==="screenshot" ? ' class="thumb-cell"'
      : WRAP_COLS.has(c) ? ' class="wrap"' : '';
    return `<td${cls}>${fmtCell(c,r[c])}</td>`;
  }).join('')+'</tr>').join('');
  renderPager('pager-'+name, g.page, total, size, p=>setPage(name,p));
}
// generic table events (delegated once): sort on header click.
document.querySelector('.main').addEventListener('click',e=>{
  const th=e.target.closest('th.sortable'); if(!th) return;
  const section=th.closest('section'); if(!section) return;
  const name=section.id.replace('v-',''); const g=GENERIC[name]; if(!g) return;
  const col=th.dataset.col;
  if(col===g.sortCol) g.sortDir*=-1; else { g.sortCol=col; g.sortDir=1; }
  g.page = 0;   // sort changes ordering → back to first page
  fetchGeneric(name);   // server re-sorts the full set + returns page 0
});
// click-to-copy (⧉) buttons in generic-view cells (host/target/url/title).
// Delegated on .main; stops propagation so it doesn't trigger sort/facet/close.
document.querySelector('.main').addEventListener('click',e=>{
  const cb=e.target.closest('.copybtn'); if(!cb) return;
  e.stopPropagation();
  copyText(cb.dataset.copy);
  const o=cb.textContent; cb.textContent='✓'; cb.classList.add('ok');
  setTimeout(()=>{cb.textContent=o; cb.classList.remove('ok');},900);
});
// generic search boxes (debounced — each keystroke now hits the server)
const _searchTimers = {};
document.querySelectorAll('.search[data-for]').forEach(inp=>
  inp.addEventListener('input',e=>{
    const name=inp.dataset.for;
    GENERIC[name].search=e.target.value.trim().toLowerCase();
    GENERIC[name].page = 0;   // new filter → first page
    clearTimeout(_searchTimers[name]);
    _searchTimers[name] = setTimeout(()=>fetchGeneric(name), 250);
  }));
// per-column filter boxes (delegated on .main because the thead is re-rendered;
// debounced per view). Keeps the global search box and the sort arrows intact.
const _colfTimers = {};
document.querySelector('.main').addEventListener('input',e=>{
  const inp=e.target.closest('input.colf'); if(!inp) return;
  const section=inp.closest('section'); if(!section) return;
  const name=section.id.replace('v-',''); const g=GENERIC[name]; if(!g) return;
  const col=inp.dataset.col, val=e.target.value.trim();
  if(val) g.filters[col]=val; else delete g.filters[col];
  g.page = 0;   // new filter → first page
  clearTimeout(_colfTimers[name]);
  _colfTimers[name] = setTimeout(()=>fetchGeneric(name), 250);
});
// checkbox-facet dropdowns: open/close (single-open, fully controlled so the
// live re-render can't strand one open) + clear button. Delegated on .main.
document.querySelector('.main').addEventListener('click',e=>{
  const sm=e.target.closest('details.facet > summary');
  if(sm){
    e.preventDefault();
    const det=sm.parentElement, section=det.closest('section');
    if(!section) return; const name=section.id.replace('v-',''); const g=GENERIC[name];
    if(!g) return;
    const col=det.dataset.col;
    g.openFacet = (g.openFacet===col) ? null : col;
    renderGeneric(name);   // pure re-render, no refetch
    return;
  }
  const fc=e.target.closest('button.facetclear');
  if(fc){
    e.preventDefault();
    const section=fc.closest('section'); if(!section) return;
    const name=section.id.replace('v-',''); const g=GENERIC[name]; if(!g) return;
    delete g.efilters[fc.dataset.col];
    g.page=0; fetchGeneric(name);
    return;
  }
});
// facet checkbox toggled → update the column's selected-token set, refetch.
document.querySelector('.main').addEventListener('change',e=>{
  const ck=e.target.closest('input.fchk'); if(!ck) return;
  const section=ck.closest('section'); if(!section) return;
  const name=section.id.replace('v-',''); const g=GENERIC[name]; if(!g) return;
  const col=ck.dataset.col, set=new Set(g.efilters[col]||[]);
  if(ck.checked) set.add(ck.value); else set.delete(ck.value);
  if(set.size) g.efilters[col]=[...set]; else delete g.efilters[col];
  g.page=0;
  clearTimeout(_colfTimers[name]);
  _colfTimers[name]=setTimeout(()=>fetchGeneric(name),200);
});
// click anywhere outside an open facet closes it (generic views + findings).
document.addEventListener('click',e=>{
  if(e.target.closest('details.facet')) return;
  const g=GENERIC[currentView];
  if(g && g.openFacet){ g.openFacet=null; renderGeneric(currentView); }
  else if(currentView==='findings' && findOpenFacet){ findOpenFacet=null; renderTable(); }
});
// generic CSV export (server-side, honoring the current search + column filters)
document.querySelectorAll('[data-export]').forEach(btn=>
  btn.addEventListener('click',()=>{
    const name=btn.dataset.export; const g=GENERIC[name];
    const params=new URLSearchParams(); if(g.search) params.set('q',g.search);
    for(const c in g.filters){ if(g.filters[c]) params.set('f.'+c, g.filters[c]); }
    for(const c in g.efilters){ (g.efilters[c]||[]).forEach(v=>params.append('fe.'+c, v)); }
    window.location='/api/view/'+name+'.csv'+(params.toString()?'?'+params:'');
  }));

/* ---------------- screenshots gallery ---------------- */
const SHOT_PAGE_SIZE = 50;
const SHOTS = {rows:[], search:"", page:0};
async function fetchScreenshots(){
  try{
    const d = await (await fetch('/api/screenshots')).json();
    SHOTS.rows = d.rows||[];
    renderScreenshots();
  }catch(e){ /* leave last render */ }
}
function renderScreenshots(){
  const rows = SHOTS.rows;
  const total = rows.length;
  const pages = Math.max(1, Math.ceil(total/SHOT_PAGE_SIZE));
  if(SHOTS.page >= pages) SHOTS.page = pages-1;
  if(SHOTS.page < 0) SHOTS.page = 0;
  const start = SHOTS.page*SHOT_PAGE_SIZE;
  const cap = rows.slice(start, start+SHOT_PAGE_SIZE);
  const cnt = document.getElementById('count-screenshots');
  if(cnt) cnt.textContent = `${total} screenshot${total===1?'':'s'}`;
  const g = document.getElementById('gallery');
  const pager = document.getElementById('pager-screenshots');
  if(!total){
    g.innerHTML='<div class="empty">no screenshots — run ax_gowitness (and ai_analyze_gowitness for prioritization)</div>';
    if(pager) pager.innerHTML='';
    return;
  }
  g.innerHTML = cap.map(r=>{
    const src = r.screenshot ? `/screenshot?path=${encodeURIComponent(r.screenshot)}` : '';
    const sev = r.severity ? `<span class="badge ${slug(r.severity)}">${esc(r.severity)}</span> ` : '';
    const cat = r.category ? `<span class="count">${esc(r.category)}</span>` : '';
    const sim = (r.sim_count && r.sim_count > 1) ? `<span class="count" title="visually similar screenshots (grouped)">similar ×${r.sim_count}</span>` : '';
    // Two-step URL safety (don't "simplify" to one): esc() here stops attribute
    // breakout in data-url=; safeUrl() at use-time (the <a href> below and the
    // lightbox lbLink.href) collapses javascript:/data: schemes. Both are needed.
    const thumb = src
      ? `<img class="thumb lb-open" loading="lazy" src="${src}" data-full="${src}" data-url="${esc(r.url||'')}">`
      : `<div class="thumb"></div>`;
    return `<div class="shot${r.analyzed?' analyzed':''}">
      ${thumb}
      <div class="meta">
        <div class="t">${sev}${esc(r.title||r.host||'(untitled)')}${cat?' '+cat:''}${sim?' '+sim:''}</div>
        <a class="u" href="${esc(safeUrl(r.url))}" target="_blank" rel="noopener noreferrer">${esc(r.url||'')}</a>
        ${r.detail?`<div class="d">${esc(r.detail)}</div>`:''}
      </div></div>`;
  }).join('');
  renderPager('pager-screenshots', SHOTS.page, total, SHOT_PAGE_SIZE, p=>{
    SHOTS.page = p; renderScreenshots(); window.scrollTo(0,0);
  });
}

/* ---------------- findings view (rich: facets/selection/detail) ------------
   Server-side filter (checkbox facets + text cols + search) + sort + pagination, so
   a 50k-finding run never ships as one payload. Only the current page is held in
   `pageRows`; `selected`/`total` persist across pages. */
let search = "";                 // global substring -> server q
let findE = {};                  // checkbox facets {col:[tokens]} -> fe.<col>
let findF = {};                  // text column filters {col:val} -> f.<col>
let findFacets = {};             // server-offered facet options {col:[opts]}
let findOpenFacet = null;        // which facet dropdown is open (single-open)
let sortCol = "severity", sortDir = 1;
let pageRows = [];               // just the current page
let findingsTotal = 0;           // full filtered count (for pager + count)
let selected = new Set();        // finding_ids, persists across pages
let expanded = new Set();        // expanded detail rows, persists across the 4s refresh
let findingsPage = 0;
let _findSearchTimer = null, _findColfTimer = null;
// Findings table columns (after the checkbox column). sev/port/tool/verdict
// render as checkbox facets (server offers options); host/finding stay text.
const FIND_COLS = ["severity","host","port","tool","title","verdict"];
const FIND_FACET_COLS = new Set(["severity","port","tool","verdict"]);
const FIND_LABEL = {severity:"sev", title:"finding"};

// Clipboard copy with a fallback for non-secure-context access (e.g. plain-http
// over an IP). localhost/127.0.0.1 is a secure context, so the API path is used.
function copyText(t){
  if(navigator.clipboard && navigator.clipboard.writeText)
    navigator.clipboard.writeText(t).catch(()=>fallbackCopy(t));
  else fallbackCopy(t);
}
function fallbackCopy(t){
  const ta=document.createElement('textarea'); ta.value=t;
  ta.style.position='fixed'; ta.style.opacity='0'; document.body.appendChild(ta);
  ta.select(); try{document.execCommand('copy');}catch(_){}
  document.body.removeChild(ta);
}
function copyBtn(v){ return v ? ` <button class="copybtn" data-copy="${esc(v)}" title="copy">⧉</button>` : ''; }

function findingsQuery(extra){
  const p = new URLSearchParams({page:findingsPage, size:pageSize('findings'),
    sort:sortCol, dir:(sortDir>0?'asc':'desc')});
  if(search) p.set('q', search);
  for(const c in findE){ (findE[c]||[]).forEach(v=>p.append('fe.'+c, v)); }
  for(const c in findF){ if(findF[c]) p.set('f.'+c, findF[c]); }
  if(extra) for(const k in extra) p.set(k, extra[k]);
  return p;
}
function renderTable(){
  const shown = pageRows;
  const size = pageSize('findings');
  const anyFilter = Object.keys(findF).some(c=>findF[c])
    || Object.keys(findE).some(c=>(findE[c]||[]).length);
  document.getElementById('count').textContent =
    `${findingsTotal} findings${(search||anyFilter)?' (filtered)':''}`
    + (selected.size?`  ·  ${selected.size} selected`:"");
  // Rebuild the thead each render (arrows + facet options/selection change; the
  // 4s live refresh re-renders too). sev/port/tool/verdict -> checkbox facet;
  // host/finding -> substring box. Preserve the focused text box + caret so
  // typing a filter never loses focus across the rebuild.
  const table = document.querySelector('#v-findings table');
  const thead = table.querySelector('thead');
  const act = document.activeElement;
  const focusCol = (act && act.classList && act.classList.contains('colf')
    && thead.contains(act)) ? act.dataset.col : null;
  const caret = focusCol ? [act.selectionStart, act.selectionEnd] : null;
  const selAll = document.getElementById('selall');
  const selAllOn = selAll && selAll.checked ? 'checked' : '';
  const sortRow = '<tr><th class="chk"><input type="checkbox" id="selall" '
    + `title="select all (filtered)" ${selAllOn}></th>`
    + FIND_COLS.map(c=>{
        const label = FIND_LABEL[c]||c;
        const arrow = c===sortCol ? ` <span class="arrow">${sortDir>0?'▲':'▼'}</span>`:'';
        return `<th class="sortable" data-col="${esc(c)}">${esc(label)}${arrow}</th>`;
      }).join('') + '</tr>';
  const filterRow = '<tr class="filterrow"><th></th>'
    + FIND_COLS.map(c=>{
        const opts = findFacets[c];
        if(FIND_FACET_COLS.has(c) && opts && opts.length){
          const sel = findE[c]||[]; const label = FIND_LABEL[c]||c;
          const summary = sel.length ? `${label} (${sel.length})` : label;
          const box = opts.map(o=>
            `<label><input type="checkbox" class="fchk" data-col="${esc(c)}" `
            +`value="${esc(o)}" ${sel.includes(o)?'checked':''}> ${esc(o)}</label>`).join('')
            + (sel.length?`<button class="facetclear" data-col="${esc(c)}">clear</button>`:'');
          return `<th><details class="facet" data-col="${esc(c)}"${findOpenFacet===c?' open':''}>`
            +`<summary class="${sel.length?'on':''}">${esc(summary)}</summary>`
            +`<div class="facetbox">${box}</div></details></th>`;
        }
        return `<th><input class="colf" data-col="${esc(c)}" value="${esc(findF[c]||'')}" `
          +`placeholder="filter…" autocomplete="off"></th>`;
      }).join('') + '</tr>';
  thead.innerHTML = sortRow + filterRow;
  if(focusCol){
    const inp = thead.querySelector('.colf[data-col="'+CSS.escape(focusCol)+'"]');
    if(inp){ inp.focus(); if(caret) try{ inp.setSelectionRange(caret[0],caret[1]); }catch(_){} }
  }
  const body = document.getElementById('rows');
  if(!shown.length){
    // Out-of-range page (filtered/refreshed set shrank under us): clamp to the
    // last valid page and re-fetch rather than stranding on a blank page.
    const lastPage = findingsTotal>0 ? Math.ceil(findingsTotal/size)-1 : 0;
    if(findingsTotal>0 && findingsPage>lastPage){ findingsPage=lastPage; fetchFindings(); return; }
    body.innerHTML='<tr><td colspan="7" class="empty">no matching findings</td></tr>';
    renderPager('pager-findings', 0, 0, size, p=>{ findingsPage=p; fetchFindings(); });
    return;
  }
  body.innerHTML = shown.map(r=>{
    const sev=(r.severity||'info').toLowerCase();
    const v=(r.verdict||'').toLowerCase();
    const vcell = r.verdict ? `<span class="v-${slug(v)}">${esc(r.verdict)}</span>` : '';
    const fp = r.false_positive ? ' <span class="badge low">FP</span>' : '';
    const ck = selected.has(r.finding_id) ? "checked" : "";
    const disp = expanded.has(r.finding_id) ? "" : "none";
    const det = `<tr class="detail" data-for="${esc(r.finding_id)}" style="display:${disp}">
      <td colspan="7">
        <div class="kv"><span class="k">matched at</span><span class="v mono">${esc(r.matched_at||'—')}</span>${copyBtn(r.matched_at)}</div>
        <div class="kv"><span class="k">host</span><span class="v mono">${esc(r.host||'—')}</span>${copyBtn(r.host)}</div>
        <div class="kv"><span class="k">claim</span><span class="v mono">${esc(r.claim||'—')}</span></div>
        <div class="kv"><span class="k">cve</span><span class="v mono">${esc(r.cve_id||'—')}</span></div>
        <div class="kv"><span class="k">triage</span><span class="v">${esc(r.triage_status||'new')}${r.false_positive?' · false positive':''}</span></div>
        <div class="kv"><span class="k">finding id</span><span class="v mono">${esc(r.finding_id)}</span></div>
        <div class="kv"><span class="k">full title</span><span class="v">${esc(r.title||'')}</span></div>
      </td></tr>`;
    return `<tr class="frow" data-id="${esc(r.finding_id)}">
      <td class="chk"><input type="checkbox" class="rowck" data-id="${esc(r.finding_id)}" ${ck}></td>
      <td><span class="badge ${slug(sev)}">${esc(sev)}</span></td>
      <td class="mono">${esc(r.host)}${copyBtn(r.host)}</td><td class="mono">${r.port==null?'':r.port}</td>
      <td>${esc(r.tool)}</td><td class="wrap">${esc(r.title||r.cve_id||'')}${fp}</td>
      <td>${vcell}</td></tr>${det}`;
  }).join('');
  renderPager('pager-findings', findingsPage, findingsTotal, size,
              p=>{ findingsPage=p; fetchFindings(); });
}
async function fetchFindings(){
  try{
    const fd = await (await fetch('/api/findings?'+findingsQuery())).json();
    pageRows = fd.findings||[];
    findingsTotal = fd.total||0;
    findFacets = fd.facets||{};
    renderTable();
  }catch(e){ /* keep last render; live dot shows disconnect */ }
}
document.getElementById('search').addEventListener('input',e=>{
  search = e.target.value.trim().toLowerCase(); findingsPage=0;
  clearTimeout(_findSearchTimer);
  _findSearchTimer = setTimeout(fetchFindings, 250);
});
// All findings HEADER interactions are delegated on the (stable) <thead> element,
// whose innerHTML renderTable rebuilds each render — so sort clicks, facet
// open/close + clear, checkbox-facet toggles, text-column filters, and
// select-all all survive the rebuild (per-element listeners would not).
const findThead = document.querySelector('#v-findings thead');
findThead.addEventListener('click',e=>{
  const sm=e.target.closest('details.facet > summary');
  if(sm){ e.preventDefault(); const col=sm.parentElement.dataset.col;
    findOpenFacet=(findOpenFacet===col)?null:col; renderTable(); return; }
  const fc=e.target.closest('button.facetclear');
  if(fc){ e.preventDefault(); delete findE[fc.dataset.col]; findingsPage=0; fetchFindings(); return; }
  const th=e.target.closest('th.sortable');
  if(th){ const col=th.dataset.col;
    if(col===sortCol) sortDir*=-1; else { sortCol=col; sortDir=1; }
    findingsPage=0; fetchFindings(); }
});
findThead.addEventListener('input',e=>{
  const inp=e.target.closest('input.colf'); if(!inp) return;
  const col=inp.dataset.col, val=e.target.value.trim();
  if(val) findF[col]=val; else delete findF[col];
  findingsPage=0;
  clearTimeout(_findColfTimer);
  _findColfTimer = setTimeout(fetchFindings, 250);
});
findThead.addEventListener('change',async e=>{
  // Select-all spans the FULL filtered set (all pages), not just the visible
  // page: fetch the id list server-side (ids_only) so no rows are shipped.
  if(e.target.id==='selall'){
    const on=e.target.checked;
    try{ const fd=await (await fetch('/api/findings?'+findingsQuery({ids_only:1}))).json();
      (fd.ids||[]).forEach(id=> on?selected.add(id):selected.delete(id));
    }catch(_){ pageRows.forEach(r=> on?selected.add(r.finding_id):selected.delete(r.finding_id)); }
    renderTable(); return;
  }
  const ck=e.target.closest('input.fchk'); if(!ck) return;
  const col=ck.dataset.col, set=new Set(findE[col]||[]);
  if(ck.checked) set.add(ck.value); else set.delete(ck.value);
  if(set.size) findE[col]=[...set]; else delete findE[col];
  findingsPage=0;
  clearTimeout(_findColfTimer); _findColfTimer=setTimeout(fetchFindings,200);
});
document.getElementById('rows').addEventListener('click',e=>{
  const cb=e.target.closest('.copybtn');
  if(cb){ e.stopPropagation(); copyText(cb.dataset.copy);
    const o=cb.textContent; cb.textContent='✓'; cb.classList.add('ok');
    setTimeout(()=>{cb.textContent=o; cb.classList.remove('ok');},900);
    return; }
  const ck=e.target.closest('.rowck');
  if(ck){ e.stopPropagation();
    if(ck.checked) selected.add(ck.dataset.id); else selected.delete(ck.dataset.id);
    document.getElementById('count').textContent =
      `${findingsTotal} findings` + (selected.size?`  ·  ${selected.size} selected`:"");
    return; }
  const row=e.target.closest('tr.frow');
  if(row){ const id=row.dataset.id; const det=row.nextElementSibling;
    if(det && det.classList.contains('detail')){
      const show = det.style.display==='none';
      det.style.display = show?'':'none';
      if(show) expanded.add(id); else expanded.delete(id);
    } }
});
document.getElementById('export').addEventListener('click',()=>{
  const params=new URLSearchParams();
  // Selected ids export exactly those; otherwise the CSV honors the current
  // facet + text + search filters server-side (the .csv route re-runs them).
  if(selected.size){ params.set('ids',[...selected].join(',')); }
  else {
    if(search){ params.set('q', search); }
    for(const c in findE){ (findE[c]||[]).forEach(v=>params.append('fe.'+c, v)); }
    for(const c in findF){ if(findF[c]) params.set('f.'+c, findF[c]); }
  }
  window.location = '/api/findings.csv?'+params.toString();
});

/* ---------------- overview + shared status poll ---------------- */
function fmtCount(n){
  // Comma-format counts; cap the DISPLAY at 100,000+ so a huge count can't blow
  // out the sidebar. Non-numbers (the '·' placeholder) pass through unchanged.
  if(typeof n!=='number' || isNaN(n)) return n;
  return n>100000 ? '100,000+' : n.toLocaleString();
}
function setBadge(id,n){ const el=document.getElementById(id); if(el) el.textContent=fmtCount(n); }
// Severity breakdown: 100% stacked bar + legend, info excluded. Reuses the
// product severity palette (--critical/--high/--medium/--low) so identity is
// consistent with the badges; the legend labels every segment (never color-alone).
const SEV_LEVELS = ["critical","high","medium","low"];
function renderSevChart(bySev){
  const box=document.getElementById('sevchart');
  const counts=SEV_LEVELS.map(s=>({s, n:(bySev&&bySev[s])||0}));
  const total=counts.reduce((a,x)=>a+x.n,0);
  box.hidden=false;
  const bar=document.getElementById('sevbar'), leg=document.getElementById('sevlegend');
  if(!total){
    bar.innerHTML=''; leg.innerHTML='<span class="empty">No critical/high/medium/low findings.</span>';
    return;
  }
  bar.innerHTML=counts.filter(x=>x.n>0).map(x=>{
    const pct=(x.n/total*100);
    return `<div class="seg ${x.s}" style="width:${pct}%" title="${x.s}: ${x.n} (${pct.toFixed(1)}%)"></div>`;
  }).join('');
  leg.innerHTML=counts.map(x=>{
    const pct=total?(x.n/total*100):0;
    return `<span class="it"><span class="sw ${x.s}"></span>${x.s} <b>${x.n}</b> · ${pct.toFixed(0)}%</span>`;
  }).join('');
}
async function refreshStatus(){
  const st = await (await fetch('/api/status')).json();
  if(!st.available) return;
  const c = st.counts||{};
  renderSevChart(st.by_severity);
  setBadge('n-findings',c.findings??'·'); setBadge('n-ports',c.ports??'·');
  setBadge('n-targets',c.targets??'·'); setBadge('n-web',c.web??'·');
  setBadge('n-focus',c.focus??'·'); setBadge('n-screenshots',c.screenshots??'·');
  setBadge('n-coverage',c.coverage??'·');
  document.getElementById('cards').innerHTML =
    [['findings',c.findings,'findings'],['open ports',c.ports,'ports'],
     ['targets',c.targets,'targets'],['web endpoints',c.web,'web'],
     ['screenshots',c.screenshots,'screenshots']].map(([l,n,v])=>
    `<div class="card click" data-view="${v}"><div class="n">${fmtCount(n??0)}</div><div class="l">${l}</div></div>`).join('');
  const p = st.progress || {}, cur = p.current;
  const total = p.total||0, done = p.done||0, pct = total?Math.round(done/total*100):0;
  const runs = p.runs_count||0;
  const runPrefix = runs>1 ? `Run ${p.run_seq} · ` : "";
  const cum = p.cumulative||{};
  const cumLine = runs>1
    ? `<div class="cum">· ${cum.done||0} steps across ${runs} runs total</div>` : "";
  if(cur){
    const running = cur.status==='running';
    const label = running
      ? `${runPrefix}step ${cur.idx}/${total} — <b>${esc(cur.module)}</b> <span class="run">running…</span>`
      : (done>=total && total>0 ? `${runPrefix}finished — ${done}/${total} steps`
         : `${runPrefix}step ${cur.idx}/${total} — <b>${esc(cur.module)}</b> (${esc(cur.status)})`);
    document.getElementById('status').innerHTML =
      `<div class="bar"><div class="fill" style="width:${pct}%"></div></div>`+
      `<div class="barlabel">${label}</div>${cumLine}`;
  } else { document.getElementById('status').textContent='no steps recorded yet'; }
  document.getElementById('steps').innerHTML = renderSteps(p.steps||[]);
  // Previous runs: everything except runs[0] (the current run shown above).
  const older = (p.runs||[]).slice(1);
  document.getElementById('runs').innerHTML = older.length
    ? `<div class="runs-hd">Previous runs</div>` + older.map(renderRun).join('') : "";
}
function renderSteps(steps){
  return steps.map(s=>{
    const cls={completed:'s-done',failed:'s-fail',running:'s-run'}[s.status]||'s-pend';
    const mark={completed:'✓',failed:'✗',running:'▶'}[s.status]||'·';
    // Queued steps (not yet started) have no index — show a queue marker, no "null.".
    const label = (s.idx==null) ? esc(s.module) : `${s.idx}. ${esc(s.module)}`;
    return `<span class="step ${cls}" title="${esc(s.status)}">${mark} ${label}</span>`;
  }).join('');
}
const RUN_STATUS = {completed:'completed', completed_with_errors:'completed with errors',
  running:'running', incomplete:'incomplete', pending:'pending'};
function fmtRunDur(s){
  if(s==null) return '';
  if(s<60) return `${Math.round(s)}s`;
  if(s<3600) return `${Math.floor(s/60)}m ${Math.round(s%60)}s`;
  return `${Math.floor(s/3600)}h ${Math.floor(s%3600/60)}m`;
}
function renderRun(r){
  const open = openRuns.has(r.run_seq);
  const dur = fmtRunDur(r.duration_s);
  const fail = r.failed ? ` · ${r.failed} failed` : '';
  const head = `<div class="run-hd" data-seq="${r.run_seq}">`+
    `<span class="caret">${open?'▾':'▸'}</span>Run ${r.run_seq} · `+
    `<span class="run-st st-${r.status}">${RUN_STATUS[r.status]||r.status}</span> `+
    `${r.done}/${r.total}${fail}${dur?` · ${dur}`:''}</div>`;
  const body = open ? `<div class="steps run-steps">${renderSteps(r.steps||[])}</div>` : "";
  return `<div class="runbox">${head}${body}</div>`;
}
// Expand/collapse a previous run; openRuns persists across the 4s refresh.
const openRuns = new Set();
document.getElementById('runs').addEventListener('click',e=>{
  const hd=e.target.closest('.run-hd'); if(!hd) return;
  const seq=parseInt(hd.dataset.seq,10);
  if(openRuns.has(seq)) openRuns.delete(seq); else openRuns.add(seq);
  refreshStatus();
});
// clicking an overview card jumps to that view
document.getElementById('cards').addEventListener('click',e=>{
  const card=e.target.closest('.card[data-view]'); if(card) showView(card.dataset.view);
});

async function refresh(){
  try{
    await refreshStatus();
    if(currentView==="findings") await fetchFindings();
    else if(currentView==="screenshots") await fetchScreenshots();
    else if(GENERIC[currentView]) await fetchGeneric(currentView);
    document.getElementById('livelabel').textContent='live';
    document.getElementById('dot').classList.remove('off');
  }catch(e){
    document.getElementById('livelabel').textContent='disconnected';
    document.getElementById('dot').classList.add('off');
  }
}
/* ---------------- lightbox (click a thumbnail for the full image) --------- */
const lb = document.getElementById('lightbox');
const lbImg = document.getElementById('lb-img');
const lbLink = document.getElementById('lb-link');
function openLightbox(full, url){
  lbImg.src = full;
  if(url){ lbLink.href = safeUrl(url); lbLink.textContent = url; lbLink.style.display=''; }
  else { lbLink.href = safeUrl(full); lbLink.textContent = 'open image'; lbLink.style.display=''; }
  lb.classList.add('open');
}
function closeLightbox(){ lb.classList.remove('open'); lbImg.src=''; }
// delegated: any .lb-open thumbnail in the web table or the gallery
document.body.addEventListener('click',e=>{
  const img=e.target.closest('img.lb-open');
  if(img){ e.stopPropagation();
    openLightbox(img.dataset.full, img.dataset.url); return; }
});
document.getElementById('lb-close').addEventListener('click',closeLightbox);
lb.addEventListener('click',e=>{ if(e.target===lb) closeLightbox(); }); // backdrop
document.addEventListener('keydown',e=>{ if(e.key==='Escape') closeLightbox(); });

refresh(); setInterval(refresh, 4000);
</script>
</body></html>"""
