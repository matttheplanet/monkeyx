"""Per-engagement SQLite store (``scan.db``) for the MonkeyX engine.

One database per engagement, living next to ``discovery-ledger.jsonl`` at
``output_dir/scan.db``. It is engine-owned and single-writer: ``--continue`` /
``--resume`` reopen the *same* file and upsert, so the schema setup is
idempotent (``CREATE TABLE IF NOT EXISTS`` + guarded ``ALTER TABLE``).

This module is the source of truth for new consumers (report renderers,
downstream tooling) while the engine keeps dual-writing the legacy JSONL for
existing ones. Every call site wraps these helpers so a DB error is logged and
never aborts a scan — the JSONL remains the fallback.

Design notes:
- Stdlib ``sqlite3`` only (matches ``core/knowledge.py``); no ORM.
- A single long-lived connection per ``ScanDB`` guarded by a ``threading.Lock``.
  ``check_same_thread=False`` lets a parallel-group worker thread reuse it; every
  write goes through the lock, so cross-thread use is safe. WAL lets downstream
  readers (report renderers, tooling) read while the engine writes.
- All SQL is parameterized. No shell, no string-built queries.
"""

# PEP 604 (X | None) annotations are used below; the future import makes them
# lazy strings so the bundled standalone viewer also runs on Python 3.9 (macOS
# ships 3.9 by default) — not just the documented 3.10+.
from __future__ import annotations

import hashlib
import logging
import os
import sqlite3
import threading
import uuid
from datetime import datetime, timezone

logger = logging.getLogger("monkeyx.core.scan_db")

SCHEMA_VERSION = 9

# Findings-type records that earn a row in `findings`. Open ports are tracked in
# the `ports` table (via the ledger), not here, so findings stay signal.
FINDING_TYPES = frozenset({
    "nuclei_finding", "script_output", "finding", "vulnerability", "dns_security",
})

# Record types that are ALWAYS genuine findings (independent of severity).
# NOTE: this deliberately EXCLUDES "script_output" — an nmap script row is
# context (ssl-cert, http-title, service banners) unless it was reclassified to
# "vulnerability" by normalize's state-aware NSE classifier. FINDING_TYPES above
# governs what gets MINTED into the findings table (script_output stays, as
# queryable context); REAL_FINDING_TYPES governs what counts as a FINDING in
# views/reports/CSV so info context doesn't drown the genuine findings.
REAL_FINDING_TYPES = frozenset({
    "nuclei_finding", "finding", "vulnerability", "dns_security",
})


def is_finding_record(record) -> bool:
    """True if a normalized record is a genuine finding (for views/counts).

    A record counts as a finding when its type is a real finding type, OR it
    carries a non-info severity (a below-'finding'-typed row that a tool still
    rated). Excludes open_port and info-level script_output context.
    """
    rtype = record.get("type")
    if rtype in REAL_FINDING_TYPES:
        return True
    sev = (record.get("severity") or "").lower()
    return bool(sev) and sev != "info"


def focus_includes_info(verdict, poc_command=None) -> bool:
    """Whether an info/unrated finding still earns a place in the focus list.

    The focus list normally suppresses info-severity noise (tech-detect, script
    output) — see :func:`is_finding_record`. But when something has actively
    *flagged* an info finding it is signal, not noise: a validation reached a
    non-dismissive verdict (``confirmed``/``unclear``) or produced proof (a
    ``poc_command``). Those surface. Refuted or unverified info stays out —
    it was either dismissed or never examined. Used by both modules/focus.py and
    the webserver focus view so the report and the live view never diverge.
    """
    return (verdict or "").lower() in ("confirmed", "unclear") or bool(poc_command)


def in_focus(record, verdict=None, poc_command=None) -> bool:
    """Whether a finding earns a place in the prioritized focus list / view.

    Focus is the "where do I start" shortlist, a STRICTER gate than
    :func:`is_finding_record` (which governs the findings table / CSV, where an
    info-severity detection is legitimately kept as context). A finding is in
    focus when it is a genuine finding with a REAL (non-info) severity, OR it was
    actively flagged (validated confirmed/unclear, or carries proof — see
    :func:`focus_includes_info`).

    Without this, nuclei's info-severity detections (tech-detect, DNS SPF/MX/NS
    fingerprints, wildcard-dns, ...) count as findings via their `nuclei_finding`
    type and drown the list — a real run produced 138 such rows. Used by both
    modules/focus.py and the webserver focus view so report and live view agree.
    """
    sev = (record.get("severity") or "").lower()
    if is_finding_record(record) and sev != "info":
        return True
    return focus_includes_info(verdict, poc_command)


# --------------------------------------------------------------------------- #
# Stable identity
# --------------------------------------------------------------------------- #

def norm_host(value) -> str:
    """Canonical host form: lowercased, trailing dot stripped.

    Kept identical to ``eval_harness._norm_host`` so the two never drift — the
    finding_id join depends on both sides normalizing the same way.
    """
    return str(value or "").lower().rstrip(".")


_IPV4_RE = __import__("re").compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def _looks_like_hostname(v: str) -> bool:
    v = (v or "").strip()
    return bool(v) and "." in v and "/" not in v and " " not in v \
        and not _IPV4_RE.match(v)


def host_ip_maps_from_parents(conn) -> tuple[dict, dict]:
    """Build (host_to_ip, ip_to_hosts) from the target_parents table.

    dnsx re-logs an IP with each hostname it resolved from/to as a parent
    (row: target=<ip> type=ip parent=<hostname>), so those rows give the
    IP↔hostname linkage the finding dedup needs — read-only, from scan.db alone.
    """
    host_to_ip: dict[str, str] = {}
    ip_to_hosts: dict[str, set] = {}
    try:
        rows = conn.execute(
            "SELECT target, target_type, parent FROM target_parents "
            "WHERE target_type='ip'").fetchall()
    except Exception:
        return host_to_ip, ip_to_hosts
    for r in rows:
        ip = (r["target"] if hasattr(r, "keys") else r[0]) or ""
        parent = (r["parent"] if hasattr(r, "keys") else r[2]) or ""
        if not _IPV4_RE.match(ip) or not _looks_like_hostname(parent):
            continue
        h = norm_host(parent)
        ip_to_hosts.setdefault(ip, set()).add(h)
        host_to_ip.setdefault(h, ip)   # first-wins; a host maps to one IP here
    return host_to_ip, ip_to_hosts


def dedup_ip_hostname_findings(rows: list, host_to_ip: dict, claim_key: str = "claim") -> list:
    """Collapse the weburls IP↔hostname dual-emit for PRESENTATION only.

    Same finding (same claim/port/proto) minted once on a bare IP and once on a
    hostname that resolves to it → keep the HOSTNAME row (host stays the name)
    with its resolved ``ip`` stamped alongside, and drop the redundant bare-IP
    row. Distinct vhosts on a shared IP stay separate; an IP-only finding keeps
    host=IP with ip=itself. Never merges across different claim/port/proto, and
    never touches scan.db (raw rows remain the source of truth). Input rows are
    dicts; returns new dicts with an added ``ip`` key, order-preserving.
    """
    from collections import defaultdict
    groups = defaultdict(list)
    order = []
    for r in rows:
        k = (r.get(claim_key), r.get("port"), r.get("proto"))
        if k not in groups:
            order.append(k)
        groups[k].append(r)

    out = []
    for k in order:
        members = groups[k]
        # IPs that some hostname-member in this group resolves to.
        hostname_ips = {host_to_ip.get(norm_host(m.get("host") or ""))
                        for m in members
                        if not _IPV4_RE.match(str(m.get("host") or ""))}
        hostname_ips.discard(None)
        for m in members:
            host = str(m.get("host") or "")
            r = dict(m)
            if _IPV4_RE.match(host):
                if host in hostname_ips:
                    continue                       # dual-emit duplicate — drop the IP row
                r["ip"] = host                     # IP-only finding
            else:
                r["ip"] = host_to_ip.get(norm_host(host))  # hostname primary, IP alongside
            out.append(r)
    return out


def finding_id(host, port, proto, claim) -> str:
    """First 12 hex of ``sha1("{host}|{port}|{proto}|{claim}")``.

    Components are normalized so the same finding always hashes the same,
    whoever computes it (normalize at mint time, ai_validate at join time):
    host via :func:`norm_host`, port as a bare int (``""`` when absent), proto
    lowercased, claim as-is (tool discriminator — template id / script id /
    dns check / bbot type).
    """
    h = norm_host(host)
    p = "" if port in (None, "") else str(int(port))
    pr = str(proto or "").lower()
    c = str(claim or "")
    raw = f"{h}|{p}|{pr}|{c}"
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:12]


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


# --------------------------------------------------------------------------- #
# Schema
# --------------------------------------------------------------------------- #

_DDL = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);

-- Raw --exclude rule lines, so --continue/--resume honor exclusions even when
-- --exclude isn't re-passed. Stored verbatim and re-parsed by seed_exclusions.
CREATE TABLE IF NOT EXISTS exclusions (
    rule TEXT PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS targets (
    target        TEXT NOT NULL,
    target_type   TEXT NOT NULL,
    source        TEXT,
    scope         TEXT,
    in_scope      INTEGER NOT NULL DEFAULT 0,
    channel       TEXT,
    parent        TEXT,
    discovered_at TEXT,
    PRIMARY KEY (target, target_type)
);
CREATE INDEX IF NOT EXISTS idx_targets_type ON targets(target_type);
CREATE INDEX IF NOT EXISTS idx_targets_parent ON targets(parent);

CREATE TABLE IF NOT EXISTS ports (
    host       TEXT NOT NULL,
    port       INTEGER NOT NULL,
    proto      TEXT NOT NULL DEFAULT 'tcp',
    state      TEXT DEFAULT 'open',
    service    TEXT,
    product    TEXT,
    version    TEXT,
    banner     TEXT,
    tunnel     TEXT,
    reason     TEXT,
    method     TEXT,
    confidence TEXT,
    extra      TEXT,
    source     TEXT,
    updated_at TEXT,
    verdict          TEXT,
    verdict_evidence TEXT,
    PRIMARY KEY (host, port, proto)
);
CREATE INDEX IF NOT EXISTS idx_ports_host ON ports(host);

CREATE TABLE IF NOT EXISTS target_parents (
    target      TEXT NOT NULL,
    target_type TEXT NOT NULL,
    parent      TEXT NOT NULL,
    PRIMARY KEY (target, target_type, parent)
);
CREATE INDEX IF NOT EXISTS idx_target_parents_lookup ON target_parents(target, target_type);
CREATE INDEX IF NOT EXISTS idx_target_parents_parent ON target_parents(parent);

CREATE TABLE IF NOT EXISTS web_endpoints (
    host         TEXT NOT NULL,
    url          TEXT NOT NULL,
    port         INTEGER,
    scheme       TEXT,
    status_code  INTEGER,
    title        TEXT,
    webserver    TEXT,
    tech         TEXT,
    content_type TEXT,
    cdn          INTEGER DEFAULT 0,
    tls          TEXT,
    screenshot   TEXT,
    source_file  TEXT,
    updated_at   TEXT,
    PRIMARY KEY (host, url)
);
CREATE INDEX IF NOT EXISTS idx_web_endpoints_host ON web_endpoints(host);

CREATE TABLE IF NOT EXISTS web_dirs (
    host        TEXT,
    url         TEXT NOT NULL,
    port        INTEGER,
    status_code INTEGER,
    size        INTEGER,
    words       INTEGER,
    lines       INTEGER,
    tool        TEXT NOT NULL,
    source_file TEXT,
    updated_at  TEXT,
    PRIMARY KEY (url, tool)
);
CREATE INDEX IF NOT EXISTS idx_web_dirs_host ON web_dirs(host);

CREATE TABLE IF NOT EXISTS mx_domains (
    domain   TEXT PRIMARY KEY,
    mx_hosts TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id     TEXT PRIMARY KEY,
    host           TEXT NOT NULL,
    hostname       TEXT,
    port           INTEGER,
    proto          TEXT,
    claim          TEXT NOT NULL,
    tool           TEXT NOT NULL,
    type           TEXT,
    severity       TEXT,
    title          TEXT,
    template       TEXT,
    description    TEXT,
    detail         TEXT,
    matched_at     TEXT,
    cve_id         TEXT,
    cwe_id         TEXT,
    matcher_name   TEXT,
    tags           TEXT,
    source_file    TEXT,
    first_seen     TEXT,
    last_seen      TEXT,
    verdict        TEXT,
    triage_status  TEXT NOT NULL DEFAULT 'new',
    false_positive INTEGER NOT NULL DEFAULT 0,
    notes          TEXT
);
CREATE INDEX IF NOT EXISTS idx_findings_host ON findings(host, port);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_verdict ON findings(verdict);

CREATE TABLE IF NOT EXISTS validations (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id   TEXT,
    host         TEXT,
    port         INTEGER,
    proto        TEXT,
    verdict      TEXT NOT NULL,
    evidence     TEXT,
    poc_command  TEXT,
    severity     TEXT,
    action       TEXT,
    tool_history TEXT,
    created_at   TEXT,
    FOREIGN KEY (finding_id) REFERENCES findings(finding_id)
);
CREATE INDEX IF NOT EXISTS idx_validations_finding ON validations(finding_id);
CREATE INDEX IF NOT EXISTS idx_validations_port ON validations(host, port, proto);

CREATE TABLE IF NOT EXISTS progress_events (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    event            TEXT NOT NULL,
    step             TEXT,
    idx              INTEGER,
    total_steps      INTEGER,
    run_seq          INTEGER,
    started_at       TEXT,
    finished_at      TEXT,
    duration_seconds REAL,
    error            TEXT,
    raw              TEXT
);

CREATE TABLE IF NOT EXISTS module_runs (
    module      TEXT PRIMARY KEY,
    runs        INTEGER NOT NULL DEFAULT 0,
    last_run    TEXT,
    last_status TEXT
);

CREATE TABLE IF NOT EXISTS module_coverage (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    module      TEXT NOT NULL,
    target      TEXT NOT NULL,
    target_type TEXT,               -- target | url | domain
    run_seq     INTEGER,            -- which invocation (history across --continue)
    step_index  INTEGER,
    status      TEXT NOT NULL DEFAULT 'fed',  -- fed | step_failed | reached | no_response
    ts          TEXT
);
CREATE INDEX IF NOT EXISTS idx_coverage_target ON module_coverage(target);
CREATE INDEX IF NOT EXISTS idx_coverage_module_run ON module_coverage(module, run_seq);
"""

# Columns added after v1 ship go here as (table, column, coldef) so reopening an
# older scan.db on --continue self-heals.
# New TABLES don't need entries — CREATE TABLE IF NOT EXISTS in _DDL adds them.
_ADDED_COLUMNS: tuple[tuple[str, str, str], ...] = (
    # v2: widen ports with nmap detail fields (analyze reads these)
    ("ports", "tunnel", "TEXT"),
    ("ports", "reason", "TEXT"),
    ("ports", "method", "TEXT"),
    ("ports", "confidence", "TEXT"),
    ("ports", "extra", "TEXT"),
    # v2: widen findings for nuclei / evidence-grounding parity
    ("findings", "hostname", "TEXT"),
    ("findings", "template", "TEXT"),
    ("findings", "description", "TEXT"),
    ("findings", "cwe_id", "TEXT"),
    ("findings", "matcher_name", "TEXT"),
    # v3: per-invocation progress scoping (distinguish --continue runs)
    ("progress_events", "run_seq", "INTEGER"),
    # v4: ai_validate verdicts link to a port/service (recommendations are
    # port-scoped, not per-finding), and the verdict surfaces on the port.
    ("validations", "proto", "TEXT"),
    ("ports", "verdict", "TEXT"),
    ("ports", "verdict_evidence", "TEXT"),
    # v5: gowitness screenshot path (relative to output-dir root) so the web
    # view / report can render a thumbnail per endpoint.
    ("web_endpoints", "screenshot", "TEXT"),
    # v7: authorization channel per target (t=host-full/-t, dl/ul=name-safe) so
    # the web view / report can show the scanning ceiling, not just in_scope.
    ("targets", "channel", "TEXT"),
    # v8: gowitness perceptual-hash group id, carried from gowitness.sqlite3 so
    # the web view can group visually-similar screenshots (gowitness's built-in
    # similarity) even when ai_analyze_gowitness has not run.
    ("web_endpoints", "phash_group", "INTEGER"),
    # v9: MonkeyX severity re-rating (see core/severity_rerate.py). `severity`
    # stays the EFFECTIVE (elevated) rating everything sorts by; these preserve
    # the tool's own rating + why we elevated, so the change is auditable.
    ("findings", "original_severity", "TEXT"),
    ("findings", "severity_source", "TEXT"),
    ("findings", "rerate_reason", "TEXT"),
)


def db_path_for(output_dir: str) -> str:
    return os.path.join(output_dir, "scan.db")


# --------------------------------------------------------------------------- #
# Connection wrapper
# --------------------------------------------------------------------------- #

class ScanDB:
    """A single engagement's SQLite handle with its own write lock.

    All mutating methods are atomic (one committed transaction) and serialized
    by ``self._lock``, so the handle is safe to share across the engine's
    parallel-group worker threads.
    """

    def __init__(self, output_dir: str):
        self.path = db_path_for(output_dir)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, timeout=30.0, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.execute("PRAGMA busy_timeout=30000")
        self._ensure_schema()

    # -- schema -------------------------------------------------------------- #

    def _ensure_schema(self) -> None:
        with self._lock:
            self._conn.executescript(_DDL)
            existing = {}
            for table, column, coldef in _ADDED_COLUMNS:
                cols = existing.get(table)
                if cols is None:
                    cols = {
                        r["name"]
                        for r in self._conn.execute(f"PRAGMA table_info({table})")
                    }
                    existing[table] = cols
                if column not in cols:
                    self._conn.execute(
                        f"ALTER TABLE {table} ADD COLUMN {column} {coldef}"
                    )
                    cols.add(column)
            # Reflect the code that last opened this DB (not just creation), so a
            # v1 file reopened by v2 code reports 2 after its columns are ALTERed in.
            self._conn.execute(
                """
                INSERT INTO meta(key, value) VALUES('schema_version', ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (str(SCHEMA_VERSION),),
            )
            self._conn.commit()

    def close(self, checkpoint: bool = True) -> None:
        """Optionally checkpoint the WAL into the main file, then close.

        Truncating the WAL makes scan.db self-contained on disk — important
        because a downstream consumer may archive the output dir and open scan.db
        without the -wal/-shm sidecars. Best-effort: a checkpoint failure must
        not stop the close.

        Pass ``checkpoint=False`` for a short-lived secondary handle (e.g.
        normalize opening its own connection) so the run's final
        ``ledger.close()`` is the sole checkpointer and can't race an open write
        transaction on another handle.
        """
        with self._lock:
            if checkpoint:
                try:
                    self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                except sqlite3.Error as exc:  # pragma: no cover - defensive
                    logger.warning("scan.db WAL checkpoint failed: %s", exc)
            self._conn.close()

    # -- findings ------------------------------------------------------------ #

    def upsert_finding(self, *, finding_id, host, port, proto, claim, tool,
                       type=None, severity=None, title=None, detail=None,
                       matched_at=None, cve_id=None, tags=None, source_file=None,
                       hostname=None, template=None, description=None,
                       cwe_id=None, matcher_name=None, now=None) -> None:
        """Insert a finding, or refresh evidence fields if it already exists.

        Triage columns (verdict / triage_status / false_positive / notes) are
        NEVER written here, so a ``--continue`` re-normalize can't wipe a verdict
        an agent or operator recorded on a prior run. ``first_seen`` is set once;
        ``last_seen`` and the richer-of evidence fields refresh on conflict.
        """
        ts = now or _iso_now()
        # MonkeyX severity re-rating (elevate-only, curated allowlist): `severity`
        # becomes the EFFECTIVE rating everything sorts by; the tool's own rating
        # is preserved in `original_severity` with a source + reason so the change
        # is auditable. See core/severity_rerate.py. Centralized here so every
        # finding writer (normalize, ai_analyze_gowitness, …) is consistent.
        from core.severity_rerate import rerate
        effective, sev_source, rerate_reason = rerate(claim, severity)
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO findings (
                    finding_id, host, hostname, port, proto, claim, tool, type,
                    severity, original_severity, severity_source, rerate_reason,
                    title, template, description, detail, matched_at,
                    cve_id, cwe_id, matcher_name, tags, source_file,
                    first_seen, last_seen
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(finding_id) DO UPDATE SET
                    last_seen         = excluded.last_seen,
                    severity          = COALESCE(excluded.severity, findings.severity),
                    original_severity = COALESCE(excluded.original_severity, findings.original_severity),
                    severity_source   = COALESCE(excluded.severity_source, findings.severity_source),
                    rerate_reason     = COALESCE(excluded.rerate_reason, findings.rerate_reason),
                    title        = COALESCE(excluded.title, findings.title),
                    template     = COALESCE(excluded.template, findings.template),
                    description  = COALESCE(excluded.description, findings.description),
                    detail       = COALESCE(excluded.detail, findings.detail),
                    matched_at   = COALESCE(excluded.matched_at, findings.matched_at),
                    cve_id       = COALESCE(excluded.cve_id, findings.cve_id),
                    cwe_id       = COALESCE(excluded.cwe_id, findings.cwe_id),
                    matcher_name = COALESCE(excluded.matcher_name, findings.matcher_name),
                    hostname     = COALESCE(excluded.hostname, findings.hostname),
                    tags         = COALESCE(excluded.tags, findings.tags)
                """,
                (finding_id, norm_host(host), hostname, port, proto, claim, tool,
                 type, effective, severity, sev_source, rerate_reason,
                 title, template, description, detail, matched_at,
                 cve_id, cwe_id, matcher_name, tags, source_file, ts, ts),
            )
            self._conn.commit()

    def set_verdict(self, finding_id, verdict) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE findings SET verdict = ? WHERE finding_id = ?",
                (verdict, finding_id),
            )
            self._conn.commit()

    def prune_findings_by_source(self, source_file, keep_ids) -> int:
        """Delete findings from one source_file whose finding_id isn't in keep_ids.

        For a regenerating writer (e.g. ai_analyze_gowitness) that re-mints on a
        ``--continue``: upsert refreshes rows it writes again, but rows whose key
        changed (the LLM recategorized a page) or that are no longer produced
        would otherwise linger as stale duplicates. Scoping the delete to one
        ``source_file`` means we only prune that writer's own output — scanner
        findings (nuclei/nmap/…) are never touched. Returns rows deleted.
        """
        keep = set(keep_ids or ())
        with self._lock:
            rows = self._conn.execute(
                "SELECT finding_id FROM findings WHERE source_file = ?",
                (source_file,),
            ).fetchall()
            stale = [r[0] for r in rows if r[0] not in keep]
            for fid in stale:
                self._conn.execute(
                    "DELETE FROM findings WHERE finding_id = ?", (fid,))
            self._conn.commit()
        return len(stale)

    def get_finding(self, finding_id) -> sqlite3.Row | None:
        with self._lock:
            cur = self._conn.execute(
                "SELECT * FROM findings WHERE finding_id = ?", (finding_id,)
            )
            return cur.fetchone()

    def fed_coverage_targets(self, module, run_seq, step_index) -> list[str]:
        """Targets recorded 'fed' for one module run/step — a lock-held read of
        the shared connection (coverage reconciliation calls this from the
        post-step path; never reach into _conn directly and skip the lock)."""
        with self._lock:
            cur = self._conn.execute(
                "SELECT target FROM module_coverage "
                "WHERE module=? AND run_seq IS ? AND step_index IS ? AND status='fed'",
                (module, run_seq, step_index),
            )
            return [r["target"] for r in cur.fetchall()]

    def findings_at(self, host, port) -> list[sqlite3.Row]:
        """All findings on a (host, port). port=None matches host-level rows."""
        h = norm_host(host)
        with self._lock:
            if port is None:
                cur = self._conn.execute(
                    "SELECT * FROM findings WHERE host = ? AND port IS NULL", (h,)
                )
            else:
                cur = self._conn.execute(
                    "SELECT * FROM findings WHERE host = ? AND port = ?", (h, port)
                )
            return cur.fetchall()

    def focus_rows(self) -> list[sqlite3.Row]:
        """Findings joined to their latest validation, for the focus list.

        One row per finding. When a finding has several validation rows (a
        re-run/--continue can add more), the most recent by ``id`` wins so the
        verdict/evidence reflect the latest attempt. Verdict on the finding is
        preferred (ai_validate writes it there on an exact join); the joined
        validation supplies evidence/poc_command/action for display.
        """
        with self._lock:
            cur = self._conn.execute(
                """
                SELECT f.finding_id, f.host, f.hostname, f.port, f.proto, f.type,
                       f.severity, f.original_severity, f.severity_source,
                       f.rerate_reason, f.title, f.tool, f.cve_id, f.verdict,
                       f.triage_status, f.false_positive,
                       v.evidence AS v_evidence, v.poc_command AS v_poc_command,
                       v.action AS v_action, v.verdict AS v_verdict
                FROM findings f
                LEFT JOIN validations v
                  ON v.id = (
                      SELECT id FROM validations
                      WHERE finding_id = f.finding_id
                      ORDER BY id DESC LIMIT 1
                  )
                """
            )
            return cur.fetchall()

    # -- validations --------------------------------------------------------- #

    def record_validation(self, *, finding_id, host, port, verdict, proto=None,
                          evidence=None, poc_command=None, severity=None,
                          action=None, tool_history=None, now=None) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO validations (
                    finding_id, host, port, proto, verdict, evidence, poc_command,
                    severity, action, tool_history, created_at
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?)
                """,
                (finding_id, norm_host(host) if host else host, port,
                 str(proto).lower() if proto else proto, verdict,
                 evidence, poc_command, severity, action, tool_history,
                 now or _iso_now()),
            )
            self._conn.commit()

    def set_port_verdict(self, *, host, port, proto="tcp", verdict,
                         evidence=None) -> int:
        """Record an ai_validate verdict on a port/service. Returns rows updated.

        ai_validate assesses AI recommendations, which are scoped to a service on
        a port (e.g. "Test Exchange SMTP on host:587"), not to a single finding.
        This lands the verdict on the ports row so it surfaces the same way
        findings.verdict does, even when no exact finding_id join exists.
        """
        with self._lock:
            cur = self._conn.execute(
                """
                UPDATE ports SET verdict = ?, verdict_evidence = ?
                WHERE host = ? AND port = ? AND proto = ?
                """,
                (verdict, evidence, norm_host(host) if host else host,
                 port, str(proto or "tcp").lower()),
            )
            self._conn.commit()
            return cur.rowcount

    # -- ledger mirror ------------------------------------------------------- #

    def upsert_target(self, *, target, target_type, source=None, scope=None,
                      in_scope=False, channel=None, parent=None,
                      discovered_at=None, now=None) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO targets (
                    target, target_type, source, scope, in_scope, channel,
                    parent, discovered_at
                ) VALUES (?,?,?,?,?,?,?,?)
                ON CONFLICT(target, target_type) DO UPDATE SET
                    source   = COALESCE(excluded.source, targets.source),
                    scope    = COALESCE(excluded.scope, targets.scope),
                    in_scope = excluded.in_scope,
                    channel  = COALESCE(excluded.channel, targets.channel),
                    parent   = COALESCE(excluded.parent, targets.parent),
                    discovered_at =
                        COALESCE(targets.discovered_at, excluded.discovered_at)
                """,
                (target, target_type, source, scope, 1 if in_scope else 0,
                 channel, parent, discovered_at or now or _iso_now()),
            )
            self._conn.commit()

    def replace_target_parents(self, target, target_type, parents) -> None:
        """Set the full parent set for a target (DELETE then bulk insert).

        The scalar targets.parent column keeps one parent for back-compat; this
        side-table is the authoritative multi-parent record that
        get_ip_to_hostnames / URL synthesis depend on.
        """
        with self._lock:
            self._conn.execute(
                "DELETE FROM target_parents WHERE target = ? AND target_type = ?",
                (target, target_type),
            )
            clean = sorted(p for p in parents if p)
            self._conn.executemany(
                "INSERT OR IGNORE INTO target_parents "
                "(target, target_type, parent) VALUES (?,?,?)",
                [(target, target_type, p) for p in clean],
            )
            self._conn.commit()

    def upsert_port(self, *, host, port, proto="tcp", state="open", service=None,
                    product=None, version=None, banner=None, tunnel=None,
                    reason=None, method=None, confidence=None, extra=None,
                    source=None, now=None) -> None:
        """Last-write-wins on (host, port, proto); only non-empty fields overwrite."""
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO ports (
                    host, port, proto, state, service, product, version, banner,
                    tunnel, reason, method, confidence, extra, source, updated_at
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(host, port, proto) DO UPDATE SET
                    state      = COALESCE(NULLIF(excluded.state, ''), ports.state),
                    service    = COALESCE(NULLIF(excluded.service, ''), ports.service),
                    product    = COALESCE(NULLIF(excluded.product, ''), ports.product),
                    version    = COALESCE(NULLIF(excluded.version, ''), ports.version),
                    banner     = COALESCE(NULLIF(excluded.banner, ''), ports.banner),
                    tunnel     = COALESCE(NULLIF(excluded.tunnel, ''), ports.tunnel),
                    reason     = COALESCE(NULLIF(excluded.reason, ''), ports.reason),
                    method     = COALESCE(NULLIF(excluded.method, ''), ports.method),
                    confidence = COALESCE(NULLIF(excluded.confidence, ''), ports.confidence),
                    extra      = COALESCE(NULLIF(excluded.extra, ''), ports.extra),
                    source     = COALESCE(NULLIF(excluded.source, ''), ports.source),
                    updated_at = excluded.updated_at
                """,
                (norm_host(host), port, proto, state, service, product, version,
                 banner, tunnel, reason, method, confidence, extra, source,
                 now or _iso_now()),
            )
            self._conn.commit()

    def upsert_web_endpoint(self, *, host, url, port=None, scheme=None,
                            status_code=None, title=None, webserver=None,
                            tech=None, content_type=None, cdn=False, tls=None,
                            screenshot=None, phash_group=None,
                            source_file=None, now=None) -> None:
        """Last-write-wins on (host, url); only non-empty fields overwrite.

        ``tech`` and ``tls`` are JSON strings. Populated from httpx output (which
        is never normalized), so ai_analyze's web-service reader can move to the DB.
        ``screenshot`` is a gowitness image path relative to the output-dir root
        (so it resolves from an unzipped deliverable); linked in a later pass.
        ``phash_group`` is gowitness's perceptual-hash group id (visual similarity).
        """
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO web_endpoints (
                    host, url, port, scheme, status_code, title, webserver, tech,
                    content_type, cdn, tls, screenshot, phash_group, source_file, updated_at
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(host, url) DO UPDATE SET
                    port         = COALESCE(excluded.port, web_endpoints.port),
                    scheme       = COALESCE(NULLIF(excluded.scheme, ''), web_endpoints.scheme),
                    status_code  = COALESCE(excluded.status_code, web_endpoints.status_code),
                    title        = COALESCE(NULLIF(excluded.title, ''), web_endpoints.title),
                    webserver    = COALESCE(NULLIF(excluded.webserver, ''), web_endpoints.webserver),
                    tech         = COALESCE(NULLIF(excluded.tech, ''), web_endpoints.tech),
                    content_type = COALESCE(NULLIF(excluded.content_type, ''), web_endpoints.content_type),
                    cdn          = excluded.cdn,
                    tls          = COALESCE(NULLIF(excluded.tls, ''), web_endpoints.tls),
                    screenshot   = COALESCE(NULLIF(excluded.screenshot, ''), web_endpoints.screenshot),
                    phash_group  = COALESCE(excluded.phash_group, web_endpoints.phash_group),
                    updated_at   = excluded.updated_at
                """,
                (norm_host(host), url, port, scheme, status_code, title, webserver,
                 tech, content_type, 1 if cdn else 0, tls, screenshot, phash_group,
                 source_file, now or _iso_now()),
            )
            self._conn.commit()

    def upsert_web_dir(self, *, url, tool, host=None, port=None,
                       status_code=None, size=None, words=None, lines=None,
                       source_file=None, now=None) -> None:
        """Record a content-discovery hit (ffuf/feroxbuster). Deduped on
        (url, tool) so re-runs/--continue don't multiply rows; non-empty fields
        overwrite. Best-effort — the caller wraps writes so a DB error never
        aborts a scan."""
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO web_dirs (
                    host, url, port, status_code, size, words, lines, tool,
                    source_file, updated_at
                ) VALUES (?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(url, tool) DO UPDATE SET
                    host        = COALESCE(NULLIF(excluded.host, ''), web_dirs.host),
                    port        = COALESCE(excluded.port, web_dirs.port),
                    status_code = COALESCE(excluded.status_code, web_dirs.status_code),
                    size        = COALESCE(excluded.size, web_dirs.size),
                    words       = COALESCE(excluded.words, web_dirs.words),
                    lines       = COALESCE(excluded.lines, web_dirs.lines),
                    source_file = COALESCE(NULLIF(excluded.source_file, ''), web_dirs.source_file),
                    updated_at  = excluded.updated_at
                """,
                (norm_host(host) if host else host, url, port, status_code, size,
                 words, lines, tool, source_file, now or _iso_now()),
            )
            self._conn.commit()

    def set_web_screenshot(self, url: str, screenshot: str,
                           phash_group=None) -> int:
        """Attach a screenshot path (relative to output-dir root) to endpoint(s)
        matching ``url``. Keyed on url alone (host is derived), so a gowitness
        capture links regardless of which host the httpx row recorded. Also sets
        the perceptual-hash group id when provided (COALESCE — a real group id
        overwrites, None leaves it). Returns the number of rows updated (0 if the
        URL isn't a known endpoint)."""
        with self._lock:
            cur = self._conn.execute(
                "UPDATE web_endpoints SET screenshot = ?, "
                "phash_group = COALESCE(?, phash_group) WHERE url = ?",
                (screenshot, phash_group, url),
            )
            self._conn.commit()
            return cur.rowcount

    def upsert_mx_domain(self, domain, mx_hosts_json) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO mx_domains (domain, mx_hosts) VALUES (?, ?)
                ON CONFLICT(domain) DO UPDATE SET mx_hosts = excluded.mx_hosts
                """,
                (domain, mx_hosts_json),
            )
            self._conn.commit()

    def in_scope_targets(self) -> set[str]:
        """Set of targets currently flagged in_scope — for scope-parity checks."""
        with self._lock:
            cur = self._conn.execute(
                "SELECT target FROM targets WHERE in_scope = 1"
            )
            return {r["target"] for r in cur.fetchall()}

    def has_targets_of_type(self, target_type) -> bool:
        """True if any target of the given type exists (e.g. type='url')."""
        with self._lock:
            cur = self._conn.execute(
                "SELECT 1 FROM targets WHERE target_type = ? LIMIT 1",
                (target_type,),
            )
            return cur.fetchone() is not None

    # -- readers (for load_from_db + consumer migration; Stage C+) ----------- #

    def iter_targets(self) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute("SELECT * FROM targets").fetchall()

    def iter_target_parents(self) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute("SELECT * FROM target_parents").fetchall()

    def iter_ports(self) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute("SELECT * FROM ports").fetchall()

    def iter_mx_domains(self) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute("SELECT * FROM mx_domains").fetchall()

    # -- ledger-authoritative marker (for clean-break resume; Stage C/F) ----- #

    def set_meta(self, key, value) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO meta(key, value) VALUES(?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (key, str(value)),
            )
            self._conn.commit()

    def get_meta(self, key) -> str | None:
        with self._lock:
            cur = self._conn.execute(
                "SELECT value FROM meta WHERE key = ?", (key,)
            )
            row = cur.fetchone()
            return row["value"] if row else None

    # -- exclusion rules (persisted so continue/resume honor them) ----------- #

    def save_exclusions(self, rules) -> None:
        """Persist raw --exclude rule lines (idempotent; deduped by PK)."""
        rows = [(r,) for r in rules if r]
        if not rows:
            return
        with self._lock:
            self._conn.executemany(
                "INSERT INTO exclusions(rule) VALUES(?) ON CONFLICT(rule) DO NOTHING",
                rows,
            )
            self._conn.commit()

    def load_exclusions(self) -> list[str]:
        """Return the raw exclusion rule lines persisted by prior runs."""
        with self._lock:
            cur = self._conn.execute("SELECT rule FROM exclusions")
            return [row["rule"] for row in cur.fetchall()]

    def stamp_identity(self, engagement_uuid: str | None = None,
                       output_prefix: str | None = None) -> str:
        """Record durable engagement identity in ``meta``; return the uuid.

        ``engagement_uuid`` is **DB-level and stable**: it is set once (on first
        creation) and never overwritten, so a ``--continue``/``--resume`` that
        reopens the same scan.db keeps the original id even though the API mints
        a new per-run uuid each invocation. If none is supplied (CLI-only run, or
        an API that doesn't inject one), the engine generates one so every
        scan.db is always identifiable — the key a future cross-project rollup
        joins on. ``created_at`` is likewise first-wins; ``output_prefix`` is
        refreshed each run (last-continue prefix wins).
        """
        existing = self.get_meta("engagement_uuid")
        if not existing:
            existing = engagement_uuid or str(uuid.uuid4())
            self.set_meta("engagement_uuid", existing)
            self.set_meta("created_at", _iso_now())
        if output_prefix:
            self.set_meta("output_prefix", output_prefix)
        return existing

    def record_coverage(self, *, module, targets, target_type, run_seq=None,
                        step_index=None, status="fed", now=None) -> int:
        """Append coverage rows: 'module was fed these targets at this step'.

        One batched insert per module step (append-only, so run_seq history is
        preserved — a re-run via --continue adds a new batch rather than
        overwriting). `targets` is an iterable of target strings; empty/blank
        entries are skipped. Records INTENT (fed), not proven reach — Phase 2's
        reconciliation upgrades rows to reached/no_response. Returns rows written.
        Best-effort at the call site: callers wrap so a failure never aborts a run.
        """
        rows = [
            (module, str(t).strip(), target_type, run_seq, step_index,
             status, now or _iso_now())
            for t in (targets or []) if str(t).strip()
        ]
        if not rows:
            return 0
        with self._lock:
            self._conn.executemany(
                """
                INSERT INTO module_coverage
                    (module, target, target_type, run_seq, step_index, status, ts)
                VALUES (?,?,?,?,?,?,?)
                """,
                rows,
            )
            self._conn.commit()
        return len(rows)

    def mark_ledger_authoritative(self) -> None:
        """Stamp that a v2 run has persisted authoritative ledger state.

        A v1 scan.db reopened by v2 code gets its columns/tables ALTERed in
        automatically, so schema presence alone can't distinguish "genuinely
        migrated" from "old file self-healed". This marker is set by
        sync_scope_to_db once real authoritative state has been written, and
        gates DB-sourced resume (require_ledger_authoritative).
        """
        self.set_meta("ledger_authoritative", "1")

    def is_ledger_authoritative(self) -> bool:
        return self.get_meta("ledger_authoritative") == "1"

    def mark_run_dirty(self) -> None:
        """Record that a run is in progress and has not yet ended cleanly.

        Set once per invocation after the ledger has loaded prior state and
        before the scan starts writing new discoveries. It is cleared by
        mark_run_clean() at a graceful end. If the process is SIGKILLed / loses
        power mid-run, the flag stays 'dirty' so the next resume knows the
        persisted in_scope flags may be stale (a child mirrored before its
        parent was granted scope) and must be re-resolved rather than trusted.
        """
        self.set_meta("clean_shutdown", "0")

    def mark_run_clean(self) -> None:
        """Record that the run reached a graceful end with synced ledger state.

        Set at the run's clean-exit boundary, AFTER sync_scope_to_db() has
        persisted the fixpoint-resolved in_scope flags. Only then may a later
        load_from_db() trust those flags without re-running the scope fixpoint.
        """
        self.set_meta("clean_shutdown", "1")

    def was_clean_shutdown(self) -> bool:
        """True only if the last run set the clean marker (mark_run_clean).

        Absent (a pre-marker DB) or '0' (a crashed / in-progress run) both read
        as False, so load_from_db() conservatively re-resolves scope.
        """
        return self.get_meta("clean_shutdown") == "1"

    # -- progress / module history ------------------------------------------ #

    def record_progress_event(self, event: dict, raw: str) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO progress_events (
                    event, step, idx, total_steps, run_seq, started_at,
                    finished_at, duration_seconds, error, raw
                ) VALUES (?,?,?,?,?,?,?,?,?,?)
                """,
                (event.get("event"), event.get("step"), event.get("index"),
                 event.get("total_steps"), event.get("run_seq"),
                 event.get("started_at"), event.get("finished_at"),
                 event.get("duration_seconds"), event.get("error"), raw),
            )
            self._conn.commit()

    def next_run_seq(self) -> int:
        """Atomically allocate the next progress run sequence (1, 2, 3, …).

        Used by ProgressTracker so each invocation (fresh / --continue / --resume)
        stamps its events with a distinct run_seq, letting the web view separate
        'this run' from cumulative history.
        """
        with self._lock:
            cur = self._conn.execute(
                "SELECT value FROM meta WHERE key='progress_run_seq'").fetchone()
            nxt = (int(cur["value"]) if cur else 0) + 1
            self._conn.execute(
                "INSERT INTO meta(key, value) VALUES('progress_run_seq', ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (str(nxt),))
            self._conn.commit()
            return nxt

    def reconcile_coverage(self, *, module, run_seq, step_index,
                           reached=None, all_failed=False, now=None) -> int:
        """Upgrade this step's `fed` coverage rows to their outcome.

        Scoped to (module, run_seq, step_index) so only THIS run's rows change.
        - all_failed=True  -> every fed row becomes 'step_failed'.
        - otherwise         -> rows whose target is in `reached` become 'reached',
                              the remaining fed rows become 'no_response'
                              (fed + module finished + target absent from output =
                              the "maybe missed" bucket).
        Only rows still in 'fed' are touched (idempotent; a re-reconcile is safe).
        Returns rows updated.
        """
        ts = now or _iso_now()
        with self._lock:
            if all_failed:
                cur = self._conn.execute(
                    """UPDATE module_coverage SET status='step_failed', ts=?
                       WHERE module=? AND run_seq IS ? AND step_index IS ?
                         AND status='fed'""",
                    (ts, module, run_seq, step_index))
                self._conn.commit()
                return cur.rowcount
            reached_set = {str(t).strip() for t in (reached or []) if str(t).strip()}
            rows = self._conn.execute(
                """SELECT id, target FROM module_coverage
                   WHERE module=? AND run_seq IS ? AND step_index IS ?
                     AND status='fed'""",
                (module, run_seq, step_index)).fetchall()
            reached_ids = [r["id"] for r in rows if r["target"] in reached_set]
            missed_ids = [r["id"] for r in rows if r["target"] not in reached_set]
            if reached_ids:
                self._conn.executemany(
                    "UPDATE module_coverage SET status='reached', ts=? WHERE id=?",
                    [(ts, i) for i in reached_ids])
            if missed_ids:
                self._conn.executemany(
                    "UPDATE module_coverage SET status='no_response', ts=? WHERE id=?",
                    [(ts, i) for i in missed_ids])
            self._conn.commit()
            return len(reached_ids) + len(missed_ids)

    def current_run_seq(self) -> int:
        """Read the current progress run_seq WITHOUT allocating a new one.

        next_run_seq() increments (once per invocation, for the tracker); this is
        the read-only companion so coverage rows can be tagged with the same run
        the tracker is using. Returns 0 if no run has been allocated yet.
        """
        with self._lock:
            cur = self._conn.execute(
                "SELECT value FROM meta WHERE key='progress_run_seq'").fetchone()
            return int(cur["value"]) if cur else 0

    def bump_module_run(self, module, status, finished_at) -> None:
        """Increment a module's run count; keep the latest finish + its status.

        Timestamps are ISO-8601 UTC, so lexicographic compare orders them —
        matching ``summary._build_module_history``.
        """
        if not module:
            return
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO module_runs (module, runs, last_run, last_status)
                VALUES (?, 1, ?, ?)
                ON CONFLICT(module) DO UPDATE SET
                    runs = module_runs.runs + 1,
                    last_run = CASE
                        WHEN excluded.last_run >= COALESCE(module_runs.last_run, '')
                        THEN excluded.last_run ELSE module_runs.last_run END,
                    last_status = CASE
                        WHEN excluded.last_run >= COALESCE(module_runs.last_run, '')
                        THEN excluded.last_status ELSE module_runs.last_status END
                """,
                (module, finished_at, status),
            )
            self._conn.commit()


def open_db(output_dir: str) -> "ScanDB | None":
    """Open (creating if needed) the engagement scan.db.

    Returns None (and logs) on any failure, so callers can dual-write behind a
    simple truthiness check without the DB ever being able to abort a scan.
    """
    if not output_dir:
        return None
    try:
        return ScanDB(output_dir)
    except sqlite3.Error as exc:
        logger.warning("scan.db unavailable at %s: %s", output_dir, exc)
        return None
