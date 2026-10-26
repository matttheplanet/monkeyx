"""Prioritized focus list — the single "where do I start" deliverable.

Runs after ai_validate. Assembles ONE ranked list from data already produced,
with no new AI call:

  spine  — scan.db findings (LEFT JOIN validations): every atomic finding a
           scanner minted, plus its verdict/proof when ai_validate reached it.
  plus   — validated recommendations that map to NO finding row (multi-host
           attack chains, unmapped cve-research). ai_validate already recorded
           whether each rec resolved to a finding_id, so dedup is a set-membership
           check, not a re-run of the hashing join.
  fallback — if ai_validate didn't run (no validated-findings.json), read the
           ai_analyze recommendations directly so the chains still surface
           (tiered as unverified).

Sort is confirmed-first: a confirmed finding outranks an unverified one of the
same severity; refuted/false-positive rows sink to the bottom (kept for audit,
never dropped).

Output: {data_prefix}-focus.json, {reports_prefix}-focus.md. The markdown folds
into report.html automatically via html_report.py.
"""

import json
import logging
import os

from core.scan_db import ScanDB, in_focus
from core.utils import version_output_path

logger = logging.getLogger('monkeyx.modules.focus')

REQUIRED_INPUTS = frozenset()

# Lower rank sorts first.
_VERDICT_RANK = {"confirmed": 0, "unclear": 1, "unverified": 2,
                 "error": 2, None: 2, "refuted": 3}
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# ai_analyze recommendation category -> default severity when the rec carries
# none. Keys are the ai-analysis.json category names (plural). Only used on the
# fallback path (no ai_validate output); attack_chains carry an explicit impact.
_CATEGORY_DEFAULT_SEV = {
    "quick_wins": "high",
    "attack_chains": "high",
    "requires_verification": "medium",
    "cve_research": "medium",
}


def _rank_key(entry: dict) -> tuple:
    return (
        1 if entry.get("false_positive") else 0,
        _VERDICT_RANK.get(entry.get("verdict"), 2),
        _SEVERITY_RANK.get((entry.get("severity") or "info").lower(), 4),
        0 if entry.get("proof") else 1,
    )


_CLUSTER_MEMBERS_CAP = 25


def _cluster_key(e: dict) -> tuple:
    # Same systemic issue = same title + severity + tool + verdict + FP-ness.
    # verdict/FP are in the key so a CONFIRMED host is never merged into (and
    # hidden behind) an unverified cluster of the same title — they cluster
    # separately, which keeps the count honest.
    return ((e.get("title") or "").strip().lower(),
            (e.get("severity") or "info").lower(),
            (e.get("tool") or "").lower(),
            e.get("verdict") or "unverified",
            bool(e.get("false_positive")))


def _cluster_entries(entries: list) -> list:
    """Collapse per-host replicas of one systemic issue into a single entry.

    Groups by :func:`_cluster_key`; within a group the best entry by
    ``_rank_key`` (proof-bearing first) is the representative and carries
    ``member_count`` + ``members`` (a capped list of the affected targets).
    Singletons pass through with ``member_count=1``. Ordering within a group is
    otherwise preserved.
    """
    groups: dict = {}
    order: list = []
    for e in entries:
        k = _cluster_key(e)
        if k not in groups:
            groups[k] = []
            order.append(k)
        groups[k].append(e)

    out = []
    for k in order:
        members = groups[k]
        if len(members) == 1:
            members[0]["member_count"] = 1
            out.append(members[0])
            continue
        rep = dict(min(members, key=_rank_key))     # best carries the strongest evidence
        rep["member_count"] = len(members)
        seen, targets = set(), []
        for e in [rep] + members:
            t = e.get("target")
            if t and t not in seen:
                seen.add(t)
                targets.append(t)
        rep["members"] = targets[:_CLUSTER_MEMBERS_CAP]
        rep["members_truncated"] = len(targets) > _CLUSTER_MEMBERS_CAP
        out.append(rep)
    return out


def _sev_label(e: dict) -> str:
    """Severity cell text, annotating a MonkeyX re-rating: 'HIGH (↑ from INFO)'."""
    sev = (e.get("severity") or "?").upper()
    if e.get("severity_source") == "monkeyx_rule" and e.get("original_severity"):
        return f"{sev} (↑ from {e['original_severity'].upper()})"
    return sev


def run_focus(prefix, **kwargs):
    data_prefix = kwargs.get('data_prefix', prefix)
    reports_prefix = kwargs.get('reports_prefix', prefix)
    output_dir = os.path.dirname(os.path.dirname(data_prefix)) if data_prefix else None

    if not output_dir or not os.path.isdir(output_dir):
        logger.warning("focus: no output dir resolved from prefix %s", data_prefix)
        return {'module': 'focus', 'status': 'skipped', 'reason': 'no output dir'}

    print("\n[*] Building prioritized focus list")

    entries, seen_fids = _spine_from_db(output_dir)
    entries.extend(_plus_from_validations(data_prefix, seen_fids))

    total_findings = len(entries)
    # Cluster systemic issues that repeat across many hosts (e.g. one Host-header
    # behavior across 368 hosts, spf_missing across 60 domains) into ONE entry
    # with a member_count + representative targets. Otherwise the "start here"
    # list is thousands of near-identical rows and the real leads drown.
    entries = _cluster_entries(entries)

    entries.sort(key=_rank_key)
    for i, entry in enumerate(entries, 1):
        entry['rank'] = i

    confirmed = sum(1 for e in entries if e.get('verdict') == 'confirmed')

    json_output = f"{data_prefix}-focus.json"
    version_output_path(json_output)
    with open(json_output, 'w') as f:
        json.dump({'count': len(entries), 'total_findings': total_findings,
                   'confirmed': confirmed, 'focus': entries}, f, indent=2)

    md_output = f"{reports_prefix}-focus.md"
    version_output_path(md_output)
    _render_markdown(entries, confirmed, md_output)

    print(f"[+] Focus list: {len(entries)} items ({confirmed} confirmed)")
    print(f"    Report: {md_output}")

    return {
        'module': 'focus',
        'status': 'success',
        'count': len(entries),
        'confirmed': confirmed,
        'output_files': [json_output, md_output],
    }


def _spine_from_db(output_dir: str) -> tuple[list, set]:
    """Findings + latest verdict from scan.db. Returns (entries, seen finding_ids)."""
    entries, seen = [], set()
    db = ScanDB(output_dir)
    try:
        rows = db.focus_rows()
    finally:
        db.close(checkpoint=False)

    for r in rows:
        # Genuine NON-INFO findings qualify; an info finding qualifies only when
        # flagged (validated confirmed/unclear or has proof) — see in_focus.
        # Keeps parity with the webserver focus view.
        verdict = r['verdict'] or r['v_verdict']
        poc = r['v_poc_command']
        if not in_focus({'type': r['type'], 'severity': r['severity']}, verdict, poc):
            continue
        fid = r['finding_id']
        seen.add(fid)
        port = r['port']
        host = r['host']
        entries.append({
            'source': 'finding',
            'finding_id': fid,
            'target': f"{host}:{port}" if port else host,
            'hostname': r['hostname'],
            'title': r['title'],
            'severity': r['severity'],
            'original_severity': r['original_severity'],
            'severity_source': r['severity_source'],
            'rerate_reason': r['rerate_reason'],
            'verdict': verdict or 'unverified',
            'tool': r['tool'],
            'cve': r['cve_id'],
            'proof': poc,
            'evidence': r['v_evidence'],
            'action': r['v_action'],
            'false_positive': bool(r['false_positive']),
        })
    return entries, seen


def _plus_from_validations(data_prefix: str, seen_fids: set) -> list:
    """Validated recommendations with no finding row (chains, unmapped items).

    Falls back to ai-analysis.json recommendations when ai_validate produced no
    output, so the analysis-only narratives still appear (tiered unverified).
    """
    vpath = f"{data_prefix}-validated-findings.json"
    if os.path.exists(vpath):
        return _plus_from_validated(vpath, seen_fids)

    apath = f"{data_prefix}-ai-analysis.json"
    if os.path.exists(apath):
        return _plus_from_analysis(apath)
    return []


def _plus_from_validated(vpath: str, seen_fids: set) -> list:
    try:
        with open(vpath) as f:
            results = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.warning("focus: could not read %s: %s", vpath, e)
        return []

    entries = []
    for v in results:
        if not isinstance(v, dict):
            continue
        # Already represented in the spine (exact finding_id join) -> skip dup.
        if v.get('finding_id') in seen_fids and v.get('finding_id') is not None:
            continue
        if any(fid in seen_fids for fid in (v.get('finding_ids') or [])):
            continue
        finding = v.get('finding') or {}
        entries.append({
            'source': 'analysis',
            'finding_id': None,
            'target': finding.get('target'),
            'hostname': None,
            'title': finding.get('action'),
            'severity': v.get('severity'),
            'verdict': v.get('verdict') or 'unverified',
            'tool': 'ai_analyze',
            'cve': None,
            'proof': v.get('poc_command'),
            'evidence': v.get('evidence'),
            'action': finding.get('action'),
            'false_positive': False,
        })
    return entries


def _plus_from_analysis(apath: str) -> list:
    try:
        with open(apath) as f:
            recs = (json.load(f) or {}).get('recommendations') or {}
    except (json.JSONDecodeError, OSError) as e:
        logger.warning("focus: could not read %s: %s", apath, e)
        return []

    entries = []
    for category, default_sev in _CATEGORY_DEFAULT_SEV.items():
        for item in (recs.get(category) or []):
            if not isinstance(item, dict):
                continue
            # attack_chains carry an explicit impact; use it as severity.
            severity = (item.get('impact') or default_sev).lower()
            commands = item.get('commands') or []
            entries.append({
                'source': 'analysis',
                'finding_id': None,
                'target': item.get('target'),
                'hostname': None,
                'title': item.get('action'),
                'severity': severity,
                'verdict': 'unverified',
                'tool': 'ai_analyze',
                'cve': None,
                'proof': commands[0] if commands else None,
                'evidence': item.get('evidence'),
                'action': item.get('action'),
                'false_positive': False,
            })
    return entries


_VERDICT_BADGE = {
    'confirmed': 'CONFIRMED', 'unclear': 'unclear',
    'refuted': 'refuted', 'error': 'error', 'unverified': 'unverified',
}
_START_HERE_N = 15


def _md_cell(value) -> str:
    """Escape a value for a markdown table cell (pipes/newlines break tables)."""
    s = str(value if value is not None else '')
    return s.replace('|', '\\|').replace('\n', ' ').replace('\r', ' ').strip()


def _render_markdown(entries: list, confirmed: int, output_path: str) -> None:
    lines = ["# Focus — Start Here", ""]
    if not entries:
        lines.append("No findings to prioritize yet. Run scanning + "
                     "`ai_analyze`/`ai_validate` first.")
        with open(output_path, 'w') as f:
            f.write("\n".join(lines) + "\n")
        return

    clustered = sum(1 for e in entries if e.get('member_count', 1) > 1)
    lines.append(f"**{len(entries)} prioritized items** — {confirmed} confirmed. "
                 "Confirmed findings first, then unverified by severity; "
                 "refuted/false-positive last."
                 + (f" Systemic issues affecting multiple hosts are clustered "
                    f"into one item ({clustered} clustered) — see the host count "
                    f"in the Hosts column." if clustered else ""))
    lines.append("")
    lines.append("| # | Target | Hosts | Severity | Verdict | Finding | Proof |")
    lines.append("|---|--------|-------|----------|---------|---------|-------|")
    for e in entries[:_START_HERE_N]:
        proof = e.get('proof')
        proof_cell = f"`{_md_cell(proof)}`" if proof else "—"
        n = e.get('member_count', 1)
        hosts_cell = f"{n}" if n > 1 else "—"
        lines.append(
            f"| {e['rank']} | {_md_cell(e.get('target'))} "
            f"| {hosts_cell} "
            f"| {_md_cell(_sev_label(e))} "
            f"| {_VERDICT_BADGE.get(e.get('verdict'), e.get('verdict'))} "
            f"| {_md_cell(e.get('title'))} | {proof_cell} |"
        )
    lines.append("")
    if len(entries) > _START_HERE_N:
        lines.append(f"_Showing top {_START_HERE_N} of {len(entries)}. "
                     "Full ranked set in `-focus.json`._")
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("## Details")
    lines.append("")
    for e in entries:
        lines.append(f"### {e['rank']}. {e.get('title') or e.get('target') or 'finding'}")
        lines.append("")
        meta = [
            f"**Target:** `{e.get('target') or '?'}`",
            f"**Severity:** {_sev_label(e)}",
            f"**Verdict:** {e.get('verdict')}",
            f"**Source:** {e.get('source')}",
        ]
        if e.get('cve'):
            meta.append(f"**CVE:** {e['cve']}")
        if e.get('finding_id'):
            meta.append(f"**finding_id:** `{e['finding_id']}`")
        lines.append(" · ".join(meta))
        lines.append("")
        if e.get('severity_source') == 'monkeyx_rule' and e.get('rerate_reason'):
            lines.append(f"_Severity elevated by MonkeyX from "
                         f"{(e.get('original_severity') or '?').upper()}: "
                         f"{e['rerate_reason']}._")
            lines.append("")
        n = e.get('member_count', 1)
        if n > 1:
            shown = ", ".join(f"`{_md_cell(t)}`" for t in (e.get('members') or []))
            more = " …" if e.get('members_truncated') else ""
            lines.append(f"**Affects {n} hosts** (same finding): {shown}{more}")
            lines.append("")
        if e.get('proof'):
            lines.append("**Proof / repro:**")
            lines.append("")
            lines.append("```bash")
            lines.append(str(e['proof']))
            lines.append("```")
            lines.append("")
        if e.get('evidence'):
            lines.append(f"**Evidence:** {e['evidence']}")
            lines.append("")

    with open(output_path, 'w') as f:
        f.write("\n".join(lines) + "\n")
