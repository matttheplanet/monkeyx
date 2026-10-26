"""Consolidated HTML report — merges all markdown reports into a single navigable file.

Called from monkeyx.py's finally block after generate_summary(). Finds all .md
files in the reports/ directory, converts to HTML sections, and assembles a
self-contained report with sticky TOC sidebar, collapsible sections, and
severity color coding.
"""

import glob
import html
import logging
import os
import re
import shutil
from datetime import datetime, timezone

from core.utils import version_output_path

logger = logging.getLogger('monkeyx.modules.html_report')

REQUIRED_INPUTS = frozenset()

_SECTION_ORDER = [
    ("summary", "Scan Debrief"),
    ("focus", "Focus — Start Here"),
    ("analysis", "Programmatic Analysis"),
    ("ai-analysis", "AI Analysis"),
    ("validation-report", "Validation Results"),
    ("dns-security", "DNS Security"),
    ("ai-gowitness", "Screenshot Analysis"),
]


def _remove_stale_root_report(output_dir):
    """Delete a leftover root report.html when this run produces no report.

    Keeps the front-door copy honest: without this, a run that generates no
    markdown reports would leave the previous run's report.html sitting at the
    root, looking current. Best-effort — never fatal.
    """
    stale = os.path.join(output_dir, "report.html")
    try:
        if os.path.isfile(stale):
            os.remove(stale)
            logger.info("Removed stale root report.html (no report produced this run)")
    except OSError as e:
        logger.warning("Could not remove stale root report.html: %s", e)


def generate_html_report(output_dir):
    """Generate consolidated HTML report from all markdown files in reports/.

    Args:
        output_dir: Root output directory (contains reports/*.md)

    Returns:
        Path to the written report.html, or None if no reports found.
    """
    if not output_dir or not os.path.isdir(output_dir):
        return None

    reports_dir = os.path.join(output_dir, "reports")
    if not os.path.isdir(reports_dir):
        _remove_stale_root_report(output_dir)
        return None

    md_files = sorted(
        f for f in glob.glob(os.path.join(reports_dir, "*.md"))
        if not re.search(r'\.run\d+\.md$', f)
        # Exclude the retired Critical & High Findings report. It is no longer
        # generated, but a stale file from an earlier run would otherwise still
        # be picked up by the unknown-file fallback in _order_sections().
        and not os.path.basename(f).startswith("critical-high-findings")
    )

    if not md_files:
        _remove_stale_root_report(output_dir)
        return None

    sections = _order_sections(md_files)
    if not sections:
        _remove_stale_root_report(output_dir)
        return None

    html_content = _build_html(sections, output_dir)
    output_path = os.path.join(reports_dir, "report.html")
    version_output_path(output_path)
    with open(output_path, 'w', encoding="utf-8") as f:
        f.write(html_content)

    print(f"[+] HTML report: {output_path}")

    # Surface the report at the output-dir root as the human "front door".
    # The HTML is self-contained (internal anchors + inlined base64 images), so
    # a root copy has no broken links. Best-effort: a copy failure must never
    # fail the run — the canonical report in reports/ is still returned.
    try:
        root_copy = os.path.join(output_dir, "report.html")
        shutil.copy2(output_path, root_copy)
        print(f"[+] HTML report (root copy): {root_copy}")
    except OSError as e:
        logger.warning("Could not copy report.html to output-dir root: %s", e)

    return output_path


def run_html_report(prefix, **kwargs):
    """Module interface — allows running as an explicit workflow step."""
    prefix = kwargs.get('data_prefix', prefix)
    data_dir = os.path.dirname(prefix) if prefix else '.'
    output_dir = os.path.dirname(data_dir)

    result = generate_html_report(output_dir)
    return {
        'module': 'html_report',
        'status': 'success' if result else 'warning',
        'output_files': [result] if result else [],
    }


def _matches_section_key(key, basename):
    """Match a section key against a filename as a hyphen-delimited segment sequence.

    To avoid 'analysis' matching 'ai-analysis', we check that the matched segments
    are not preceded by additional alphabetic segments that form a longer key.
    """
    stem = basename.rsplit('.', 1)[0]
    parts = re.split(r'[-_]', stem)
    key_parts = re.split(r'[-_]', key)
    for i in range(len(parts) - len(key_parts) + 1):
        if parts[i:i + len(key_parts)] == key_parts:
            if i > 0 and parts[i - 1].isalpha():
                continue
            return True
    return False


def _order_sections(md_files):
    """Order markdown files according to _SECTION_ORDER, with unknown files at the end."""
    ordered = []
    used = set()

    for key, title in _SECTION_ORDER:
        for path in md_files:
            basename = os.path.basename(path).lower()
            if _matches_section_key(key, basename) and path not in used:
                ordered.append((title, path))
                used.add(path)
                break

    for path in md_files:
        if path not in used:
            basename = os.path.basename(path)
            name = os.path.splitext(basename)[0]
            title = name.replace("-", " ").replace("_", " ").title()
            # Strip date prefix if present
            title = re.sub(r'^\d{4}[\s\-]\d{2}[\s\-]\d{2}[\s\-]\d+[\s\-]*', '', title)
            ordered.append((title, path))

    return ordered


def _md_to_html(md_text):
    """Lightweight markdown to HTML conversion. Handles the subset we generate."""
    lines = md_text.split('\n')
    html_lines = []
    in_list = False  # 'ol' | 'ul' | False
    in_nested_ul = False  # nested <ul> inside an <ol> <li>
    li_open = False  # whether current <li> is still unclosed (for nesting)
    in_code = False
    in_table = False
    table_header_done = False

    def _close_nested():
        nonlocal in_nested_ul
        if in_nested_ul:
            html_lines.append('</ul>')
            in_nested_ul = False

    def _close_li():
        nonlocal li_open
        if li_open:
            _close_nested()
            html_lines.append('</li>')
            li_open = False

    def _close_list():
        nonlocal in_list
        if in_list:
            _close_li()
            html_lines.append('</ol>' if in_list == 'ol' else '</ul>')
            in_list = False

    for line in lines:
        # Code blocks
        if line.strip().startswith('```'):
            if in_code:
                html_lines.append('</code></pre>')
                in_code = False
            else:
                _close_list()
                html_lines.append('<pre><code>')
                in_code = True
            continue
        if in_code:
            html_lines.append(html.escape(line))
            continue

        # Tables
        if '|' in line and line.strip().startswith('|'):
            cells = [c.strip() for c in line.strip().strip('|').split('|')]
            if all(re.match(r'^[-:]+$', c) for c in cells):
                table_header_done = True
                continue
            if not in_table:
                _close_list()
                html_lines.append('<table>')
                in_table = True
                table_header_done = False
            if not table_header_done:
                html_lines.append('<tr>' + ''.join(f'<th>{_inline(c)}</th>' for c in cells) + '</tr>')
            else:
                html_lines.append('<tr>' + ''.join(f'<td>{_inline(c)}</td>' for c in cells) + '</tr>')
            continue
        elif in_table:
            html_lines.append('</table>')
            in_table = False
            table_header_done = False

        # Headers
        header_match = re.match(r'^(#{1,6})\s+(.*)', line)
        if header_match:
            _close_list()
            level = len(header_match.group(1))
            text = header_match.group(2)
            anchor = re.sub(r'[^a-z0-9]+', '-', text.lower()).strip('-')
            html_lines.append(f'<h{level} id="{anchor}">{_inline(text)}</h{level}>')
            continue

        # Indented bullet under a numbered list item → nested <ul>
        indent_bullet = re.match(r'^(\s{2,})[-*]\s+(.*)', line)
        if indent_bullet and in_list == 'ol' and li_open:
            if not in_nested_ul:
                html_lines.append('<ul>')
                in_nested_ul = True
            content = indent_bullet.group(2)
            html_lines.append(f'<li>{_inline(content)}</li>')
            continue

        # Top-level bullet list items
        if re.match(r'^[-*]\s+', line):
            if in_list == 'ol':
                _close_list()
            if not in_list:
                html_lines.append('<ul>')
                in_list = 'ul'
            else:
                _close_li()
            content = re.sub(r'^[-*]\s+', '', line)
            html_lines.append(f'<li>{_inline(content)}</li>')
            li_open = False
            continue

        # Numbered list items
        if re.match(r'^\d+\.\s+', line):
            if in_list == 'ul':
                _close_list()
            if not in_list:
                html_lines.append('<ol>')
                in_list = 'ol'
            else:
                _close_li()
            content = re.sub(r'^\d+\.\s+', '', line)
            html_lines.append(f'<li>{_inline(content)}')
            li_open = True
            continue

        # Blank lines — defer list close until we see non-list content
        if line.strip() == '':
            if in_list and li_open:
                _close_nested()
            continue

        # Horizontal rules
        if re.match(r'^---+$', line.strip()):
            _close_list()
            html_lines.append('<hr>')
            continue

        # Regular paragraph
        _close_list()
        html_lines.append(f'<p>{_inline(line)}</p>')

    _close_list()
    if in_code:
        html_lines.append('</code></pre>')
    if in_table:
        html_lines.append('</table>')

    return '\n'.join(html_lines)


def _inline(text):
    """Convert inline markdown (bold, italic, code, links) to HTML."""
    text = html.escape(text)
    # Bold
    text = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', text)
    # Italic
    text = re.sub(r'\*(.+?)\*', r'<em>\1</em>', text)
    # Inline code
    text = re.sub(r'`(.+?)`', r'<code class="inline">\1</code>', text)
    # Links — only emit an anchor for safe schemes. A javascript:/data: href
    # contains no HTML-special chars, so it survives html.escape() above and
    # would otherwise become a stored-XSS sink when scan-derived text (banners,
    # AI markdown) is rendered. Unsafe hrefs are left as escaped literal text.
    def _safe_link(m):
        label, href = m.group(1), m.group(2)
        if re.match(r'^(https?:|mailto:|#|/)', href.strip(), re.IGNORECASE):
            return f'<a href="{href}">{label}</a>'
        return m.group(0)
    text = re.sub(r'\[(.+?)\]\((.+?)\)', _safe_link, text)
    # Severity badges
    text = re.sub(r'\bCRITICAL\b', '<span class="badge critical">CRITICAL</span>', text)
    text = re.sub(r'\bHIGH\b', '<span class="badge high">HIGH</span>', text)
    text = re.sub(r'\bMEDIUM\b', '<span class="badge medium">MEDIUM</span>', text)
    text = re.sub(r'\bLOW\b', '<span class="badge low">LOW</span>', text)
    return text


def _latest_step_status(output_dir, module_name):
    """Return (status, error) for the most recent run of a module.

    Reads the append-only progress.jsonl at the output-dir root (the same source
    summary.py's Failed Modules table uses). Returns the LAST step_completed /
    step_failed event for the module so --continue/--resume reruns reflect the
    latest attempt. status is 'failed', the step_completed outcome (e.g.
    'success'), or None if the module has no recorded outcome. Best-effort — any
    read/parse error yields (None, None) so the report never fails on this.
    """
    import json
    path = os.path.join(output_dir, "progress.jsonl")
    status, error = None, None
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except ValueError:
                    continue
                if ev.get("step") != module_name:
                    continue
                if ev.get("event") == "step_failed":
                    status, error = "failed", ev.get("error")
                elif ev.get("event") == "step_completed":
                    status, error = ev.get("status", "success"), None
    except OSError:
        return None, None
    return status, error


def _ai_failure_banner(output_dir):
    """HTML banner if ai_analyze failed this run, else ''.

    ai_analyze writes its markdown UNCONDITIONALLY — even on total provider
    failure it emits an empty-looking "no findings" report that is otherwise
    indistinguishable from a genuine clean result. Surface the failure inline so
    a reader of the AI Analysis section isn't misled into trusting a report the
    AI never actually produced.
    """
    status, error = _latest_step_status(output_dir, "ai_analyze")
    if status != "failed":
        return ""
    detail = html.escape(error) if error else "The AI provider calls did not complete."
    return (
        '<div class="section-alert">'
        '<strong>⚠ AI analysis did not complete.</strong> '
        'The content below was written before the analysis finished and does '
        'NOT reflect a successful AI review — treat any "no findings" result as '
        'inconclusive, not clean.'
        f'<div class="alert-detail">{detail}</div>'
        '</div>'
    )


def _build_html(sections, output_dir):
    """Assemble the full HTML document."""
    timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
    dirname = os.path.basename(output_dir)

    # Build TOC and body
    toc_items = []
    body_sections = []

    for i, (title, path) in enumerate(sections):
        section_id = f"section-{i}"

        with open(path, encoding="utf-8") as f:
            md_content = f.read()

        # Extract h2 headings for sub-navigation
        sub_headings = re.findall(r'^##\s+(.+)$', md_content, re.MULTILINE)

        toc_items.append(f'<li><a href="#{section_id}">{html.escape(title)}</a>')
        if sub_headings:
            toc_items.append('<ul class="nav-sub">')
            for sh in sub_headings:
                sub_anchor = f"{section_id}--{re.sub(r'[^a-z0-9]+', '-', sh.lower()).strip('-')}"
                toc_items.append(f'<li><a href="#{sub_anchor}">{html.escape(sh)}</a></li>')
            toc_items.append('</ul>')
        toc_items.append('</li>')

        # Rewrite h2 anchors in the HTML to match the TOC links
        section_html = _md_to_html(md_content)
        for sh in sub_headings:
            old_anchor = re.sub(r'[^a-z0-9]+', '-', sh.lower()).strip('-')
            new_anchor = f"{section_id}--{old_anchor}"
            section_html = section_html.replace(
                f'id="{old_anchor}"',
                f'id="{new_anchor}"',
                1,
            )

        # The AI Analysis markdown is written even when ai_analyze failed, and
        # then reads like a clean "no findings" result. Prepend a failure banner
        # so it can't be mistaken for a successful review.
        if "ai-analysis" in os.path.basename(path):
            section_html = _ai_failure_banner(output_dir) + section_html

        body_sections.append(
            f'<section id="{section_id}" class="report-section">\n'
            f'<h1 class="section-title">{html.escape(title)}</h1>\n'
            f'<div class="section-body">{section_html}</div>\n'
            f'</section>'
        )

    toc_html = '\n'.join(toc_items)
    body_html = '\n'.join(body_sections)

    return f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>MonkeyX Report — {html.escape(dirname)}</title>
<style>
:root {{
    --bg: #0a0e14;
    --surface: #12171f;
    --surface-alt: #1a2030;
    --border: #2a3545;
    --text: #e6edf3;
    --text-muted: #7a8da0;
    --accent: #ff6b35;
    --accent-dim: #cc5528;
    --accent-glow: rgba(255, 107, 53, 0.15);
    --critical: #ff4757;
    --high: #ff7b3a;
    --medium: #ffa82e;
    --low: #7a8da0;
    --info: #4dabf7;
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
    background: var(--bg);
    color: var(--text);
    line-height: 1.6;
    display: flex;
}}
nav {{
    position: fixed;
    top: 0;
    left: 0;
    width: 280px;
    height: 100vh;
    overflow-y: auto;
    background: var(--surface);
    border-right: 1px solid var(--border);
    padding: 0;
    z-index: 100;
}}
nav .nav-brand {{
    padding: 24px 20px 20px;
    border-bottom: 1px solid var(--border);
    margin-bottom: 12px;
    background: linear-gradient(180deg, var(--surface-alt) 0%, var(--surface) 100%);
    display: flex;
    align-items: center;
    gap: 14px;
}}
nav .nav-brand .logo {{
    width: 42px;
    height: 42px;
    flex-shrink: 0;
}}
nav .nav-brand .brand-text {{
    display: flex;
    flex-direction: column;
}}
nav .nav-brand .brand-name {{
    font-size: 18px;
    font-weight: 700;
    color: var(--accent);
    letter-spacing: -0.5px;
    line-height: 1.2;
}}
nav .nav-brand .brand-sub {{
    font-size: 10px;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 1.5px;
    margin-top: 2px;
}}
nav .nav-header {{
    padding: 0 20px 12px;
    border-bottom: 1px solid var(--border);
    margin-bottom: 12px;
}}
nav .nav-header h2 {{
    font-size: 13px;
    color: var(--text);
    margin-bottom: 4px;
    font-weight: 600;
}}
nav .nav-header .meta {{
    font-size: 11px;
    color: var(--text-muted);
}}
nav ul {{
    list-style: none;
    padding: 0 14px;
}}
nav li {{
    margin: 2px 0;
}}
nav a {{
    display: block;
    padding: 7px 14px;
    color: var(--text-muted);
    text-decoration: none;
    font-size: 13px;
    border-radius: 6px;
    transition: all 0.15s;
    border-left: 2px solid transparent;
}}
nav a:hover {{
    color: var(--text);
    background: var(--surface-alt);
    border-left-color: var(--border);
}}
nav a.active {{
    color: var(--accent);
    background: var(--accent-glow);
    border-left-color: var(--accent);
}}
nav .nav-sub {{
    list-style: none;
    padding: 0 0 0 12px;
    margin: 2px 0 4px;
}}
nav .nav-sub li {{
    margin: 0;
}}
nav .nav-sub a {{
    font-size: 11px;
    padding: 3px 12px;
    color: var(--text-muted);
    opacity: 0.8;
}}
main {{
    margin-left: 280px;
    padding: 40px 60px;
    max-width: 920px;
    width: 100%;
}}
.report-section {{
    margin-bottom: 48px;
    padding-bottom: 32px;
    border-bottom: 1px solid var(--border);
}}
.section-title {{
    font-size: 22px;
    margin-bottom: 20px;
    padding-bottom: 10px;
    border-bottom: 2px solid var(--accent);
    color: var(--accent);
    font-weight: 700;
}}
.section-body h1 {{ font-size: 20px; margin: 28px 0 14px; color: var(--text); }}
.section-body h2 {{ font-size: 18px; margin: 24px 0 12px; color: var(--text); }}
.section-body h3 {{ font-size: 16px; margin: 20px 0 10px; color: var(--text); }}
.section-body h4 {{
    font-size: 14px;
    margin: 24px 0 12px;
    padding: 12px 16px;
    background: var(--surface);
    border: 1px solid var(--border);
    border-left: 3px solid var(--accent);
    border-radius: 6px;
    color: var(--text);
    font-weight: 600;
    letter-spacing: 0;
    text-transform: none;
}}
.section-body h4 + p,
.section-body h4 + pre {{
    margin-left: 16px;
    padding-left: 16px;
    border-left: 2px solid var(--border);
}}
.section-body p {{ margin: 10px 0; color: var(--text); line-height: 1.7; }}
.section-body ul {{ margin: 12px 0 12px 24px; }}
.section-body ol {{ margin: 12px 0 12px 0; padding-left: 24px; counter-reset: none; }}
.section-body ol li {{ margin: 8px 0; padding-left: 4px; }}
.section-body li {{ margin: 6px 0; line-height: 1.6; }}
.section-body strong {{ color: var(--text); }}
.section-body a {{ color: var(--accent); text-decoration: none; }}
.section-body a:hover {{ text-decoration: underline; }}
.section-body pre {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 16px;
    overflow-x: auto;
    margin: 12px 0;
    font-size: 13px;
}}
.section-body code {{
    font-family: "SF Mono", "Fira Code", Consolas, monospace;
    font-size: 13px;
}}
.section-body code.inline {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 3px;
    padding: 2px 6px;
    font-size: 12px;
}}
.section-body table {{
    width: 100%;
    border-collapse: collapse;
    margin: 12px 0;
    font-size: 13px;
}}
.section-body th, .section-body td {{
    padding: 8px 12px;
    border: 1px solid var(--border);
    text-align: left;
}}
.section-body th {{
    background: var(--surface);
    font-weight: 600;
}}
.section-body hr {{
    border: none;
    border-top: 1px solid var(--border);
    margin: 20px 0;
    opacity: 0.5;
}}
.section-body ol > li {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-left: 3px solid var(--accent-dim);
    border-radius: 8px;
    padding: 14px 18px;
    margin: 14px 0;
    list-style-position: inside;
}}
.section-body ol > li ul {{
    margin: 8px 0 4px 12px;
    padding: 6px 0 6px 14px;
    list-style: none;
    border-left: 2px solid var(--border);
}}
.section-body ol > li ul li {{
    background: none;
    border: none;
    padding: 3px 0;
    margin: 3px 0;
    color: var(--text-muted);
    font-size: 13px;
    line-height: 1.5;
}}
.section-body h2 {{
    margin-top: 32px;
    padding-top: 16px;
    border-top: 1px solid var(--border);
}}
.section-body h2:first-child {{
    margin-top: 0;
    padding-top: 0;
    border-top: none;
}}
.badge {{
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.5px;
}}
.badge.critical {{ background: var(--critical); color: #fff; }}
.badge.high {{ background: var(--high); color: #fff; }}
.badge.medium {{ background: var(--medium); color: #000; }}
.badge.low {{ background: var(--low); color: #000; }}
.section-alert {{
    background: rgba(255, 71, 87, 0.12);
    border: 1px solid var(--critical);
    border-left: 4px solid var(--critical);
    border-radius: 4px;
    padding: 12px 16px;
    margin-bottom: 20px;
    color: var(--text);
    font-size: 14px;
}}
.section-alert strong {{ color: var(--critical); }}
.section-alert .alert-detail {{ color: var(--text-muted); font-size: 13px; }}
@media (max-width: 900px) {{
    nav {{ width: 220px; }}
    main {{ margin-left: 220px; padding: 20px 30px; }}
}}
.report-footer {{
    margin-top: 60px;
    padding: 20px 0;
    border-top: 1px solid var(--border);
    text-align: center;
    font-size: 12px;
    color: var(--text-muted);
}}
.report-footer .sep {{
    margin: 0 8px;
    color: var(--border);
}}
@media print {{
    nav {{ display: none; }}
    main {{ margin-left: 0; padding: 20px; max-width: 100%; }}
    .report-section {{ page-break-inside: avoid; }}
}}
</style>
</head>
<body>
<nav>
    <div class="nav-brand">
        <svg class="logo" viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">
            <defs>
                <linearGradient id="mg" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" stop-color="#ff6b35"/>
                    <stop offset="100%" stop-color="#cc5528"/>
                </linearGradient>
            </defs>
            <circle cx="50" cy="50" r="46" fill="none" stroke="url(#mg)" stroke-width="3"/>
            <circle cx="50" cy="52" r="28" fill="none" stroke="url(#mg)" stroke-width="2.5"/>
            <circle cx="38" cy="46" r="6" fill="#ff6b35"/>
            <circle cx="62" cy="46" r="6" fill="#ff6b35"/>
            <circle cx="38" cy="46" r="2.5" fill="#0a0e14"/>
            <circle cx="62" cy="46" r="2.5" fill="#0a0e14"/>
            <ellipse cx="50" cy="60" rx="10" ry="7" fill="none" stroke="#ff6b35" stroke-width="2"/>
            <circle cx="46" cy="60" r="2" fill="#ff6b35"/>
            <circle cx="54" cy="60" r="2" fill="#ff6b35"/>
            <path d="M24 38 Q20 28 28 24" stroke="url(#mg)" stroke-width="2.5" fill="none" stroke-linecap="round"/>
            <path d="M76 38 Q80 28 72 24" stroke="url(#mg)" stroke-width="2.5" fill="none" stroke-linecap="round"/>
        </svg>
        <div class="brand-text">
            <span class="brand-name">MonkeyX</span>
            <span class="brand-sub">Security Report</span>
        </div>
    </div>
    <div class="nav-header">
        <h2>{html.escape(dirname)}</h2>
        <div class="meta">{timestamp}</div>
    </div>
    <ul>
        {toc_html}
    </ul>
</nav>
<main>
    {body_html}
    <footer class="report-footer">
        <span>Generated by MonkeyX</span>
        <span class="sep">&middot;</span>
        <span>{timestamp}</span>
    </footer>
</main>
<script>
// Highlight active section in nav
const sections = document.querySelectorAll('.report-section');
const navLinks = document.querySelectorAll('nav a');
const observer = new IntersectionObserver(entries => {{
    entries.forEach(entry => {{
        if (entry.isIntersecting) {{
            navLinks.forEach(link => link.classList.remove('active'));
            const id = entry.target.id;
            const active = document.querySelector(`nav a[href="#${{id}}"]`);
            if (active) active.classList.add('active');
        }}
    }});
}}, {{ rootMargin: '-20% 0px -80% 0px' }});
sections.forEach(s => observer.observe(s));
</script>
</body>
</html>'''
