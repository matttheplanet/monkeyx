"""Knowledge base system — retrieves relevant docs for AI module prompts.

Supports local folders and git repos as sources. Uses SQLite FTS5 for
keyword search, with path/filename matching as the primary retrieval strategy.

Config: ~/.monkeyx/knowledge.yaml
Index: ~/.monkeyx/knowledge.db (SQLite with FTS5)
Sync: monkeyx --sync-knowledge
"""

import logging
import os
import re
import sqlite3
import subprocess
import time
from pathlib import Path

logger = logging.getLogger("monkeyx.core.knowledge")

_MONKEYX_DIR = Path.home() / ".monkeyx"
_CONFIG_PATH = _MONKEYX_DIR / "knowledge.yaml"
_DEFAULT_DB_PATH = _MONKEYX_DIR / "knowledge.db"
_KNOWLEDGE_DIR = _MONKEYX_DIR / "knowledge"

_config_cache = None
_db_path_cache = None

_PORT_SERVICE_MAP = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 80: "http", 110: "pop3", 111: "rpc",
    143: "imap", 161: "snmp", 389: "ldap", 443: "https",
    445: "smb", 993: "imap", 995: "pop3", 1433: "mssql",
    3306: "mysql", 3389: "rdp", 5432: "postgresql",
    5900: "vnc", 6379: "redis", 8080: "http", 8443: "https",
    9200: "elasticsearch", 27017: "mongodb",
}

_MAX_CHUNK_CHARS = 2000
_MIN_CHUNK_CHARS = 100


# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------

def load_config() -> dict:
    global _config_cache
    if _config_cache is not None:
        return _config_cache
    if not _CONFIG_PATH.exists():
        _config_cache = {}
        return _config_cache
    try:
        import yaml
        with _CONFIG_PATH.open() as f:
            _config_cache = yaml.safe_load(f) or {}
    except Exception as e:
        logger.warning("Failed to load knowledge config: %s", e)
        _config_cache = {}
    return _config_cache


def reload():
    global _config_cache, _db_path_cache
    _config_cache = None
    _db_path_cache = None


def _get_db_path() -> Path:
    global _db_path_cache
    if _db_path_cache is not None:
        return _db_path_cache
    config = load_config()
    db_str = config.get("settings", {}).get("db_path", "")
    if db_str:
        _db_path_cache = Path(os.path.expanduser(db_str))
    else:
        _db_path_cache = _DEFAULT_DB_PATH
    return _db_path_cache


def _get_max_tokens() -> int:
    config = load_config()
    return config.get("settings", {}).get("max_tokens_per_injection", 4000)


# ---------------------------------------------------------------------------
# Source sync
# ---------------------------------------------------------------------------

def sync_sources() -> dict[str, str]:
    config = load_config()
    sources = config.get("sources", [])
    results = {}

    for source in sources:
        name = source.get("name", "unnamed")
        src_type = source.get("type", "local")
        try:
            if src_type == "local":
                results[name] = _sync_local(source)
            elif src_type == "git":
                results[name] = _sync_git(source)
            else:
                results[name] = f"error: unknown type '{src_type}'"
        except Exception as e:
            results[name] = f"error: {e}"
            logger.error("Failed to sync '%s': %s", name, e)

    return results


def _sync_local(source: dict) -> str:
    path = Path(os.path.expanduser(source.get("path", "")))
    if not path.exists():
        return f"error: path does not exist: {path}"
    if not path.is_dir():
        return f"error: not a directory: {path}"
    return "ok (local)"


def _sync_git(source: dict) -> str:
    url = source.get("url", "")
    branch = source.get("branch", "main")
    dest = Path(os.path.expanduser(source.get("path", "")))
    sparse_paths = source.get("sparse_paths", [])

    if not url:
        return "error: no url specified"
    if not dest:
        return "error: no path specified"

    dest.parent.mkdir(parents=True, exist_ok=True)

    if dest.exists() and (dest / ".git").exists():
        subprocess.run(
            ["git", "-C", str(dest), "pull", "--ff-only"],
            capture_output=True, timeout=120,
        )
        return "updated"

    cmd = ["git", "clone", "--filter=blob:none", "--depth", "1",
           "--branch", branch]
    if sparse_paths:
        cmd.append("--sparse")
    cmd.extend([url, str(dest)])

    subprocess.run(cmd, capture_output=True, timeout=300, check=True)

    if sparse_paths:
        subprocess.run(
            ["git", "-C", str(dest), "sparse-checkout", "set"] + sparse_paths,
            capture_output=True, timeout=60, check=True,
        )

    return "cloned"


# ---------------------------------------------------------------------------
# Indexing
# ---------------------------------------------------------------------------

def index_sources() -> dict:
    config = load_config()
    sources = config.get("sources", [])
    db_path = _get_db_path()
    db_path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(db_path))
    _ensure_schema(conn)

    total_files = 0
    total_chunks = 0
    indexed_sources = 0

    for source in sources:
        name = source.get("name", "unnamed")
        src_type = source.get("type", "local")
        priority = source.get("priority", "community")
        file_glob = source.get("file_glob", "**/*.md")

        if src_type == "local":
            base_path = Path(os.path.expanduser(source.get("path", "")))
        elif src_type == "git":
            base_path = Path(os.path.expanduser(source.get("path", "")))
        else:
            continue

        if not base_path.exists():
            logger.warning("Skipping '%s': path does not exist: %s", name, base_path)
            continue

        indexed_sources += 1
        existing_files = set()

        for md_file in base_path.glob(file_glob):
            if not md_file.is_file():
                continue
            rel_path = str(md_file.relative_to(base_path))
            existing_files.add(rel_path)

            try:
                content = md_file.read_text(errors="replace")
            except Exception as e:
                logger.warning("Failed to read %s: %s", md_file, e)
                continue

            chunks = _chunk_markdown(content, rel_path)
            if not chunks:
                continue

            total_files += 1
            now = time.time()

            conn.execute(
                "DELETE FROM chunks WHERE source_name = ? AND file_path = ?",
                (name, rel_path),
            )

            for chunk in chunks:
                conn.execute(
                    "INSERT INTO chunks (source_name, file_path, heading, content, priority, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (name, rel_path, chunk["heading"], chunk["content"], priority, now),
                )
                total_chunks += 1

        # Remove stale entries for this source
        cursor = conn.execute(
            "SELECT DISTINCT file_path FROM chunks WHERE source_name = ?", (name,)
        )
        for (fp,) in cursor.fetchall():
            if fp not in existing_files:
                conn.execute(
                    "DELETE FROM chunks WHERE source_name = ? AND file_path = ?",
                    (name, fp),
                )

    # Rebuild FTS index
    conn.execute("INSERT INTO chunks_fts(chunks_fts) VALUES('rebuild')")
    conn.commit()
    conn.close()

    return {"sources": indexed_sources, "files": total_files, "chunks": total_chunks}


def _ensure_schema(conn: sqlite3.Connection):
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS chunks (
            id INTEGER PRIMARY KEY,
            source_name TEXT NOT NULL,
            file_path TEXT NOT NULL,
            heading TEXT,
            content TEXT NOT NULL,
            priority TEXT NOT NULL DEFAULT 'community',
            updated_at REAL
        );
        CREATE INDEX IF NOT EXISTS idx_chunks_source ON chunks(source_name);
        CREATE INDEX IF NOT EXISTS idx_chunks_path ON chunks(file_path);
        CREATE VIRTUAL TABLE IF NOT EXISTS chunks_fts USING fts5(
            file_path, heading, content,
            content='chunks', content_rowid='id'
        );
        CREATE TRIGGER IF NOT EXISTS chunks_ai AFTER INSERT ON chunks BEGIN
            INSERT INTO chunks_fts(rowid, file_path, heading, content)
            VALUES (new.id, new.file_path, new.heading, new.content);
        END;
        CREATE TRIGGER IF NOT EXISTS chunks_ad AFTER DELETE ON chunks BEGIN
            INSERT INTO chunks_fts(chunks_fts, rowid, file_path, heading, content)
            VALUES ('delete', old.id, old.file_path, old.heading, old.content);
        END;
        CREATE TRIGGER IF NOT EXISTS chunks_au AFTER UPDATE ON chunks BEGIN
            INSERT INTO chunks_fts(chunks_fts, rowid, file_path, heading, content)
            VALUES ('delete', old.id, old.file_path, old.heading, old.content);
            INSERT INTO chunks_fts(rowid, file_path, heading, content)
            VALUES (new.id, new.file_path, new.heading, new.content);
        END;
    """)


# ---------------------------------------------------------------------------
# Markdown chunking
# ---------------------------------------------------------------------------

_HEADING_RE = re.compile(r"^(#{1,3})\s+(.+)", re.MULTILINE)
_FRONTMATTER_RE = re.compile(r"^---\s*\n.*?\n---\s*\n", re.DOTALL)


def _chunk_markdown(content: str, file_path: str) -> list[dict]:
    content = _FRONTMATTER_RE.sub("", content)
    content = re.sub(r"<!--.*?-->", "", content, flags=re.DOTALL)

    if not content.strip():
        return []

    sections = []
    heading_stack = []
    current_text = []
    current_heading = ""

    for line in content.split("\n"):
        m = _HEADING_RE.match(line)
        if m:
            if current_text:
                text = "\n".join(current_text).strip()
                if text:
                    sections.append({"heading": current_heading, "content": text})
                current_text = []

            level = len(m.group(1))
            title = m.group(2).strip()
            heading_stack = heading_stack[:level - 1]
            heading_stack.append(title)
            current_heading = " > ".join(heading_stack)
        else:
            current_text.append(line)

    if current_text:
        text = "\n".join(current_text).strip()
        if text:
            sections.append({"heading": current_heading, "content": text})

    # Split oversized chunks, merge tiny ones
    result = []
    for section in sections:
        content_text = section["content"]
        heading = section["heading"]

        if len(content_text) > _MAX_CHUNK_CHARS:
            for sub_chunk in _split_at_paragraphs(content_text, _MAX_CHUNK_CHARS):
                result.append({"heading": heading, "content": sub_chunk})
        elif len(content_text) < _MIN_CHUNK_CHARS and result:
            result[-1]["content"] += "\n\n" + content_text
        else:
            result.append({"heading": heading, "content": content_text})

    return result


def _split_at_paragraphs(text: str, max_chars: int) -> list[str]:
    paragraphs = re.split(r"\n\n+", text)
    chunks = []
    current = ""

    for para in paragraphs:
        if current and len(current) + len(para) + 2 > max_chars:
            chunks.append(current.strip())
            current = para
        else:
            current = current + "\n\n" + para if current else para

    if current.strip():
        chunks.append(current.strip())

    return chunks if chunks else [text[:max_chars]]


# ---------------------------------------------------------------------------
# Retrieval
# ---------------------------------------------------------------------------

def retrieve(
    query_terms: list[str] | None = None,
    port: int | None = None,
    protocol: str | None = None,
    service: str | None = None,
    max_tokens: int | None = None,
) -> str:
    """Retrieve relevant knowledge chunks for AI prompt injection.

    Returns a formatted string ready to append to a prompt, or empty string
    if no knowledge base is configured or nothing relevant is found.
    """
    text, _refs = retrieve_with_refs(
        query_terms=query_terms,
        port=port,
        protocol=protocol,
        service=service,
        max_tokens=max_tokens,
    )
    return text


def retrieve_with_refs(
    query_terms: list[str] | None = None,
    port: int | None = None,
    protocol: str | None = None,
    service: str | None = None,
    max_tokens: int | None = None,
) -> tuple[str, list[dict]]:
    """Retrieve knowledge chunks plus a structured list of the sources used.

    Same as ``retrieve()`` but also returns the reference list actually
    injected into the prompt (after the token-budget truncation), so callers
    can surface an attribution/"references" call-out in their output. Each ref
    is ``{"source": str, "file_path": str, "heading": str}``. Returns
    ``("", [])`` when nothing is configured or found.
    """
    config = load_config()
    if not config.get("sources"):
        return "", []

    db_path = _get_db_path()
    if not db_path.exists():
        return "", []

    if max_tokens is None:
        max_tokens = _get_max_tokens()

    # Build search terms
    search_terms = set()
    if query_terms:
        search_terms.update(t.lower().strip() for t in query_terms if t.strip())
    if service:
        search_terms.add(service.lower())
    if protocol:
        search_terms.add(protocol.lower())
    if port and port in _PORT_SERVICE_MAP:
        search_terms.add(_PORT_SERVICE_MAP[port])

    if not search_terms:
        return "", []

    try:
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        results = _search(conn, search_terms)
        conn.close()
    except Exception as e:
        logger.warning("Knowledge retrieval failed: %s", e)
        return "", []

    if not results:
        return "", []

    return _format_results_with_refs(results, max_tokens)


def _search(conn: sqlite3.Connection, terms: set[str]) -> list[dict]:
    """Search for relevant chunks using path matching then FTS5."""
    scored = []

    # Pass 1: path/filename match
    all_chunks = conn.execute(
        "SELECT id, source_name, file_path, heading, content, priority FROM chunks"
    ).fetchall()

    for row in all_chunks:
        fp_lower = row["file_path"].lower()
        score = 0
        for term in terms:
            if term in fp_lower:
                score += 10
            if f"pentesting-{term}" in fp_lower:
                score += 20

        if score > 0:
            scored.append({
                "id": row["id"],
                "source": row["source_name"],
                "file_path": row["file_path"],
                "heading": row["heading"],
                "content": row["content"],
                "priority": row["priority"],
                "score": score,
            })

    # Pass 2: FTS5 keyword search (only if path matching gave <10 results)
    if len(scored) < 10:
        fts_terms = " OR ".join(f'"{t}"' for t in terms if len(t) > 2)
        if fts_terms:
            try:
                fts_rows = conn.execute(
                    "SELECT rowid, rank FROM chunks_fts WHERE chunks_fts MATCH ? "
                    "ORDER BY rank LIMIT 20",
                    (fts_terms,),
                ).fetchall()

                existing_ids = {r["id"] for r in scored}
                for fts_row in fts_rows:
                    if fts_row["rowid"] in existing_ids:
                        continue
                    chunk = conn.execute(
                        "SELECT id, source_name, file_path, heading, content, priority "
                        "FROM chunks WHERE id = ?",
                        (fts_row["rowid"],),
                    ).fetchone()
                    if chunk:
                        scored.append({
                            "id": chunk["id"],
                            "source": chunk["source_name"],
                            "file_path": chunk["file_path"],
                            "heading": chunk["heading"],
                            "content": chunk["content"],
                            "priority": chunk["priority"],
                            "score": 5,
                        })
            except Exception as e:
                logger.debug("FTS search failed: %s", e)

    # Rank: user priority > community, then by score
    priority_boost = {"user": 100, "community": 0}
    scored.sort(
        key=lambda r: (priority_boost.get(r["priority"], 0) + r["score"]),
        reverse=True,
    )

    return scored


def _format_results(results: list[dict], max_tokens: int) -> str:
    text, _refs = _format_results_with_refs(results, max_tokens)
    return text


def _format_results_with_refs(
    results: list[dict], max_tokens: int
) -> tuple[str, list[dict]]:
    """Format results for prompt injection and return the refs actually used.

    The returned ``refs`` list contains exactly the chunks that fit within the
    token budget (including a partially-truncated final chunk), so it reflects
    what the model was actually shown — the right thing to attribute.
    """
    max_chars = max_tokens * 4
    lines = [
        "--- Reference Knowledge Base ---",
        "IMPORTANT: When using information from this knowledge base in your analysis, "
        "cite the source using the format [Source: <source_name>/<file_path>]. "
        "If you follow steps from an SOP, reference which SOP you followed.",
        "",
    ]
    refs: list[dict] = []
    current_chars = 0

    def _add_ref(r: dict) -> None:
        ref = {
            "source": r["source"],
            "file_path": r["file_path"],
            "heading": r["heading"] or "",
        }
        if ref not in refs:
            refs.append(ref)

    for r in results:
        header = f"### [{r['source']}] {r['file_path']}"
        if r["heading"]:
            header += f" > {r['heading']}"

        entry = f"{header}\n\n{r['content']}\n"
        entry_len = len(entry)

        if current_chars + entry_len > max_chars:
            remaining = max_chars - current_chars
            if remaining > 200:
                lines.append(entry[:remaining] + "\n[...truncated]")
                _add_ref(r)
            break

        lines.append(entry)
        _add_ref(r)
        current_chars += entry_len

    lines.append("--- End Reference Knowledge Base ---")
    return "\n".join(lines), refs
