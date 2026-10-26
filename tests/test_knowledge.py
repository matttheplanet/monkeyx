"""Smoke tests for core.knowledge — chunking, indexing, retrieval."""
import os
import sqlite3
import tempfile
from unittest.mock import patch

import pytest

from core.knowledge import (
    _chunk_markdown,
    _ensure_schema,
    _format_results,
    _search,
    _split_at_paragraphs,
    retrieve,
    reload,
)


def test_chunk_markdown_basic():
    md = """# SSH Pentesting

## Enumeration

Use nmap to find SSH versions. Check for banner information that reveals the exact OpenSSH version. Look for deprecated key exchange algorithms and weak ciphers in the negotiation.

## Exploitation

Check for weak keys and known vulnerabilities. Test for CVE-2018-15473 user enumeration. Attempt brute force with hydra using common credential wordlists against discovered accounts.
"""
    chunks = _chunk_markdown(md, "pentesting-ssh.md")
    assert len(chunks) >= 2
    assert chunks[0]["heading"] == "SSH Pentesting > Enumeration"
    assert "nmap" in chunks[0]["content"]


def test_chunk_markdown_strips_frontmatter():
    md = """---
title: Test
tags: [security]
---

# Content

Actual content here that should be indexed and returned.
"""
    chunks = _chunk_markdown(md, "test.md")
    assert len(chunks) == 1
    assert "title: Test" not in chunks[0]["content"]
    assert "Actual content" in chunks[0]["content"]


def test_chunk_markdown_empty():
    assert _chunk_markdown("", "empty.md") == []
    assert _chunk_markdown("   \n\n  ", "blank.md") == []


def test_split_at_paragraphs():
    text = "Para one.\n\nPara two.\n\nPara three is longer and should cause a split."
    chunks = _split_at_paragraphs(text, max_chars=40)
    assert len(chunks) >= 2
    for chunk in chunks:
        assert len(chunk) <= 80  # some tolerance for paragraph boundaries


def test_ensure_schema():
    db = tempfile.mktemp(suffix=".db")
    try:
        conn = sqlite3.connect(db)
        _ensure_schema(conn)
        tables = [r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()]
        assert "chunks" in tables
        assert "chunks_fts" in tables
        conn.close()
    finally:
        os.unlink(db)


def test_search_path_matching():
    db = tempfile.mktemp(suffix=".db")
    try:
        conn = sqlite3.connect(db)
        _ensure_schema(conn)
        conn.execute(
            "INSERT INTO chunks (source_name, file_path, heading, content, priority, updated_at) "
            "VALUES (?, ?, ?, ?, ?, 0)",
            ("hacktricks", "network-services-pentesting/pentesting-ssh.md",
             "SSH", "Test SSH content about OpenSSH", "community"),
        )
        conn.execute(
            "INSERT INTO chunks (source_name, file_path, heading, content, priority, updated_at) "
            "VALUES (?, ?, ?, ?, ?, 0)",
            ("hacktricks", "network-services-pentesting/pentesting-smtp.md",
             "SMTP", "Test SMTP relay content", "community"),
        )
        conn.execute("INSERT INTO chunks_fts(chunks_fts) VALUES('rebuild')")
        conn.commit()
        conn.row_factory = sqlite3.Row

        results = _search(conn, {"ssh"})
        assert len(results) >= 1
        assert any("ssh" in r["file_path"] for r in results)

        results = _search(conn, {"smtp"})
        assert len(results) >= 1
        assert all("smtp" in r["file_path"] for r in results)

        conn.close()
    finally:
        os.unlink(db)


def test_search_priority_ranking():
    db = tempfile.mktemp(suffix=".db")
    try:
        conn = sqlite3.connect(db)
        _ensure_schema(conn)
        conn.execute(
            "INSERT INTO chunks (source_name, file_path, heading, content, priority, updated_at) "
            "VALUES (?, ?, ?, ?, ?, 0)",
            ("hacktricks", "pentesting-ssh.md", "SSH", "Community SSH guide", "community"),
        )
        conn.execute(
            "INSERT INTO chunks (source_name, file_path, heading, content, priority, updated_at) "
            "VALUES (?, ?, ?, ?, ?, 0)",
            ("internal-sops", "ssh-sop.md", "SSH SOP", "Internal SSH assessment steps", "user"),
        )
        conn.execute("INSERT INTO chunks_fts(chunks_fts) VALUES('rebuild')")
        conn.commit()
        conn.row_factory = sqlite3.Row

        results = _search(conn, {"ssh"})
        assert len(results) == 2
        # User priority should rank first
        assert results[0]["priority"] == "user"
        conn.close()
    finally:
        os.unlink(db)


def test_format_results_truncation():
    results = [
        {"source": "test", "file_path": "a.md", "heading": "H", "content": "x" * 500},
        {"source": "test", "file_path": "b.md", "heading": "H", "content": "y" * 500},
        {"source": "test", "file_path": "c.md", "heading": "H", "content": "z" * 500},
    ]
    # 100 tokens * 4 = 400 chars budget — should only fit ~1 entry
    formatted = _format_results(results, max_tokens=100)
    assert "--- Reference Knowledge Base ---" in formatted
    assert "--- End Reference Knowledge Base ---" in formatted
    assert "IMPORTANT:" in formatted


def test_format_results_citation_instruction():
    results = [{"source": "sops", "file_path": "test.md", "heading": "", "content": "content"}]
    formatted = _format_results(results, max_tokens=1000)
    assert "cite the source" in formatted.lower() or "Source:" in formatted


def test_retrieve_no_config():
    reload()
    with patch("core.knowledge._CONFIG_PATH") as mock_path:
        mock_path.exists.return_value = False
        reload()
        result = retrieve(query_terms=["ssh"])
        assert result == ""


def test_retrieve_no_db():
    from pathlib import Path
    reload()
    with patch("core.knowledge._get_db_path") as mock_db:
        mock_db.return_value = Path(tempfile.mktemp(suffix=".db"))  # non-existent path
        with patch("core.knowledge.load_config", return_value={"sources": [{"name": "test"}]}):
            result = retrieve(query_terms=["ssh"])
            assert result == ""
