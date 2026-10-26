"""Mechanical lint: ban a few footguns that already caused real bugs.

These are NOT judgment calls — they are unambiguous patterns that should never
appear in shipped code, so CI fails the build rather than relying on review or a
skill to remember. Keep this list SHORT and unambiguous; nuanced checks belong
in /security-review, not here.

Covered:
  1. subprocess(..., shell=True)  — shell injection surface (the ai_validate RCE).
  2. defusedxml.ElementTree used for Element/SubElement/ElementTree construction
     — defusedxml only exports parsers; this raises AttributeError at import/runtime
     (the bug that silently dropped `normalize` from the module registry).
"""

import os
import re

_REPO_ROOT = os.path.join(os.path.dirname(__file__), "..")

# Directories we don't lint (tests may reference patterns as strings/mocks).
_SKIP_DIRS = {"tests", ".git", "__pycache__", ".pytest_cache", "docs", "examples"}


def _iter_source_files():
    for dirpath, dirnames, filenames in os.walk(_REPO_ROOT):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fn in filenames:
            if fn.endswith(".py"):
                yield os.path.join(dirpath, fn)


def _lines(path):
    with open(path, encoding="utf-8", errors="ignore") as f:
        return f.readlines()


def test_no_shell_true():
    """No subprocess call may pass shell=True — commands must use argv lists."""
    pattern = re.compile(r"shell\s*=\s*True")
    offenders = []
    for path in _iter_source_files():
        for i, line in enumerate(_lines(path), 1):
            # Allow an explicit opt-out marker for a reviewed, justified exception.
            if pattern.search(line) and "lint-allow: shell-true" not in line:
                rel = os.path.relpath(path, _REPO_ROOT)
                offenders.append(f"{rel}:{i}: {line.strip()}")
    assert not offenders, (
        "shell=True is banned (shell-injection surface). Use an argv list with "
        "shell=False. If truly justified, append '# lint-allow: shell-true' and "
        "get it reviewed.\n" + "\n".join(offenders)
    )


def test_no_defusedxml_element_construction():
    """A file importing defusedxml.ElementTree as ET must not use it to build
    elements — defusedxml only exports parsers (parse/fromstring/ParseError).
    Use the stdlib xml.etree.ElementTree (aliased) for Element/SubElement/etc.
    """
    import_re = re.compile(r"import\s+defusedxml\.ElementTree\s+as\s+(\w+)")
    offenders = []
    for path in _iter_source_files():
        text = "".join(_lines(path))
        m = import_re.search(text)
        if not m:
            continue
        alias = m.group(1)  # usually "ET"
        bad_re = re.compile(rf"\b{re.escape(alias)}\.(Element|SubElement|ElementTree|TreeBuilder)\b")
        for i, line in enumerate(text.splitlines(), 1):
            if bad_re.search(line):
                rel = os.path.relpath(path, _REPO_ROOT)
                offenders.append(f"{rel}:{i}: {line.strip()}")
    assert not offenders, (
        "defusedxml.ElementTree does not export Element/SubElement/ElementTree "
        "(it only parses). Import stdlib xml.etree.ElementTree separately for "
        "construction/type-annotations.\n" + "\n".join(offenders)
    )
