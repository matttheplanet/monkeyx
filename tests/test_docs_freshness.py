"""Doc-freshness guards: fail when the README drifts from the actual code.

This repo has repeatedly shipped README examples referencing modules/workflows
that were renamed or removed (ax_tcp_baseline, `-w full`, a nonexistent nessus
scanner, phantom ax_dnsx_resolve). These tests make that drift a CI failure
instead of a support ticket.

They intentionally check only what is cheap and unambiguous — that every
module/workflow *named* in the README exists — rather than asserting the whole
-h block char-for-char (which would break on harmless wording tweaks).
"""

import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from workflows import AVAILABLE_MODULES, WORKFLOWS

_REPO_ROOT = os.path.join(os.path.dirname(__file__), "..")
_README = os.path.join(_REPO_ROOT, "README.md")


def _readme_text():
    with open(_README, encoding="utf-8") as f:
        return f.read()


def _modules_referenced_in_readme(text):
    """Every module name following a `-m`/`--modules` flag in a README command.

    Grabs the run of bare tokens after -m up to the next flag/pipe/redirect, so
    `-m ax_nmap_tcp ax_nuclei` yields both. Ignores placeholders in <angle> or
    UPPERCASE (e.g. MODULE) form.
    """
    names = set()
    for m in re.finditer(r'(?:-m|--modules)\s+([^\n|>&#]+)', text):
        for tok in m.group(1).split():
            if tok.startswith("-"):
                break  # reached the next flag
            if tok.startswith("<") or tok.upper() == tok:
                continue  # placeholder like <MODULE> or MODULE
            if re.fullmatch(r"[a-z0-9_]+", tok):
                names.add(tok)
    return names


def _workflows_referenced_in_readme(text):
    """Every workflow name following a `-w`/`--workflow` flag in a README command."""
    names = set()
    for m in re.finditer(r'(?:-w|--workflow)\s+([A-Za-z0-9_]+)', text):
        tok = m.group(1)
        if tok.upper() == tok and not tok.islower():
            continue  # placeholder like WORKFLOW
        names.add(tok)
    return names


def test_readme_module_references_exist():
    text = _readme_text()
    referenced = _modules_referenced_in_readme(text)
    assert referenced, "sanity: expected to find some -m module references in README"
    unknown = sorted(m for m in referenced if m not in AVAILABLE_MODULES)
    assert not unknown, (
        f"README references modules that don't exist: {unknown}. "
        f"Available: {sorted(AVAILABLE_MODULES)}"
    )


def test_readme_workflow_references_exist():
    text = _readme_text()
    referenced = _workflows_referenced_in_readme(text)
    assert referenced, "sanity: expected to find some -w workflow references in README"
    unknown = sorted(w for w in referenced if w not in WORKFLOWS)
    assert not unknown, (
        f"README references workflows that don't exist: {unknown}. "
        f"Available: {sorted(WORKFLOWS)}"
    )
