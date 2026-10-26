"""Guard: CLAUDE.md is a lean index, not a monolith.

The harness only auto-loads CLAUDE.md up to a char limit; past it, the file is
silently truncated. To keep it a reliable map we cap it well under that limit —
deep-dive prose belongs in docs/*.md (linked from the index), not inline here.

If this fails, don't raise the budget: move the new prose into the relevant
docs/*.md and leave a one-line pointer in CLAUDE.md.
"""
import glob
import os

import pytest

# Comfortable headroom under the harness's 40k auto-load limit.
BUDGET_CHARS = 38_000

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _claude_md_files():
    # Top-level CLAUDE.md plus any nested ones the repo grows later.
    found = set(glob.glob(os.path.join(REPO_ROOT, "**", "CLAUDE.md"), recursive=True))
    # Never scan a vendored/submodule copy under site-packages/node_modules/etc.
    return sorted(
        p for p in found
        if not any(seg in p.split(os.sep)
                   for seg in ("site-packages", "node_modules", ".venv", "venv"))
    )


@pytest.mark.parametrize("path", _claude_md_files())
def test_claude_md_under_budget(path):
    size = os.path.getsize(path)
    rel = os.path.relpath(path, REPO_ROOT)
    assert size <= BUDGET_CHARS, (
        f"{rel} is {size} chars, over the {BUDGET_CHARS} budget. "
        f"Move deep-dive content into docs/*.md and link it from the index "
        f"instead of inlining it here."
    )
