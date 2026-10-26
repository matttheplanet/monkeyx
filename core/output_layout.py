"""Canonical on-disk layout for a run's output directory.

Central definition of where the exported ledger list files live. The ledger
exports its scoped target/port/URL/domain lists to ``ledger-*.txt`` files that
modules consume as tool inputs. These used to sit loose in ``data/`` alongside
the normalized scanner output; they now live together in ``data/ledger/`` so the
data dir stays readable and the intermediate list files are grouped.

Both the producer (workflows.py -> TargetLedger exporters) and every consumer
(tool_runners, ai_validate, analyze, ...) build their paths through
``ledger_file`` so the location is defined exactly once. The exporters create
the directory on write, so callers never need to mkdir it themselves.
"""

import os

# Subdirectory of the run's ``data/`` dir holding the exported ledger-*.txt files.
LEDGER_SUBDIR = "ledger"


def ledger_dir(data_dir: str) -> str:
    """Directory (inside ``data/``) holding the exported ledger-*.txt list files."""
    return os.path.join(data_dir, LEDGER_SUBDIR)


def ledger_file(data_dir: str, name: str) -> str:
    """Absolute path to an exported ledger list file within the ledger subdir."""
    return os.path.join(data_dir, LEDGER_SUBDIR, name)
