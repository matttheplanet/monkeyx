"""Tests for the standalone-viewer bundler (viewer/bundle.py).

The engine owns the viewer as the single source of truth: the CLI results zip
(monkeyx.py) calls bundle_viewer(), and downstream consumers reuse the same
helper, so this guards the contents/layout of the viewer/ folder that ships in
every results zip.
"""

import os
import sys
from zipfile import ZipFile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from viewer.bundle import bundle_viewer

_EXPECTED = {
    "viewer/view_report.py",
    "viewer/requirements-viewer.txt",
    "viewer/core/__init__.py",
    "viewer/run.sh",
    "viewer/run.bat",
    "viewer/webserver.py",
    "viewer/core/scan_db.py",
}


def _bundle(tmp_path):
    zp = tmp_path / "out.zip"
    with ZipFile(zp, "w") as z:
        bundle_viewer(z)
    return zp


def test_bundle_contains_full_viewer_surface(tmp_path):
    with ZipFile(_bundle(tmp_path)) as z:
        assert _EXPECTED <= set(z.namelist())


def test_run_sh_keeps_executable_bit(tmp_path):
    with ZipFile(_bundle(tmp_path)) as z:
        mode = (z.getinfo("viewer/run.sh").external_attr >> 16) & 0o777
        assert mode & 0o111  # `./viewer/run.sh` works straight from an unzip


def test_bundled_webserver_and_scan_db_are_live_copies(tmp_path):
    """The two executable files are copied verbatim from the engine tree, so the
    viewer can never drift from the schema that produced a run's scan.db."""
    engine = os.path.join(os.path.dirname(__file__), "..")
    with ZipFile(_bundle(tmp_path)) as z:
        assert z.read("viewer/webserver.py") == \
            open(os.path.join(engine, "webserver.py"), "rb").read()
        assert z.read("viewer/core/scan_db.py") == \
            open(os.path.join(engine, "core", "scan_db.py"), "rb").read()


def test_core_init_is_the_stub_not_the_real_package(tmp_path):
    """viewer/core/__init__.py must be the stub — the real core/__init__.py
    eager-imports fleet/axiom, which a viewer-only client does not have."""
    with ZipFile(_bundle(tmp_path)) as z:
        stub = z.read("viewer/core/__init__.py").decode()
    # No executable import statements (the real one does `from .fleet import ...`),
    # so a viewer-only client never triggers the fleet/axiom import chain.
    code_lines = [ln.strip() for ln in stub.splitlines()
                  if ln.strip() and not ln.strip().startswith(('"', "#"))]
    assert not any(ln.startswith(("import ", "from ")) for ln in code_lines)
    assert "report viewer" in stub
