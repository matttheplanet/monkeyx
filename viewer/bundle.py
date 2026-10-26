"""Bundle the standalone report viewer into a results zip.

Single source of truth for what the ``viewer/`` folder in a results zip contains.
The engine CLI (``monkeyx.py`` results-archive block) calls this, and downstream
consumers that produce their own results zip reuse the same helper — so every
producer ships the identical viewer.

The launcher / bootstrap scripts / stub live beside this file; the two files the
viewer actually executes (``webserver.py`` + ``core/scan_db.py``) are copied LIVE
from the engine tree, so the viewer can never drift from the schema that produced
the run's ``scan.db``.
"""

import logging
import os
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

logger = logging.getLogger("monkeyx.viewer.bundle")

_VIEWER_DIR = os.path.dirname(os.path.abspath(__file__))
_ENGINE_DIR = os.path.dirname(_VIEWER_DIR)

# (source path, arcname in zip, executable). run.sh keeps its +x bit so a client
# can `./viewer/run.sh` straight from an unzip.
_MEMBERS = (
    (os.path.join(_VIEWER_DIR, "view_report.py"), "viewer/view_report.py", False),
    (os.path.join(_VIEWER_DIR, "requirements-viewer.txt"),
     "viewer/requirements-viewer.txt", False),
    (os.path.join(_VIEWER_DIR, "core_init_stub.py"), "viewer/core/__init__.py", False),
    (os.path.join(_VIEWER_DIR, "run.sh"), "viewer/run.sh", True),
    (os.path.join(_VIEWER_DIR, "run.bat"), "viewer/run.bat", False),
    (os.path.join(_ENGINE_DIR, "webserver.py"), "viewer/webserver.py", False),
    (os.path.join(_ENGINE_DIR, "core", "scan_db.py"), "viewer/core/scan_db.py", False),
)


def bundle_viewer(archive: ZipFile) -> None:
    """Write the ``viewer/`` folder into an already-open results-zip ``archive``.

    Best-effort: a missing source file is skipped, and any error is swallowed so
    it can never fail an otherwise-successful run (mirrors report.html/README.txt).
    """
    for src, arcname, executable in _MEMBERS:
        try:
            if not (os.path.exists(src) and os.path.isfile(src)):
                logger.warning("Viewer source missing, skipped: %s", src)
                continue
            with open(src, "rb") as fh:
                data = fh.read()
            info = ZipInfo(arcname)
            info.external_attr = (0o755 if executable else 0o644) << 16
            info.compress_type = ZIP_DEFLATED
            archive.writestr(info, data)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("Skipped viewer file %s: %s", arcname, exc)
