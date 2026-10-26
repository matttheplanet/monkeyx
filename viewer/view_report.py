#!/usr/bin/env python3
"""Standalone MonkeyX report viewer.

Bundled inside every results zip under ``viewer/``. Lets a client who received
ONLY the scan output (not a full MonkeyX install) browse their ``scan.db`` in the
same live web view the operator uses — findings, focus list, ports, targets, web
endpoints, with search + CSV export.

    pip install -r viewer/requirements-viewer.txt
    python viewer/view_report.py            # serves the scan.db next to viewer/
    python viewer/view_report.py ./some-dir # or point at another unzipped run

Only depends on fastapi + uvicorn (see requirements-viewer.txt). Reads scan.db
read-only, binds 127.0.0.1 by default. This is the SAME webserver.py the engine
ships — copied verbatim into the zip at build time, so it never drifts from the
schema that produced your data.
"""

import argparse
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))


def _default_output_dir() -> str:
    # The zip lays out scan.db at the root and this launcher under viewer/, so
    # the run directory is our parent. Fall back to cwd if that has no scan.db.
    parent = os.path.dirname(_HERE)
    if os.path.exists(os.path.join(parent, "scan.db")):
        return parent
    return os.getcwd()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Serve a live web view of a MonkeyX run's scan.db.")
    parser.add_argument(
        "output_dir", nargs="?", default=None,
        help="Run directory containing scan.db (default: the directory this "
             "viewer was unzipped into).")
    parser.add_argument("--host", default="127.0.0.1",
                        help="Interface to bind (default 127.0.0.1, localhost "
                             "only). Use 0.0.0.0 to expose on the network.")
    parser.add_argument("--port", type=int, default=8765,
                        help="Port to bind (default 8765).")
    args = parser.parse_args()

    output_dir = args.output_dir or _default_output_dir()
    if not os.path.exists(os.path.join(output_dir, "scan.db")):
        print(f"[!] No scan.db found in {output_dir}")
        print("    Point the viewer at the unzipped run directory, e.g.:")
        print("      python viewer/view_report.py /path/to/unzipped-run")
        return 1

    # webserver.py lives beside this launcher and does `from core import scan_db`;
    # our bundled viewer/core/ (stub __init__ + scan_db.py) satisfies that without
    # needing the full engine's core package (which pulls in fleet/axiom).
    sys.path.insert(0, _HERE)
    try:
        from webserver import serve
    except ImportError as exc:
        print(f"[!] Could not load the viewer: {exc}")
        print("    Easiest: let the bootstrap script make a venv + install for you:")
        print("      ./viewer/run.sh        (macOS/Linux)")
        print("      viewer\\run.bat         (Windows)")
        print("    Or install manually: pip install -r viewer/requirements-viewer.txt")
        return 1

    serve(output_dir, host=args.host, port=args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
