"""Minimal ``core`` package for the standalone report viewer.

The engine's real ``core/__init__.py`` eagerly imports fleet/axiom/utils, which a
client running only the viewer does not have installed. The viewer needs just
``core.scan_db``, so this stub package ships an empty __init__ next to a verbatim
copy of scan_db.py. Bundled into the results zip as ``viewer/core/__init__.py``.
"""
