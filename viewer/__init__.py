"""MonkeyX standalone report viewer (bundled into results zips).

Package marker so ``from viewer.bundle import bundle_viewer`` resolves in the
engine tree. The client-facing files here (view_report.py, run.sh, run.bat,
requirements-viewer.txt, core_init_stub.py) are copied into the ``viewer/`` folder
of a results zip by :func:`viewer.bundle.bundle_viewer`; this __init__ is NOT
shipped in the zip.
"""
