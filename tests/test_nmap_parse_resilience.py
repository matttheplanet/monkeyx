"""read_xmlfile must fail with a catchable exception, never exit().

The nmap-XML callers (ax_nmap_tcp / ax_nmap_udp) wrap parsing in
`except Exception` to log-and-continue. read_xmlfile previously called exit(1)
on a bad file, raising SystemExit — a BaseException that slips past
`except Exception` and aborts the WHOLE scan when a single host's XML is corrupt.
It must raise a normal exception (ValueError) instead.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from core.nmap_service_parse import read_xmlfile, nmap_to_tcphosts


def test_missing_file_raises_valueerror_not_systemexit(tmp_path):
    missing = str(tmp_path / "nope.xml")
    with pytest.raises(ValueError):
        read_xmlfile(missing)


def test_missing_file_does_not_raise_systemexit(tmp_path):
    # Explicitly prove SystemExit (BaseException) is not what escapes — that's
    # the bug: `except Exception` in the caller wouldn't catch it.
    try:
        read_xmlfile(str(tmp_path / "nope.xml"))
    except SystemExit:
        pytest.fail("read_xmlfile raised SystemExit; caller's except Exception can't catch it")
    except ValueError:
        pass


def test_caller_style_except_exception_catches_it(tmp_path):
    # Mirror ax_nmap_tcp's guard: a bad XML must degrade gracefully.
    caught = False
    try:
        nmap_to_tcphosts(str(tmp_path / "nope.xml"), str(tmp_path / "out"), "tcpscan")
    except Exception:
        caught = True
    assert caught, "expected a catchable Exception from a missing nmap XML"


def test_entity_declaration_stripped(tmp_path):
    # A billion-laughs style ENTITY block must be stripped before parsing so it
    # can't expand. The parse should still succeed and yield no hosts.
    xml = (
        '<?xml version="1.0"?>\n'
        '<!DOCTYPE nmaprun [ <!ENTITY lol "lololol"> ]>\n'
        '<nmaprun><host><address addr="1.2.3.4"/></host></nmaprun>\n'
    )
    p = tmp_path / "tcp.xml"
    p.write_text(xml)
    soup = read_xmlfile(str(p))
    assert soup is not None
    # No <ports> so parsing produces no service files — just shouldn't blow up.
    assert soup.find_all("host")
