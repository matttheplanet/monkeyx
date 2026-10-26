"""Regression test for bbot target command-injection (security review Finding 1).

bbot targets include SCAN-DERIVED values (redirect Location headers, crawled
URLs, PTR hostnames) that never pass shell-charset validation, and the bbot
command runs via bash_command (/bin/bash -c). Previously small target lists were
inlined with only single-quote wrapping, so a target containing `'$(...)'` could
break out and run code on the scanning host. _build_target_arg must ALWAYS write
targets to a file and pass only that (single, quoted) filename on the command
line — never the target values themselves.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules import _bbot_common


_MALICIOUS = "http://x'$(touch /tmp/monkeyx_pwned)'.example.com/"


def test_target_arg_is_always_a_file_not_inline(tmp_path):
    out = str(tmp_path / "scan-bbot.jsonl")
    arg, target_file = _bbot_common._build_target_arg(["example.com"], out)
    # Never inline: a temp file is always produced and the arg is just its path.
    assert target_file is not None
    assert os.path.exists(target_file)
    assert arg == f"'{target_file}'"
    os.unlink(target_file)


def test_malicious_target_never_reaches_command_line(tmp_path):
    out = str(tmp_path / "scan-bbot.jsonl")
    arg, target_file = _bbot_common._build_target_arg(
        [_MALICIOUS, "example.com"], out)
    try:
        # The shell-metachar payload must NOT appear in the command-line arg…
        assert "$(" not in arg
        assert _MALICIOUS not in arg
        # …it lives in the file (bbot reads -t <file> natively), verbatim.
        assert _MALICIOUS in open(target_file).read()
    finally:
        os.unlink(target_file)


def test_small_list_still_uses_a_file(tmp_path):
    # The old code inlined lists of <=50; confirm even a 1-element list files it.
    out = str(tmp_path / "scan-bbot.jsonl")
    arg, target_file = _bbot_common._build_target_arg(["a.com"], out)
    try:
        assert target_file is not None and arg == f"'{target_file}'"
    finally:
        os.unlink(target_file)
