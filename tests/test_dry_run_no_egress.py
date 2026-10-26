"""Regression: --dry-run must make NO external calls.

Modules that reach an external service (the AI providers ai_analyze /
ai_analyze_gowitness / ai_validate, and shodan_enrich which posts
client IPs to the Shodan API) must NOT be in _PASSTHROUGH_DRY_RUN. Under
--dry-run they must fall through to a synthetic fixture instead of executing for
real — otherwise `monkeyx --continue ./out --dry-run -m ai_analyze` would send
scan data (IPs, page titles, screenshots) to a third party despite the operator
asking for a dry run.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import workflows


_EGRESS_MODULES = (
    "ai_analyze",
    "ai_analyze_gowitness",
    "ai_validate",
    "shodan_enrich",
)


class TestEgressModulesNotPassthrough:
    def test_egress_modules_excluded_from_passthrough(self):
        leaked = set(_EGRESS_MODULES) & workflows._PASSTHROUGH_DRY_RUN
        assert not leaked, (
            f"network-egress modules must not passthrough --dry-run: {leaked}")

    def test_local_transforms_still_passthrough(self):
        # The pure-local file transforms must keep running for real so a dry-run
        # still exercises the normalize -> analyze -> report path.
        for name in ("normalize", "analyze", "focus", "summary",
                     "jsonl_to_csv", "nmap_converter"):
            assert name in workflows._PASSTHROUGH_DRY_RUN, f"{name} dropped"


class TestDryRunDoesNotInvokeEgressModule:
    def test_ai_module_real_fn_never_called_under_dry_run(self, monkeypatch):
        # Replace the real module callable with a landmine: if --dry-run ever
        # routed to it, it would raise and egress client data in production.
        for name in _EGRESS_MODULES:
            if name not in workflows.AVAILABLE_MODULES:
                continue

            def _landmine(**kwargs):
                raise AssertionError(
                    f"{name} executed under --dry-run — external call would fire")

            monkeypatch.setitem(workflows.AVAILABLE_MODULES, name, _landmine)
            result = workflows.run_module(name, _dry_run=True, prefix="/tmp/dryrun-test")
            assert result.get("status") == "success"
