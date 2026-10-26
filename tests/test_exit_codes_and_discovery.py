"""Batch-1 hardening regression tests.

#3  Process exit-code contract: a run with a failed step must not exit 0
    (the private API keys off the exit code; a swallowed failure marked a
    partially-covered engagement as a clean success). Also asserts the
    pause/fatal/clean codes are the values the API/CI/Docker expect.
#9  Module discovery must register only functions DEFINED in a module — the
    shared run_* helpers (run_ax_module, run_bbot_flags, run_bbot_modules)
    imported into modules must not leak into AVAILABLE_MODULES as fake modules.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.checkpoint import (
    EXIT_CODE_OK,
    EXIT_CODE_FATAL,
    EXIT_CODE_STEP_FAILURES,
    EXIT_CODE_PAUSED,
)


# --- #3: exit-code contract ---------------------------------------------- #

class TestExitCodeConstants:
    def test_distinct_and_expected_values(self):
        # These exact integers are the wire contract the API subprocess wrapper,
        # CI, and Docker jobs branch on. Changing them silently breaks all three.
        assert EXIT_CODE_OK == 0
        assert EXIT_CODE_FATAL == 1
        assert EXIT_CODE_STEP_FAILURES == 3
        assert EXIT_CODE_PAUSED == 42
        assert len({EXIT_CODE_OK, EXIT_CODE_FATAL,
                    EXIT_CODE_STEP_FAILURES, EXIT_CODE_PAUSED}) == 4


class TestCompletionExitCode:
    def _fn(self):
        from monkeyx import _completion_exit_code
        return _completion_exit_code

    def test_all_succeeded_is_ok(self):
        fn = self._fn()
        results = [{"module": "a", "status": "success"},
                   {"module": "b", "status": "success"}]
        assert fn(results) == EXIT_CODE_OK

    def test_one_failed_step_is_step_failures(self):
        fn = self._fn()
        results = [{"module": "a", "status": "success"},
                   {"module": "b", "status": "failed", "error": "boom"}]
        assert fn(results) == EXIT_CODE_STEP_FAILURES

    def test_empty_results_is_ok(self):
        fn = self._fn()
        assert fn([]) == EXIT_CODE_OK
        assert fn(None) == EXIT_CODE_OK

    def test_non_dict_results_ignored(self):
        fn = self._fn()
        # Defensive: a stray non-dict result must not crash or be counted failed.
        assert fn(["oops", {"status": "success"}]) == EXIT_CODE_OK


# --- #9: module discovery leak ------------------------------------------- #

class TestModuleDiscoveryNoHelperLeak:
    def test_shared_helpers_not_registered(self):
        import workflows
        leaked = {"ax_module", "bbot_flags", "bbot_modules"} & set(
            workflows.AVAILABLE_MODULES)
        assert not leaked, f"shared run_* helpers leaked as modules: {leaked}"

    def test_real_modules_still_present(self):
        import workflows
        # A representative slice across every module family — the __module__
        # guard must not drop any genuinely-defined module.
        for name in ("normalize", "ax_nuclei", "ax_testssl", "ax_wafw00f",
                     "bbot_cloud", "bbot_recon", "bbot_passive", "bbot_dast",
                     "bbot_takeover", "bbot_code", "shodan_enrich"):
            assert name in workflows.AVAILABLE_MODULES, f"{name} missing"

    def test_every_registered_callable_is_own_module(self):
        import workflows
        # The invariant the fix enforces: each registered run_* is defined in the
        # module it was discovered from, never an imported helper.
        for name, fn in workflows.AVAILABLE_MODULES.items():
            mod = getattr(fn, "__module__", "")
            assert mod.startswith("modules."), (
                f"{name} -> {mod} is not a modules.* function")
