"""Checkpoint support for pause/resume of scan workflows."""

import json
import os
import tempfile
from datetime import datetime, timezone

CHECKPOINT_VERSION = 1
CHECKPOINT_FILENAME = "checkpoint.json"
PAUSE_SENTINEL_FILENAME = "pause.requested"

# Process exit-code contract (consumed by the private API's subprocess wrapper,
# CI, and Docker jobs — all of which key off the exit code, not stdout):
#   0  = clean success (every step succeeded)
#   1  = fatal engine error (an exception escaped run_modules) OR invalid
#        input/config caught before the run
#   3  = the run completed but one or more pipeline steps failed (the engine
#        logs step failures and continues; a partially-covered engagement must
#        not look identical to a clean one)
#   42 = paused (checkpoint written; resume with --resume)
#   signal-death (-15/-9) = cancelled/terminated externally
EXIT_CODE_OK = 0
EXIT_CODE_FATAL = 1
EXIT_CODE_STEP_FAILURES = 3
EXIT_CODE_PAUSED = 42

def _reject_shell_metachars(kwargs: dict) -> None:
    """Raise ValueError if any restored kwarg carries a shell-quote-breaking char.

    Restored checkpoint kwargs re-enter single-quote-wrapped shell commands
    (ax scan '{target}' --fleet '{fleet}' ...) on resume WITHOUT passing back
    through the argparse `shell_safe_str` validator that guards them at
    first-run time. A locally-tampered checkpoint.json could smuggle a "'" or
    NUL to break out of that quoting.

    We validate EVERY string value (and string items in list/tuple values),
    not a hand-maintained subset of keys — so a checkpoint kwarg added later
    that reaches a shell command can't silently bypass the guard. Non-string
    scalars (int/float/bool) can't carry these characters and are skipped.
    """
    def _check(key, val):
        if isinstance(val, str) and ("'" in val or "\x00" in val):
            raise ValueError(
                f"checkpoint kwarg '{key}' contains an illegal shell character "
                f"(possible tampering): {val!r}"
            )
        elif isinstance(val, (list, tuple)):
            for item in val:
                _check(key, item)

    for key, val in kwargs.items():
        _check(key, val)


class Checkpoint:
    def __init__(self, output_dir: str):
        self.output_dir = output_dir
        self.checkpoint_path = os.path.join(output_dir, CHECKPOINT_FILENAME)
        self.sentinel_path = os.path.join(output_dir, PAUSE_SENTINEL_FILENAME)

    def is_pause_requested(self) -> bool:
        return os.path.exists(self.sentinel_path)

    def request_pause(self) -> None:
        os.makedirs(self.output_dir, exist_ok=True)
        with open(self.sentinel_path, "w") as f:
            f.write(datetime.now(timezone.utc).isoformat())

    def clear_pause_request(self) -> None:
        try:
            os.remove(self.sentinel_path)
        except FileNotFoundError:
            pass

    def write(
        self,
        next_step_index: int,
        total_steps: int,
        workflow: str | None,
        modules: list[str],
        kwargs: dict,
        fleet_killed: bool,
        steps: list | None = None,
    ) -> None:
        data = {
            "version": CHECKPOINT_VERSION,
            "paused_at": datetime.now(timezone.utc).isoformat(),
            "next_step_index": next_step_index,
            "total_steps": total_steps,
            "workflow": workflow,
            "modules": modules,
            "kwargs": _serialize_kwargs(kwargs),
            "fleet_killed": fleet_killed,
        }
        if steps is not None:
            data["steps"] = serialize_steps(steps)
        dir_fd = None
        try:
            fd, tmp_path = tempfile.mkstemp(
                dir=self.output_dir, suffix=".tmp", prefix="checkpoint-"
            )
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, self.checkpoint_path)
            dir_fd = os.open(self.output_dir, os.O_RDONLY)
            os.fsync(dir_fd)
        finally:
            if dir_fd is not None:
                os.close(dir_fd)

    @classmethod
    def load(cls, output_dir: str) -> dict:
        path = os.path.join(output_dir, CHECKPOINT_FILENAME)
        if not os.path.exists(path):
            raise FileNotFoundError(f"No checkpoint file at {path}")
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if data.get("version") != CHECKPOINT_VERSION:
            raise ValueError(
                f"Checkpoint version mismatch: expected {CHECKPOINT_VERSION}, "
                f"got {data.get('version')}"
            )
        # Re-validate restored kwargs against shell-metachar injection before they
        # flow back into fleet/scan commands on resume.
        _reject_shell_metachars(data.get("kwargs", {}))
        return data

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            data = self.load(self.output_dir)
        except FileNotFoundError:
            return ["checkpoint.json does not exist"]
        except (json.JSONDecodeError, ValueError) as e:
            return [f"checkpoint.json is invalid: {e}"]

        kwargs = data.get("kwargs", {})

        target = kwargs.get("target")
        if target and not os.path.exists(target):
            errors.append(f"Target file does not exist: {target}")

        url_file = kwargs.get("url_file")
        if url_file and not os.path.exists(url_file):
            if os.path.basename(url_file) != "master-urls.txt":
                errors.append(f"URL file does not exist: {url_file}")

        domainlist = kwargs.get("domainlist")
        if domainlist and not os.path.exists(domainlist):
            errors.append(f"Domain list file does not exist: {domainlist}")

        data_prefix = kwargs.get("data_prefix", "")
        if data_prefix:
            data_dir = os.path.dirname(data_prefix)
            if data_dir and not os.path.isdir(data_dir):
                errors.append(f"Data directory does not exist: {data_dir}")

        return errors

    def delete(self) -> None:
        try:
            os.remove(self.checkpoint_path)
        except FileNotFoundError:
            pass


def _serialize_kwargs(kwargs: dict) -> dict:
    """Convert kwargs to JSON-safe dict, keeping only checkpoint-relevant keys."""
    keep_keys = {
        "target", "fleet", "scan_type", "data_prefix", "reports_prefix",
        "prefix", "url_file", "domainlist", "scope_filter", "user_url_file",
        "nodes", "dry_run", "exclusion_file",
    }
    result = {}
    for k, v in kwargs.items():
        if k in keep_keys and v is not None:
            result[k] = str(v) if not isinstance(v, (str, int, float, bool)) else v
    return result


def serialize_steps(steps) -> list[dict]:
    """Serialize step structure (ModuleStep/ParallelGroup/WaitStep) to JSON-safe list."""
    from workflows import ModuleStep, ParallelGroup, WaitStep
    serialized = []
    for step in steps:
        if isinstance(step, ModuleStep):
            serialized.append({"type": "module", "name": step.name, "args": step.args})
        elif isinstance(step, ParallelGroup):
            serialized.append({
                "type": "parallel",
                "steps": [{"name": s.name, "args": s.args} for s in step.steps],
            })
        elif isinstance(step, WaitStep):
            serialized.append({"type": "wait", "name": step.name})
    return serialized


def deserialize_steps(raw: list[dict]) -> list:
    """Deserialize JSON step list back to ModuleStep/ParallelGroup/WaitStep objects."""
    from workflows import ModuleStep, ParallelGroup, WaitStep
    steps = []
    for item in raw:
        if item.get("type") == "module":
            steps.append(ModuleStep(name=item["name"], args=item.get("args", {})))
        elif item.get("type") == "parallel":
            group_steps = [
                ModuleStep(name=s["name"], args=s.get("args", {}))
                for s in item["steps"]
            ]
            steps.append(ParallelGroup(steps=group_steps))
        elif item.get("type") == "wait":
            steps.append(WaitStep(name=item["name"]))
    return steps
