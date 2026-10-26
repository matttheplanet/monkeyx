"""Unit tests for core/checkpoint.py."""

import json
import os
import tempfile

import pytest
from core.checkpoint import (
    CHECKPOINT_FILENAME,
    CHECKPOINT_VERSION,
    EXIT_CODE_PAUSED,
    PAUSE_SENTINEL_FILENAME,
    Checkpoint,
)


@pytest.fixture
def tmp_output_dir():
    with tempfile.TemporaryDirectory() as d:
        yield d


@pytest.fixture
def checkpoint(tmp_output_dir):
    return Checkpoint(tmp_output_dir)


def _sample_kwargs(tmp_output_dir):
    target = os.path.join(tmp_output_dir, "targets.txt")
    with open(target, "w") as f:
        f.write("10.0.0.1\n")
    url_file = os.path.join(tmp_output_dir, "master-urls.txt")
    with open(url_file, "w") as f:
        f.write("http://example.com\n")
    return {
        "target": target,
        "fleet": "testfleet",
        "scan_type": "sS",
        "data_prefix": os.path.join(tmp_output_dir, "data", "prefix"),
        "reports_prefix": os.path.join(tmp_output_dir, "reports", "prefix"),
        "prefix": os.path.join(tmp_output_dir, "prefix"),
        "url_file": url_file,
        "scope_filter": "warn",
    }


class TestCheckpointWrite:
    def test_write_creates_valid_json(self, checkpoint, tmp_output_dir):
        kwargs = _sample_kwargs(tmp_output_dir)
        checkpoint.write(
            next_step_index=3,
            total_steps=9,
            workflow="standard",
            modules=["subfinder", "dns_resolve", "ax_tcp_baseline"],
            kwargs=kwargs,
            fleet_killed=False,
        )
        assert os.path.exists(checkpoint.checkpoint_path)
        with open(checkpoint.checkpoint_path) as f:
            data = json.load(f)
        assert data["version"] == CHECKPOINT_VERSION
        assert data["next_step_index"] == 3
        assert data["total_steps"] == 9
        assert data["workflow"] == "standard"
        assert data["modules"] == ["subfinder", "dns_resolve", "ax_tcp_baseline"]
        assert data["fleet_killed"] is False
        assert data["kwargs"]["fleet"] == "testfleet"
        assert "paused_at" in data

    def test_write_is_atomic(self, checkpoint, tmp_output_dir):
        kwargs = _sample_kwargs(tmp_output_dir)
        checkpoint.write(3, 9, "standard", ["a"], kwargs, False)
        # No .tmp files should remain
        tmp_files = [f for f in os.listdir(tmp_output_dir) if f.endswith(".tmp")]
        assert tmp_files == []

    def test_write_overwrites_existing(self, checkpoint, tmp_output_dir):
        kwargs = _sample_kwargs(tmp_output_dir)
        checkpoint.write(2, 9, "standard", ["a"], kwargs, False)
        checkpoint.write(5, 9, "standard", ["a", "b"], kwargs, True)
        data = Checkpoint.load(tmp_output_dir)
        assert data["next_step_index"] == 5
        assert data["fleet_killed"] is True


class TestCheckpointLoad:
    def test_load_returns_correct_data(self, checkpoint, tmp_output_dir):
        kwargs = _sample_kwargs(tmp_output_dir)
        checkpoint.write(4, 8, "fast", ["ax_nuclei"], kwargs, True)
        data = Checkpoint.load(tmp_output_dir)
        assert data["next_step_index"] == 4
        assert data["workflow"] == "fast"

    def test_load_raises_on_missing_file(self, tmp_output_dir):
        with pytest.raises(FileNotFoundError):
            Checkpoint.load(tmp_output_dir)

    def test_load_raises_on_corrupt_json(self, tmp_output_dir):
        path = os.path.join(tmp_output_dir, CHECKPOINT_FILENAME)
        with open(path, "w") as f:
            f.write("not json{{{")
        with pytest.raises(json.JSONDecodeError):
            Checkpoint.load(tmp_output_dir)

    def test_load_raises_on_version_mismatch(self, tmp_output_dir):
        path = os.path.join(tmp_output_dir, CHECKPOINT_FILENAME)
        with open(path, "w") as f:
            json.dump({"version": 999}, f)
        with pytest.raises(ValueError, match="version mismatch"):
            Checkpoint.load(tmp_output_dir)

    def test_load_rejects_shell_metachar_in_kwargs(self, tmp_output_dir):
        """A locally-tampered checkpoint must not smuggle a ' into fleet/target,
        which re-enter single-quote-wrapped shell commands on resume."""
        path = os.path.join(tmp_output_dir, CHECKPOINT_FILENAME)
        with open(path, "w") as f:
            json.dump({"version": CHECKPOINT_VERSION,
                       "kwargs": {"fleet": "x'; touch /tmp/pwned; echo '"}}, f)
        with pytest.raises(ValueError, match="illegal shell character"):
            Checkpoint.load(tmp_output_dir)

    def test_load_rejects_nul_byte_in_kwargs(self, tmp_output_dir):
        path = os.path.join(tmp_output_dir, CHECKPOINT_FILENAME)
        with open(path, "w") as f:
            json.dump({"version": CHECKPOINT_VERSION,
                       "kwargs": {"target": "a\x00b"}}, f)
        with pytest.raises(ValueError, match="illegal shell character"):
            Checkpoint.load(tmp_output_dir)

    def test_load_rejects_metachar_in_any_key(self, tmp_output_dir):
        # The guard is generic now — a metachar in a key OUTSIDE the old
        # hand-maintained subset (e.g. scan_type) must still be rejected, since
        # any restored kwarg can reach a shell command on resume.
        path = os.path.join(tmp_output_dir, CHECKPOINT_FILENAME)
        with open(path, "w") as f:
            json.dump({"version": CHECKPOINT_VERSION,
                       "kwargs": {"scan_type": "sS'; rm -rf /; echo '"}}, f)
        with pytest.raises(ValueError, match="illegal shell character"):
            Checkpoint.load(tmp_output_dir)

    def test_load_rejects_metachar_in_list_value(self, tmp_output_dir):
        path = os.path.join(tmp_output_dir, CHECKPOINT_FILENAME)
        with open(path, "w") as f:
            json.dump({"version": CHECKPOINT_VERSION,
                       "kwargs": {"extra": ["ok", "bad'; touch /tmp/x; echo '"]}}, f)
        with pytest.raises(ValueError, match="illegal shell character"):
            Checkpoint.load(tmp_output_dir)

    def test_load_allows_clean_kwargs(self, tmp_output_dir):
        path = os.path.join(tmp_output_dir, CHECKPOINT_FILENAME)
        with open(path, "w") as f:
            json.dump({"version": CHECKPOINT_VERSION,
                       "kwargs": {"fleet": "myfleet", "target": "/tmp/targets.txt"}}, f)
        data = Checkpoint.load(tmp_output_dir)
        assert data["kwargs"]["fleet"] == "myfleet"


class TestCheckpointValidate:
    def test_validate_passes_with_valid_checkpoint(self, checkpoint, tmp_output_dir):
        kwargs = _sample_kwargs(tmp_output_dir)
        os.makedirs(os.path.join(tmp_output_dir, "data"), exist_ok=True)
        checkpoint.write(3, 9, "standard", ["a"], kwargs, False)
        errors = checkpoint.validate()
        assert errors == []

    def test_validate_fails_on_missing_file(self, checkpoint):
        errors = checkpoint.validate()
        assert len(errors) == 1
        assert "does not exist" in errors[0]

    def test_validate_fails_on_missing_target(self, checkpoint, tmp_output_dir):
        kwargs = _sample_kwargs(tmp_output_dir)
        checkpoint.write(3, 9, "standard", ["a"], kwargs, False)
        os.remove(kwargs["target"])
        errors = checkpoint.validate()
        assert any("Target file" in e for e in errors)


class TestPauseSentinel:
    def test_is_pause_requested_false_when_no_sentinel(self, checkpoint):
        assert checkpoint.is_pause_requested() is False

    def test_is_pause_requested_true_when_sentinel_exists(self, checkpoint):
        checkpoint.request_pause()
        assert checkpoint.is_pause_requested() is True

    def test_request_pause_creates_sentinel(self, checkpoint, tmp_output_dir):
        checkpoint.request_pause()
        assert os.path.exists(os.path.join(tmp_output_dir, PAUSE_SENTINEL_FILENAME))

    def test_clear_pause_request_removes_sentinel(self, checkpoint):
        checkpoint.request_pause()
        assert checkpoint.is_pause_requested() is True
        checkpoint.clear_pause_request()
        assert checkpoint.is_pause_requested() is False

    def test_clear_pause_request_noop_when_no_sentinel(self, checkpoint):
        checkpoint.clear_pause_request()  # should not raise


class TestCheckpointDelete:
    def test_delete_removes_checkpoint(self, checkpoint, tmp_output_dir):
        kwargs = _sample_kwargs(tmp_output_dir)
        checkpoint.write(3, 9, "standard", ["a"], kwargs, False)
        assert os.path.exists(checkpoint.checkpoint_path)
        checkpoint.delete()
        assert not os.path.exists(checkpoint.checkpoint_path)

    def test_delete_noop_when_no_checkpoint(self, checkpoint):
        checkpoint.delete()  # should not raise


class TestExitCode:
    def test_exit_code_is_42(self):
        assert EXIT_CODE_PAUSED == 42


class TestStepSerialization:
    def test_roundtrip_module_steps(self):
        from core.checkpoint import serialize_steps, deserialize_steps
        from workflows import ModuleStep, ParallelGroup

        steps = [
            ModuleStep(name="ax_tcp_baseline", args={}),
            ModuleStep(name="ax_nmap_udptop200", args={"top_ports": 500}),
            ParallelGroup(steps=[
                ModuleStep(name="ax_nuclei", args={}),
                ModuleStep(name="ax_gowitness", args={"threads": 4}),
            ]),
            ModuleStep(name="normalize", args={}),
        ]

        serialized = serialize_steps(steps)
        restored = deserialize_steps(serialized)

        assert len(restored) == 4
        assert isinstance(restored[0], ModuleStep)
        assert restored[0].name == "ax_tcp_baseline"
        assert restored[1].args == {"top_ports": 500}
        assert isinstance(restored[2], ParallelGroup)
        assert len(restored[2].steps) == 2
        assert restored[2].steps[0].name == "ax_nuclei"
        assert restored[2].steps[1].args == {"threads": 4}
        assert restored[3].name == "normalize"

    def test_checkpoint_stores_steps(self, checkpoint, tmp_output_dir):
        from core.checkpoint import serialize_steps, deserialize_steps
        from workflows import ModuleStep, ParallelGroup

        kwargs = _sample_kwargs(tmp_output_dir)
        steps = [
            ModuleStep(name="a", args={}),
            ParallelGroup(steps=[ModuleStep(name="b", args={"x": 1})]),
        ]
        checkpoint.write(1, 3, "standard", ["a", "b"], kwargs, False, steps=steps)
        data = Checkpoint.load(tmp_output_dir)
        assert "steps" in data
        restored = deserialize_steps(data["steps"])
        assert isinstance(restored[1], ParallelGroup)
        assert restored[1].steps[0].args == {"x": 1}


class TestValidateUrlFile:
    def test_missing_master_urls_is_not_an_error(self, checkpoint, tmp_output_dir):
        kwargs = _sample_kwargs(tmp_output_dir)
        # Point url_file at a non-existent master-urls.txt
        kwargs["url_file"] = os.path.join(tmp_output_dir, "data", "master-urls.txt")
        os.makedirs(os.path.join(tmp_output_dir, "data"), exist_ok=True)
        checkpoint.write(1, 5, "standard", ["a"], kwargs, False)
        errors = checkpoint.validate()
        assert not any("URL file" in e for e in errors)

    def test_missing_custom_url_file_is_error(self, checkpoint, tmp_output_dir):
        kwargs = _sample_kwargs(tmp_output_dir)
        kwargs["url_file"] = os.path.join(tmp_output_dir, "custom-urls.txt")
        os.makedirs(os.path.join(tmp_output_dir, "data"), exist_ok=True)
        checkpoint.write(1, 5, "standard", ["a"], kwargs, False)
        errors = checkpoint.validate()
        assert any("URL file" in e for e in errors)
