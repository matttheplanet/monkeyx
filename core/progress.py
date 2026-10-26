"""Step-level progress tracking via append-only JSONL."""

import json
import logging
import os
import threading
import time
from datetime import datetime, timezone

from core import scan_db

logger = logging.getLogger("monkeyx.core.progress")


class ProgressTracker:
    """Writes progress events to {output_dir}/progress.jsonl.

    Each write opens the file in append mode, writes one JSON line, and flushes.
    A threading lock prevents interleaved writes from parallel group members.
    """

    def __init__(self, output_dir: str, total_steps: int, start_index: int = 0):
        self.path = os.path.join(output_dir, "progress.jsonl")
        self.total_steps = total_steps
        self._index = start_index
        # Re-entrant: step_started holds it while calling _write_event, which
        # re-acquires it so every JSONL append is serialized against concurrent
        # parallel-group members (step_completed/step_failed run in worker threads).
        self._lock = threading.RLock()
        # Dual-write to the per-engagement scan.db (source of truth for new
        # consumers). None if the DB can't be opened — JSONL remains the fallback.
        self._db = scan_db.open_db(output_dir)
        # Per-invocation sequence so the web view can separate THIS run's steps
        # from cumulative history across --continue/--resume. Stamped on every
        # event. Falls back to 1 if the DB is unavailable.
        try:
            self._run_seq = self._db.next_run_seq() if self._db else 1
        except Exception:  # pragma: no cover - defensive, never block a run
            self._run_seq = 1
        # Live in-memory view for the console heartbeat (see HeartbeatPrinter).
        # Guarded by the same RLock; parallel-group workers mutate these.
        self._run_start = time.monotonic()
        self._running: list[str] = []
        self._completed = 0

    def run_planned(self, steps: list) -> None:
        """Record the full ordered plan for THIS run (per run_seq) so the live view
        can show modules that are queued but haven't started yet. `steps` is the
        resolved, post-auto-injection ordered list; each item is a module name
        (str) or a list/tuple of names (a parallel group)."""
        plan = []
        for entry in steps:
            if isinstance(entry, (list, tuple)):
                for name in entry:
                    plan.append({"name": name, "group": True})
            elif entry:
                plan.append({"name": entry, "group": False})
        event = {
            "event": "run_planned",
            "steps": plan,
            "total_steps": self.total_steps,
            "planned_at": _now(),
        }
        self._write_event(event)

    def step_started(self, step_name: str, parallel_group: bool = False) -> dict:
        with self._lock:
            self._index += 1
            self._running.append(step_name)
            event = {
                "event": "step_started",
                "step": step_name,
                "index": self._index,
                "total_steps": self.total_steps,
                "started_at": _now(),
            }
            if parallel_group:
                event["parallel_group"] = True
            self._write_event(event)
            return event

    def _mark_done(self, step_name: str) -> None:
        """Update the live heartbeat view: drop the step from running, count it."""
        with self._lock:
            try:
                self._running.remove(step_name)
            except ValueError:
                pass
            self._completed += 1

    def step_completed(self, step_name: str, started_event: dict, result: dict) -> None:
        self._mark_done(step_name)
        finished = _now()
        started_at = started_event.get("started_at", finished)
        duration = _duration(started_at, finished)
        output_files = result.get("output_files", []) if isinstance(result, dict) else []
        # Preserve the module's own outcome. A module fed nothing (e.g. a
        # host-class port scan on a URL-only run) returns status "skipped" — the
        # tracker must record that, not relabel it "success" (which read as
        # "scanned, found 0 ports"). Absent/other -> "success".
        outcome = result.get("status", "success") if isinstance(result, dict) else "success"
        if outcome not in ("success", "skipped", "warning"):
            outcome = "success"
        warning = result.get("warning") if isinstance(result, dict) else None

        event = {
            "event": "step_completed",
            "step": step_name,
            "index": started_event.get("index"),
            "total_steps": self.total_steps,
            "started_at": started_at,
            "finished_at": finished,
            "duration_seconds": duration,
            "output_files": output_files,
            "status": outcome,
        }
        if warning:
            event["warning"] = warning
        self._write_event(event)

    def step_failed(self, step_name: str, started_event: dict, error: str) -> None:
        self._mark_done(step_name)
        finished = _now()
        event = {
            "event": "step_failed",
            "step": step_name,
            "index": started_event.get("index"),
            "total_steps": self.total_steps,
            "started_at": started_event.get("started_at", finished),
            "finished_at": finished,
            "error": error,
        }
        self._write_event(event)

    def parallel_group_started(self, module_names: list[str]) -> dict:
        event = {
            "event": "parallel_group_started",
            "steps": module_names,
            "total_steps": self.total_steps,
            "started_at": _now(),
        }
        self._write_event(event)
        return event

    def parallel_group_completed(self, started_event: dict) -> None:
        finished = _now()
        started_at = started_event.get("started_at", finished)
        event = {
            "event": "parallel_group_completed",
            "steps": started_event.get("steps", []),
            "total_steps": self.total_steps,
            "started_at": started_at,
            "finished_at": finished,
            "duration_seconds": _duration(started_at, finished),
        }
        self._write_event(event)

    def scan_cancelled(self, at_step: str, next_step_index: int) -> None:
        event = {
            "event": "scan_cancelled",
            "step": at_step,
            "next_step_index": next_step_index,
            "total_steps": self.total_steps,
            "cancelled_at": _now(),
        }
        self._write_event(event)

    def scan_paused(self, next_step_index: int) -> None:
        event = {
            "event": "scan_paused",
            "next_step_index": next_step_index,
            "total_steps": self.total_steps,
            "paused_at": _now(),
        }
        self._write_event(event)

    def scan_resumed(self, resumed_from_index: int) -> None:
        event = {
            "event": "scan_resumed",
            "resumed_from_index": resumed_from_index,
            "total_steps": self.total_steps,
            "resumed_at": _now(),
        }
        self._write_event(event)

    def fleet_scaled(self, from_nodes: int, to_nodes: int, reason: str,
                     old_fleet: str, new_fleet: str) -> None:
        """Record an --auto-scale transition (up or down) in the event stream.

        Emitted by FleetScaler when it retires one fleet and spins up another so
        scaling is visible in progress.jsonl / scan.db progress_events alongside
        step progress, not just in the logs and cost-summary."""
        event = {
            "event": "fleet_scaled",
            "direction": "up" if to_nodes > from_nodes else "down",
            "from_nodes": int(from_nodes),
            "to_nodes": int(to_nodes),
            "reason": reason,
            "old_fleet": old_fleet,
            "new_fleet": new_fleet,
            "total_steps": self.total_steps,
            "scaled_at": _now(),
        }
        self._write_event(event)

    def _write_event(self, event: dict) -> None:
        event.setdefault("run_seq", self._run_seq)
        with self._lock:
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(event, separators=(",", ":")) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            self._mirror_to_db(event)

    def _mirror_to_db(self, event: dict) -> None:
        """Mirror an event into scan.db. Never fatal — JSONL is authoritative."""
        if self._db is None:
            return
        try:
            self._db.record_progress_event(
                event, json.dumps(event, separators=(",", ":")))
            etype = event.get("event")
            if etype in ("step_completed", "step_failed"):
                # Honor the module's recorded outcome (success/skipped/warning);
                # step_failed is always "failed".
                status = event.get("status", "success") if etype == "step_completed" else "failed"
                self._db.bump_module_run(
                    event.get("step"), status, event.get("finished_at"))
        except Exception as exc:  # pragma: no cover - defensive, DB never aborts a run
            logger.warning("scan.db progress mirror failed: %s", exc)

    def status_snapshot(self) -> tuple[float, int, int, list[str]]:
        """Live run status for the console heartbeat:
        (elapsed_seconds, completed_steps, total_steps, running_step_names)."""
        with self._lock:
            return (time.monotonic() - self._run_start,
                    self._completed, self.total_steps, list(self._running))

    def close(self) -> None:
        """Checkpoint + close the scan.db mirror. Safe to call once at run end."""
        if self._db is not None:
            self._db.close()
            self._db = None


class HeartbeatPrinter:
    """Prints a one-line run status to stdout every `interval` seconds.

    A daemon thread reads the tracker's live snapshot; the first line is emitted
    after one full interval, so sub-interval runs (and the test suite) print
    nothing. Always-on by default — construct and `start()` it around the run,
    and `stop()` it on every exit path.
    """

    def __init__(self, tracker, interval: float = 15.0):
        self._tracker = tracker
        self._interval = interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(
            target=self._loop, name="monkeyx-heartbeat", daemon=True)
        self._thread.start()

    def _loop(self) -> None:
        while not self._stop.wait(self._interval):
            try:
                elapsed, done, total, running = self._tracker.status_snapshot()
            except Exception:  # pragma: no cover - never let the heartbeat crash a run
                continue
            mins, secs = divmod(int(elapsed), 60)
            hrs, mins = divmod(mins, 60)
            ts = f"{hrs}:{mins:02d}:{secs:02d}" if hrs else f"{mins:02d}:{secs:02d}"
            running_str = ", ".join(running) if running else "—"
            print(f"[⏳] {ts} elapsed · {done}/{total} steps done · running: {running_str}",
                  flush=True)

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None


class _NoOpTracker:
    """Drop-in replacement that silently discards all events."""

    def run_planned(self, *args, **kwargs):
        pass

    def step_started(self, *args, **kwargs):
        return {"started_at": _now(), "index": 0}

    def step_completed(self, *args, **kwargs):
        pass

    def step_failed(self, *args, **kwargs):
        pass

    def status_snapshot(self):
        return (0.0, 0, 0, [])

    def parallel_group_started(self, *args, **kwargs):
        return {"started_at": _now(), "steps": []}

    def parallel_group_completed(self, *args, **kwargs):
        pass

    def scan_cancelled(self, *args, **kwargs):
        pass

    def scan_paused(self, *args, **kwargs):
        pass

    def scan_resumed(self, *args, **kwargs):
        pass

    def fleet_scaled(self, *args, **kwargs):
        pass

    def close(self, *args, **kwargs):
        pass


NO_OP_TRACKER = _NoOpTracker()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _duration(started_at: str, finished_at: str) -> float:
    try:
        start = datetime.fromisoformat(started_at)
        end = datetime.fromisoformat(finished_at)
        return round((end - start).total_seconds(), 1)
    except (ValueError, TypeError):
        return 0.0
