"""Cost tracking for MonkeyX runs.

Records fleet compute time and AI provider costs, writes a summary
to logs/costs.txt at end of run.
"""

import json
import os
import time
import logging
from datetime import datetime, timezone

logger = logging.getLogger('monkeyx.core.cost_tracker')


class CostTracker:
    """Accumulates fleet and AI costs across a scan run."""

    def __init__(self):
        # A run may use several fleet "generations" when --auto-scale resizes:
        # each scale event retires one fleet and spins up another (new name, new
        # node count). Track each generation so node-hours sum across the whole
        # run instead of assuming the initial size for its entire duration.
        self._fleet_generations: list[dict] = []  # {name, nodes, start, end}
        self._ai_entries = []
        self._run_start = time.monotonic()
        self._run_start_wall = datetime.now(timezone.utc)

    def _open_generation(self) -> dict | None:
        for g in self._fleet_generations:
            if g["end"] is None:
                return g
        return None

    def fleet_started(self, fleet_name: str, nodes: int):
        self.fleet_stopped()          # defensively close any still-open generation
        self._fleet_generations.append({
            "name": fleet_name, "nodes": int(nodes) if nodes else 0,
            "start": time.monotonic(), "end": None,
        })

    def fleet_scaled(self, new_fleet_name: str, new_nodes: int):
        """Record an auto-scale transition: close the current generation and open
        a new one at the same instant, so per-generation node-hours are summed."""
        now = time.monotonic()
        current = self._open_generation()
        if current is None:
            self.fleet_started(new_fleet_name, new_nodes)
            return
        current["end"] = now
        self._fleet_generations.append({
            "name": new_fleet_name, "nodes": int(new_nodes) if new_nodes else 0,
            "start": now, "end": None,
        })

    def fleet_stopped(self):
        now = time.monotonic()
        for g in self._fleet_generations:
            if g["end"] is None:
                g["end"] = now

    def record_ai_usage(self, usage_summary: dict):
        self._ai_entries.append(usage_summary)

    def _generation_duration_s(self, g: dict) -> float:
        end = g["end"] if g["end"] is not None else time.monotonic()
        return max(0.0, end - g["start"])

    def _used_fleet(self) -> bool:
        return bool(self._fleet_generations)

    def _peak_nodes(self) -> int:
        return max((g["nodes"] for g in self._fleet_generations), default=0)

    def get_fleet_duration_s(self) -> float:
        # Generations don't overlap (each closes when the next opens), so total
        # fleet wall-time is the sum of generation durations.
        return sum(self._generation_duration_s(g) for g in self._fleet_generations)

    def get_fleet_node_hours(self) -> float:
        return sum(self._generation_duration_s(g) / 3600 * g["nodes"]
                   for g in self._fleet_generations)

    def _instance_type(self) -> str:
        """Cloud instance/server type, for cost calc. Not programmatically known
        (it lives in the axiom provider config), so the operator declares it once
        via monkeyx.config `fleet.instance_type`. Empty if unset."""
        try:
            from core.config import load_fleet_config
            return str(load_fleet_config().get("instance_type") or "").strip()
        except Exception:
            return ""

    def to_dict(self) -> dict:
        """Structured cost/compute summary for the deliverable (reports/summary).

        Mirrors the txt report so the summary module can render fleet node-hours
        + AI cost without reparsing text. AI aggregates every recorded call
        (ai_analyze + ai_validate + ai_analyze_gowitness), so the total is the
        whole run's spend, not just ai_analyze's."""
        run_duration = time.monotonic() - self._run_start
        ai_cost = sum(e.get("total_cost_usd", 0) for e in self._ai_entries)
        fleet = None
        if self._used_fleet():
            generations = [{
                "name": g["name"], "nodes": g["nodes"],
                "uptime_s": round(self._generation_duration_s(g), 1),
                "node_hours": round(self._generation_duration_s(g) / 3600 * g["nodes"], 2),
            } for g in self._fleet_generations]
            fleet = {
                # 'nodes' is the PEAK across generations (back-compat key); the
                # per-generation breakdown lives in 'generations'.
                "name": self._fleet_generations[-1]["name"],
                "nodes": self._peak_nodes(),
                "instance_type": self._instance_type() or None,
                "uptime_s": round(self.get_fleet_duration_s(), 1),
                "node_hours": round(self.get_fleet_node_hours(), 2),
                "scaled": len(generations) > 1,
                "generations": generations,
            }
        ai = None
        if self._ai_entries:
            ai = {
                "calls": sum(e.get("calls", 0) for e in self._ai_entries),
                "input_tokens": sum(e.get("input_tokens", 0) for e in self._ai_entries),
                "output_tokens": sum(e.get("output_tokens", 0) for e in self._ai_entries),
                "total_cost_usd": round(ai_cost, 4),
                "cost_is_estimate": any(e.get("cost_is_estimate") for e in self._ai_entries),
                "cost_unknown": any(e.get("cost_unknown") for e in self._ai_entries),
                "providers": sorted({e.get("provider", "unknown") for e in self._ai_entries}),
                "models": sorted({e.get("model", "unknown") for e in self._ai_entries}),
            }
        return {
            "run_duration_s": round(run_duration, 1),
            "fleet": fleet,
            "ai": ai,
        }

    def write(self, output_path: str):
        run_duration = time.monotonic() - self._run_start
        now = datetime.now(timezone.utc)

        lines = []
        lines.append("=" * 60)
        lines.append("MonkeyX Run Cost Summary")
        lines.append("=" * 60)
        lines.append("")
        lines.append(f"Run started:  {self._run_start_wall.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        lines.append(f"Run finished: {now.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        lines.append(f"Total duration: {_format_duration(run_duration)}")
        lines.append("")

        # Fleet section
        lines.append("-" * 60)
        lines.append("FLEET COMPUTE")
        lines.append("-" * 60)
        if self._used_fleet():
            fleet_duration = self.get_fleet_duration_s()
            node_hours = self.get_fleet_node_hours()
            gens = self._fleet_generations
            if len(gens) > 1:
                # Auto-scale happened — show each generation so the node-hours
                # total is auditable, not a mystery number.
                lines.append(f"Fleet (auto-scaled across {len(gens)} generations):")
                for i, g in enumerate(gens, 1):
                    gh = self._generation_duration_s(g) / 3600 * g["nodes"]
                    lines.append(
                        f"  [{i}] {g['name']}: {g['nodes']} nodes, "
                        f"{_format_duration(self._generation_duration_s(g))}, "
                        f"{gh:.2f} node-hours")
                lines.append(f"Peak nodes:     {self._peak_nodes()}")
            else:
                lines.append(f"Fleet name:     {gens[0]['name']}")
                lines.append(f"Nodes:          {gens[0]['nodes']}")
            instance_type = self._instance_type()
            if instance_type:
                lines.append(f"Instance type:  {instance_type}")
            lines.append(f"Fleet uptime:   {_format_duration(fleet_duration)}")
            lines.append(f"Node-hours:     {node_hours:.2f}")
        else:
            lines.append("No fleet used (local-only run)")
        lines.append("")

        # AI section
        lines.append("-" * 60)
        lines.append("AI PROVIDER COSTS")
        lines.append("-" * 60)
        if self._ai_entries:
            total_calls = 0
            total_input = 0
            total_output = 0
            total_cost = 0.0
            total_ai_duration = 0.0
            has_estimate = False
            has_unknown = False

            for entry in self._ai_entries:
                total_calls += entry.get("calls", 0)
                total_input += entry.get("input_tokens", 0)
                total_output += entry.get("output_tokens", 0)
                total_cost += entry.get("total_cost_usd", 0)
                total_ai_duration += entry.get("total_duration_s", 0)
                if entry.get("cost_is_estimate"):
                    has_estimate = True
                if entry.get("cost_unknown"):
                    has_unknown = True

            for entry in self._ai_entries:
                provider = entry.get("provider", "unknown")
                model = entry.get("model", "unknown")
                lines.append(f"Provider: {provider} ({model})")
                lines.append(f"  Calls:         {entry.get('calls', 0)}")
                lines.append(f"  Input tokens:  {entry.get('input_tokens', 0):,}")
                lines.append(f"  Output tokens: {entry.get('output_tokens', 0):,}")
                lines.append(f"  Total tokens:  {entry.get('total_tokens', 0):,}")
                cost = entry.get("total_cost_usd", 0)
                if cost:
                    est = " (estimated)" if entry.get("cost_is_estimate") else ""
                    lines.append(f"  Cost:          ${cost:.4f}{est}")
                elif entry.get("cost_unknown"):
                    lines.append("  Cost:          unknown (no pricing for this model)")
                if entry.get("total_duration_s"):
                    lines.append(f"  Duration:      {_format_duration(entry['total_duration_s'])}")
                lines.append("")

            if len(self._ai_entries) > 1:
                lines.append("AI TOTALS:")
                lines.append(f"  Total calls:   {total_calls}")
                lines.append(f"  Total tokens:  {total_input + total_output:,}")
                if total_cost:
                    est = " (estimated)" if has_estimate else ""
                    unk = " + unpriced models" if has_unknown else ""
                    lines.append(f"  Total cost:    ${total_cost:.4f}{est}{unk}")
                elif has_unknown:
                    lines.append("  Total cost:    unknown (no pricing for the model(s) used)")
                lines.append("")
        else:
            lines.append("No AI provider used")
            lines.append("")

        # Grand total
        lines.append("-" * 60)
        lines.append("TOTAL ESTIMATED COST")
        lines.append("-" * 60)
        ai_cost = sum(e.get("total_cost_usd", 0) for e in self._ai_entries)
        ai_unknown = any(e.get("cost_unknown") for e in self._ai_entries)
        if ai_cost:
            lines.append(f"AI:      ${ai_cost:.4f}" + (" + unknown" if ai_unknown else ""))
        elif ai_unknown:
            lines.append("AI:      unknown (no pricing for the model(s) used)")
        else:
            lines.append("AI:      $0.0000")
        if self._used_fleet():
            lines.append(f"Fleet:   {self.get_fleet_node_hours():.2f} node-hours (cost depends on provider)")
        lines.append("")

        text = "\n".join(lines) + "\n"

        try:
            with open(output_path, 'w') as f:
                f.write(text)
            logger.info("Cost summary written to %s", output_path)
        except OSError as e:
            logger.error("Failed to write cost summary: %s", e)

        # Stable structured sibling so the scan debrief (modules/summary.py) can
        # fold the cost/compute figures into reports/summary.md. Overwritten each
        # run (latest wins) — the timestamped .txt above keeps the history.
        json_path = os.path.join(os.path.dirname(output_path), "cost-summary.json")
        try:
            with open(json_path, 'w') as f:
                json.dump(self.to_dict(), f, indent=2)
        except OSError as e:
            logger.error("Failed to write cost summary JSON: %s", e)


NO_OP_COST_TRACKER = None


def _format_duration(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        m, s = divmod(seconds, 60)
        return f"{int(m)}m {int(s)}s"
    else:
        h, remainder = divmod(seconds, 3600)
        m, s = divmod(remainder, 60)
        return f"{int(h)}h {int(m)}m {int(s)}s"
