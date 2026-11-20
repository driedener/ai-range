"""Run IDs, agent traces (range-agenttrace) and ground truth (range-groundtruth)."""
from __future__ import annotations

import datetime as dt
import json
import secrets
import time
from typing import Any

from .elastic import Elastic

GROUNDTRUTH_STREAM = "range-groundtruth"
TRACE_STREAM = "range-agenttrace"


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def new_run_id(prefix: str = "run") -> str:
    return f"{prefix}-{dt.datetime.now(dt.timezone.utc):%Y%m%d-%H%M%S}-{secrets.token_hex(2)}"


def _truncate(text: str, limit: int = 20000) -> str:
    return text if len(text) <= limit else text[:limit] + f"\n…[{len(text) - limit} characters truncated]"


class Tracer:
    """Writes the tool calls and LLM usage of an agent run to range-agenttrace.

    Write errors never abort the agent - they are only counted/printed.
    """

    def __init__(self, es: Elastic, run_id: str, agent_name: str, role: str, model: str):
        self.es = es
        self.run_id = run_id
        self.agent_name = agent_name
        self.role = role
        self.model = model
        self.errors = 0
        self._started: dict[str, float] = {}

    def _base(self) -> dict[str, Any]:
        return {
            "@timestamp": now_iso(),
            "run": {"id": self.run_id},
            "agent": {"name": self.agent_name, "role": self.role},
            "llm": {"model": self.model},
        }

    async def _write(self, doc: dict) -> None:
        try:
            await self.es.index_doc(TRACE_STREAM, doc)
        except Exception as exc:  # noqa: BLE001 - tracing must not stop the run
            self.errors += 1
            print(f"[trace] write error: {exc}")

    def tool_started(self, tool_use_id: str | None) -> None:
        if tool_use_id:
            self._started[tool_use_id] = time.monotonic()

    async def tool_call(self, tool_name: str, tool_input: Any, output: Any, tool_use_id: str | None,
                        outcome: str = "success", error: str | None = None) -> None:
        doc = self._base()
        doc["tool"] = {"name": tool_name}
        if isinstance(tool_input, dict):
            doc["tool"]["input"] = tool_input
        else:
            doc["tool"]["input_raw"] = str(tool_input)
        out = output if isinstance(output, str) else json.dumps(output, ensure_ascii=False, default=str)
        doc["tool"]["output"] = _truncate(out)
        doc["event"] = {"outcome": outcome}
        start = self._started.pop(tool_use_id, None) if tool_use_id else None
        if start is not None:
            doc["event"]["duration"] = int((time.monotonic() - start) * 1e9)
        if error:
            doc["error"] = {"message": error}
        doc["message"] = f"{self.agent_name} -> {tool_name} ({outcome})"
        await self._write(doc)

    async def run_summary(self, result: Any, prompt: str) -> None:
        """The SDK ResultMessage (cost, tokens, turns) as one trace document."""
        doc = self._base()
        usage = getattr(result, "usage", None) or {}
        tokens = {
            "input": usage.get("input_tokens"),
            "output": usage.get("output_tokens"),
            "cache_read": usage.get("cache_read_input_tokens"),
            "cache_write": usage.get("cache_creation_input_tokens"),
        }
        tokens = {k: v for k, v in tokens.items() if v is not None}
        if tokens:
            tokens["total"] = sum(tokens.values())
            doc["llm"]["tokens"] = tokens
        doc["llm"]["cost_usd"] = getattr(result, "total_cost_usd", None)
        doc["llm"]["turns"] = getattr(result, "num_turns", None)
        is_error = bool(getattr(result, "is_error", False))
        doc["event"] = {"outcome": "failure" if is_error else "success", "action": "run-summary"}
        if getattr(result, "duration_ms", None) is not None:
            doc["event"]["duration"] = int(result.duration_ms * 1e6)
        doc["tool"] = {"name": "run-summary", "input_raw": _truncate(prompt, 4000),
                       "output": _truncate(str(getattr(result, "result", "") or ""))}
        doc["message"] = f"{self.agent_name} run finished ({getattr(result, 'subtype', '?')})"
        await self._write(doc)


async def write_groundtruth(es: Elastic, run_id: str, agent_name: str, *, technique_id: str,
                            technique_name: str, tactic: str, command: str, target_hosts: list[str],
                            target_ips: list[str], source_ip: str, outcome: str, message: str,
                            started: str, extra: dict | None = None) -> None:
    """One document per executed attack step. Written by the tool, not by the LLM."""
    doc: dict[str, Any] = {
        "@timestamp": started,
        "run": {"id": run_id},
        "agent": {"name": agent_name},
        "source": {"ip": source_ip},
        "threat": {"technique": {"id": technique_id, "name": technique_name}, "tactic": {"name": tactic}},
        "process": {"command_line": command},
        "event": {"outcome": outcome, "end": now_iso()},
        "message": message,
    }
    if target_ips:
        # destination.ip has type ip: Elasticsearch rejects networks there (e.g. 10.0.21.0/24 for scans)
        # and drops the whole document. Networks are therefore stored only in range.target_ips.
        single = next((ip for ip in target_ips if "/" not in ip), None)
        if single:
            doc["destination"] = {"ip": single}
        doc["range"] = {"target_ips": target_ips}
    if target_hosts:
        doc["host"] = {"name": target_hosts[0].lower()}
        doc.setdefault("range", {})["target_hosts"] = [h.lower() for h in target_hosts]
    if extra:
        doc.setdefault("range", {}).update(extra)
    await es.index_doc(GROUNDTRUTH_STREAM, doc)
