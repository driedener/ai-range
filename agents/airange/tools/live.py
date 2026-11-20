"""Parallel exercise mode: Blue works live while Red attacks.

`LiveShift` is the shared state in the orchestrator: Red reports that it is done, then a settle time
follows (rules/detections need time), and then it is "end of shift". Blue only learns about this through the
`wait_for_alerts` tool – it never sees what Red does, only new alerts and, at the end, the end of the shift.
"""
from __future__ import annotations

import asyncio
import datetime as dt
import time
from typing import Any, Awaitable, Callable

from claude_agent_sdk import SdkMcpTool

from ..runner import make_tool

POLL_S = 20
MAX_WAIT_S = 300
MAX_ALERTS = 30


class LiveShift:
    def __init__(self, settle_s: int):
        self.settle_s = settle_s
        self._red_done_at: float | None = None

    def red_finished(self) -> None:
        if self._red_done_at is None:
            self._red_done_at = time.monotonic()

    @property
    def over(self) -> bool:
        return self._red_done_at is not None and time.monotonic() - self._red_done_at >= self.settle_s


Poller = Callable[[dt.datetime], Awaitable[tuple[list[dict], dt.datetime]]]


def s1_poller(uam: Any) -> Poller:
    """New UAM alerts since `cursor` (createdAt) -> (rows, new cursor)."""
    from ..uam import f_range, parse_ts, summary  # noqa: PLC0415

    async def poll(cursor: dt.datetime) -> tuple[list[dict], dt.datetime]:
        alerts, _ = await uam.alerts([f_range("createdAt", cursor + dt.timedelta(milliseconds=1))],
                                     limit=100, sort_by="createdAt", order="ASC")
        times = [t for t in (parse_ts(a.get("createdAt")) for a in alerts) if t]
        return [summary(a) for a in alerts], max(times, default=cursor)
    return poll


def elastic_poller(es: Any) -> Poller:
    from .blue import alert_summary, search_alerts  # noqa: PLC0415

    async def poll(cursor: dt.datetime) -> tuple[list[dict], dt.datetime]:
        body = {
            "size": 100,
            "query": {"bool": {"filter": [
                {"range": {"@timestamp": {"gt": cursor.isoformat(timespec="milliseconds").replace("+00:00", "Z")}}},
                {"bool": {"must_not": {"exists": {"field": "kibana.alert.building_block_type"}}}},
            ]}},
            "sort": [{"@timestamp": {"order": "asc"}}],
            "_source": ["@timestamp", "kibana.alert.*", "host.name", "user.name", "process.name", "process.pid",
                        "process.command_line", "source.ip"],
        }
        hits = (await search_alerts(es, body))["hits"]["hits"]
        rows = [alert_summary(h) for h in hits]
        times = [dt.datetime.fromisoformat(str(r["@timestamp"]).replace("Z", "+00:00")) for r in rows if r.get("@timestamp")]
        return rows, max(times, default=cursor)
    return poll


def build_live_tool(shift: LiveShift, poll: Poller, start: dt.datetime) -> SdkMcpTool:
    state = {"cursor": start}

    async def wait_for_alerts(args: dict) -> dict:
        from ..runner import text_result  # noqa: PLC0415

        max_wait = max(POLL_S, min(int(args.get("max_wait_s") or 180), MAX_WAIT_S))
        deadline = time.monotonic() + max_wait
        while True:
            try:
                rows, cursor = await poll(state["cursor"])
            except Exception as exc:  # noqa: BLE001 – sit out short outages, only report at the end
                if time.monotonic() >= deadline:
                    return text_result(f"Querying new alerts failed: {str(exc)[:300]}", is_error=True)
                await asyncio.sleep(POLL_S)
                continue
            if rows:
                state["cursor"] = cursor
                return text_result({"new_alerts": len(rows), "alerts": rows[:MAX_ALERTS],
                                    "note": (f"{len(rows) - MAX_ALERTS} more – use list_alerts"
                                             if len(rows) > MAX_ALERTS else None),
                                    "shift_end": False})
            if shift.over:
                return text_result({"new_alerts": 0, "shift_end": True,
                                    "note": "End of shift: no further monitoring needed. Finish handling open "
                                            "incidents, then write the situation report."})
            if time.monotonic() >= deadline:
                return text_result({"new_alerts": 0, "shift_end": False,
                                    "note": f"No new alerts in {max_wait} s."})
            await asyncio.sleep(POLL_S)

    schema = {"type": "object", "properties": {
        "max_wait_s": {"type": "integer", "minimum": POLL_S, "maximum": MAX_WAIT_S, "default": 180,
                       "description": "Wait at most this long for new alerts (seconds)."}}}
    return make_tool(
        "wait_for_alerts",
        "Live monitoring: waits until new alerts arrive (since the last call), at most max_wait_s. "
        "Returns the new alerts, 'No new alerts' or shift_end=true. Call it again and again between "
        "investigations until shift_end=true arrives.",
        schema, wait_for_alerts)
