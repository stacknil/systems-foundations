from __future__ import annotations

from collections import Counter
from collections.abc import Iterable

from .models import NormalizedEvent


def build_summary(events: Iterable[NormalizedEvent]) -> str:
    rows = list(events)
    lines = ["# Linux Auth Observe Summary", ""]
    lines.append(f"- Total events: {len(rows)}")

    if rows:
        ts_values = sorted(event.ts for event in rows)
        lines.append(f"- Time range: {ts_values[0]} to {ts_values[-1]}")
    else:
        lines.append("- Time range: n/a")

    lines.extend(
        [
            "",
            "## By Event Type",
            "",
            _render_count_table("event_type", _count(rows, "event_type")),
            "",
            "## By Outcome",
            "",
            _render_count_table("outcome", _count(rows, "outcome")),
            "",
            "## By User",
            "",
            _render_count_table("user", _count(rows, "user")),
            "",
            "## By Source IP",
            "",
            _render_count_table("src_ip", _count(rows, "src_ip")),
            "",
            "## By Service",
            "",
            _render_count_table("service", _count(rows, "service")),
            "",
        ]
    )
    return "\n".join(lines)


def _count(rows: list[NormalizedEvent], field_name: str) -> Counter[str]:
    counter: Counter[str] = Counter()
    for row in rows:
        value = getattr(row, field_name)
        counter[_display_value(value)] += 1
    return counter


def _display_value(value: object) -> str:
    if value in (None, ""):
        return "(none)"
    return str(value)


def _render_count_table(label: str, counts: Counter[str]) -> str:
    lines = [f"| {label} | count |", "| --- | ---: |"]
    for value, count in sorted(counts.items(), key=lambda item: (-item[1], item[0])):
        lines.append(f"| {value} | {count} |")
    if len(lines) == 2:
        lines.append("| (none) | 0 |")
    return "\n".join(lines)
