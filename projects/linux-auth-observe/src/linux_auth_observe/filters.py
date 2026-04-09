from __future__ import annotations

from collections.abc import Iterable, Iterator
from datetime import datetime, timezone
from pathlib import Path
import json

from .models import NormalizedEvent


def load_events(path: str | Path) -> Iterator[NormalizedEvent]:
    with Path(path).open("r", encoding="utf-8") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            line = raw_line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSON on line {line_number}") from exc
            yield NormalizedEvent.from_mapping(payload)


def iter_filtered_events(
    events: Iterable[NormalizedEvent],
    *,
    user: str | None = None,
    ip: str | None = None,
    service: str | None = None,
    since: str | None = None,
    until: str | None = None,
) -> Iterator[NormalizedEvent]:
    since_dt = _parse_time(since)
    until_dt = _parse_time(until)

    user_filter = _normalize_text(user)
    ip_filter = _normalize_text(ip)
    service_filter = _normalize_text(service)

    for event in events:
        if user_filter and _normalize_text(event.user) != user_filter:
            continue
        if ip_filter and _normalize_text(event.src_ip) != ip_filter:
            continue
        if service_filter and _normalize_text(event.service) != service_filter:
            continue

        event_dt = _parse_time(event.ts)
        if since_dt and event_dt < since_dt:
            continue
        if until_dt and event_dt > until_dt:
            continue
        yield event


def _normalize_text(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip()
    return cleaned.casefold() if cleaned else None


def _parse_time(value: str | None) -> datetime | None:
    if value is None:
        return None
    text = value.strip()
    if not text:
        return None
    dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)
