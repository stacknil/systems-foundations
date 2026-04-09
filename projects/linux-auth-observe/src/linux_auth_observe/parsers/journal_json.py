from __future__ import annotations

import json

from .common import classify_event, coerce_int, coerce_text, parse_journal_timestamp


def parse_line(line: str):
    try:
        payload = json.loads(line)
    except json.JSONDecodeError as exc:
        raise ValueError("invalid journal JSON line") from exc

    message = coerce_text(payload.get("MESSAGE"))
    if message is None:
        raise ValueError("journal record missing MESSAGE")

    ts = parse_journal_timestamp(
        payload.get("__REALTIME_TIMESTAMP") or payload.get("_SOURCE_REALTIME_TIMESTAMP")
    )
    host = coerce_text(payload.get("_HOSTNAME") or payload.get("HOSTNAME")) or "unknown-host"
    program = coerce_text(payload.get("SYSLOG_IDENTIFIER") or payload.get("_COMM"))
    pid = coerce_int(payload.get("_PID"))
    unit = coerce_text(
        payload.get("_SYSTEMD_UNIT") or payload.get("UNIT") or payload.get("OBJECT_SYSTEMD_UNIT")
    )

    return classify_event(
        ts=ts,
        host=host,
        collector="journald",
        parser_name="journal_json",
        program=program,
        pid=pid,
        message=message,
        raw=line.rstrip("\n"),
        unit=unit,
    )
