from __future__ import annotations

import json

from .common import (
    InvalidJournalFieldError,
    InvalidJournalRecordError,
    classify_event,
    coerce_text,
    parse_journal_timestamp,
)


def parse_line(line: str):
    try:
        payload = json.loads(line)
    except json.JSONDecodeError as exc:
        raise InvalidJournalRecordError("invalid journal JSON line") from exc
    if not isinstance(payload, dict):
        raise InvalidJournalRecordError("journal line must decode to an object")

    message = coerce_text(payload.get("MESSAGE"))
    if message is None:
        raise InvalidJournalRecordError("journal record missing MESSAGE")

    ts = parse_journal_timestamp(
        payload.get("__REALTIME_TIMESTAMP") or payload.get("_SOURCE_REALTIME_TIMESTAMP")
    )
    host = coerce_text(payload.get("_HOSTNAME") or payload.get("HOSTNAME")) or "unknown-host"
    program = coerce_text(payload.get("SYSLOG_IDENTIFIER") or payload.get("_COMM"))
    pid = _parse_optional_pid(payload.get("_PID"))
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


def _parse_optional_pid(value: object) -> int | None:
    text = coerce_text(value)
    if text is None:
        return None
    try:
        return int(text)
    except ValueError as exc:
        raise InvalidJournalFieldError("journal record has non-numeric _PID") from exc
