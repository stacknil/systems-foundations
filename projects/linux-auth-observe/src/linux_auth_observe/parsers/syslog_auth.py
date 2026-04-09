from __future__ import annotations

from datetime import datetime

from .common import (
    SYSLOG_LINE_RE,
    MalformedSyslogLineError,
    SyslogTimestampResolver,
    classify_event,
    coerce_int,
    parse_syslog_timestamp,
)


def build_timestamp_resolver(
    *,
    year: int | None = None,
    timezone_name: str = "local",
    reference_time: datetime | None = None,
) -> SyslogTimestampResolver:
    return SyslogTimestampResolver(
        timezone_name=timezone_name,
        year=year,
        reference_time=reference_time,
    )


def parse_line(
    line: str,
    *,
    collector: str,
    year: int | None = None,
    timezone_name: str = "local",
    reference_time: datetime | None = None,
    timestamp_resolver: SyslogTimestampResolver | None = None,
):
    match = SYSLOG_LINE_RE.match(line)
    if match is None:
        raise MalformedSyslogLineError("malformed syslog auth line")

    ts = parse_syslog_timestamp(
        match.group("month"),
        match.group("day"),
        match.group("clock"),
        year=year,
        timezone_name=timezone_name,
        reference_time=reference_time,
        resolver=timestamp_resolver,
    )
    return classify_event(
        ts=ts,
        host=match.group("host"),
        collector=collector,
        parser_name="syslog_auth",
        program=match.group("program"),
        pid=coerce_int(match.group("pid")),
        message=match.group("message"),
        raw=line.rstrip("\n"),
        unit=None,
    )
