from __future__ import annotations

from .common import SYSLOG_LINE_RE, classify_event, coerce_int, parse_syslog_timestamp


def parse_line(
    line: str,
    *,
    collector: str,
    year: int,
    timezone_name: str = "local",
):
    match = SYSLOG_LINE_RE.match(line)
    if match is None:
        return None

    ts = parse_syslog_timestamp(
        match.group("month"),
        match.group("day"),
        match.group("clock"),
        year=year,
        timezone_name=timezone_name,
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
