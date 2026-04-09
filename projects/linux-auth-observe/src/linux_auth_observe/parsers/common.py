from __future__ import annotations

from datetime import datetime, timezone, tzinfo
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
import os
import re

from ..models import NormalizedEvent

MONTHS = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}

SYSLOG_LINE_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<clock>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<program>[\w./@+-]+)(?:\[(?P<pid>\d+)\])?:\s(?P<message>.*)$"
)
SSH_SUCCESS_RE = re.compile(
    r"Accepted\s+\S+\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)",
)
SSH_FAILURE_RE = re.compile(
    r"Failed\s+\S+\s+for\s+(?:invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)",
)
SUDO_COMMAND_RE = re.compile(
    r"(?P<actor>\S+)\s*:\s*TTY=.*;\s*PWD=.*;\s*USER=(?P<target>\S+)\s*;\s*COMMAND=(?P<command>.+)$",
)
PAM_SESSION_RE = re.compile(
    r"pam_unix\((?P<service>[^:]+):session\): session "
    r"(?P<state>opened|closed) for user (?P<target>[^\s(]+)(?:\(uid=\d+\))?"
    r"(?: by (?P<actor>[^\s(]+|\(uid=\d+\)))?.*",
)
SYSTEMD_UNIT_RE = re.compile(r"(?P<unit>[\w@.-]+\.service)")


def parse_syslog_timestamp(
    month: str,
    day: str,
    clock: str,
    *,
    year: int,
    timezone_name: str = "local",
) -> str:
    month_number = MONTHS.get(month)
    if month_number is None:
        raise ValueError(f"unsupported month: {month}")

    hour, minute, second = (int(part) for part in clock.split(":", maxsplit=2))
    local_dt = datetime(
        year,
        month_number,
        int(day),
        hour,
        minute,
        second,
        tzinfo=resolve_timezone(timezone_name),
    )
    return to_utc_iso(local_dt)


def parse_journal_timestamp(value: object) -> str:
    if value in (None, ""):
        raise ValueError("journal record missing __REALTIME_TIMESTAMP")
    micros = int(coerce_text(value) or "0")
    return to_utc_iso(datetime.fromtimestamp(micros / 1_000_000, tz=timezone.utc))


def resolve_timezone(timezone_name: str) -> tzinfo:
    if timezone_name == "local":
        return datetime.now().astimezone().tzinfo or timezone.utc

    try:
        return ZoneInfo(timezone_name)
    except ZoneInfoNotFoundError as exc:
        raise ValueError(f"unknown timezone: {timezone_name}") from exc


def to_utc_iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def coerce_text(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, list):
        if not value:
            return None
        value = value[0]
    text = str(value).strip()
    return text or None


def coerce_int(value: object) -> int | None:
    text = coerce_text(value)
    if text is None:
        return None
    return int(text)


def classify_event(
    *,
    ts: str,
    host: str,
    collector: str,
    parser_name: str,
    program: str | None,
    pid: int | None,
    message: str,
    raw: str,
    unit: str | None = None,
) -> NormalizedEvent | None:
    program_name = normalize_program(program)

    ssh_match = SSH_SUCCESS_RE.search(message)
    if program_name == "sshd" and ssh_match:
        return make_event(
            ts=ts,
            host=host,
            collector=collector,
            parser_name=parser_name,
            event_type="ssh_login_success",
            outcome="success",
            user=ssh_match.group("user"),
            src_ip=ssh_match.group("ip"),
            src_port=int(ssh_match.group("port")),
            service="sshd",
            unit=unit,
            pid=pid,
            program=program_name,
            message=message,
            raw=raw,
        )

    ssh_match = SSH_FAILURE_RE.search(message)
    if program_name == "sshd" and ssh_match:
        return make_event(
            ts=ts,
            host=host,
            collector=collector,
            parser_name=parser_name,
            event_type="ssh_login_failure",
            outcome="failure",
            user=ssh_match.group("user"),
            src_ip=ssh_match.group("ip"),
            src_port=int(ssh_match.group("port")),
            service="sshd",
            unit=unit,
            pid=pid,
            program=program_name,
            message=message,
            raw=raw,
        )

    sudo_match = SUDO_COMMAND_RE.match(message)
    if program_name == "sudo" and sudo_match:
        return make_event(
            ts=ts,
            host=host,
            collector=collector,
            parser_name=parser_name,
            event_type="sudo_command",
            outcome="success",
            user=sudo_match.group("actor"),
            src_ip=None,
            src_port=None,
            service="sudo",
            unit=unit,
            pid=pid,
            program=program_name,
            message=message,
            raw=raw,
        )

    pam_match = PAM_SESSION_RE.search(message)
    if pam_match:
        session_service = normalize_service(pam_match.group("service"))
        state = pam_match.group("state")
        target_user = pam_match.group("target")
        actor = pam_match.group("actor")
        actor_user = actor if actor and not actor.startswith("(") else None
        user = actor_user or target_user

        if session_service == "sudo":
            event_type = "sudo_session_open" if state == "opened" else "sudo_session_close"
            service = "sudo"
        elif session_service == "su":
            event_type = "su_session"
            service = "su"
        else:
            event_type = "session_open" if state == "opened" else "session_close"
            service = session_service

        return make_event(
            ts=ts,
            host=host,
            collector=collector,
            parser_name=parser_name,
            event_type=event_type,
            outcome="success",
            user=user,
            src_ip=None,
            src_port=None,
            service=service,
            unit=unit,
            pid=pid,
            program=program_name,
            message=message,
            raw=raw,
        )

    if collector == "journald":
        service_event = classify_service_state_event(
            ts=ts,
            host=host,
            parser_name=parser_name,
            program=program_name,
            pid=pid,
            unit=unit,
            message=message,
            raw=raw,
        )
        if service_event is not None:
            return service_event

    return None


def classify_service_state_event(
    *,
    ts: str,
    host: str,
    parser_name: str,
    program: str | None,
    pid: int | None,
    unit: str | None,
    message: str,
    raw: str,
) -> NormalizedEvent | None:
    if program != "systemd" and unit is None:
        return None

    lower_message = message.casefold()
    if lower_message.startswith("started ") or lower_message.startswith("stopped "):
        outcome = "success"
    elif lower_message.startswith("failed ") or lower_message.startswith("failed to start "):
        outcome = "failure"
    else:
        return None

    detected_unit = unit or extract_unit(message)
    service = normalize_service(detected_unit or program)
    return make_event(
        ts=ts,
        host=host,
        collector="journald",
        parser_name=parser_name,
        event_type="service_state_change",
        outcome=outcome,
        user=None,
        src_ip=None,
        src_port=None,
        service=service,
        unit=detected_unit,
        pid=pid,
        program=program,
        message=message,
        raw=raw,
    )


def extract_unit(message: str) -> str | None:
    match = SYSTEMD_UNIT_RE.search(message)
    return match.group("unit") if match else None


def normalize_program(program: str | None) -> str | None:
    text = coerce_text(program)
    if text is None:
        return None
    return os.path.basename(text).casefold()


def normalize_service(value: str | None) -> str | None:
    text = coerce_text(value)
    if text is None:
        return None

    lowered = text.casefold()
    if lowered.endswith(".service"):
        lowered = lowered[:-8]
    if lowered.startswith("sudo"):
        return "sudo"
    if lowered.startswith("su"):
        return "su"
    return lowered


def make_event(
    *,
    ts: str,
    host: str,
    collector: str,
    parser_name: str,
    event_type: str,
    outcome: str,
    user: str | None,
    src_ip: str | None,
    src_port: int | None,
    service: str | None,
    unit: str | None,
    pid: int | None,
    program: str | None,
    message: str,
    raw: str,
) -> NormalizedEvent:
    return NormalizedEvent(
        ts=ts,
        host=host or "unknown-host",
        collector=collector,
        parser=parser_name,
        event_family="auth",
        event_type=event_type,
        outcome=outcome,
        user=coerce_text(user),
        src_ip=coerce_text(src_ip),
        src_port=src_port,
        service=normalize_service(service),
        unit=coerce_text(unit),
        pid=pid,
        program=normalize_program(program),
        message=message,
        raw=raw,
    )
