from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone, tzinfo
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
SSH_AUTH_RE = re.compile(
    r"^(?P<action>Accepted|Failed)\s+(?P<method>\S+)\s+for\s+"
    r"(?:(?P<invalid>invalid user)\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\[[^\]]+\]|\S+)\s+"
    r"port\s+(?P<port>\d+)(?:\s+\S+.*)?$",
)
SUDO_PREFIX_RE = re.compile(r"^(?P<actor>\S+)\s*:\s*(?P<body>.+)$")
SUDO_KV_RE = re.compile(
    r"(?:^|;\s*)(?P<key>[A-Z_]+)=(?P<value>.*?)(?=(?:;\s*[A-Z_]+=)|$)",
)
PAM_SESSION_RE = re.compile(
    r"^pam_unix\((?P<service>[^:]+):session\):\s*session "
    r"(?P<state>opened|closed) for user (?P<target>[^\s(]+)(?:\(uid=\d+\))?"
    r"(?: by (?P<actor>[^\s(]+)(?:\(uid=\d+\))?| by \((?:uid=\d+)\))?.*$",
)
SYSTEMD_UNIT_RE = re.compile(r"(?P<unit>[\w@.-]+\.service)")
YEAR_INFERENCE_FUTURE_WINDOW = timedelta(days=183)


class ParseError(ValueError):
    """Base class for parser failures that should remain batch-safe."""


class MalformedSyslogLineError(ParseError):
    """Raised when a syslog line does not match the expected auth prefix."""


class InvalidSyslogTimestampError(ParseError):
    """Raised when a syslog timestamp cannot be parsed safely."""


class InvalidJournalRecordError(ParseError):
    """Raised when a journald JSON line is malformed or incomplete."""


class InvalidJournalFieldError(ParseError):
    """Raised when a required journald field has an invalid value."""


class MalformedSSHAuthMessageError(ParseError):
    """Raised when an ssh auth message has a known prefix but a bad shape."""


class MalformedSudoCommandError(ParseError):
    """Raised when a sudo command message is missing required fields."""


class MalformedPamSessionError(ParseError):
    """Raised when a PAM session message has a known prefix but a bad shape."""


@dataclass(slots=True)
class SyslogTimestampResolver:
    timezone_name: str = "local"
    year: int | None = None
    reference_time: datetime | None = None
    _timezone: tzinfo = field(init=False, repr=False)
    _active_year: int | None = field(default=None, init=False, repr=False)
    _last_local_dt: datetime | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        self._timezone = resolve_timezone(self.timezone_name)

    def parse(self, month: str, day: str, clock: str) -> str:
        month_number = MONTHS.get(month)
        if month_number is None:
            raise InvalidSyslogTimestampError(f"unsupported month: {month}")

        try:
            day_number = int(day)
            hour, minute, second = (int(part) for part in clock.split(":", maxsplit=2))
        except ValueError as exc:
            raise InvalidSyslogTimestampError(f"invalid syslog timestamp: {month} {day} {clock}") from exc

        if self._active_year is None:
            self._active_year = self._infer_initial_year(month_number, day_number, hour, minute, second)

        local_dt = self._build_local_dt(self._active_year, month_number, day_number, hour, minute, second)
        if self._should_roll_over(local_dt):
            self._active_year += 1
            local_dt = self._build_local_dt(self._active_year, month_number, day_number, hour, minute, second)

        self._last_local_dt = local_dt
        return to_utc_iso(local_dt)

    def _infer_initial_year(
        self,
        month_number: int,
        day_number: int,
        hour: int,
        minute: int,
        second: int,
    ) -> int:
        if self.year is not None:
            return self.year

        reference = self.reference_time or datetime.now(self._timezone)
        if reference.tzinfo is None:
            reference = reference.replace(tzinfo=self._timezone)
        else:
            reference = reference.astimezone(self._timezone)

        candidate = self._build_local_dt(reference.year, month_number, day_number, hour, minute, second)
        if candidate - reference > YEAR_INFERENCE_FUTURE_WINDOW:
            return reference.year - 1
        return reference.year

    def _should_roll_over(self, candidate: datetime) -> bool:
        previous = self._last_local_dt
        if previous is None:
            return False
        return previous.month == 12 and candidate.month == 1 and candidate < previous

    def _build_local_dt(
        self,
        year: int,
        month_number: int,
        day_number: int,
        hour: int,
        minute: int,
        second: int,
    ) -> datetime:
        try:
            return datetime(
                year,
                month_number,
                day_number,
                hour,
                minute,
                second,
                tzinfo=self._timezone,
            )
        except ValueError as exc:
            raise InvalidSyslogTimestampError(
                f"invalid syslog timestamp: {year:04d}-{month_number:02d}-{day_number:02d} {hour:02d}:{minute:02d}:{second:02d}"
            ) from exc


def parse_syslog_timestamp(
    month: str,
    day: str,
    clock: str,
    *,
    year: int | None = None,
    timezone_name: str = "local",
    reference_time: datetime | None = None,
    resolver: SyslogTimestampResolver | None = None,
) -> str:
    active_resolver = resolver or SyslogTimestampResolver(
        timezone_name=timezone_name,
        year=year,
        reference_time=reference_time,
    )
    return active_resolver.parse(month, day, clock)


def parse_journal_timestamp(value: object) -> str:
    if value in (None, ""):
        raise InvalidJournalRecordError("journal record missing __REALTIME_TIMESTAMP")
    try:
        micros = int(coerce_text(value) or "0")
    except ValueError as exc:
        raise InvalidJournalFieldError("journal record has non-numeric __REALTIME_TIMESTAMP") from exc
    return to_utc_iso(datetime.fromtimestamp(micros / 1_000_000, tz=timezone.utc))


def resolve_timezone(timezone_name: str) -> tzinfo:
    if timezone_name == "local":
        return datetime.now().astimezone().tzinfo or timezone.utc

    try:
        return ZoneInfo(timezone_name)
    except ZoneInfoNotFoundError as exc:
        raise InvalidSyslogTimestampError(f"unknown timezone: {timezone_name}") from exc


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

    if program_name == "sshd":
        ssh_details = parse_ssh_auth_message(message)
    else:
        ssh_details = None
    if ssh_details and ssh_details["outcome"] == "success":
        return make_event(
            ts=ts,
            host=host,
            collector=collector,
            parser_name=parser_name,
            event_type="ssh_login_success",
            outcome="success",
            user=ssh_details["user"],
            src_ip=ssh_details["src_ip"],
            src_port=ssh_details["src_port"],
            service="sshd",
            unit=unit,
            pid=pid,
            program=program_name,
            message=message,
            raw=raw,
        )

    if ssh_details and ssh_details["outcome"] == "failure":
        return make_event(
            ts=ts,
            host=host,
            collector=collector,
            parser_name=parser_name,
            event_type="ssh_login_failure",
            outcome="failure",
            user=ssh_details["user"],
            src_ip=ssh_details["src_ip"],
            src_port=ssh_details["src_port"],
            service="sshd",
            unit=unit,
            pid=pid,
            program=program_name,
            message=message,
            raw=raw,
        )

    if program_name == "sudo":
        sudo_details = parse_sudo_command_message(message)
    else:
        sudo_details = None
    if sudo_details is not None:
        return make_event(
            ts=ts,
            host=host,
            collector=collector,
            parser_name=parser_name,
            event_type="sudo_command",
            outcome="success",
            user=sudo_details["actor"],
            src_ip=None,
            src_port=None,
            service="sudo",
            unit=unit,
            pid=pid,
            program=program_name,
            message=message,
            raw=raw,
        )

    pam_session = parse_pam_session_message(message)
    if pam_session is not None:
        session_service = normalize_service(pam_session["service"])
        state = pam_session["state"]
        target_user = pam_session["target_user"]
        actor_user = pam_session["actor_user"]
        if session_service in {"sudo", "su"}:
            user = actor_user or target_user
        else:
            user = target_user

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


def parse_ssh_auth_message(message: str) -> dict[str, object] | None:
    if not (message.startswith("Accepted ") or message.startswith("Failed ")):
        return None

    match = SSH_AUTH_RE.match(message)
    if match is None:
        raise MalformedSSHAuthMessageError("malformed ssh auth message")

    raw_ip = sanitize_network_token(match.group("ip"))
    port = parse_port(match.group("port"), label="ssh port")
    action = match.group("action")
    return {
        "user": match.group("user"),
        "src_ip": raw_ip,
        "src_port": port,
        "outcome": "success" if action == "Accepted" else "failure",
    }


def parse_sudo_command_message(message: str) -> dict[str, str] | None:
    if "COMMAND=" not in message and "USER=" not in message:
        return None

    prefix_match = SUDO_PREFIX_RE.match(message)
    if prefix_match is None:
        raise MalformedSudoCommandError("malformed sudo command message")

    actor = prefix_match.group("actor")
    fields = {
        match.group("key"): match.group("value").strip()
        for match in SUDO_KV_RE.finditer(prefix_match.group("body"))
    }

    if not actor:
        raise MalformedSudoCommandError("malformed sudo command message: missing actor")
    if "USER" not in fields:
        raise MalformedSudoCommandError("malformed sudo command message: missing USER field")
    if "COMMAND" not in fields:
        raise MalformedSudoCommandError("malformed sudo command message: missing COMMAND field")

    return {"actor": actor}


def parse_pam_session_message(message: str) -> dict[str, str] | None:
    if "pam_unix(" not in message or ":session):" not in message:
        return None

    pam_match = PAM_SESSION_RE.match(message)
    if pam_match is None:
        raise MalformedPamSessionError("malformed PAM session message")

    actor_user = pam_match.group("actor")
    return {
        "service": pam_match.group("service"),
        "state": pam_match.group("state"),
        "target_user": pam_match.group("target"),
        "actor_user": actor_user or "",
    }


def extract_unit(message: str) -> str | None:
    match = SYSTEMD_UNIT_RE.search(message)
    return match.group("unit") if match else None


def parse_port(value: str, *, label: str) -> int:
    try:
        port = int(value)
    except ValueError as exc:
        raise MalformedSSHAuthMessageError(f"invalid {label}: {value}") from exc
    if port < 0 or port > 65535:
        raise MalformedSSHAuthMessageError(f"invalid {label}: {value}")
    return port


def sanitize_network_token(value: str | None) -> str | None:
    text = coerce_text(value)
    if text is None:
        return None
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    return text.rstrip(",;")


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
