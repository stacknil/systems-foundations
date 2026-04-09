from __future__ import annotations

from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from linux_auth_observe.parsers import journal_json, syslog_auth


FIXTURES = PROJECT_ROOT / "tests" / "fixtures"


def test_auth_log_ssh_failure_parses() -> None:
    first_line = (FIXTURES / "ubuntu_auth.log").read_text(encoding="utf-8").splitlines()[0]

    event = syslog_auth.parse_line(
        first_line,
        collector="auth.log",
        year=2026,
        timezone_name="Asia/Shanghai",
    )

    assert event is not None
    assert event.ts == "2026-04-08T13:20:01Z"
    assert event.collector == "auth.log"
    assert event.event_type == "ssh_login_failure"
    assert event.outcome == "failure"
    assert event.user == "alice"
    assert event.src_ip == "192.0.2.10"
    assert event.src_port == 51422
    assert event.service == "sshd"
    assert event.raw == first_line


def test_secure_sudo_and_session_parse() -> None:
    lines = (FIXTURES / "rhel_secure.log").read_text(encoding="utf-8").splitlines()

    command = syslog_auth.parse_line(lines[0], collector="secure", year=2026, timezone_name="Asia/Shanghai")
    session_open = syslog_auth.parse_line(
        lines[1],
        collector="secure",
        year=2026,
        timezone_name="Asia/Shanghai",
    )
    session_close = syslog_auth.parse_line(
        lines[2],
        collector="secure",
        year=2026,
        timezone_name="Asia/Shanghai",
    )
    su_session = syslog_auth.parse_line(lines[3], collector="secure", year=2026, timezone_name="Asia/Shanghai")

    assert command is not None
    assert command.event_type == "sudo_command"
    assert command.user == "alice"
    assert command.service == "sudo"

    assert session_open is not None
    assert session_open.event_type == "sudo_session_open"
    assert session_open.user == "alice"

    assert session_close is not None
    assert session_close.event_type == "sudo_session_close"
    assert session_close.service == "sudo"

    assert su_session is not None
    assert su_session.event_type == "su_session"
    assert su_session.user == "alice"
    assert su_session.service == "su"


def test_journal_json_mapping() -> None:
    lines = (FIXTURES / "journal_sample.jsonl").read_text(encoding="utf-8").splitlines()

    ssh_event = journal_json.parse_line(lines[0])
    service_event = journal_json.parse_line(lines[2])

    assert ssh_event is not None
    assert ssh_event.ts == "2026-04-08T13:20:01Z"
    assert ssh_event.event_type == "ssh_login_success"
    assert ssh_event.user == "bob"
    assert ssh_event.src_ip == "198.51.100.24"

    assert service_event is not None
    assert service_event.event_type == "service_state_change"
    assert service_event.outcome == "failure"
    assert service_event.service == "sshd"
    assert service_event.unit == "sshd.service"
