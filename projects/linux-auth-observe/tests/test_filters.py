from __future__ import annotations

from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from linux_auth_observe.filters import iter_filtered_events
from linux_auth_observe.models import NormalizedEvent


def test_filter_behavior() -> None:
    events = [
        NormalizedEvent(
            ts="2026-04-08T13:20:01Z",
            host="lab-host",
            collector="auth.log",
            parser="syslog_auth",
            event_family="auth",
            event_type="ssh_login_failure",
            outcome="failure",
            user="alice",
            src_ip="192.0.2.10",
            src_port=51422,
            service="sshd",
            unit=None,
            pid=1234,
            program="sshd",
            message="Failed password for alice from 192.0.2.10 port 51422 ssh2",
            raw="raw-1",
        ),
        NormalizedEvent(
            ts="2026-04-08T13:21:00Z",
            host="lab-host",
            collector="journald",
            parser="journal_json",
            event_family="auth",
            event_type="ssh_login_success",
            outcome="success",
            user="bob",
            src_ip="198.51.100.24",
            src_port=60222,
            service="sshd",
            unit="sshd.service",
            pid=4123,
            program="sshd",
            message="Accepted password for bob from 198.51.100.24 port 60222 ssh2",
            raw="raw-2",
        ),
        NormalizedEvent(
            ts="2026-04-08T13:22:00Z",
            host="rhel-lab",
            collector="secure",
            parser="syslog_auth",
            event_family="auth",
            event_type="sudo_command",
            outcome="success",
            user="alice",
            src_ip=None,
            src_port=None,
            service="sudo",
            unit=None,
            pid=2222,
            program="sudo",
            message="alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id",
            raw="raw-3",
        ),
    ]

    by_user = list(iter_filtered_events(events, user="alice"))
    by_ip = list(iter_filtered_events(events, ip="198.51.100.24"))
    by_service = list(iter_filtered_events(events, service="sudo"))
    by_time = list(
        iter_filtered_events(
            events,
            since="2026-04-08T13:21:00Z",
            until="2026-04-08T13:22:00Z",
        )
    )

    assert [event.event_type for event in by_user] == ["ssh_login_failure", "sudo_command"]
    assert [event.user for event in by_ip] == ["bob"]
    assert [event.service for event in by_service] == ["sudo"]
    assert [event.event_type for event in by_time] == ["ssh_login_success", "sudo_command"]
