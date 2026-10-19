from pathlib import Path

import pytest

from linux_process_observe.parsers.procfs import parse_procfs_root
from linux_process_observe.parsers.ss_text import parse_ss_text


PROJECT_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = PROJECT_ROOT / "tests" / "fixtures"


def test_procfs_process_identity_and_credentials() -> None:
    records = parse_procfs_root(FIXTURES / "baseline" / "proc", host_id="lab-host")

    assert [item.pid for item in records] == [1, 120, 220, 230]
    sshd = next(item for item in records if item.pid == 120)
    worker = next(item for item in records if item.pid == 220)
    assert sshd.process_id == "lab-host:120:1200"
    assert sshd.ppid == 1
    assert sshd.parent_process_id == "lab-host:1:100"
    assert sshd.uid == sshd.effective_uid == 0
    assert worker.gid == worker.effective_gid == 1001
    assert worker.executable == "/opt/example/bin/app-worker"
    assert worker.argv == ["/opt/example/bin/app-worker", "--config", "/etc/example/app.conf"]


def test_ss_process_and_endpoint_parsing() -> None:
    observations = parse_ss_text((FIXTURES / "baseline" / "ss.txt").read_text(encoding="utf-8"))

    established = next(item for item in observations if item.state == "ESTAB")
    unlinked = next(item for item in observations if item.protocol == "udp")
    assert established.local_address == "192.0.2.10"
    assert established.remote_address == "198.51.100.20"
    assert [(item.name, item.pid) for item in established.process_refs] == [("sshd", 120)]
    assert unlinked.process_refs == []


def test_malformed_procfs_and_ss_inputs_fail_closed() -> None:
    with pytest.raises(ValueError, match="pid 500: missing stat"):
        parse_procfs_root(FIXTURES / "malformed" / "proc", host_id="lab-host")

    with pytest.raises(ValueError, match="malformed ss endpoint on line 2"):
        parse_ss_text((FIXTURES / "malformed" / "ss_bad.txt").read_text(encoding="utf-8"))

    with pytest.raises(ValueError, match="unsupported ss protocol on line 1: u_str"):
        parse_ss_text("u_str ESTAB 0 0 /run/example.sock *  users:((\"example\",pid=10,fd=3))")


SS_SOCKET = "tcp LISTEN 0 64 127.0.0.1:9000 0.0.0.0:*"
SS_WORKER_A = '("worker-a",pid=120,fd=3)'
SS_WORKER_B = '("worker-b",pid=220,fd=4)'
SS_BAD_WORKER = '("worker-b",pid=bad,fd=4)'


@pytest.mark.parametrize(
    ("tail", "expected"),
    [
        pytest.param(f"users:({SS_WORKER_A})", [("worker-a", 120)], id="single"),
        pytest.param(f"users:({SS_WORKER_A},{SS_WORKER_B})",
                     [("worker-a", 120), ("worker-b", 220)], id="multiple"),
        pytest.param(f"users:({SS_WORKER_B},{SS_WORKER_A})",
                     [("worker-a", 120), ("worker-b", 220)], id="reversed"),
        pytest.param(f"users:({SS_WORKER_A},{SS_WORKER_A})",
                     [("worker-a", 120)], id="duplicate"),
        pytest.param(f'users:({SS_WORKER_A},("worker-a",pid=120,fd=9))',
                     [("worker-a", 120)], id="different-fd"),
        pytest.param("", [], id="missing"),
        pytest.param('users:(("worker, (a)",pid=120,fd=3))',
                     [("worker, (a)", 120)], id="quoted-delimiters"),
        pytest.param('users:(("worker-a",pid=000120,fd=00))',
                     [("worker-a", 120)], id="leading-zeroes"),
        pytest.param('users:(("worker-a",pid=\u0661\u0662\u0660,fd=3))',
                     [("worker-a", 120)], id="decimal-digits"),
        pytest.param('users:(("worker-a",pid=0,fd=0))',
                     [("worker-a", 0)], id="zero"),
    ],
)
def test_complete_ss_users_preserves_reference_projection(tail, expected):
    line = SS_SOCKET + (f" {tail}" if tail else "")
    refs = parse_ss_text(line)[0].process_refs

    assert [(item.name, item.pid) for item in refs] == expected


@pytest.mark.parametrize(
    "tail",
    [
        pytest.param(f"users:({SS_WORKER_A},{SS_BAD_WORKER})", id="valid-then-malformed"),
        pytest.param(f"users:({SS_BAD_WORKER},{SS_WORKER_A})", id="malformed-then-valid"),
        pytest.param(f"users:({SS_WORKER_A}", id="truncated-wrapper"),
        pytest.param('users:(("worker-a",pid=120', id="truncated-reference"),
        pytest.param(f"users:({SS_WORKER_A},garbage)", id="garbage-inside"),
        pytest.param(f"users:({SS_WORKER_A}) trailing", id="garbage-after"),
        pytest.param('users:(("worker-a",pid=120junk,fd=3))', id="pid-suffix"),
        pytest.param('users:(("worker-a",pid=120,fd=bad))', id="nonnumeric-fd"),
        pytest.param(SS_WORKER_A, id="missing-wrapper"),
        pytest.param(f"users:({SS_BAD_WORKER})", id="malformed-only"),
        pytest.param("users:()", id="empty-users"),
    ],
)
def test_incomplete_ss_users_rejects_entire_field(tail):
    with pytest.raises(ValueError, match=r"^malformed ss process field on line 1$"):
        parse_ss_text(f"{SS_SOCKET} {tail}")


@pytest.mark.parametrize("malformed", [False, True])
def test_ss_users_long_repeated_list_is_consumed_completely(malformed):
    tail = "users:(" + ",".join([SS_WORKER_A] * 2000) + ")"
    if malformed:
        with pytest.raises(ValueError, match=r"^malformed ss process field on line 1$"):
            parse_ss_text(f"{SS_SOCKET} {tail} trailing")
    else:
        refs = parse_ss_text(f"{SS_SOCKET} {tail}")[0].process_refs
        assert [(item.name, item.pid) for item in refs] == [("worker-a", 120)]
