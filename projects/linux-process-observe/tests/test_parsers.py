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
