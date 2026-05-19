from __future__ import annotations

from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from linux_socket_observe.diff import compare_snapshots
from linux_socket_observe.report import build_diff_report
from linux_socket_observe.snapshot import build_snapshot


FIXTURES = PROJECT_ROOT / "tests" / "fixtures"


def test_snapshot_diff_basics() -> None:
    before = build_snapshot(
        ss_path=FIXTURES / "baseline" / "ss.txt",
        ip_addr_path=FIXTURES / "baseline" / "ip_addr.json",
        ip_link_path=FIXTURES / "baseline" / "ip_link.json",
        ip_neigh_path=FIXTURES / "baseline" / "ip_neigh.json",
        ip_link_stats_path=FIXTURES / "baseline" / "ip_link_stats.txt",
    )
    after = build_snapshot(
        ss_path=FIXTURES / "changed" / "ss.txt",
        ip_addr_path=FIXTURES / "changed" / "ip_addr.json",
        ip_link_path=FIXTURES / "changed" / "ip_link.json",
        ip_neigh_path=FIXTURES / "changed" / "ip_neigh.json",
        ip_link_stats_path=FIXTURES / "changed" / "ip_link_stats.txt",
    )

    diff = compare_snapshots(before, after)
    report = build_diff_report(diff)

    assert diff.interfaces_added == ["wg0"]
    assert diff.interfaces_removed == ["cni0"]
    assert "eth0: mtu 1500 -> 9000" in diff.interface_changes
    assert "eth0 inet 192.0.2.11/24" in diff.addresses_added
    assert "eth0 inet 192.0.2.10/24" in diff.addresses_removed
    assert "eth0 192.0.2.1: state REACHABLE -> STALE" in diff.neighbor_changes
    assert "python3" in report
    assert "wg0" in report
