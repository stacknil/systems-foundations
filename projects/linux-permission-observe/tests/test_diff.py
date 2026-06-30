from __future__ import annotations

from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from linux_permission_observe.diff import compare_snapshots
from linux_permission_observe.report import build_diff_report
from linux_permission_observe.snapshot import build_snapshot


FIXTURES = PROJECT_ROOT / "tests" / "fixtures"


def test_permission_diff_basics() -> None:
    before = build_snapshot(
        files_path=FIXTURES / "baseline" / "files.tsv",
        groups_path=FIXTURES / "baseline" / "groups.txt",
        sudoers_path=FIXTURES / "baseline" / "sudoers.txt",
    )
    after = build_snapshot(
        files_path=FIXTURES / "changed" / "files.tsv",
        groups_path=FIXTURES / "changed" / "groups.txt",
        sudoers_path=FIXTURES / "changed" / "sudoers.txt",
    )

    diff = compare_snapshots(before, after)
    report = build_diff_report(diff)

    assert "/etc/sudoers.d/app-admin" in diff.files_added
    assert "/etc/ssh/sshd_config: mode 0644 -> 0664" in diff.file_changes
    assert "/usr/local/bin/deploy-helper: owner root -> deploybot" in diff.file_changes
    assert "sudo: added members bob" in diff.group_changes
    assert any("bob lab-host=(root)" in item for item in diff.sudoers_added)
    assert "Linux Permission Observe Drift" in report

