from __future__ import annotations

from pathlib import Path
import json
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from linux_permission_observe.cli import main


FIXTURES = PROJECT_ROOT / "tests" / "fixtures"


def test_cli_snapshot_and_diff_smoke_path(tmp_path: Path) -> None:
    before_path = tmp_path / "before.json"
    after_path = tmp_path / "after.json"
    report_path = tmp_path / "diff.md"

    assert (
        main(
            [
                "snapshot",
                "--files",
                str(FIXTURES / "baseline" / "files.tsv"),
                "--groups",
                str(FIXTURES / "baseline" / "groups.txt"),
                "--sudoers",
                str(FIXTURES / "baseline" / "sudoers.txt"),
                "--output",
                str(before_path),
            ]
        )
        == 0
    )
    assert (
        main(
            [
                "snapshot",
                "--files",
                str(FIXTURES / "changed" / "files.tsv"),
                "--groups",
                str(FIXTURES / "changed" / "groups.txt"),
                "--sudoers",
                str(FIXTURES / "changed" / "sudoers.txt"),
                "--output",
                str(after_path),
            ]
        )
        == 0
    )
    assert main(["diff", "--before", str(before_path), "--after", str(after_path), "--output", str(report_path)]) == 0

    payload = json.loads(after_path.read_text(encoding="utf-8"))
    report = report_path.read_text(encoding="utf-8")

    assert payload["schema_version"] == "0.1.0"
    assert len(payload["files"]) == 5
    assert "Changed files" in report
    assert "Added sudoers rules" in report


def test_cli_reports_snapshot_input_failures_cleanly(tmp_path: Path, capsys) -> None:
    output_path = tmp_path / "broken.json"

    exit_code = main(
        [
            "snapshot",
            "--files",
            str(FIXTURES / "malformed" / "files_bad.tsv"),
            "--groups",
            str(FIXTURES / "baseline" / "groups.txt"),
            "--sudoers",
            str(FIXTURES / "baseline" / "sudoers.txt"),
            "--output",
            str(output_path),
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 1
    assert "error command=snapshot input=files" in captured.err
    assert "type=ValueError" in captured.err
    assert "invalid mode on files TSV line 2" in captured.err
    assert not output_path.exists()

