from pathlib import Path
import json

from linux_process_observe.cli import main


PROJECT_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = PROJECT_ROOT / "tests" / "fixtures"


def test_cli_snapshot_diff_report_smoke_path(tmp_path: Path) -> None:
    baseline_dir = tmp_path / "baseline"
    changed_dir = tmp_path / "changed"
    diff_dir = tmp_path / "diff"

    assert _snapshot("baseline", "2026-07-05T00:00:00Z", baseline_dir) == 0
    assert _snapshot("changed", "2026-07-05T00:05:00Z", changed_dir) == 0
    assert (
        main(
            [
                "diff",
                "--before-processes",
                str(baseline_dir / "process_snapshot.json"),
                "--after-processes",
                str(changed_dir / "process_snapshot.json"),
                "--before-links",
                str(baseline_dir / "process_socket_links.json"),
                "--after-links",
                str(changed_dir / "process_socket_links.json"),
                "--output-dir",
                str(diff_dir),
            ]
        )
        == 0
    )

    assert {item.name for item in baseline_dir.iterdir()} == {"process_snapshot.json", "process_socket_links.json"}
    assert {item.name for item in diff_dir.iterdir()} == {"process_diff.json", "report.md"}
    payload = json.loads((diff_dir / "process_diff.json").read_text(encoding="utf-8"))
    assert payload["schema"] == "stacknil.system-evidence.v1"
    assert "Processes: +1 / -1 / 1 modified" in (diff_dir / "report.md").read_text(encoding="utf-8")


def test_cli_reports_malformed_procfs_with_input_context(tmp_path: Path, capsys) -> None:
    exit_code = main(
        [
            "snapshot",
            "--proc-root",
            str(FIXTURES / "malformed" / "proc"),
            "--ss",
            str(FIXTURES / "baseline" / "ss.txt"),
            "--host-id",
            "lab-host",
            "--observed-at",
            "2026-07-05T00:00:00Z",
            "--output-dir",
            str(tmp_path),
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 1
    assert "error command=snapshot input=proc-root" in captured.err
    assert "type=ValueError" in captured.err
    assert "pid 500: missing stat" in captured.err
    assert not (tmp_path / "process_snapshot.json").exists()


def _snapshot(name: str, observed_at: str, output_dir: Path) -> int:
    return main(
        [
            "snapshot",
            "--proc-root",
            str(FIXTURES / name / "proc"),
            "--ss",
            str(FIXTURES / name / "ss.txt"),
            "--host-id",
            "lab-host",
            "--observed-at",
            observed_at,
            "--output-dir",
            str(output_dir),
        ]
    )
