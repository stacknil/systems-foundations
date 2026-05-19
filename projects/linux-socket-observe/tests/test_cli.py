from __future__ import annotations

from pathlib import Path
import json
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from linux_socket_observe.cli import main


FIXTURES = PROJECT_ROOT / "tests" / "fixtures"


def test_cli_smoke_path(tmp_path: Path) -> None:
    before_path = tmp_path / "before.json"
    after_path = tmp_path / "after.json"
    report_path = tmp_path / "diff.md"

    assert (
        main(
            [
                "snapshot",
                "--ss",
                str(FIXTURES / "baseline" / "ss.txt"),
                "--ip-addr",
                str(FIXTURES / "baseline" / "ip_addr.json"),
                "--ip-link",
                str(FIXTURES / "baseline" / "ip_link.json"),
                "--ip-neigh",
                str(FIXTURES / "baseline" / "ip_neigh.json"),
                "--ip-link-stats",
                str(FIXTURES / "baseline" / "ip_link_stats.txt"),
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
                "--ss",
                str(FIXTURES / "changed" / "ss.txt"),
                "--ip-addr",
                str(FIXTURES / "changed" / "ip_addr.json"),
                "--ip-link",
                str(FIXTURES / "changed" / "ip_link.json"),
                "--ip-neigh",
                str(FIXTURES / "changed" / "ip_neigh.json"),
                "--ip-link-stats",
                str(FIXTURES / "changed" / "ip_link_stats.txt"),
                "--output",
                str(after_path),
            ]
        )
        == 0
    )
    assert main(["diff", "--before", str(before_path), "--after", str(after_path), "--output", str(report_path)]) == 0

    before_payload = json.loads(before_path.read_text(encoding="utf-8"))
    report = report_path.read_text(encoding="utf-8")

    assert before_payload["schema_version"] == "0.1.0"
    assert len(before_payload["sockets"]) == 4
    assert len(before_payload["interfaces"]) == 3
    assert "# Linux Socket Observe Diff" in report
    assert "Changed interfaces" in report


def test_cli_reports_snapshot_input_failures_cleanly(tmp_path: Path, capsys) -> None:
    output_path = tmp_path / "broken.json"

    exit_code = main(
        [
            "snapshot",
            "--ss",
            str(FIXTURES / "malformed" / "ss_bad.txt"),
            "--ip-addr",
            str(FIXTURES / "baseline" / "ip_addr.json"),
            "--ip-link",
            str(FIXTURES / "baseline" / "ip_link.json"),
            "--ip-neigh",
            str(FIXTURES / "baseline" / "ip_neigh.json"),
            "--output",
            str(output_path),
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 1
    assert "error command=snapshot input=ss" in captured.err
    assert "type=ValueError" in captured.err
    assert "malformed ss endpoint on line 2" in captured.err
    assert not output_path.exists()


def test_cli_reports_diff_input_failures_cleanly(tmp_path: Path, capsys) -> None:
    before_path = tmp_path / "before.json"
    before_path.write_text("{not-json", encoding="utf-8")
    after_path = tmp_path / "after.json"
    after_path.write_text("{}", encoding="utf-8")
    report_path = tmp_path / "diff.md"

    exit_code = main(
        [
            "diff",
            "--before",
            str(before_path),
            "--after",
            str(after_path),
            "--output",
            str(report_path),
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 1
    assert "error command=diff input=before" in captured.err
    assert "type=JSONDecodeError" in captured.err
    assert "before is not valid JSON" in captured.err
    assert not report_path.exists()
