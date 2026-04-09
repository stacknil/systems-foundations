from __future__ import annotations

from pathlib import Path
import json
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from linux_auth_observe.cli import main


FIXTURES = PROJECT_ROOT / "tests" / "fixtures"


def test_normalize_cli_writes_valid_jsonl_for_all_supported_fixture_types(tmp_path: Path) -> None:
    cases = [
        ("ubuntu_auth.log", "auto", 5),
        ("rhel_secure.log", "auto", 4),
        ("journal_sample.jsonl", "auto", 3),
    ]

    for fixture_name, source, expected_count in cases:
        output_path = tmp_path / f"{fixture_name}.jsonl"
        exit_code = main(
            [
                "normalize",
                "--input",
                str(FIXTURES / fixture_name),
                "--source",
                source,
                "--year",
                "2026",
                "--timezone",
                "Asia/Shanghai",
                "--output",
                str(output_path),
            ]
        )

        assert exit_code == 0
        payloads = [json.loads(line) for line in output_path.read_text(encoding="utf-8").splitlines()]
        assert len(payloads) == expected_count
        assert all("raw" in payload and "message" in payload for payload in payloads)


def test_filter_cli_constrains_by_user_ip_and_service(tmp_path: Path, capsys) -> None:
    normalized_path = tmp_path / "events.jsonl"
    main(
        [
            "normalize",
            "--input",
            str(FIXTURES / "ubuntu_auth.log"),
            "--source",
            "auto",
            "--year",
            "2026",
            "--timezone",
            "Asia/Shanghai",
            "--output",
            str(normalized_path),
        ]
    )

    exit_code = main(
        [
            "filter",
            "--input",
            str(normalized_path),
            "--user",
            "alice",
            "--ip",
            "192.0.2.10",
            "--service",
            "sshd",
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 0
    rows = [json.loads(line) for line in captured.out.splitlines()]
    assert len(rows) == 2
    assert {row["event_type"] for row in rows} == {"ssh_login_failure", "ssh_login_success"}


def test_summary_cli_writes_readable_markdown_report(tmp_path: Path) -> None:
    normalized_path = tmp_path / "events.jsonl"
    report_path = tmp_path / "summary.md"
    main(
        [
            "normalize",
            "--input",
            str(FIXTURES / "journal_sample.jsonl"),
            "--source",
            "auto",
            "--year",
            "2026",
            "--timezone",
            "Asia/Shanghai",
            "--output",
            str(normalized_path),
        ]
    )

    exit_code = main(
        [
            "summary",
            "--input",
            str(normalized_path),
            "--output",
            str(report_path),
        ]
    )

    report = report_path.read_text(encoding="utf-8")
    assert exit_code == 0
    assert "# Linux Auth Observe Summary" in report
    assert "## By Event Type" in report
    assert "| service_state_change | 1 |" in report


def test_normalize_cli_can_write_structured_parse_errors(tmp_path: Path, capsys) -> None:
    normalized_path = tmp_path / "events.jsonl"
    error_path = tmp_path / "errors.jsonl"

    exit_code = main(
        [
            "normalize",
            "--input",
            str(FIXTURES / "ubuntu_auth_with_error.log"),
            "--source",
            "auto",
            "--year",
            "2026",
            "--timezone",
            "Asia/Shanghai",
            "--output",
            str(normalized_path),
            "--error-output",
            str(error_path),
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "error source=auth.log line=2 type=MalformedSyslogLineError" in captured.err

    normalized_rows = [json.loads(line) for line in normalized_path.read_text(encoding="utf-8").splitlines()]
    error_rows = [json.loads(line) for line in error_path.read_text(encoding="utf-8").splitlines()]

    assert len(normalized_rows) == 2
    assert len(error_rows) == 1
    assert error_rows[0]["source"] == "auth.log"
    assert error_rows[0]["line"] == 2
    assert error_rows[0]["error_type"] == "MalformedSyslogLineError"
    assert error_rows[0]["raw"] == "THIS IS NOT SYSLOG"
