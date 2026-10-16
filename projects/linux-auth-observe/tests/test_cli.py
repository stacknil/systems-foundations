from __future__ import annotations

from pathlib import Path
import errno
import json
import os
import subprocess
import sys

import pytest

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


@pytest.mark.parametrize("source", ["auto", "journal_json"])
@pytest.mark.parametrize("error_output", [False, True])
def test_normalize_cli_reports_missing_input_without_traceback(tmp_path: Path, source: str, error_output: bool) -> None:
    output_path = tmp_path / "events.jsonl"
    error_path = tmp_path / "errors.jsonl"
    output_path.write_text("existing events\n", encoding="utf-8")
    error_path.write_text("existing errors\n", encoding="utf-8")
    args = ["normalize", "--input", "missing.log", "--source", source, "--output", "events.jsonl"]
    if error_output:
        args += ["--error-output", "errors.jsonl"]
    env = os.environ.copy()
    env["PYTHONPATH"] = str(PROJECT_ROOT / "src")
    result = subprocess.run(
        [sys.executable, "-m", "linux_auth_observe", *args],
        cwd=tmp_path, env=env, capture_output=True, text=True, timeout=10,
    )

    assert result.returncode == 1
    assert result.stdout == ""
    assert result.stderr.startswith("error input=missing.log type=FileNotFoundError message=")
    assert len(result.stderr.splitlines()) == 1
    assert "Traceback" not in result.stderr
    assert output_path.read_text(encoding="utf-8") == "existing events\n"
    assert error_path.read_text(encoding="utf-8") == "existing errors\n"


@pytest.mark.parametrize("source", ["auto", "journal_json"])
@pytest.mark.parametrize("error_output", [False, True])
def test_normalize_cli_reports_input_permission_error(tmp_path: Path, capsys, monkeypatch, source: str, error_output: bool) -> None:
    input_path = tmp_path / "unreadable.log"
    output_path = tmp_path / "events.jsonl"
    error_path = tmp_path / "errors.jsonl"
    input_path.write_text("synthetic input\n", encoding="utf-8")
    output_path.write_text("existing events\n", encoding="utf-8")
    error_path.write_text("existing errors\n", encoding="utf-8")
    original_open = Path.open

    def deny_input_open(path: Path, *args, **kwargs):
        if path == input_path:
            raise PermissionError(errno.EACCES, "Permission denied", str(path))
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", deny_input_open)
    args = ["normalize", "--input", str(input_path), "--source", source, "--output", str(output_path)]
    if error_output:
        args += ["--error-output", str(error_path)]
    exit_code = main(args)
    captured = capsys.readouterr()

    assert exit_code == 1
    assert captured.out == ""
    assert captured.err.startswith(f"error input={input_path} type=PermissionError message=")
    assert len(captured.err.splitlines()) == 1
    assert "Traceback" not in captured.err
    assert output_path.read_text(encoding="utf-8") == "existing events\n"
    assert error_path.read_text(encoding="utf-8") == "existing errors\n"


def test_normalize_cli_does_not_relabel_output_open_failures(tmp_path: Path) -> None:
    input_path = tmp_path / "empty.jsonl"
    input_path.write_text("", encoding="utf-8")

    with pytest.raises(OSError):
        main(["normalize", "--input", str(input_path), "--source", "journal_json", "--output", str(tmp_path)])


def test_normalize_cli_reports_oserror_without_strerror(tmp_path: Path, capsys, monkeypatch) -> None:
    input_path = tmp_path / "input.jsonl"
    output_path = tmp_path / "events.jsonl"
    error_path = tmp_path / "errors.jsonl"
    input_path.write_text("synthetic input\n", encoding="utf-8")
    failure = OSError("synthetic input open failure")
    assert failure.strerror is None
    original_open = Path.open

    def fail_input_open(path: Path, *args, **kwargs):
        if path == input_path:
            raise failure
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", fail_input_open)
    exit_code = main([
        "normalize", "--input", str(input_path), "--source", "journal_json",
        "--output", str(output_path), "--error-output", str(error_path),
    ])
    captured = capsys.readouterr()

    assert exit_code == 1
    assert captured.out == ""
    assert captured.err == f"error input={input_path} type=OSError message={failure}\n"
    assert not output_path.exists()
    assert not error_path.exists()
