from pathlib import Path
import json

import pytest

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


def test_cli_diff_rejects_reversed_snapshot_order(tmp_path: Path, capsys) -> None:
    baseline_dir = tmp_path / "baseline"
    changed_dir = tmp_path / "changed"
    diff_dir = tmp_path / "diff"
    assert _snapshot("baseline", "2026-07-05T00:10:00Z", baseline_dir) == 0
    assert _snapshot("changed", "2026-07-05T00:05:00Z", changed_dir) == 0

    exit_code = main(
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
    captured = capsys.readouterr()

    assert exit_code == 1
    assert "error command=diff input=artifacts" in captured.err
    assert "before observed_at must be earlier than after observed_at" in captured.err
    assert not diff_dir.exists()


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


@pytest.mark.parametrize("malformed_first", [False, True])
@pytest.mark.parametrize("existing_output", [False, True])
def test_cli_rejects_partial_ss_users_without_touching_outputs(
    tmp_path, capsys, malformed_first, existing_output
):
    good = '("sshd",pid=120,fd=3)'
    bad = '("app-worker",pid=bad,fd=7)'
    members = f"{bad},{good}" if malformed_first else f"{good},{bad}"
    ss = tmp_path / "ss.txt"
    ss.write_text(
        "udp UNCONN 0 0 0.0.0.0:68 0.0.0.0:*\n\n"
        f"tcp LISTEN 0 64 127.0.0.1:9000 0.0.0.0:* users:({members})\n",
        encoding="utf-8",
    )
    original_input = ss.read_bytes()
    output = tmp_path / "output"
    preserved = {}
    if existing_output:
        output.mkdir()
        for name in ("process_snapshot.json", "process_socket_links.json",
                     "process_diff.json", "report.md", "events.jsonl"):
            path = output / name
            path.write_text(f"preserve {name}\n", encoding="utf-8")
            preserved[name] = path.read_bytes()

    result = main([
        "snapshot", "--proc-root", str(FIXTURES / "baseline" / "proc"),
        "--ss", str(ss), "--host-id", "lab-host",
        "--observed-at", "2026-07-05T00:05:00Z", "--output-dir", str(output),
    ])
    captured = capsys.readouterr()

    assert result == 1
    assert captured.out == ""
    assert "error command=snapshot input=ss" in captured.err
    assert f"path={ss}" in captured.err
    assert "type=ValueError message=malformed ss process field on line 2" in captured.err
    assert "Traceback" not in captured.err
    assert ss.read_bytes() == original_input
    if existing_output:
        assert {path.name: path.read_bytes() for path in output.iterdir()} == preserved
    else:
        assert not output.exists()


def test_complete_ss_users_keeps_valid_diff_and_blocks_malformed_after(tmp_path, capsys):
    prefix = "tcp LISTEN 0 64 127.0.0.1:9000 0.0.0.0:*"
    first = '("sshd",pid=120,fd=3)'
    second = '("app-worker",pid=220,fd=7)'
    ss = tmp_path / "ss.txt"
    pairs = []
    for label, time, members in [
        ("before", "2026-07-05T00:00:00Z", f"{first},{second}"),
        ("after", "2026-07-05T00:05:00Z", f"{second},{first}"),
    ]:
        ss.write_text(f"{prefix} users:({members})\n", encoding="utf-8")
        output = tmp_path / label
        assert main([
            "snapshot", "--proc-root", str(FIXTURES / "baseline" / "proc"),
            "--ss", str(ss), "--host-id", "lab-host", "--observed-at", time,
            "--output-dir", str(output),
        ]) == 0
        links = json.loads((output / "process_socket_links.json").read_text(encoding="utf-8"))
        assert [row["pid"] for row in links["records"]] == [120, 220]
        assert all(row["linked"] is True for row in links["records"])
        pairs.append(output)

    diff_args = []
    for label, output in zip(("before", "after"), pairs):
        diff_args.extend([
            f"--{label}-processes", str(output / "process_snapshot.json"),
            f"--{label}-links", str(output / "process_socket_links.json"),
        ])
    diff_dir = tmp_path / "diff"
    assert main(["diff", *diff_args, "--output-dir", str(diff_dir)]) == 0
    assert json.loads((diff_dir / "process_diff.json").read_text(encoding="utf-8"))["records"] == []
    events = diff_dir / "events.jsonl"
    assert main(["adapt", "--input", str(diff_dir / "process_diff.json"),
                 "--output", str(events)]) == 0
    assert events.read_bytes() == b""
    assert "Process/socket links: +0 / -0" in (diff_dir / "report.md").read_text(encoding="utf-8")
    preserved = {path: path.read_bytes() for directory in [*pairs, diff_dir] for path in directory.iterdir()}
    capsys.readouterr()

    ss.write_text(f'{prefix} users:({first},("app-worker",pid=bad,fd=7))\n', encoding="utf-8")
    original_input = ss.read_bytes()
    failed_output = tmp_path / "malformed-after"
    assert main([
        "snapshot", "--proc-root", str(FIXTURES / "baseline" / "proc"),
        "--ss", str(ss), "--host-id", "lab-host",
        "--observed-at", "2026-07-05T00:05:00Z", "--output-dir", str(failed_output),
    ]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "error command=snapshot input=ss" in captured.err
    assert "malformed ss process field on line 1" in captured.err
    assert "Traceback" not in captured.err
    assert not failed_output.exists()
    assert all(path.read_bytes() == content for path, content in preserved.items())
    assert ss.read_bytes() == original_input
