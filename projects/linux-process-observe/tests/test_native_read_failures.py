"""Saved-input failure contracts; POSIX probes require real native filesystem behavior."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from linux_process_observe.cli import main
from linux_process_observe.snapshot import build_snapshot_artifacts

PROJECT = Path(__file__).resolve().parents[1]
FIXTURES = PROJECT / "tests/fixtures"
POSIX = pytest.mark.skipif(os.name != "posix", reason="requires POSIX links or FIFO objects")
UNPRIVILEGED = pytest.mark.skipif(
    os.name != "posix" or getattr(os, "geteuid", lambda: 0)() == 0,
    reason="requires an unprivileged POSIX user; root bypasses chmod denial",
)


@pytest.fixture
def saved(tmp_path):
    proc = tmp_path / "proc"
    shutil.copytree(FIXTURES / "baseline/proc", proc)
    ss = tmp_path / "ss.txt"
    shutil.copy2(FIXTURES / "baseline/ss.txt", ss)
    return proc, ss, tmp_path / "output"


def arguments(proc, ss, output):
    return ["snapshot", "--proc-root", str(proc), "--ss", str(ss), "--host-id", "lab-host",
            "--observed-at", "2026-07-05T00:05:00Z", "--output-dir", str(output)]


def contents(output):
    return {path.name: path.read_bytes() for path in output.iterdir()} if output.exists() else {}


def seed(saved, capsys):
    assert main(arguments(*saved)) == 0
    capsys.readouterr()
    return contents(saved[2])


def rejected(saved, capsys, category, kind, detail, preserved):
    assert main(arguments(*saved)) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert f"error command=snapshot input={category}" in captured.err
    assert f"type={kind}" in captured.err and detail in captured.err
    assert "Traceback" not in captured.err and "PRIVATE_FIELD_CONTENT" not in captured.err
    assert contents(saved[2]) == preserved
    if not preserved:
        assert not saved[2].exists()


@UNPRIVILEGED
@pytest.mark.parametrize("which", ["status", "proc-root", "ss"])
def test_native_permission_denial_is_not_empty_success(saved, capsys, which):
    proc, ss, _ = saved
    preserved = seed(saved, capsys)
    path = {"status": proc / "120/status", "proc-root": proc, "ss": ss}[which]
    mode = path.stat().st_mode
    try:
        path.chmod(0)
        rejected(saved, capsys, "ss" if which == "ss" else "proc-root",
                 "PermissionError", "Permission denied", preserved)
    finally:
        path.chmod(mode)


@pytest.mark.parametrize("existing", [False, True])
def test_required_file_disappearing_after_discovery_rejects_all(saved, capsys, monkeypatch, existing):
    proc, _, _ = saved
    preserved = seed(saved, capsys) if existing else {}
    original = Path.iterdir
    discovered = []
    def entries(path):
        items = list(original(path))
        if path == proc:
            discovered.extend(items)
            (proc / "120/stat").unlink()
        return iter(items)
    monkeypatch.setattr(Path, "iterdir", entries)
    rejected(saved, capsys, "proc-root", "ValueError", "pid 120: missing stat", preserved)
    assert proc / "120" in discovered


@pytest.mark.parametrize("field", ["status", "stat", "cmdline", "exe", "ss"])
def test_invalid_text_has_field_attribution_and_preserves_outputs(saved, capsys, field):
    proc, ss, _ = saved
    preserved = seed(saved, capsys)
    target = ss if field == "ss" else proc / "120" / field
    target.write_bytes(b"PRIVATE_FIELD_CONTENT\xff")
    kind = "ValueError" if field == "cmdline" else "UnicodeDecodeError"
    rejected(saved, capsys, "ss" if field == "ss" else "proc-root", kind,
             "ss:" if field == "ss" else f"pid 120: {field}", preserved)


@POSIX
def test_invalid_executable_link_text_is_rejected_before_any_write(saved, capsys):
    proc, _, _ = saved
    preserved = seed(saved, capsys)
    target = proc / "120/exe"
    target.unlink()
    os.symlink(b"\xff", os.fsencode(target))
    rejected(saved, capsys, "proc-root", "UnicodeDecodeError", "pid 120: exe", preserved)


@pytest.mark.parametrize("field", ["status", "ss"])
def test_directory_in_place_of_required_file_is_rejected(saved, capsys, field):
    proc, ss, _ = saved
    preserved = seed(saved, capsys)
    target = ss if field == "ss" else proc / "120/status"
    target.unlink()
    target.mkdir()
    rejected(saved, capsys, "ss" if field == "ss" else "proc-root", "IsADirectoryError",
             "ss:" if field == "ss" else "pid 120: status", preserved)


def child_env():
    return dict(os.environ, PYTHONPATH=str(PROJECT / "src"), PYTHONDONTWRITEBYTECODE="1",
                PYTHONNOUSERSITE="1")


@POSIX
@pytest.mark.parametrize("field", ["status", "exe", "ss"])
def test_fifo_input_is_bounded_failure_without_writer(saved, capsys, field, tmp_path):
    proc, ss, output = saved
    preserved = seed(saved, capsys)
    target = ss if field == "ss" else proc / "120" / field
    target.unlink()
    os.mkfifo(target)
    result = subprocess.run([sys.executable, "-m", "linux_process_observe", *arguments(*saved)],
                            cwd=tmp_path, env=child_env(), capture_output=True, text=True, timeout=5)
    assert result.returncode == 1 and result.stdout == ""
    assert f"input={'ss' if field == 'ss' else 'proc-root'}" in result.stderr
    assert "regular file" in result.stderr and "Traceback" not in result.stderr
    assert contents(output) == preserved


@POSIX
def test_replacement_with_fifo_after_stat_cannot_block_or_be_read(saved, tmp_path):
    # A pre-open stat alone is insufficient. Replace the object deterministically
    # after inspection; run in a bounded child so a blocking-open mutant fails.
    code = """
import os, sys
from pathlib import Path
from unittest.mock import patch
from linux_process_observe.parsers.saved_files import read_saved_bytes
path = Path(sys.argv[1])
original = Path.stat
changed = []
def inspect(self, *args, **kwargs):
    result = original(self, *args, **kwargs)
    if self == path and not changed:
        changed.append(True)
        path.unlink()
        os.mkfifo(path)
    return result
with patch.object(Path, 'stat', inspect):
    try:
        read_saved_bytes(path, context='pid 120: status')
    except ValueError as error:
        assert 'regular file' in str(error) and changed
    else:
        raise AssertionError('replacement FIFO accepted')
"""
    result = subprocess.run([sys.executable, "-c", code, str(saved[0] / "120/status")],
                            cwd=tmp_path, env=child_env(), capture_output=True, text=True, timeout=5)
    assert result.returncode == 0, result.stderr


@POSIX
@pytest.mark.parametrize("exists", [False, True])
def test_executable_link_target_is_context_not_a_file_to_follow(saved, tmp_path, exists):
    proc, ss, _ = saved
    executable = tmp_path / "synthetic-executable"
    if exists:
        executable.write_text("context only", encoding="utf-8")
    target = proc / "120/exe"
    target.unlink()
    target.symlink_to(executable)
    processes, _ = build_snapshot_artifacts(proc_root=proc, ss_path=ss, host_id="lab-host",
                                             observed_at="2026-07-05T00:05:00Z")
    assert next(row for row in processes.records if row["pid"] == 120)["executable"] == str(executable)


@POSIX
def test_numeric_directory_links_keep_existing_trusted_export_profile(saved, tmp_path):
    proc, ss, _ = saved
    real = tmp_path / "saved-pid"
    shutil.move(proc / "120", real)
    (proc / "120").symlink_to(real, target_is_directory=True)
    (proc / "999").symlink_to(tmp_path / "missing-pid", target_is_directory=True)
    (proc / "1000").write_text("not a directory", encoding="utf-8")
    (proc / "metadata").mkdir()
    processes, _ = build_snapshot_artifacts(proc_root=proc, ss_path=ss, host_id="lab-host",
                                             observed_at="2026-07-05T00:05:00Z")
    assert [row["pid"] for row in processes.records] == [1, 120, 220, 230]


def test_empty_readable_export_is_distinct_from_failed_enumeration(saved):
    proc, ss, output = saved
    empty = proc.parent / "empty"
    empty.mkdir()
    ss.write_text("", encoding="utf-8")
    assert main(arguments(empty, ss, output)) == 0
    for name in ("process_snapshot.json", "process_socket_links.json"):
        assert json.loads((output / name).read_text(encoding="utf-8"))["records"] == []


@pytest.mark.parametrize("field,detail", [("pid", "stat pid is 121"),
                                        ("ppid", "PPid differs"), ("state", "state differs")])
def test_inconsistent_saved_identity_rejects_existing_outputs(saved, capsys, field, detail):
    proc, _, _ = saved
    preserved = seed(saved, capsys)
    path = proc / "120/stat"
    text = path.read_text(encoding="utf-8")
    closing = text.rfind(")")
    prefix, columns = text[:closing + 1], text[closing + 1:].split()
    if field == "pid":
        prefix = prefix.replace("120 (", "121 (", 1)
    else:
        columns[1 if field == "ppid" else 0] = "999" if field == "ppid" else "R"
    path.write_text(prefix + " " + " ".join(columns), encoding="utf-8")
    rejected(saved, capsys, "proc-root", "ValueError", detail, preserved)


@POSIX
def test_broken_required_file_link_rejects_existing_outputs(saved, capsys):
    proc, _, _ = saved
    preserved = seed(saved, capsys)
    path = proc / "120/status"
    path.unlink()
    path.symlink_to("missing-status")
    rejected(saved, capsys, "proc-root", "ValueError", "pid 120: missing status", preserved)


@pytest.mark.parametrize("command", ["snapshot", "diff"])
def test_output_failure_has_separate_attribution(saved, capsys, tmp_path, command):
    target = tmp_path / "occupied-output"
    target.write_bytes(b"preserve unrelated output")
    args = arguments(saved[0], saved[1], target)
    if command == "diff":
        args = ["diff"]
        for phase, name in (("before", "baseline"), ("after", "changed")):
            for option, filename in (("processes", "process_snapshot.json"), ("links", "process_socket_links.json")):
                args.extend([f"--{phase}-{option}", str(PROJECT / "tests/golden" / name / filename)])
        args.extend(["--output-dir", str(target)])
    assert main(args) == 1
    captured = capsys.readouterr()
    assert captured.out == "" and f"error command={command} input=output" in captured.err
    assert "type=FileExistsError" in captured.err and "Traceback" not in captured.err
    assert target.read_bytes() == b"preserve unrelated output"
