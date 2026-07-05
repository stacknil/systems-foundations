from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import os

from ..models import ProcessRecord


REQUIRED_STATUS_FIELDS = ("Name", "State", "PPid", "Uid", "Gid")


def parse_procfs_root(root: str | Path, *, host_id: str) -> list[ProcessRecord]:
    root_path = Path(root)
    if not root_path.exists():
        raise FileNotFoundError(f"proc root not found: {root_path}")
    if not root_path.is_dir():
        raise NotADirectoryError(f"proc root is not a directory: {root_path}")

    records = [
        _parse_pid_directory(path, host_id=host_id)
        for path in sorted(
            (item for item in root_path.iterdir() if item.is_dir() and item.name.isdigit()),
            key=lambda item: int(item.name),
        )
    ]
    processes_by_pid = {item.pid: item for item in records}
    return [
        replace(
            item,
            parent_process_id=processes_by_pid[item.ppid].process_id if item.ppid in processes_by_pid else None,
        )
        for item in records
    ]


def _parse_pid_directory(pid_path: Path, *, host_id: str) -> ProcessRecord:
    pid = int(pid_path.name)
    status = _parse_status(_read_text(pid_path, "status"), pid=pid)
    stat = _parse_stat(_read_text(pid_path, "stat"), pid=pid)
    argv = _parse_cmdline(_read_bytes(pid_path, "cmdline"))
    executable = _read_executable(pid_path)

    if int(status["PPid"]) != stat["ppid"]:
        raise ValueError(f"pid {pid}: PPid differs between status and stat")
    if str(status["State"])[0] != stat["state"]:
        raise ValueError(f"pid {pid}: state differs between status and stat")

    uid_values = _parse_id_row(str(status["Uid"]), pid=pid, field="Uid")
    gid_values = _parse_id_row(str(status["Gid"]), pid=pid, field="Gid")
    start_time_ticks = stat["start_time_ticks"]

    return ProcessRecord(
        record_type="process",
        process_id=f"{host_id}:{pid}:{start_time_ticks}",
        pid=pid,
        ppid=stat["ppid"],
        parent_process_id=None,
        name=str(status["Name"]),
        state=stat["state"],
        uid=uid_values[0],
        effective_uid=uid_values[1],
        gid=gid_values[0],
        effective_gid=gid_values[1],
        executable=executable,
        argv=argv,
        start_time_ticks=start_time_ticks,
    )


def _read_text(pid_path: Path, name: str) -> str:
    try:
        return (pid_path / name).read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise ValueError(f"pid {pid_path.name}: missing {name}") from exc


def _read_bytes(pid_path: Path, name: str) -> bytes:
    try:
        return (pid_path / name).read_bytes()
    except FileNotFoundError as exc:
        raise ValueError(f"pid {pid_path.name}: missing {name}") from exc


def _read_executable(pid_path: Path) -> str:
    path = pid_path / "exe"
    try:
        value = os.readlink(path) if path.is_symlink() else path.read_text(encoding="utf-8").strip()
    except FileNotFoundError as exc:
        raise ValueError(f"pid {pid_path.name}: missing exe") from exc
    if not value:
        raise ValueError(f"pid {pid_path.name}: empty exe")
    return value


def _parse_status(text: str, *, pid: int) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", maxsplit=1)
        fields[key] = value.strip()
    missing = [field for field in REQUIRED_STATUS_FIELDS if not fields.get(field)]
    if missing:
        raise ValueError(f"pid {pid}: status missing {','.join(missing)}")
    return fields


def _parse_stat(text: str, *, pid: int) -> dict[str, int | str]:
    value = text.strip()
    opening = value.find("(")
    closing = value.rfind(")")
    if opening <= 0 or closing <= opening:
        raise ValueError(f"pid {pid}: malformed stat")

    try:
        stat_pid = int(value[:opening].strip())
        remaining = value[closing + 1 :].split()
        state = remaining[0]
        ppid = int(remaining[1])
        start_time_ticks = int(remaining[19])
    except (IndexError, ValueError) as exc:
        raise ValueError(f"pid {pid}: malformed stat") from exc

    if stat_pid != pid:
        raise ValueError(f"pid {pid}: stat pid is {stat_pid}")
    if len(state) != 1:
        raise ValueError(f"pid {pid}: malformed stat state")
    return {"state": state, "ppid": ppid, "start_time_ticks": start_time_ticks}


def _parse_cmdline(raw: bytes) -> list[str]:
    try:
        value = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("cmdline is not valid UTF-8") from exc
    value = value.rstrip("\r\n")
    separator = "\x00" if "\x00" in value else "\\0"
    return [item for item in value.split(separator) if item]


def _parse_id_row(value: str, *, pid: int, field: str) -> list[int]:
    parts = value.split()
    if len(parts) < 2:
        raise ValueError(f"pid {pid}: malformed {field}")
    try:
        return [int(item) for item in parts]
    except ValueError as exc:
        raise ValueError(f"pid {pid}: malformed {field}") from exc
