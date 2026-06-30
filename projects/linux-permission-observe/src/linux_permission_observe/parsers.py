from __future__ import annotations

import csv
import re
from io import StringIO

from .models import FileRecord, GroupRecord, SudoersRule

_SUDOERS_RE = re.compile(r"^(?P<subject>\S+)\s+(?P<hosts>[^=]+)=\((?P<run_as>[^)]*)\)\s+(?P<rest>.+)$")


def parse_files_tsv(text: str) -> list[FileRecord]:
    rows = csv.DictReader(_without_comments(text), delimiter="\t")
    required = {"path", "mode", "owner", "group", "type"}
    if rows.fieldnames is None or set(rows.fieldnames) != required:
        raise ValueError("files TSV header must be: path, mode, owner, group, type")

    records: list[FileRecord] = []
    for line_number, row in enumerate(rows, start=2):
        path = _required(row.get("path"), "path", line_number)
        mode = _required(row.get("mode"), "mode", line_number)
        owner = _required(row.get("owner"), "owner", line_number)
        group = _required(row.get("group"), "group", line_number)
        file_type = _required(row.get("type"), "type", line_number)
        if not re.fullmatch(r"[0-7]{4}", mode):
            raise ValueError(f"invalid mode on files TSV line {line_number}: {mode}")
        records.append(FileRecord(path=path, mode=mode, owner=owner, group=group, type=file_type))
    return sorted(records, key=lambda item: item.path)


def parse_groups(text: str) -> list[GroupRecord]:
    records: list[GroupRecord] = []
    for line_number, raw_line in _iter_data_lines(text):
        parts = raw_line.split(":")
        if len(parts) != 4:
            raise ValueError(f"malformed group line {line_number}")
        name, _password, gid_text, members_text = parts
        if not name:
            raise ValueError(f"missing group name on line {line_number}")
        try:
            gid = int(gid_text)
        except ValueError as exc:
            raise ValueError(f"invalid gid on group line {line_number}: {gid_text}") from exc
        members = sorted(member for member in members_text.split(",") if member)
        records.append(GroupRecord(name=name, gid=gid, members=members))
    return sorted(records, key=lambda item: item.name)


def parse_sudoers(text: str) -> list[SudoersRule]:
    records: list[SudoersRule] = []
    for line_number, raw_line in _iter_data_lines(text):
        match = _SUDOERS_RE.match(raw_line)
        if match is None:
            raise ValueError(f"malformed sudoers line {line_number}")
        rest = match.group("rest").strip()
        tags: list[str] = []
        while True:
            tag_match = re.match(r"^([A-Z_]+):\s*(.*)$", rest)
            if tag_match is None:
                break
            tags.append(tag_match.group(1))
            rest = tag_match.group(2).strip()
        commands = [command.strip() for command in rest.split(",") if command.strip()]
        if not commands:
            raise ValueError(f"missing command list on sudoers line {line_number}")
        hosts = [host.strip() for host in match.group("hosts").split(",") if host.strip()]
        records.append(
            SudoersRule(
                subject=match.group("subject"),
                hosts=hosts,
                run_as=match.group("run_as").strip(),
                tags=tags,
                commands=commands,
                raw=raw_line,
            )
        )
    return sorted(records, key=lambda item: (item.subject, item.raw))


def _without_comments(text: str) -> StringIO:
    lines = [line for _line_number, line in _iter_data_lines(text)]
    return StringIO("\n".join(lines))


def _iter_data_lines(text: str):
    for line_number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        yield line_number, stripped


def _required(value: str | None, name: str, line_number: int) -> str:
    if value is None or value == "":
        raise ValueError(f"missing {name} on files TSV line {line_number}")
    return value

