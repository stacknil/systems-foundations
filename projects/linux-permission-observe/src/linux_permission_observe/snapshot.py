from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import json

from .models import PermissionSnapshot
from .parsers import parse_files_tsv, parse_groups, parse_sudoers

SCHEMA_VERSION = "0.1.0"


@dataclass(slots=True)
class SnapshotInputError(ValueError):
    input_name: str
    path: str
    error_type: str
    message: str

    def __str__(self) -> str:
        return self.message


def build_snapshot(*, files_path: str | Path, groups_path: str | Path, sudoers_path: str | Path) -> PermissionSnapshot:
    return PermissionSnapshot(
        schema_version=SCHEMA_VERSION,
        files=_read_and_parse(files_path, input_name="files", parser=parse_files_tsv),
        groups=_read_and_parse(groups_path, input_name="groups", parser=parse_groups),
        sudoers=_read_and_parse(sudoers_path, input_name="sudoers", parser=parse_sudoers),
    )


def load_snapshot(path: str | Path, *, input_name: str = "snapshot") -> PermissionSnapshot:
    path_obj = Path(path)
    try:
        payload = json.loads(path_obj.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SnapshotInputError(input_name, str(path_obj), exc.__class__.__name__, f"{input_name} file not found") from exc
    except json.JSONDecodeError as exc:
        raise SnapshotInputError(input_name, str(path_obj), exc.__class__.__name__, f"{input_name} is not valid JSON") from exc

    try:
        return PermissionSnapshot.from_mapping(payload)
    except (KeyError, TypeError, ValueError) as exc:
        raise SnapshotInputError(
            input_name,
            str(path_obj),
            exc.__class__.__name__,
            f"{input_name} does not match the expected permission snapshot schema",
        ) from exc


def _read_and_parse(path: str | Path, *, input_name: str, parser):
    path_obj = Path(path)
    try:
        return parser(path_obj.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SnapshotInputError(input_name, str(path_obj), exc.__class__.__name__, f"{input_name} file not found") from exc
    except ValueError as exc:
        raise SnapshotInputError(input_name, str(path_obj), exc.__class__.__name__, str(exc)) from exc

