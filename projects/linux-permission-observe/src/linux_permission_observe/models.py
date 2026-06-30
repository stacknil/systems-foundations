from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Mapping
import json


@dataclass(slots=True)
class FileRecord:
    path: str
    mode: str
    owner: str
    group: str
    type: str


@dataclass(slots=True)
class GroupRecord:
    name: str
    gid: int
    members: list[str]


@dataclass(slots=True)
class SudoersRule:
    subject: str
    hosts: list[str]
    run_as: str
    tags: list[str]
    commands: list[str]
    raw: str


@dataclass(slots=True)
class PermissionSnapshot:
    schema_version: str
    files: list[FileRecord]
    groups: list[GroupRecord]
    sudoers: list[SudoersRule]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "files": [asdict(item) for item in self.files],
            "groups": [asdict(item) for item in self.groups],
            "sudoers": [asdict(item) for item in self.sudoers],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)

    @classmethod
    def from_mapping(cls, payload: Mapping[str, Any]) -> "PermissionSnapshot":
        return cls(
            schema_version=str(payload["schema_version"]),
            files=[FileRecord(**item) for item in payload.get("files", [])],
            groups=[GroupRecord(**item) for item in payload.get("groups", [])],
            sudoers=[SudoersRule(**item) for item in payload.get("sudoers", [])],
        )

