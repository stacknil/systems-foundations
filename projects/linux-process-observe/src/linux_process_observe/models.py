from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any, Mapping
import json
import re


EVIDENCE_SCHEMA = "stacknil.system-evidence.v1"
_FRACTIONAL_COMPONENT = re.compile(r"[.,](\d+)")


def parse_observed_at(value: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("observed_at must be a non-empty string")
    if any(len(digits) > 6 for digits in _FRACTIONAL_COMPONENT.findall(value)):
        raise ValueError("observed_at supports at most 6 fractional second digits")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("observed_at must be ISO 8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("observed_at must include a timezone")
    return parsed


@dataclass(frozen=True, slots=True)
class ProcessRecord:
    record_type: str
    process_id: str
    pid: int
    ppid: int
    parent_process_id: str | None
    name: str
    state: str
    uid: int
    effective_uid: int
    gid: int
    effective_gid: int
    executable: str
    argv: list[str]
    start_time_ticks: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ProcessRef:
    name: str
    pid: int


@dataclass(frozen=True, slots=True)
class SocketObservation:
    protocol: str
    state: str
    recv_q: int
    send_q: int
    local_address: str
    local_port: str | int
    remote_address: str
    remote_port: str | int
    process_refs: list[ProcessRef]


@dataclass(frozen=True, slots=True)
class ProcessSocketLink:
    record_type: str
    linked: bool
    process_id: str | None
    pid: int | None
    process_name: str | None
    executable: str | None
    uid: int | None
    gid: int | None
    protocol: str
    state: str
    socket_role: str
    exposure: str
    recv_q: int
    send_q: int
    local_address: str
    local_port: str | int
    remote_address: str
    remote_port: str | int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class EvidenceEnvelope:
    schema: str
    source: str
    host_id: str
    observed_at: str
    records: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "source": self.source,
            "host_id": self.host_id,
            "observed_at": self.observed_at,
            "records": self.records,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)

    @classmethod
    def from_mapping(cls, payload: Mapping[str, Any]) -> "EvidenceEnvelope":
        schema = payload["schema"]
        source = payload["source"]
        host_id = payload["host_id"]
        observed_at = payload["observed_at"]
        records = payload["records"]

        if schema != EVIDENCE_SCHEMA:
            raise ValueError(f"unsupported evidence schema: {schema}")
        if not isinstance(source, str) or not source.strip():
            raise ValueError("source must be a non-empty string")
        if not isinstance(host_id, str) or not host_id.strip():
            raise ValueError("host_id must be a non-empty string")
        parse_observed_at(observed_at)
        if not isinstance(records, list) or not all(isinstance(item, dict) for item in records):
            raise ValueError("records must be a list of objects")

        return cls(
            schema=schema,
            source=source,
            host_id=host_id,
            observed_at=observed_at,
            records=[dict(item) for item in records],
        )
