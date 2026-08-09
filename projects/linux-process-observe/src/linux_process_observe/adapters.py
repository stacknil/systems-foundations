from __future__ import annotations

from pathlib import Path
from typing import Any
import json

from .models import EVIDENCE_SCHEMA, EvidenceEnvelope


_CHANGE_TYPES = frozenset(("added", "removed", "modified"))
_EVENT_TYPES = {
    "process_change": "process",
    "process_socket_link_change": "socket_link",
}
_TIME_SEMANTICS = "snapshot_diff_observed_at"
_SOCKET_FIELDS = (
    "protocol",
    "state",
    "local_address",
    "local_port",
    "remote_address",
    "remote_port",
)


def build_telemetry_events(diff: EvidenceEnvelope) -> list[dict[str, Any]]:
    """Map a process diff envelope to telemetry-lab-compatible JSONL records."""
    if diff.schema != EVIDENCE_SCHEMA:
        raise ValueError(f"unsupported evidence schema: {diff.schema}")
    if diff.source != "procfs+ss":
        raise ValueError("process diff must use source=procfs+ss")

    return [
        _map_record(diff, record, index)
        for index, record in enumerate(diff.records, start=1)
    ]


def write_telemetry_events(events: list[dict[str, Any]], path: str | Path) -> None:
    """Write deterministic one-event-per-line telemetry JSONL."""
    output_path = Path(path)
    if output_path.exists() and output_path.is_dir():
        raise ValueError(f"output path is a directory: {output_path}")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="\n") as handle:
        for event in events:
            handle.write(
                json.dumps(
                    event,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            )


def _map_record(
    diff: EvidenceEnvelope,
    record: dict[str, Any],
    index: int,
) -> dict[str, Any]:
    record_type = _required_string(record, "record_type", index)
    event_prefix = _EVENT_TYPES.get(record_type)
    if event_prefix is None:
        raise ValueError(f"record {index} has unsupported record_type={record_type}")

    change_type = _required_string(record, "change_type", index)
    if change_type not in _CHANGE_TYPES:
        raise ValueError(f"record {index} has unsupported change_type={change_type}")

    identity = _required_string(record, "identity", index)
    selected = _selected_record(record, change_type, index)
    if event_prefix == "process":
        target = _required_string(selected, "executable", index)
    else:
        target = _socket_target(selected, index)

    source = _source_value(diff.host_id, selected)
    changes = record.get("changes", {})
    if not isinstance(changes, dict):
        raise ValueError(f"record {index} changes must be an object")

    return {
        "timestamp": diff.observed_at,
        "event_type": f"{event_prefix}_{change_type}",
        "source": source,
        "target": target,
        "status": change_type,
        "metadata": {
            "change_type": change_type,
            "evidence_schema": diff.schema,
            "evidence_source": diff.source,
            "host_id": diff.host_id,
            "identity": identity,
            "process_id": selected.get("process_id"),
            "record_index": index,
            "record_type": record_type,
            "time_semantics": _TIME_SEMANTICS,
            "changes": changes,
        },
    }


def _selected_record(
    record: dict[str, Any],
    change_type: str,
    index: int,
) -> dict[str, Any]:
    key = "before" if change_type == "removed" else "after"
    selected = record.get(key)
    if not isinstance(selected, dict):
        raise ValueError(f"record {index} {change_type} change requires an object in {key}")
    return selected


def _source_value(host_id: str, record: dict[str, Any]) -> str:
    process_id = record.get("process_id")
    if isinstance(process_id, str) and process_id.strip():
        return process_id

    pid = record.get("pid")
    if isinstance(pid, int) and not isinstance(pid, bool):
        return f"{host_id}:pid:{pid}"
    return f"{host_id}:unlinked"


def _socket_target(record: dict[str, Any], index: int) -> str:
    values = {
        field: _required_value(record, field, index) for field in _SOCKET_FIELDS
    }
    return (
        f"{values['protocol']} {values['state']} "
        f"{values['local_address']}:{values['local_port']} -> "
        f"{values['remote_address']}:{values['remote_port']}"
    )


def _required_string(record: dict[str, Any], field: str, index: int) -> str:
    value = record.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"record {index} missing non-empty {field}")
    return value.strip()


def _required_value(record: dict[str, Any], field: str, index: int) -> str | int:
    value = record.get(field)
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ValueError(f"record {index} missing valid {field}")
    if isinstance(value, str) and not value.strip():
        raise ValueError(f"record {index} missing valid {field}")
    return value
