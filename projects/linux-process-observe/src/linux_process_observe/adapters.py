from __future__ import annotations

from pathlib import Path
from typing import Any
import json

from .models import EVIDENCE_SCHEMA, EvidenceEnvelope


_EVENT_TYPES = {
    "process_change": "process",
    "process_socket_link_change": "socket_link",
}
_CHANGE_TYPES = {
    "process_change": frozenset(("added", "removed", "modified")),
    "process_socket_link_change": frozenset(("added", "removed")),
}
_INNER_RECORD_TYPES = {
    "process_change": "process",
    "process_socket_link_change": "process_socket_link",
}
ADAPTER_CONTRACT = "stacknil.system-evidence.telemetry.v1"
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
    if change_type not in _CHANGE_TYPES[record_type]:
        raise ValueError(
            f"record {index} has unsupported change_type={change_type} "
            f"for record_type={record_type}"
        )

    identity = _required_string(record, "identity", index)
    before, after, selected = _change_records(
        record,
        change_type,
        index,
        expected_record_type=_INNER_RECORD_TYPES[record_type],
    )
    if event_prefix == "process":
        for process_record in (before, after):
            if process_record is not None:
                _validate_process_identity(process_record, identity, index)
        source = _required_string(selected, "process_id", index)
        target = _required_string(selected, "executable", index)
    else:
        source = _socket_source(diff.host_id, selected, index)
        target = _socket_target(selected, index)

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
            "adapter_contract": ADAPTER_CONTRACT,
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


def _change_records(
    record: dict[str, Any],
    change_type: str,
    index: int,
    *,
    expected_record_type: str,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None, dict[str, Any]]:
    if "before" not in record or "after" not in record:
        raise ValueError(f"record {index} must contain before and after")

    before = record["before"]
    after = record["after"]
    if change_type == "added":
        if before is not None or not isinstance(after, dict):
            raise ValueError(
                f"record {index} added change requires before=null and after=object"
            )
        selected = after
    elif change_type == "removed":
        if not isinstance(before, dict) or after is not None:
            raise ValueError(
                f"record {index} removed change requires before=object and after=null"
            )
        selected = before
    else:
        if not isinstance(before, dict) or not isinstance(after, dict):
            raise ValueError(
                f"record {index} modified change requires before=object and after=object"
            )
        selected = after

    for change_record in (before, after):
        if change_record is None:
            continue
        inner_type = _required_string(change_record, "record_type", index)
        if inner_type != expected_record_type:
            raise ValueError(
                f"record {index} inner record_type must be {expected_record_type}"
            )
    return before, after, selected


def _validate_process_identity(
    record: dict[str, Any], identity: str, index: int
) -> None:
    process_id = _required_string(record, "process_id", index)
    if process_id != identity:
        raise ValueError(f"record {index} process_id must match identity")


def _socket_source(host_id: str, record: dict[str, Any], index: int) -> str:
    process_id = record.get("process_id")
    linked = record.get("linked")
    if linked is True:
        if not isinstance(process_id, str) or not process_id.strip():
            raise ValueError(f"record {index} linked socket requires process_id")
        return process_id.strip()
    if linked is not False:
        raise ValueError(f"record {index} socket linked must be boolean")
    if process_id is not None:
        raise ValueError(f"record {index} unlinked socket process_id must be null")

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
