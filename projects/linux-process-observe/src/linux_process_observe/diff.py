from __future__ import annotations

from typing import Any

from .models import EVIDENCE_SCHEMA, EvidenceEnvelope


def build_diff_envelope(
    *,
    before_processes: EvidenceEnvelope,
    after_processes: EvidenceEnvelope,
    before_links: EvidenceEnvelope,
    after_links: EvidenceEnvelope,
) -> EvidenceEnvelope:
    _validate_artifacts(before_processes, after_processes, before_links, after_links)

    before_process_map = _records_by_key(before_processes, record_type="process", key="process_id")
    after_process_map = _records_by_key(after_processes, record_type="process", key="process_id")
    before_link_map = _links_by_identity(before_links)
    after_link_map = _links_by_identity(after_links)

    changes: list[dict[str, Any]] = []
    for identity in sorted(after_process_map.keys() - before_process_map.keys()):
        changes.append(_change("process_change", "added", identity, None, after_process_map[identity]))
    for identity in sorted(before_process_map.keys() - after_process_map.keys()):
        changes.append(_change("process_change", "removed", identity, before_process_map[identity], None))
    for identity in sorted(before_process_map.keys() & after_process_map.keys()):
        before = before_process_map[identity]
        after = after_process_map[identity]
        field_changes = _field_changes(before, after)
        if field_changes:
            changes.append(_change("process_change", "modified", identity, before, after, field_changes))

    for identity in sorted(after_link_map.keys() - before_link_map.keys()):
        changes.append(_change("process_socket_link_change", "added", identity, None, after_link_map[identity]))
    for identity in sorted(before_link_map.keys() - after_link_map.keys()):
        changes.append(_change("process_socket_link_change", "removed", identity, before_link_map[identity], None))

    return EvidenceEnvelope(
        schema=EVIDENCE_SCHEMA,
        source="procfs+ss",
        host_id=after_processes.host_id,
        observed_at=after_processes.observed_at,
        records=changes,
    )


def _validate_artifacts(*envelopes: EvidenceEnvelope) -> None:
    host_ids = {item.host_id for item in envelopes}
    if len(host_ids) != 1:
        raise ValueError("all artifacts must use the same host_id")
    if envelopes[0].source != "procfs" or envelopes[1].source != "procfs":
        raise ValueError("process artifacts must use source=procfs")
    if envelopes[2].source != "procfs+ss" or envelopes[3].source != "procfs+ss":
        raise ValueError("link artifacts must use source=procfs+ss")


def _records(envelope: EvidenceEnvelope, record_type: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for index, record in enumerate(envelope.records, start=1):
        if record.get("record_type") != record_type:
            raise ValueError(f"record {index} must have record_type={record_type}")
        records.append(record)
    return records


def _records_by_key(envelope: EvidenceEnvelope, *, record_type: str, key: str) -> dict[str, dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}
    for record in _records(envelope, record_type):
        value = record.get(key)
        if not isinstance(value, str) or not value:
            raise ValueError(f"{record_type} record missing {key}")
        if value in records:
            raise ValueError(f"duplicate {record_type} {key}: {value}")
        records[value] = record
    return records


def _link_identity(record: dict[str, Any]) -> str:
    process = record.get("process_id") or f"pid={record.get('pid', 'unknown')}"
    return (
        f"{process}|{record.get('protocol')}|{record.get('state')}|"
        f"{record.get('local_address')}:{record.get('local_port')}|"
        f"{record.get('remote_address')}:{record.get('remote_port')}"
    )


def _links_by_identity(envelope: EvidenceEnvelope) -> dict[str, dict[str, Any]]:
    links: dict[str, dict[str, Any]] = {}
    for record in _records(envelope, "process_socket_link"):
        identity = _link_identity(record)
        if identity in links:
            raise ValueError(f"duplicate process_socket_link identity: {identity}")
        links[identity] = record
    return links


def _field_changes(before: dict[str, Any], after: dict[str, Any]) -> dict[str, dict[str, Any]]:
    immutable = {"record_type", "process_id", "pid", "start_time_ticks"}
    changes: dict[str, dict[str, Any]] = {}
    for field in sorted((before.keys() | after.keys()) - immutable):
        if before.get(field) != after.get(field):
            changes[field] = {"before": before.get(field), "after": after.get(field)}
    return changes


def _change(
    record_type: str,
    change_type: str,
    identity: str,
    before: dict[str, Any] | None,
    after: dict[str, Any] | None,
    changes: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "record_type": record_type,
        "change_type": change_type,
        "identity": identity,
        "before": before,
        "after": after,
        "changes": changes or {},
    }
