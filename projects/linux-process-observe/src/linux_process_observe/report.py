from __future__ import annotations

from typing import Any

from .models import EvidenceEnvelope


def build_markdown_report(diff: EvidenceEnvelope) -> str:
    process_changes = [item for item in diff.records if item.get("record_type") == "process_change"]
    socket_changes = [item for item in diff.records if item.get("record_type") == "process_socket_link_change"]

    lines = ["# Linux Process Observe Diff", ""]
    lines.append(f"- Host: `{_safe(diff.host_id)}`")
    lines.append(f"- Observed at: `{diff.observed_at}`")
    lines.append(
        "- Processes: "
        f"+{_count(process_changes, 'added')} / -{_count(process_changes, 'removed')} / "
        f"{_count(process_changes, 'modified')} modified"
    )
    lines.append(f"- Process/socket links: +{_count(socket_changes, 'added')} / -{_count(socket_changes, 'removed')}")

    lines.extend(["", "## Processes", ""])
    lines.extend(_render_changes("Added", process_changes, "added", _process_summary))
    lines.extend([""])
    lines.extend(_render_changes("Removed", process_changes, "removed", _process_summary))
    lines.extend([""])
    lines.extend(_render_changes("Modified", process_changes, "modified", _modified_process_summary))

    lines.extend(["", "## Process/socket links", ""])
    lines.extend(_render_changes("Added", socket_changes, "added", _socket_summary))
    lines.extend([""])
    lines.extend(_render_changes("Removed", socket_changes, "removed", _socket_summary))
    lines.append("")
    return "\n".join(lines)


def _count(records: list[dict[str, Any]], change_type: str) -> int:
    return sum(item.get("change_type") == change_type for item in records)


def _render_changes(title: str, records: list[dict[str, Any]], change_type: str, formatter) -> list[str]:
    lines = [f"### {title}", ""]
    selected = [item for item in records if item.get("change_type") == change_type]
    if not selected:
        return lines + ["- none"]
    return lines + [f"- `{_safe(formatter(item))}`" for item in selected]


def _process_summary(change: dict[str, Any]) -> str:
    record = change.get("after") or change.get("before") or {}
    return (
        f"{record.get('process_id')} name={record.get('name')} uid={record.get('uid')} "
        f"gid={record.get('gid')} exe={record.get('executable')}"
    )


def _modified_process_summary(change: dict[str, Any]) -> str:
    fields = ", ".join(
        f"{name}: {values.get('before')} -> {values.get('after')}"
        for name, values in change.get("changes", {}).items()
    )
    return f"{change.get('identity')} {fields}"


def _socket_summary(change: dict[str, Any]) -> str:
    record = change.get("after") or change.get("before") or {}
    process = record.get("process_id") or f"pid={record.get('pid')}"
    return (
        f"{process} {record.get('protocol')} {record.get('state')} "
        f"{record.get('local_address')}:{record.get('local_port')} -> "
        f"{record.get('remote_address')}:{record.get('remote_port')} exposure={record.get('exposure')}"
    )


def _safe(value: object) -> str:
    return str(value).replace("`", "'")
