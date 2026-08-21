from __future__ import annotations

from dataclasses import dataclass
from datetime import timezone
from ipaddress import ip_address
from pathlib import Path
from typing import Any
import json

from .models import (
    EVIDENCE_SCHEMA,
    EvidenceEnvelope,
    ProcessRecord,
    ProcessSocketLink,
    SocketObservation,
    parse_observed_at,
)
from .parsers.procfs import parse_procfs_root
from .parsers.ss_text import parse_ss_text


@dataclass(slots=True)
class EvidenceInputError(ValueError):
    input_name: str
    path: str
    error_type: str
    message: str

    def __str__(self) -> str:
        return self.message


def build_snapshot_artifacts(
    *,
    proc_root: str | Path,
    ss_path: str | Path,
    host_id: str,
    observed_at: str,
) -> tuple[EvidenceEnvelope, EvidenceEnvelope]:
    normalized_host = host_id.strip()
    if not normalized_host:
        raise EvidenceInputError("host-id", "-", "ValueError", "host_id must be non-empty")
    normalized_time = normalize_observed_at(observed_at)

    try:
        processes = parse_procfs_root(proc_root, host_id=normalized_host)
    except (FileNotFoundError, NotADirectoryError, OSError, UnicodeError, ValueError) as exc:
        raise EvidenceInputError("proc-root", str(proc_root), exc.__class__.__name__, str(exc)) from exc

    ss_path_obj = Path(ss_path)
    try:
        observations = parse_ss_text(ss_path_obj.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, UnicodeError, ValueError) as exc:
        raise EvidenceInputError("ss", str(ss_path_obj), exc.__class__.__name__, str(exc)) from exc

    process_envelope = EvidenceEnvelope(
        schema=EVIDENCE_SCHEMA,
        source="procfs",
        host_id=normalized_host,
        observed_at=normalized_time,
        records=[item.to_dict() for item in processes],
    )
    link_envelope = EvidenceEnvelope(
        schema=EVIDENCE_SCHEMA,
        source="procfs+ss",
        host_id=normalized_host,
        observed_at=normalized_time,
        records=[item.to_dict() for item in link_processes_to_sockets(processes, observations)],
    )
    return process_envelope, link_envelope


def link_processes_to_sockets(
    processes: list[ProcessRecord], observations: list[SocketObservation]
) -> list[ProcessSocketLink]:
    processes_by_pid = {item.pid: item for item in processes}
    links: list[ProcessSocketLink] = []

    for socket in observations:
        refs = socket.process_refs or [None]
        for ref in refs:
            process = processes_by_pid.get(ref.pid) if ref is not None else None
            links.append(
                ProcessSocketLink(
                    record_type="process_socket_link",
                    linked=process is not None,
                    process_id=process.process_id if process else None,
                    pid=process.pid if process else (ref.pid if ref else None),
                    process_name=process.name if process else (ref.name if ref else None),
                    executable=process.executable if process else None,
                    uid=process.uid if process else None,
                    gid=process.gid if process else None,
                    protocol=socket.protocol,
                    state=socket.state,
                    socket_role=_socket_role(socket.state),
                    exposure=_exposure(socket.local_address),
                    recv_q=socket.recv_q,
                    send_q=socket.send_q,
                    local_address=socket.local_address,
                    local_port=socket.local_port,
                    remote_address=socket.remote_address,
                    remote_port=socket.remote_port,
                )
            )

    return sorted(links, key=_link_sort_key)


def load_envelope(path: str | Path, *, input_name: str) -> EvidenceEnvelope:
    path_obj = Path(path)
    try:
        payload = json.loads(path_obj.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise EvidenceInputError(input_name, str(path_obj), exc.__class__.__name__, f"{input_name} file not found") from exc
    except json.JSONDecodeError as exc:
        raise EvidenceInputError(input_name, str(path_obj), exc.__class__.__name__, f"{input_name} is not valid JSON") from exc
    except OSError as exc:
        raise EvidenceInputError(input_name, str(path_obj), exc.__class__.__name__, str(exc)) from exc

    try:
        if not isinstance(payload, dict):
            raise ValueError("envelope must be a JSON object")
        return EvidenceEnvelope.from_mapping(payload)
    except (KeyError, TypeError, ValueError) as exc:
        raise EvidenceInputError(
            input_name,
            str(path_obj),
            exc.__class__.__name__,
            f"{input_name} does not match the evidence envelope: {exc}",
        ) from exc


def write_envelope(envelope: EvidenceEnvelope, path: str | Path) -> None:
    path_obj = Path(path)
    path_obj.parent.mkdir(parents=True, exist_ok=True)
    path_obj.write_text(envelope.to_json() + "\n", encoding="utf-8", newline="\n")


def normalize_observed_at(value: str) -> str:
    try:
        parsed = parse_observed_at(value)
    except ValueError as exc:
        raise EvidenceInputError("observed-at", "-", exc.__class__.__name__, str(exc)) from exc
    normalized = parsed.astimezone(timezone.utc)
    timespec = "microseconds" if normalized.microsecond else "seconds"
    return normalized.isoformat(timespec=timespec).replace("+00:00", "Z")


def _socket_role(state: str) -> str:
    if state == "LISTEN":
        return "listener"
    if state in {"ESTAB", "ESTABLISHED"}:
        return "connection"
    return "endpoint"


def _exposure(address: str) -> str:
    if address in {"*", "0.0.0.0", "::"}:
        return "wildcard"
    try:
        return "loopback" if ip_address(address).is_loopback else "specific"
    except ValueError:
        return "unknown"


def _link_sort_key(item: ProcessSocketLink) -> tuple[Any, ...]:
    return (
        item.protocol,
        item.state,
        item.local_address,
        str(item.local_port),
        item.remote_address,
        str(item.remote_port),
        item.pid if item.pid is not None else -1,
    )
