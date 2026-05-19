from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path
import json

from .models import NetworkSnapshot
from .parsers import ip_json, link_stats, ss_text

SCHEMA_VERSION = "0.1.0"


@dataclass(slots=True)
class SnapshotInputError(ValueError):
    input_name: str
    path: str
    error_type: str
    message: str

    def __str__(self) -> str:
        return self.message


def build_snapshot(
    *,
    ss_path: str | Path,
    ip_addr_path: str | Path,
    ip_link_path: str | Path,
    ip_neigh_path: str | Path,
    ip_link_stats_path: str | Path | None = None,
) -> NetworkSnapshot:
    sockets = _read_and_parse(ss_path, input_name="ss", parser=ss_text.parse_ss_text)
    interfaces = _read_and_parse(ip_link_path, input_name="ip-link", parser=ip_json.parse_link_json)
    addresses = _read_and_parse(ip_addr_path, input_name="ip-addr", parser=ip_json.parse_addr_json)
    neighbors = _read_and_parse(ip_neigh_path, input_name="ip-neigh", parser=ip_json.parse_neigh_json)

    if ip_link_stats_path is not None:
        stats_by_ifname = _read_and_parse(
            ip_link_stats_path,
            input_name="ip-link-stats",
            parser=link_stats.parse_link_stats_text,
        )
        interfaces = [
            replace(interface, stats=dict(stats_by_ifname[interface.ifname]))
            if interface.ifname in stats_by_ifname
            else interface
            for interface in interfaces
        ]

    return NetworkSnapshot(
        schema_version=SCHEMA_VERSION,
        sockets=sockets,
        interfaces=interfaces,
        addresses=addresses,
        neighbors=neighbors,
    )


def load_snapshot(path: str | Path, *, input_name: str = "snapshot") -> NetworkSnapshot:
    path_obj = Path(path)
    try:
        payload = json.loads(path_obj.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SnapshotInputError(
            input_name=input_name,
            path=str(path_obj),
            error_type=exc.__class__.__name__,
            message=f"{input_name} file not found",
        ) from exc
    except json.JSONDecodeError as exc:
        raise SnapshotInputError(
            input_name=input_name,
            path=str(path_obj),
            error_type=exc.__class__.__name__,
            message=f"{input_name} is not valid JSON",
        ) from exc

    try:
        return NetworkSnapshot.from_mapping(payload)
    except (KeyError, TypeError, ValueError) as exc:
        raise SnapshotInputError(
            input_name=input_name,
            path=str(path_obj),
            error_type=exc.__class__.__name__,
            message=f"{input_name} does not match the expected snapshot schema",
        ) from exc


def _read_text(path: str | Path) -> str:
    return Path(path).read_text(encoding="utf-8")


def _read_and_parse(path: str | Path, *, input_name: str, parser):
    path_obj = Path(path)
    try:
        text = _read_text(path_obj)
        return parser(text)
    except FileNotFoundError as exc:
        raise SnapshotInputError(
            input_name=input_name,
            path=str(path_obj),
            error_type=exc.__class__.__name__,
            message=f"{input_name} file not found",
        ) from exc
    except ValueError as exc:
        raise SnapshotInputError(
            input_name=input_name,
            path=str(path_obj),
            error_type=exc.__class__.__name__,
            message=str(exc),
        ) from exc
