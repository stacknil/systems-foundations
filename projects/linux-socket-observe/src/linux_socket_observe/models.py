from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Mapping
import json


@dataclass(slots=True)
class SocketRecord:
    netid: str
    state: str
    family: str
    recv_q: int
    send_q: int
    local_address: str
    local_port: str | int
    peer_address: str
    peer_port: str | int
    processes: list[str]
    pids: list[int]


@dataclass(slots=True)
class InterfaceRecord:
    ifindex: int
    ifname: str
    flags: list[str]
    mtu: int
    operstate: str | None
    link_type: str | None
    address: str | None
    broadcast: str | None
    stats: dict[str, int] | None


@dataclass(slots=True)
class AddressRecord:
    ifindex: int
    ifname: str
    family: str
    local: str
    prefixlen: int
    scope: str | None
    label: str | None
    broadcast: str | None


@dataclass(slots=True)
class NeighborRecord:
    dev: str
    dst: str
    lladdr: str | None
    state: str | None


@dataclass(slots=True)
class NetworkSnapshot:
    schema_version: str
    sockets: list[SocketRecord]
    interfaces: list[InterfaceRecord]
    addresses: list[AddressRecord]
    neighbors: list[NeighborRecord]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "sockets": [_record_to_dict(item) for item in self.sockets],
            "interfaces": [_record_to_dict(item) for item in self.interfaces],
            "addresses": [_record_to_dict(item) for item in self.addresses],
            "neighbors": [_record_to_dict(item) for item in self.neighbors],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)

    @classmethod
    def from_mapping(cls, payload: Mapping[str, Any]) -> "NetworkSnapshot":
        return cls(
            schema_version=str(payload["schema_version"]),
            sockets=[SocketRecord(**item) for item in payload.get("sockets", [])],
            interfaces=[InterfaceRecord(**item) for item in payload.get("interfaces", [])],
            addresses=[AddressRecord(**item) for item in payload.get("addresses", [])],
            neighbors=[NeighborRecord(**item) for item in payload.get("neighbors", [])],
        )


def _record_to_dict(record: object) -> dict[str, Any]:
    return asdict(record)
